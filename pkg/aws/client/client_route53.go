// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	route53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/gardener/external-dns-management/pkg/controller/provider/aws/data"
)

// GetDNSHostedZones returns a map of all DNS hosted zone names mapped to their IDs.
func (c *Client) GetDNSHostedZones(ctx context.Context) (map[string]string, error) {
	zones := make(map[string]string)

	paginator := route53.NewListHostedZonesPaginator(&c.Route53, &route53.ListHostedZonesInput{})
	for paginator.HasMorePages() {
		output, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, zone := range output.HostedZones {
			zones[normalizeName(aws.ToString(zone.Name))] = normalizeZoneId(aws.ToString(zone.Id))
		}

	}
	return zones, nil
}

// CreateDNSHostedZone creates the DNS hosted zone with the given name and comment, and returns the ID of the
// newly created zone.
func (c *Client) CreateDNSHostedZone(ctx context.Context, name, comment string) (string, error) {
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return "", err
	}
	output, err := c.Route53.CreateHostedZone(ctx, &route53.CreateHostedZoneInput{
		CallerReference:  aws.String(strconv.Itoa(int(time.Now().Unix()))),
		Name:             aws.String(name),
		HostedZoneConfig: &route53types.HostedZoneConfig{Comment: aws.String(comment)},
	})

	if err != nil {
		return "", err
	}
	return aws.ToString(output.HostedZone.Id), nil
}

// DeleteDNSHostedZone deletes the DNS hosted zone with the given ID.
func (c *Client) DeleteDNSHostedZone(ctx context.Context, zoneId string) error {
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return err
	}
	_, err := c.Route53.DeleteHostedZone(ctx, &route53.DeleteHostedZoneInput{
		Id: aws.String(zoneId),
	})
	return ignoreHostedZoneNotFound(err)
}

func normalizeName(name string) string {
	if strings.HasPrefix(name, "\\052.") {
		name = "*" + name[4:]
	}
	if strings.HasSuffix(name, ".") {
		return name[:len(name)-1]
	}
	return name
}

func normalizeZoneId(zoneId string) string {
	parts := strings.Split(zoneId, "/")
	return parts[len(parts)-1]
}

// CreateOrUpdateDNSRecordSet creates or updates the DNS recordset in the DNS hosted zone with the given zone ID,
// with the given name, type, values, and TTL.
// A CNAME record for AWS load balancers in a known zone may be mapped to A and/or AAAA recordsets with alias target.
func (c *Client) CreateOrUpdateDNSRecordSet(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64, stack IPStack) error {
	awsRecordType := route53types.RRType(recordType)
	rrs := newResourceRecordSets(name, awsRecordType, newResourceRecords(awsRecordType, values), ttl, stack)
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return err
	}
	_, err := c.Route53.ChangeResourceRecordSets(ctx, newChangeResourceRecordSetsInput(zoneId, route53types.ChangeActionUpsert, rrs))
	return err
}

// DeleteDNSRecordSet deletes the DNS recordset(s) in the DNS hosted zone with the given zone ID,
// with the given name, type, values, and TTL.
// If values is empty and TTL is 0 or if there are potential alias targets for a CNAME type, the actual state will be
// determined by reading the recordset(s) from the zone.
// Otherwise, an attempt will be made to delete the recordset with the given values / TTL.
// The idea is to ensure a consistent and foolproof behavior while sending as few requests as possible to avoid
// rate limit issues.
func (c *Client) DeleteDNSRecordSet(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64, stack IPStack) error {
	awsRecordType := route53types.RRType(recordType)
	if len(values) > 0 && ttl > 0 && !isPotentialAliasTarget(awsRecordType, values[0]) {
		// try deletion with known values, but only if it is no CNAME record with potential alias target records.
		// For CNAME records we don't know if the record(s) have been created with or without target records, as the list of
		// canonicalHostedZoneIds may have changed in the meantime.
		rrss := newResourceRecordSets(name, awsRecordType, newResourceRecords(awsRecordType, values), ttl, stack)
		if err := c.waitForRoute53RateLimiter(ctx); err != nil {
			return err
		}
		if _, err := c.Route53.ChangeResourceRecordSets(ctx, newChangeResourceRecordSetsInput(zoneId, route53types.ChangeActionDelete, rrss)); err == nil {
			return nil
		}
		// if there is any error, fallback to read/delete
	}
	rrss, err := c.GetDNSRecordSets(ctx, zoneId, name, recordType)
	if err != nil {
		return err
	}
	if len(rrss) == 0 {
		return nil
	}
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return err
	}
	_, err = c.Route53.ChangeResourceRecordSets(ctx, newChangeResourceRecordSetsInput(zoneId, route53types.ChangeActionDelete, rrss))
	return ignoreResourceRecordSetNotFound(err)
}

// GetDNSRecordSets returns the DNS recordset(s) in the DNS hosted zone with the given zone ID, and with the given name and type.
// For record type CNAME there may be multiple DNS recordsets if mapped to alias targets A or AAAA recordsets.
func (c *Client) GetDNSRecordSets(ctx context.Context, zoneId, name, recordType string) ([]*route53types.ResourceRecordSet, error) {
	awsRecordType := route53types.RRType(recordType)
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return nil, err
	}
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(zoneId),
		MaxItems:        aws.Int32(1),
		StartRecordName: aws.String(name),
		StartRecordType: awsRecordType,
	}
	if awsRecordType == route53types.RRTypeCname {
		input.MaxItems = aws.Int32(5) // potential CNAME, AliasTarget A and AliasTarget AAAA
		input.StartRecordType = route53types.RRType("")
	}
	out, err := c.Route53.ListResourceRecordSets(ctx, input)
	if ignoreResourceRecordSetNotFound(err) != nil {
		return nil, err
	}
	if out == nil || len(out.ResourceRecordSets) == 0 { // no records in zone
		return nil, nil
	}
	var recordSets []*route53types.ResourceRecordSet
	for _, rrs := range out.ResourceRecordSets {
		if normalizeName(aws.ToString(rrs.Name)) == name {
			switch rrs.Type {
			case awsRecordType:
				recordSets = append(recordSets, &rrs)
			case route53types.RRTypeA, route53types.RRTypeAaaa:
				if awsRecordType == route53types.RRTypeCname && rrs.AliasTarget != nil {
					recordSets = append(recordSets, &rrs)
				}
			}
		}
	}
	return recordSets, nil
}

func (c *Client) waitForRoute53RateLimiter(ctx context.Context) error {
	timeoutCtx, cancel := context.WithTimeout(ctx, c.Route53RateLimiterWaitTimeout)
	defer cancel()
	t := time.Now()
	if err := c.Route53RateLimiter.Wait(timeoutCtx); err != nil {
		return &Route53RateLimiterWaitError{Cause: err}
	}
	if waitDuration := time.Since(t); waitDuration.Seconds() > 1/float64(c.Route53RateLimiter.Limit()) {
		c.Logger.Info("Waited for client-side route53 rate limiter", "waitDuration", waitDuration.String())
	}
	return nil
}

func newChangeResourceRecordSetsInput(zoneId string, action route53types.ChangeAction, rrss []*route53types.ResourceRecordSet) *route53.ChangeResourceRecordSetsInput {
	var changes []route53types.Change
	for _, rrs := range rrss {
		changes = append(changes, route53types.Change{
			Action:            action,
			ResourceRecordSet: rrs,
		})
	}
	return &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneId),
		ChangeBatch: &route53types.ChangeBatch{
			Changes: changes,
		},
	}
}

func newResourceRecords(recordType route53types.RRType, values []string) []route53types.ResourceRecord {
	var resourceRecords []route53types.ResourceRecord
	if recordType == route53types.RRTypeCname {
		resourceRecords = append(resourceRecords, route53types.ResourceRecord{
			Value: aws.String(values[0]),
		})
	} else {
		for _, value := range values {
			if recordType == route53types.RRTypeTxt {
				value = encloseInQuotes(value)
			}
			resourceRecords = append(resourceRecords, route53types.ResourceRecord{
				Value: aws.String(value),
			})
		}
	}
	return resourceRecords
}

func newResourceRecordSets(name string, recordType route53types.RRType, resourceRecords []route53types.ResourceRecord, ttl int64, stack IPStack) []*route53types.ResourceRecordSet {
	if recordType == route53types.RRTypeCname {
		loadBalanceHostname := aws.ToString(resourceRecords[0].Value)
		// if it is a loadbalancer in a known canoncial hosted zone, create resource sets with alias targets for IPv4 and/or IPv6
		if zoneId := canonicalHostedZoneId(loadBalanceHostname); zoneId != "" {
			var rrss []*route53types.ResourceRecordSet
			for _, recordType := range GetAliasRecordTypes(stack) {
				rrs := route53types.ResourceRecordSet{
					Name: aws.String(name),
					Type: recordType,
					AliasTarget: &route53types.AliasTarget{
						DNSName:              &loadBalanceHostname,
						HostedZoneId:         aws.String(zoneId),
						EvaluateTargetHealth: true,
					},
				}
				rrss = append(rrss, &rrs)
			}
			return rrss
		}
	}
	return []*route53types.ResourceRecordSet{
		{
			Name:            aws.String(name),
			Type:            route53types.RRType(recordType),
			ResourceRecords: resourceRecords,
			TTL:             aws.Int64(ttl),
		},
	}
}

// GetAliasRecordTypes determinate the alias record types needed, depending on the requested IPStack.
func GetAliasRecordTypes(stack IPStack) []route53types.RRType {
	switch stack {
	case IPStackIPv6:
		return []route53types.RRType{route53types.RRTypeAaaa}
	case IPStackIPDualStack:
		return []route53types.RRType{route53types.RRTypeA, route53types.RRTypeAaaa}
	default:
		return []route53types.RRType{route53types.RRTypeA}
	}
}

func isPotentialAliasTarget(recordType route53types.RRType, value string) bool {
	if recordType == route53types.RRTypeCname {
		if zoneId := canonicalHostedZoneId(value); zoneId != "" {
			return true
		}
	}
	return false
}

var (
	canonicalHostedZoneIds = data.CanonicalHostedZones()
)

// canonicalHostedZoneId returns the matching canonical hosted zone ID for the given hostname, if found.
func canonicalHostedZoneId(hostname string) string {
	for suffix, zone := range canonicalHostedZoneIds {
		if strings.HasSuffix(hostname, "."+suffix) {
			return zone
		}
	}
	return ""
}

func encloseInQuotes(s string) string {
	if s[0] != '"' || s[len(s)-1] != '"' {
		return fmt.Sprintf(`"%s"`, s)
	}
	return s
}

func ignoreResourceRecordSetNotFound(err error) error {
	if err == nil {
		return nil
	}
	var icb *route53types.InvalidChangeBatch
	if errors.As(err, &icb) && strings.Contains(strings.Join(icb.Messages, " "), "it was not found") {
		return nil
	}
	return err
}

func ignoreHostedZoneNotFound(err error) error {
	if err == nil {
		return nil
	}
	var hza *route53types.HostedZoneNotFound
	if errors.As(err, &hza) {
		return nil
	}
	return err
}

// IsNoSuchHostedZoneError returns true if the error indicates a non-existing route53 hosted zone.
func IsNoSuchHostedZoneError(err error) bool {
	var nsz *route53types.NoSuchHostedZone
	return errors.As(err, &nsz)
}

var notPermittedInZoneRegex = regexp.MustCompile(`RRSet with DNS name [^\ ]+ is not permitted in zone [^\ ]+`)

// IsNotPermittedInZoneError returns true if the error indicates that the DNS name is not permitted in the route53 hosted zone.
func IsNotPermittedInZoneError(err error) bool {
	var icb *route53types.InvalidChangeBatch
	if errors.As(err, &icb) {
		errorMessage := strings.Join(icb.Messages, " ")
		return notPermittedInZoneRegex.MatchString(errorMessage)
	}

	return false
}

// IsThrottlingError returns true if the error is a throttling error.
func IsThrottlingError(err error) bool {
	var te *route53types.ThrottlingException
	return errors.As(err, &te)
}
