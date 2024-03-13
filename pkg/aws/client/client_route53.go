// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/aws/aws-sdk-go/service/route53"
	"github.com/gardener/external-dns-management/pkg/controller/provider/aws/data"
)

// GetDNSHostedZones returns a map of all DNS hosted zone names mapped to their IDs.
func (c *Client) GetDNSHostedZones(ctx context.Context) (map[string]string, error) {
	zones := make(map[string]string)
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return nil, err
	}
	if err := c.Route53.ListHostedZonesPagesWithContext(ctx, &route53.ListHostedZonesInput{}, func(out *route53.ListHostedZonesOutput, lastPage bool) bool {
		for _, zone := range out.HostedZones {
			zones[normalizeName(aws.StringValue(zone.Name))] = normalizeZoneId(aws.StringValue(zone.Id))
		}
		return !lastPage
	}); err != nil {
		return nil, err
	}
	return zones, nil
}

// CreateDNSHostedZone creates the DNS hosted zone with the given name and comment, and returns the ID of the
// newly created zone.
func (c *Client) CreateDNSHostedZone(ctx context.Context, name, comment string) (string, error) {
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return "", err
	}
	out, err := c.Route53.CreateHostedZoneWithContext(ctx, &route53.CreateHostedZoneInput{
		CallerReference: aws.String(strconv.Itoa(int(time.Now().Unix()))),
		Name:            aws.String(name),
		HostedZoneConfig: &route53.HostedZoneConfig{
			Comment: aws.String(comment),
		},
	})
	if err != nil {
		return "", err
	}
	return aws.StringValue(out.HostedZone.Id), nil
}

// DeleteDNSHostedZone deletes the DNS hosted zone with the given ID.
func (c *Client) DeleteDNSHostedZone(ctx context.Context, zoneId string) error {
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return err
	}
	_, err := c.Route53.DeleteHostedZoneWithContext(ctx, &route53.DeleteHostedZoneInput{
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
	rrs := newResourceRecordSets(name, recordType, newResourceRecords(recordType, values), ttl, stack)
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return err
	}
	_, err := c.Route53.ChangeResourceRecordSetsWithContext(ctx, newChangeResourceRecordSetsInput(zoneId, route53.ChangeActionUpsert, rrs))
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
	if len(values) > 0 && ttl > 0 && !isPotentialAliasTarget(recordType, values[0]) {
		// try deletion with known values, but only if it is no CNAME record with potential alias target records.
		// For CNAME records we don't know if the record(s) have been created with or without target records, as the list of
		// canonicalHostedZoneIds may have changed in the meantime.
		rrss := newResourceRecordSets(name, recordType, newResourceRecords(recordType, values), ttl, stack)
		if err := c.waitForRoute53RateLimiter(ctx); err != nil {
			return err
		}
		if _, err := c.Route53.ChangeResourceRecordSetsWithContext(ctx, newChangeResourceRecordSetsInput(zoneId, route53.ChangeActionDelete, rrss)); err == nil {
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
	_, err = c.Route53.ChangeResourceRecordSetsWithContext(ctx, newChangeResourceRecordSetsInput(zoneId, route53.ChangeActionDelete, rrss))
	return ignoreResourceRecordSetNotFound(err)
}

// GetDNSRecordSets returns the DNS recordset(s) in the DNS hosted zone with the given zone ID, and with the given name and type.
// For record type CNAME there may be multiple DNS recordsets if mapped to alias targets A or AAAA recordsets.
func (c *Client) GetDNSRecordSets(ctx context.Context, zoneId, name, recordType string) ([]*route53.ResourceRecordSet, error) {
	if err := c.waitForRoute53RateLimiter(ctx); err != nil {
		return nil, err
	}
	input := &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(zoneId),
		MaxItems:        aws.String("1"),
		StartRecordName: aws.String(name),
		StartRecordType: aws.String(recordType),
	}
	if recordType == route53.RRTypeCname {
		input.MaxItems = aws.String("5") // potential CNAME, AliasTarget A and AliasTarget AAAA
		input.StartRecordType = nil
	}
	out, err := c.Route53.ListResourceRecordSetsWithContext(ctx, input)
	if ignoreResourceRecordSetNotFound(err) != nil {
		return nil, err
	}
	if out == nil || len(out.ResourceRecordSets) == 0 { // no records in zone
		return nil, nil
	}
	var recordSets []*route53.ResourceRecordSet
	for _, rrs := range out.ResourceRecordSets {
		if normalizeName(aws.StringValue(rrs.Name)) == name {
			switch aws.StringValue(rrs.Type) {
			case recordType:
				recordSets = append(recordSets, rrs)
			case route53.RRTypeA, route53.RRTypeAaaa:
				if recordType == route53.RRTypeCname && rrs.AliasTarget != nil {
					recordSets = append(recordSets, rrs)
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

func newChangeResourceRecordSetsInput(zoneId, action string, rrss []*route53.ResourceRecordSet) *route53.ChangeResourceRecordSetsInput {
	var changes []*route53.Change
	for _, rrs := range rrss {
		changes = append(changes, &route53.Change{
			Action:            aws.String(action),
			ResourceRecordSet: rrs,
		})
	}
	return &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneId),
		ChangeBatch: &route53.ChangeBatch{
			Changes: changes,
		},
	}
}

func newResourceRecords(recordType string, values []string) []*route53.ResourceRecord {
	var resourceRecords []*route53.ResourceRecord
	if recordType == route53.RRTypeCname {
		resourceRecords = append(resourceRecords, &route53.ResourceRecord{
			Value: aws.String(values[0]),
		})
	} else {
		for _, value := range values {
			if recordType == route53.RRTypeTxt {
				value = encloseInQuotes(value)
			}
			resourceRecords = append(resourceRecords, &route53.ResourceRecord{
				Value: aws.String(value),
			})
		}
	}
	return resourceRecords
}

func newResourceRecordSets(name, recordType string, resourceRecords []*route53.ResourceRecord, ttl int64, stack IPStack) []*route53.ResourceRecordSet {
	if recordType == route53.RRTypeCname {
		loadBalanceHostname := aws.StringValue(resourceRecords[0].Value)
		// if it is a loadbalancer in a known canoncial hosted zone, create resource sets with alias targets for IPv4 and/or IPv6
		if zoneId := canonicalHostedZoneId(loadBalanceHostname); zoneId != "" {
			var rrss []*route53.ResourceRecordSet
			for _, recordType := range GetAliasRecordTypes(stack) {
				rrs := &route53.ResourceRecordSet{
					Name: aws.String(name),
					Type: aws.String(recordType),
					AliasTarget: &route53.AliasTarget{
						DNSName:              &loadBalanceHostname,
						HostedZoneId:         aws.String(zoneId),
						EvaluateTargetHealth: aws.Bool(true),
					},
				}
				rrss = append(rrss, rrs)
			}
			return rrss
		}
	}
	return []*route53.ResourceRecordSet{
		{
			Name:            aws.String(name),
			Type:            aws.String(recordType),
			ResourceRecords: resourceRecords,
			TTL:             aws.Int64(ttl),
		},
	}
}

// GetAliasRecordTypes determinate the alias record types needed, depending on the requested IPStack.
func GetAliasRecordTypes(stack IPStack) []string {
	switch stack {
	case IPStackIPv6:
		return []string{route53.RRTypeAaaa}
	case IPStackIPDualStack:
		return []string{route53.RRTypeA, route53.RRTypeAaaa}
	default:
		return []string{route53.RRTypeA}
	}
}

func isPotentialAliasTarget(recordType, value string) bool {
	if recordType == route53.RRTypeCname {
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
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeInvalidChangeBatch && strings.Contains(aerr.Message(), "it was not found") {
		return nil
	}
	return err
}

func ignoreHostedZoneNotFound(err error) error {
	if err == nil {
		return nil
	}
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeHostedZoneNotFound {
		return nil
	}
	return err
}

// IsNoSuchHostedZoneError returns true if the error indicates a non-existing route53 hosted zone.
func IsNoSuchHostedZoneError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeNoSuchHostedZone {
		return true
	}
	return false
}

var notPermittedInZoneRegex = regexp.MustCompile(`RRSet with DNS name [^\ ]+ is not permitted in zone [^\ ]+`)

// IsNotPermittedInZoneError returns true if the error indicates that the DNS name is not permitted in the route53 hosted zone.
func IsNotPermittedInZoneError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeInvalidChangeBatch && notPermittedInZoneRegex.MatchString(aerr.Message()) {
		return true
	}
	return false
}

// IsThrottlingError returns true if the error is a throttling error.
func IsThrottlingError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && strings.Contains(aerr.Message(), "Throttling") {
		return true
	}
	return false
}
