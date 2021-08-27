// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
)

// GetDNSHostedZones returns a map of all DNS hosted zone names mapped to their IDs.
func (c *Client) GetDNSHostedZones(ctx context.Context) (map[string]string, error) {
	zones := make(map[string]string)
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
func (c *Client) CreateOrUpdateDNSRecordSet(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64) error {
	rrs := newResourceRecordSet(name, recordType, newResourceRecords(recordType, values), ttl)
	_, err := c.Route53.ChangeResourceRecordSetsWithContext(ctx, newChangeResourceRecordSetsInput(zoneId, route53.ChangeActionUpsert, rrs))
	return err
}

// DeleteDNSRecordSet deletes the DNS recordset in the DNS hosted zone with the given zone ID,
// with the given name, type, values, and TTL.
// If values is empty and TTL is 0, the actual state will be determined by reading the recordset from the zone.
// Otherwise, an attempt will be made to delete the recordset with the given values / TTL. If this results in a
// "values do not match" error, the actual state will again be determined by reading the recordset from the zone, and
// a second attempt to delete it will be made.
// The idea is to ensure a consistent and foolproof behavior while sending as few requests as possible to avoid
// rate limit issues.
func (c *Client) DeleteDNSRecordSet(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64) error {
	var (
		err error
		rrs *route53.ResourceRecordSet
	)
	if len(values) == 0 && ttl == 0 {
		// No values / ttl were specified, so get the resource recordset from the zone
		rrs, err = c.GetDNSRecordSet(ctx, zoneId, name, recordType)
		if err != nil {
			return err
		}
		if rrs == nil {
			return nil
		}
	} else {
		rrs = newResourceRecordSet(name, recordType, newResourceRecords(recordType, values), ttl)
	}
	_, err = c.Route53.ChangeResourceRecordSetsWithContext(ctx, newChangeResourceRecordSetsInput(zoneId, route53.ChangeActionDelete, rrs))
	if isValuesDoNotMatchError(err) && len(values) > 0 && ttl > 0 {
		// The actual values / ttl are different from the given values / ttl
		// Get the resource recordset from the zone and try again
		rrs, err = c.GetDNSRecordSet(ctx, zoneId, name, getRecordType(recordType, values[0]))
		if err != nil {
			return err
		}
		if rrs == nil {
			return nil
		}
		_, err = c.Route53.ChangeResourceRecordSetsWithContext(ctx, newChangeResourceRecordSetsInput(zoneId, route53.ChangeActionDelete, rrs))
	}
	return ignoreResourceRecordSetNotFound(err)
}

// GetDNSRecordSet returns the DNS recordset in the DNS hosted zone with the given zone ID, and with the given name and type.
func (c *Client) GetDNSRecordSet(ctx context.Context, zoneId, name, recordType string) (*route53.ResourceRecordSet, error) {
	out, err := c.Route53.ListResourceRecordSetsWithContext(ctx, &route53.ListResourceRecordSetsInput{
		HostedZoneId:    aws.String(zoneId),
		MaxItems:        aws.String("1"),
		StartRecordName: aws.String(name),
		StartRecordType: aws.String(recordType),
	})
	if ignoreResourceRecordSetNotFound(err) != nil {
		return nil, err
	}
	if out == nil || len(out.ResourceRecordSets) == 0 { // no records in zone
		return nil, nil
	}
	if rrs := out.ResourceRecordSets[0]; normalizeName(aws.StringValue(rrs.Name)) == name && aws.StringValue(rrs.Type) == recordType {
		return out.ResourceRecordSets[0], nil
	}
	return nil, nil
}

func newChangeResourceRecordSetsInput(zoneId, action string, rrs *route53.ResourceRecordSet) *route53.ChangeResourceRecordSetsInput {
	return &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: aws.String(zoneId),
		ChangeBatch: &route53.ChangeBatch{
			Changes: []*route53.Change{
				{
					Action:            aws.String(action),
					ResourceRecordSet: rrs,
				},
			},
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

func newResourceRecordSet(name, recordType string, resourceRecords []*route53.ResourceRecord, ttl int64) *route53.ResourceRecordSet {
	if recordType == route53.RRTypeCname {
		if zoneId := canonicalHostedZoneId(aws.StringValue(resourceRecords[0].Value)); zoneId != "" {
			return &route53.ResourceRecordSet{
				Name: aws.String(name),
				Type: aws.String(route53.RRTypeA),
				AliasTarget: &route53.AliasTarget{
					DNSName:              resourceRecords[0].Value,
					HostedZoneId:         aws.String(zoneId),
					EvaluateTargetHealth: aws.Bool(true),
				},
			}
		}
	}
	return &route53.ResourceRecordSet{
		Name:            aws.String(name),
		Type:            aws.String(recordType),
		ResourceRecords: resourceRecords,
		TTL:             aws.Int64(ttl),
	}
}

func getRecordType(recordType, value string) string {
	if recordType == route53.RRTypeCname {
		if zoneId := canonicalHostedZoneId(value); zoneId != "" {
			return route53.RRTypeA
		}
	}
	return recordType
}

var (
	// original code: https://github.com/kubernetes-sigs/external-dns/blob/master/provider/aws/aws.go
	// see: https://docs.aws.amazon.com/general/latest/gr/elb.html
	canonicalHostedZoneIds = map[string]string{
		// Application Load Balancers and Classic Load Balancers
		"us-east-2.elb.amazonaws.com":         "Z3AADJGX6KTTL2",
		"us-east-1.elb.amazonaws.com":         "Z35SXDOTRQ7X7K",
		"us-west-1.elb.amazonaws.com":         "Z368ELLRRE2KJ0",
		"us-west-2.elb.amazonaws.com":         "Z1H1FL5HABSF5",
		"ca-central-1.elb.amazonaws.com":      "ZQSVJUPU6J1EY",
		"ap-east-1.elb.amazonaws.com":         "Z3DQVH9N71FHZ0",
		"ap-south-1.elb.amazonaws.com":        "ZP97RAFLXTNZK",
		"ap-northeast-2.elb.amazonaws.com":    "ZWKZPGTI48KDX",
		"ap-northeast-3.elb.amazonaws.com":    "Z5LXEXXYW11ES",
		"ap-southeast-1.elb.amazonaws.com":    "Z1LMS91P8CMLE5",
		"ap-southeast-2.elb.amazonaws.com":    "Z1GM3OXH4ZPM65",
		"ap-northeast-1.elb.amazonaws.com":    "Z14GRHDCWA56QT",
		"eu-central-1.elb.amazonaws.com":      "Z215JYRZR1TBD5",
		"eu-west-1.elb.amazonaws.com":         "Z32O12XQLNTSW2",
		"eu-west-2.elb.amazonaws.com":         "ZHURV8PSTC4K8",
		"eu-west-3.elb.amazonaws.com":         "Z3Q77PNBQS71R4",
		"eu-north-1.elb.amazonaws.com":        "Z23TAZ6LKFMNIO",
		"eu-south-1.elb.amazonaws.com":        "Z3ULH7SSC9OV64",
		"sa-east-1.elb.amazonaws.com":         "Z2P70J7HTTTPLU",
		"cn-north-1.elb.amazonaws.com.cn":     "Z1GDH35T77C1KE",
		"cn-northwest-1.elb.amazonaws.com.cn": "ZM7IZAIOVVDZF",
		"us-gov-west-1.elb.amazonaws.com":     "Z33AYJ8TM3BH4J",
		"us-gov-east-1.elb.amazonaws.com":     "Z166TLBEWOO7G0",
		"me-south-1.elb.amazonaws.com":        "ZS929ML54UICD",
		"af-south-1.elb.amazonaws.com":        "Z268VQBMOI5EKX",
		// Network Load Balancers
		"elb.us-east-2.amazonaws.com":         "ZLMOA37VPKANP",
		"elb.us-east-1.amazonaws.com":         "Z26RNL4JYFTOTI",
		"elb.us-west-1.amazonaws.com":         "Z24FKFUX50B4VW",
		"elb.us-west-2.amazonaws.com":         "Z18D5FSROUN65G",
		"elb.ca-central-1.amazonaws.com":      "Z2EPGBW3API2WT",
		"elb.ap-east-1.amazonaws.com":         "Z12Y7K3UBGUAD1",
		"elb.ap-south-1.amazonaws.com":        "ZVDDRBQ08TROA",
		"elb.ap-northeast-2.amazonaws.com":    "ZIBE1TIR4HY56",
		"elb.ap-southeast-1.amazonaws.com":    "ZKVM4W9LS7TM",
		"elb.ap-southeast-2.amazonaws.com":    "ZCT6FZBF4DROD",
		"elb.ap-northeast-1.amazonaws.com":    "Z31USIVHYNEOWT",
		"elb.eu-central-1.amazonaws.com":      "Z3F0SRJ5LGBH90",
		"elb.eu-west-1.amazonaws.com":         "Z2IFOLAFXWLO4F",
		"elb.eu-west-2.amazonaws.com":         "ZD4D7Y8KGAS4G",
		"elb.eu-west-3.amazonaws.com":         "Z1CMS0P5QUZ6D5",
		"elb.eu-north-1.amazonaws.com":        "Z1UDT6IFJ4EJM",
		"elb.eu-south-1.amazonaws.com":        "Z23146JA1KNAFP",
		"elb.sa-east-1.amazonaws.com":         "ZTK26PT1VY4CU",
		"elb.cn-north-1.amazonaws.com.cn":     "Z3QFB96KMJ7ED6",
		"elb.cn-northwest-1.amazonaws.com.cn": "ZQEIKTCZ8352D",
		"elb.us-gov-west-1.amazonaws.com":     "ZMG1MZ2THAWF1",
		"elb.us-gov-east-1.amazonaws.com":     "Z1ZSMQQ6Q24QQ8",
		"elb.me-south-1.amazonaws.com":        "Z3QSRYVP46NYYV",
		"elb.af-south-1.amazonaws.com":        "Z203XCE67M25HM",
		// Global Accelerator
		"awsglobalaccelerator.com": "Z2BJ6XQ5FK7U4H",
	}
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

func isValuesDoNotMatchError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeInvalidChangeBatch && strings.Contains(aerr.Message(), "the values provided do not match the current values") {
		return true
	}
	return false
}

func IsNoSuchHostedZoneError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeNoSuchHostedZone {
		return true
	}
	return false
}

var notPermittedInZoneRegex = regexp.MustCompile(`RRSet with DNS name [^\ ]+ is not permitted in zone [^\ ]+`)

func IsNotPermittedInZoneError(err error) bool {
	if aerr, ok := err.(awserr.Error); ok && aerr.Code() == route53.ErrCodeInvalidChangeBatch && notPermittedInZoneRegex.MatchString(aerr.Message()) {
		return true
	}
	return false
}
