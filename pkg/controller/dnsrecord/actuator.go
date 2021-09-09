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

package dnsrecord

import (
	"context"
	"fmt"
	"time"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/dnsrecord"
	controllererror "github.com/gardener/gardener/extensions/pkg/controller/error"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1/helper"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/go-logr/logr"
	"k8s.io/client-go/util/retry"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

const (
	// requeueAfterOnProviderError is a value for RequeueAfter to be returned on provider errors
	// in order to prevent quick retries that could quickly exhaust the account rate limits in case of e.g.
	// configuration issues.
	requeueAfterOnProviderError = 30 * time.Second
)

type actuator struct {
	client           client.Client
	awsClientFactory awsclient.Factory
	logger           logr.Logger
}

// NewActuator creates a new dnsrecord.Actuator.
func NewActuator(awsClientFactory awsclient.Factory, logger logr.Logger) dnsrecord.Actuator {
	return &actuator{
		awsClientFactory: awsClientFactory,
		logger:           logger.WithName("aws-dnsrecord-actuator"),
	}
}

func (a *actuator) InjectClient(client client.Client) error {
	a.client = client
	return nil
}

// Reconcile reconciles the DNSRecord.
func (a *actuator) Reconcile(ctx context.Context, dns *extensionsv1alpha1.DNSRecord, cluster *extensionscontroller.Cluster) error {
	// Create AWS client
	credentials, err := aws.GetCredentialsFromSecretRef(ctx, a.client, dns.Spec.SecretRef, true)
	if err != nil {
		return fmt.Errorf("could not get AWS credentials: %+v", err)
	}
	awsClient, err := a.awsClientFactory.NewClient(string(credentials.AccessKeyID), string(credentials.SecretAccessKey), getRegion(dns, credentials))
	if err != nil {
		return fmt.Errorf("could not create AWS client: %+v", err)
	}

	// Determine DNS hosted zone ID
	zone, err := a.getZone(ctx, dns, awsClient)
	if err != nil {
		return err
	}

	// Create or update DNS recordset
	ttl := extensionsv1alpha1helper.GetDNSRecordTTL(dns.Spec.TTL)
	a.logger.Info("Creating or updating DNS recordset", "zone", zone, "name", dns.Spec.Name, "type", dns.Spec.RecordType, "values", dns.Spec.Values, "dnsrecord", kutil.ObjectName(dns))
	if err := awsClient.CreateOrUpdateDNSRecordSet(ctx, zone, dns.Spec.Name, string(dns.Spec.RecordType), dns.Spec.Values, ttl); err != nil {
		cause := fmt.Errorf("could not create or update DNS recordset in zone %s with name %s, type %s, and values %v: %+v", zone, dns.Spec.Name, dns.Spec.RecordType, dns.Spec.Values, err)
		if awsclient.IsNoSuchHostedZoneError(err) || awsclient.IsNotPermittedInZoneError(err) {
			cause = gardencorev1beta1helper.NewErrorWithCodes(cause.Error(), gardencorev1beta1.ErrorConfigurationProblem)
		}
		return &controllererror.RequeueAfterError{
			Cause:        cause,
			RequeueAfter: requeueAfterOnProviderError,
		}
	}

	// Delete meta DNS recordset if exists
	if dns.Status.LastOperation == nil || dns.Status.LastOperation.Type == gardencorev1beta1.LastOperationTypeCreate {
		name, recordType := dnsrecord.GetMetaRecordName(dns.Spec.Name), "TXT"
		a.logger.Info("Deleting meta DNS recordset", "zone", zone, "name", name, "type", recordType, "dnsrecord", kutil.ObjectName(dns))
		if err := awsClient.DeleteDNSRecordSet(ctx, zone, name, recordType, nil, 0); err != nil {
			return &controllererror.RequeueAfterError{
				Cause:        fmt.Errorf("could not delete meta DNS recordset in zone %s with name %s and type %s: %+v", zone, name, recordType, err),
				RequeueAfter: requeueAfterOnProviderError,
			}
		}
	}

	// Update resource status
	return extensionscontroller.TryUpdateStatus(ctx, retry.DefaultBackoff, a.client, dns, func() error {
		dns.Status.Zone = &zone
		return nil
	})
}

// Delete deletes the DNSRecord.
func (a *actuator) Delete(ctx context.Context, dns *extensionsv1alpha1.DNSRecord, cluster *extensionscontroller.Cluster) error {
	// Create AWS client
	credentials, err := aws.GetCredentialsFromSecretRef(ctx, a.client, dns.Spec.SecretRef, true)
	if err != nil {
		return fmt.Errorf("could not get AWS credentials: %+v", err)
	}
	awsClient, err := a.awsClientFactory.NewClient(string(credentials.AccessKeyID), string(credentials.SecretAccessKey), getRegion(dns, credentials))
	if err != nil {
		return fmt.Errorf("could not create AWS client: %+v", err)
	}

	// Determine DNS hosted zone ID
	zone, err := a.getZone(ctx, dns, awsClient)
	if err != nil {
		return err
	}

	// Delete DNS recordset
	ttl := extensionsv1alpha1helper.GetDNSRecordTTL(dns.Spec.TTL)
	a.logger.Info("Deleting DNS recordset", "zone", zone, "name", dns.Spec.Name, "type", dns.Spec.RecordType, "values", dns.Spec.Values, "dnsrecord", kutil.ObjectName(dns))
	if err := awsClient.DeleteDNSRecordSet(ctx, zone, dns.Spec.Name, string(dns.Spec.RecordType), dns.Spec.Values, ttl); err != nil {
		return &controllererror.RequeueAfterError{
			Cause:        fmt.Errorf("could not delete DNS recordset in zone %s with name %s, type %s, and values %v: %+v", zone, dns.Spec.Name, dns.Spec.RecordType, dns.Spec.Values, err),
			RequeueAfter: requeueAfterOnProviderError,
		}
	}

	return nil
}

// Restore restores the DNSRecord.
func (a *actuator) Restore(ctx context.Context, dns *extensionsv1alpha1.DNSRecord, cluster *extensionscontroller.Cluster) error {
	return a.Reconcile(ctx, dns, cluster)
}

// Migrate migrates the DNSRecord.
func (a *actuator) Migrate(ctx context.Context, dns *extensionsv1alpha1.DNSRecord, cluster *extensionscontroller.Cluster) error {
	return nil
}

func (a *actuator) getZone(ctx context.Context, dns *extensionsv1alpha1.DNSRecord, awsClient awsclient.Interface) (string, error) {
	switch {
	case dns.Spec.Zone != nil && *dns.Spec.Zone != "":
		return *dns.Spec.Zone, nil
	case dns.Status.Zone != nil && *dns.Status.Zone != "":
		return *dns.Status.Zone, nil
	default:
		// The zone is not specified in the resource status or spec. Try to determine the zone by
		// getting all hosted zones of the account and searching for the longest zone name that is a suffix of dns.spec.Name
		zones, err := awsClient.GetDNSHostedZones(ctx)
		if err != nil {
			return "", &controllererror.RequeueAfterError{
				Cause:        fmt.Errorf("could not get DNS hosted zones: %+v", err),
				RequeueAfter: requeueAfterOnProviderError,
			}
		}
		a.logger.Info("Got DNS hosted zones", "zones", zones, "dnsrecord", kutil.ObjectName(dns))
		zone := dnsrecord.FindZoneForName(zones, dns.Spec.Name)
		if zone == "" {
			return "", fmt.Errorf("could not find DNS hosted zone for name %s", dns.Spec.Name)
		}
		return zone, nil
	}
}

func getRegion(dns *extensionsv1alpha1.DNSRecord, credentials *aws.Credentials) string {
	switch {
	case dns.Spec.Region != nil && *dns.Spec.Region != "":
		return *dns.Spec.Region
	case len(credentials.Region) > 0:
		return string(credentials.Region)
	default:
		return aws.DefaultDNSRegion
	}
}
