// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package dnsrecord

import (
	"context"
	"errors"
	"fmt"
	"time"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/dnsrecord"
	"github.com/gardener/gardener/extensions/pkg/util"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1/helper"
	"github.com/gardener/gardener/pkg/controllerutils/reconciler"
	"github.com/go-logr/logr"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

const (
	// requeueAfterOnThrottlingError is a value for RequeueAfter to be returned on throttling errors
	// in order to prevent retries with backoff that may lead to longer reconciliation times when many
	// dnsrecords are reconciled at the same time.
	requeueAfterOnThrottlingError = 30 * time.Second
)

type actuator struct {
	client           k8sclient.Client
	awsClientFactory awsclient.Factory
}

// NewActuator creates a new dnsrecord.Actuator.
func NewActuator(mgr manager.Manager, awsClientFactory awsclient.Factory) dnsrecord.Actuator {
	return &actuator{
		client:           mgr.GetClient(),
		awsClientFactory: awsClientFactory,
	}
}

// Reconcile reconciles the DNSRecord.
func (a *actuator) Reconcile(ctx context.Context, log logr.Logger, dns *extensionsv1alpha1.DNSRecord, _ *extensionscontroller.Cluster) error {
	// Create AWS client
	authConfig, err := aws.GetCredentialsFromSecretRef(ctx, a.client, dns.Spec.SecretRef, true, "")
	if err != nil {
		return util.DetermineError(fmt.Errorf("could not get AWS credentials: %+v", err), helper.KnownCodes)
	}
	authConfig.Region = getRegion(dns, authConfig)
	awsClient, err := a.awsClientFactory.NewClient(*authConfig)
	if err != nil {
		return util.DetermineError(fmt.Errorf("could not create AWS client: %+v", err), helper.KnownCodes)
	}

	// Determine DNS hosted zone ID
	zone, err := a.getZone(ctx, log, dns, awsClient)
	if err != nil {
		return err
	}

	stack := getIPStack(dns)

	// Create or update DNS recordset
	ttl := extensionsv1alpha1helper.GetDNSRecordTTL(dns.Spec.TTL)
	log.Info("Creating or updating DNS recordset", "zone", zone, "name", dns.Spec.Name, "type", dns.Spec.RecordType, "values", dns.Spec.Values, "dnsrecord", k8sclient.ObjectKeyFromObject(dns))
	if err := awsClient.CreateOrUpdateDNSRecordSet(ctx, zone, dns.Spec.Name, string(dns.Spec.RecordType), dns.Spec.Values, ttl, stack); err != nil {
		return wrapAWSClientError(err, fmt.Sprintf("could not create or update DNS recordset in zone %s with name %s, type %s, and values %v", zone, dns.Spec.Name, dns.Spec.RecordType, dns.Spec.Values))
	}

	// Update resource status
	patch := k8sclient.MergeFrom(dns.DeepCopy())
	dns.Status.Zone = &zone
	return a.client.Status().Patch(ctx, dns, patch)
}

// Delete deletes the DNSRecord.
func (a *actuator) Delete(ctx context.Context, log logr.Logger, dns *extensionsv1alpha1.DNSRecord, _ *extensionscontroller.Cluster) error {
	// Create AWS client
	authConfig, err := aws.GetCredentialsFromSecretRef(ctx, a.client, dns.Spec.SecretRef, true, "")
	if err != nil {
		return fmt.Errorf("could not get AWS credentials: %+v", err)
	}
	authConfig.Region = getRegion(dns, authConfig)
	awsClient, err := a.awsClientFactory.NewClient(*authConfig)
	if err != nil {
		return util.DetermineError(fmt.Errorf("could not create AWS client: %+v", err), helper.KnownCodes)
	}

	// Determine DNS hosted zone ID
	zone, err := a.getZone(ctx, log, dns, awsClient)
	if err != nil {
		return err
	}

	stack := getIPStack(dns)

	// Delete DNS recordset
	ttl := extensionsv1alpha1helper.GetDNSRecordTTL(dns.Spec.TTL)
	log.Info("Deleting DNS recordset", "zone", zone, "name", dns.Spec.Name, "type", dns.Spec.RecordType, "values", dns.Spec.Values, "dnsrecord", k8sclient.ObjectKeyFromObject(dns))
	if err := awsClient.DeleteDNSRecordSet(ctx, zone, dns.Spec.Name, string(dns.Spec.RecordType), dns.Spec.Values, ttl, stack); err != nil && !awsclient.IsNoSuchHostedZoneError(err) {
		return wrapAWSClientError(err, fmt.Sprintf("could not delete DNS recordset in zone %s with name %s, type %s, and values %v", zone, dns.Spec.Name, dns.Spec.RecordType, dns.Spec.Values))
	}

	return nil
}

// Delete forcefully deletes the DNSRecord.
func (a *actuator) ForceDelete(ctx context.Context, log logr.Logger, dns *extensionsv1alpha1.DNSRecord, cluster *extensionscontroller.Cluster) error {
	return a.Delete(ctx, log, dns, cluster)
}

// Restore restores the DNSRecord.
func (a *actuator) Restore(ctx context.Context, log logr.Logger, dns *extensionsv1alpha1.DNSRecord, cluster *extensionscontroller.Cluster) error {
	return a.Reconcile(ctx, log, dns, cluster)
}

// Migrate migrates the DNSRecord.
func (a *actuator) Migrate(_ context.Context, _ logr.Logger, _ *extensionsv1alpha1.DNSRecord, _ *extensionscontroller.Cluster) error {
	return nil
}

func (a *actuator) getZone(ctx context.Context, log logr.Logger, dns *extensionsv1alpha1.DNSRecord, awsClient awsclient.Interface) (string, error) {
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
			return "", wrapAWSClientError(err, "could not get DNS hosted zones")
		}
		log.Info("Got DNS hosted zones", "zones", zones, "dnsrecord", k8sclient.ObjectKeyFromObject(dns))
		zone := dnsrecord.FindZoneForName(zones, dns.Spec.Name)
		if zone == "" {
			return "", gardencorev1beta1helper.NewErrorWithCodes(fmt.Errorf("could not find DNS hosted zone for name %s", dns.Spec.Name), gardencorev1beta1.ErrorConfigurationProblem)
		}
		return zone, nil
	}
}

func getRegion(dns *extensionsv1alpha1.DNSRecord, credentials *awsclient.AuthConfig) string {
	switch {
	case dns.Spec.Region != nil && *dns.Spec.Region != "":
		return *dns.Spec.Region
	case len(credentials.Region) > 0:
		return string(credentials.Region)
	default:
		return aws.DefaultDNSRegion
	}
}

func wrapAWSClientError(err error, message string) error {
	wrappedErr := fmt.Errorf("%s: %+v", message, err)
	var route53RateLimiterWaitError *awsclient.Route53RateLimiterWaitError
	if errors.As(err, &route53RateLimiterWaitError) || awsclient.IsThrottlingError(err) {
		return &reconciler.RequeueAfterError{
			Cause:        wrappedErr,
			RequeueAfter: requeueAfterOnThrottlingError,
		}
	}
	if awsclient.IsNoSuchHostedZoneError(err) || awsclient.IsNotPermittedInZoneError(err) {
		return gardencorev1beta1helper.NewErrorWithCodes(wrappedErr, gardencorev1beta1.ErrorConfigurationProblem)
	}
	return util.DetermineError(wrappedErr, helper.KnownCodes)
}

func getIPStack(dns *extensionsv1alpha1.DNSRecord) awsclient.IPStack {
	switch dns.Annotations[awsapi.AnnotationKeyIPStack] {
	case string(awsclient.IPStackIPv6):
		return awsclient.IPStackIPv6
	case string(awsclient.IPStackIPDualStack):
		return awsclient.IPStackIPDualStack
	default:
		return awsclient.IPStackIPv4
	}
}
