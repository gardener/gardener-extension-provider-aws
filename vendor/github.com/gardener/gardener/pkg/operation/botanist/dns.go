// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package botanist

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/gardener/gardener/pkg/apis/core"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/gardener/gardener/pkg/features"
	gardenletfeatures "github.com/gardener/gardener/pkg/gardenlet/features"
	"github.com/gardener/gardener/pkg/operation/botanist/component"
	"github.com/gardener/gardener/pkg/operation/botanist/component/extensions/dns"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"

	dnsv1alpha1 "github.com/gardener/external-dns-management/pkg/apis/dns/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	// DNSInternalName is a constant for a DNS resources used for the internal domain name.
	DNSInternalName = "internal"
	// DNSExternalName is a constant for a DNS resources used for the external domain name.
	DNSExternalName = "external"
	// DNSProviderRoleAdditional is a constant for additionally managed DNS providers.
	DNSProviderRoleAdditional = "managed-dns-provider"
)

// GenerateDNSProviderName creates a name for the dns provider out of the passed `secretName` and `providerType`.
func GenerateDNSProviderName(secretName, providerType string) string {
	switch {
	case secretName != "" && providerType != "":
		return fmt.Sprintf("%s-%s", providerType, secretName)
	case secretName != "":
		return secretName
	case providerType != "":
		return providerType
	default:
		return ""
	}
}

// DeployExternalDNS deploys the external DNSOwner, DNSProvider, and DNSEntry resources.
func (b *Botanist) DeployExternalDNS(ctx context.Context) error {
	if b.NeedsExternalDNS() {
		if b.isRestorePhase() {
			return dnsRestoreDeployer{
				provider: b.Shoot.Components.Extensions.DNS.ExternalProvider,
				entry:    b.Shoot.Components.Extensions.DNS.ExternalEntry,
				owner:    b.Shoot.Components.Extensions.DNS.ExternalOwner,
			}.Deploy(ctx)
		}

		return component.OpWaiter(
			b.Shoot.Components.Extensions.DNS.ExternalOwner,
			b.Shoot.Components.Extensions.DNS.ExternalProvider,
			b.Shoot.Components.Extensions.DNS.ExternalEntry,
		).Deploy(ctx)
	}

	return component.OpWaiter(
		b.Shoot.Components.Extensions.DNS.ExternalEntry,
		b.Shoot.Components.Extensions.DNS.ExternalProvider,
		b.Shoot.Components.Extensions.DNS.ExternalOwner,
	).Deploy(ctx)
}

// DeployInternalDNS deploys the internal DNSOwner, DNSProvider, and DNSEntry resources.
func (b *Botanist) DeployInternalDNS(ctx context.Context) error {
	if b.NeedsInternalDNS() {
		if b.isRestorePhase() {
			return dnsRestoreDeployer{
				provider: b.Shoot.Components.Extensions.DNS.InternalProvider,
				entry:    b.Shoot.Components.Extensions.DNS.InternalEntry,
				owner:    b.Shoot.Components.Extensions.DNS.InternalOwner,
			}.Deploy(ctx)
		}

		return component.OpWaiter(
			b.Shoot.Components.Extensions.DNS.InternalOwner,
			b.Shoot.Components.Extensions.DNS.InternalProvider,
			b.Shoot.Components.Extensions.DNS.InternalEntry,
		).Deploy(ctx)
	}

	return component.OpWaiter(
		b.Shoot.Components.Extensions.DNS.InternalEntry,
		b.Shoot.Components.Extensions.DNS.InternalProvider,
		b.Shoot.Components.Extensions.DNS.InternalOwner,
	).Deploy(ctx)
}

// DefaultExternalDNSProvider returns the external DNSProvider if external DNS is
// enabled and if not DeployWaiter which removes the external DNSProvider.
func (b *Botanist) DefaultExternalDNSProvider(seedClient client.Client) component.DeployWaiter {
	if b.NeedsExternalDNS() {
		return dns.NewProvider(
			b.Logger,
			seedClient,
			b.Shoot.SeedNamespace,
			&dns.ProviderValues{
				Name:       DNSExternalName,
				Purpose:    DNSExternalName,
				Provider:   b.Shoot.ExternalDomain.Provider,
				SecretData: b.Shoot.ExternalDomain.SecretData,
				Domains: &dns.IncludeExclude{
					Include: sets.NewString(append(b.Shoot.ExternalDomain.IncludeDomains, *b.Shoot.ExternalClusterDomain)...).List(),
					Exclude: b.Shoot.ExternalDomain.ExcludeDomains,
				},
				Zones: &dns.IncludeExclude{
					Include: b.Shoot.ExternalDomain.IncludeZones,
					Exclude: b.Shoot.ExternalDomain.ExcludeZones,
				},
			},
			nil,
		)
	}

	return component.OpDestroy(dns.NewProvider(
		b.Logger,
		seedClient,
		b.Shoot.SeedNamespace,
		&dns.ProviderValues{
			Name:    DNSExternalName,
			Purpose: DNSExternalName,
		},
		nil,
	))
}

// DefaultExternalDNSEntry returns DeployWaiter which removes the external DNSEntry.
func (b *Botanist) DefaultExternalDNSEntry(seedClient client.Client) component.DeployWaiter {
	return component.OpDestroy(dns.NewEntry(
		b.Logger,
		seedClient,
		b.Shoot.SeedNamespace,
		&dns.EntryValues{
			Name: DNSExternalName,
			TTL:  *b.Config.Controllers.Shoot.DNSEntryTTLSeconds,
		},
		nil,
	))
}

// DefaultExternalDNSOwner returns DeployWaiter which removes the external DNSOwner.
func (b *Botanist) DefaultExternalDNSOwner(seedClient client.Client) component.DeployWaiter {
	return component.OpDestroy(dns.NewOwner(
		seedClient,
		b.Shoot.SeedNamespace,
		&dns.OwnerValues{
			Name: DNSExternalName,
		},
	))
}

// DefaultInternalDNSProvider returns the internal DNSProvider if internal DNS is
// enabled and if not, DeployWaiter which removes the internal DNSProvider.
func (b *Botanist) DefaultInternalDNSProvider(seedClient client.Client) component.DeployWaiter {
	if b.NeedsInternalDNS() {
		return dns.NewProvider(
			b.Logger,
			seedClient,
			b.Shoot.SeedNamespace,
			&dns.ProviderValues{
				Name:       DNSInternalName,
				Purpose:    DNSInternalName,
				Provider:   b.Garden.InternalDomain.Provider,
				SecretData: b.Garden.InternalDomain.SecretData,
				Domains: &dns.IncludeExclude{
					Include: []string{b.Shoot.InternalClusterDomain},
				},
				Zones: &dns.IncludeExclude{
					Include: b.Garden.InternalDomain.IncludeZones,
					Exclude: b.Garden.InternalDomain.ExcludeZones,
				},
			},
			nil,
		)
	}

	return component.OpDestroy(dns.NewProvider(
		b.Logger,
		seedClient,
		b.Shoot.SeedNamespace,
		&dns.ProviderValues{
			Name:    DNSInternalName,
			Purpose: DNSInternalName,
		},
		nil,
	))
}

// DefaultInternalDNSEntry returns DeployWaiter which removes the internal DNSEntry.
func (b *Botanist) DefaultInternalDNSEntry(seedClient client.Client) component.DeployWaiter {
	return component.OpDestroy(dns.NewEntry(
		b.Logger,
		seedClient,
		b.Shoot.SeedNamespace,
		&dns.EntryValues{
			Name: DNSInternalName,
			TTL:  *b.Config.Controllers.Shoot.DNSEntryTTLSeconds,
		},
		nil,
	))
}

// DefaultInternalDNSOwner returns a DeployWaiter which removes the internal DNSOwner.
func (b *Botanist) DefaultInternalDNSOwner(seedClient client.Client) component.DeployWaiter {
	return component.OpDestroy(dns.NewOwner(
		seedClient,
		b.Shoot.SeedNamespace,
		&dns.OwnerValues{
			Name: DNSInternalName,
		},
	))
}

// AdditionalDNSProviders returns a map containing DNSProviders where the key is the provider name.
// Providers and DNSEntries which are no longer needed / or in use, contain a DeployWaiter which removes
// said DNSEntry / DNSProvider.
func (b *Botanist) AdditionalDNSProviders(ctx context.Context, gardenClient, seedClient client.Client) (map[string]component.DeployWaiter, error) {
	additionalProviders := map[string]component.DeployWaiter{}

	if b.NeedsAdditionalDNSProviders() {
		for i, provider := range b.Shoot.Info.Spec.DNS.Providers {
			p := provider
			if p.Primary != nil && *p.Primary {
				continue
			}

			var includeDomains, excludeDomains, includeZones, excludeZones []string
			if domains := p.Domains; domains != nil {
				includeDomains = domains.Include
				excludeDomains = domains.Exclude
			}

			if zones := p.Zones; zones != nil {
				includeZones = zones.Include
				excludeZones = zones.Exclude
			}

			providerType := p.Type
			if providerType == nil {
				return nil, fmt.Errorf("dns provider[%d] doesn't specify a type", i)
			}

			if *providerType == core.DNSUnmanaged {
				b.Logger.Infof("Skipping deployment of DNS provider[%d] since it specifies type %q", i, core.DNSUnmanaged)
				continue
			}

			secretName := p.SecretName
			if secretName == nil {
				return nil, fmt.Errorf("dns provider[%d] doesn't specify a secretName", i)
			}

			secret := &corev1.Secret{}
			if err := gardenClient.Get(
				ctx,
				kutil.Key(b.Shoot.Info.Namespace, *secretName),
				secret,
			); err != nil {
				return nil, fmt.Errorf("could not get dns provider secret %q: %+v", *secretName, err)
			}
			providerName := GenerateDNSProviderName(*secretName, *providerType)

			additionalProviders[providerName] = dns.NewProvider(
				b.Logger,
				seedClient,
				b.Shoot.SeedNamespace,
				&dns.ProviderValues{
					Name:       providerName,
					Purpose:    providerName,
					Labels:     map[string]string{v1beta1constants.GardenRole: DNSProviderRoleAdditional},
					SecretData: secret.Data,
					Provider:   *p.Type,
					Domains: &dns.IncludeExclude{
						Include: includeDomains,
						Exclude: excludeDomains,
					},
					Zones: &dns.IncludeExclude{
						Include: includeZones,
						Exclude: excludeZones,
					},
				},
				nil,
			)
		}
	}

	// Clean-up old providers
	providerList := &dnsv1alpha1.DNSProviderList{}
	if err := seedClient.List(
		ctx,
		providerList,
		client.InNamespace(b.Shoot.SeedNamespace),
		client.MatchingLabels{v1beta1constants.GardenRole: DNSProviderRoleAdditional},
	); err != nil {
		return nil, err
	}

	for _, p := range providerList.Items {
		if _, ok := additionalProviders[p.Name]; !ok {
			additionalProviders[p.Name] = component.OpDestroy(dns.NewProvider(
				b.Logger,
				seedClient,
				b.Shoot.SeedNamespace,
				&dns.ProviderValues{
					Name:    p.Name,
					Purpose: p.Name,
					Labels:  map[string]string{v1beta1constants.GardenRole: DNSProviderRoleAdditional},
				},
				nil,
			))
		}
	}

	return additionalProviders, nil
}

// NeedsExternalDNS returns true if the Shoot cluster needs external DNS.
func (b *Botanist) NeedsExternalDNS() bool {
	return !b.Shoot.DisableDNS &&
		b.Shoot.Info.Spec.DNS != nil &&
		b.Shoot.Info.Spec.DNS.Domain != nil &&
		b.Shoot.ExternalClusterDomain != nil &&
		!strings.HasSuffix(*b.Shoot.ExternalClusterDomain, ".nip.io") &&
		b.Shoot.ExternalDomain != nil &&
		b.Shoot.ExternalDomain.Provider != "unmanaged"
}

// NeedsInternalDNS returns true if the Shoot cluster needs internal DNS.
func (b *Botanist) NeedsInternalDNS() bool {
	return !b.Shoot.DisableDNS &&
		b.Garden.InternalDomain != nil &&
		b.Garden.InternalDomain.Provider != "unmanaged"
}

// NeedsAdditionalDNSProviders returns true if additional DNS providers
// are needed.
func (b *Botanist) NeedsAdditionalDNSProviders() bool {
	return !b.Shoot.DisableDNS &&
		b.Shoot.Info.Spec.DNS != nil &&
		len(b.Shoot.Info.Spec.DNS.Providers) > 0
}

// APIServerSNIEnabled returns true if APIServerSNI feature gate is enabled and
// the shoot uses internal and external DNS.
func (b *Botanist) APIServerSNIEnabled() bool {
	return gardenletfeatures.FeatureGate.Enabled(features.APIServerSNI) && b.NeedsInternalDNS() && b.NeedsExternalDNS()
}

// APIServerSNIPodMutatorEnabled returns false if the value of the Shoot annotation
// 'alpha.featuregates.shoot.gardener.cloud/apiserver-sni-pod-injector' is 'disable' or
// APIServereSNI feature is disabled.
func (b *Botanist) APIServerSNIPodMutatorEnabled() bool {
	sniEnabled := b.APIServerSNIEnabled()
	if !sniEnabled {
		return false
	}

	vs, ok := b.Shoot.Info.GetAnnotations()[v1beta1constants.AnnotationShootAPIServerSNIPodInjector]
	if !ok {
		return true
	}

	return vs != v1beta1constants.AnnotationShootAPIServerSNIPodInjectorDisableValue
}

// DeleteDNSProviders deletes all DNS providers in the shoot namespace of the seed.
func (b *Botanist) DeleteDNSProviders(ctx context.Context) error {
	if err := b.K8sSeedClient.Client().DeleteAllOf(
		ctx,
		&dnsv1alpha1.DNSProvider{},
		client.InNamespace(b.Shoot.SeedNamespace),
	); err != nil {
		return err
	}

	return kutil.WaitUntilResourcesDeleted(
		ctx,
		b.K8sSeedClient.Client(),
		&dnsv1alpha1.DNSProviderList{},
		5*time.Second,
		client.InNamespace(b.Shoot.SeedNamespace),
	)
}

// DestroyInternalDNS destroys the internal DNSEntry, DNSOwner, and DNSProvider resources.
func (b *Botanist) DestroyInternalDNS(ctx context.Context) error {
	return component.OpDestroyAndWait(
		b.Shoot.Components.Extensions.DNS.InternalEntry,
		b.Shoot.Components.Extensions.DNS.InternalProvider,
		b.Shoot.Components.Extensions.DNS.InternalOwner,
	).Destroy(ctx)
}

// DestroyExternalDNS destroys the external DNSEntry, DNSOwner, and DNSProvider resources.
func (b *Botanist) DestroyExternalDNS(ctx context.Context) error {
	return component.OpDestroyAndWait(
		b.Shoot.Components.Extensions.DNS.ExternalEntry,
		b.Shoot.Components.Extensions.DNS.ExternalProvider,
		b.Shoot.Components.Extensions.DNS.ExternalOwner,
	).Destroy(ctx)
}

// MigrateInternalDNS destroys the internal DNSEntry, DNSOwner, and DNSProvider resources,
// without removing the entry from the DNS provider.
func (b *Botanist) MigrateInternalDNS(ctx context.Context) error {
	return component.OpDestroy(
		b.Shoot.Components.Extensions.DNS.InternalOwner,
		b.Shoot.Components.Extensions.DNS.InternalProvider,
		b.Shoot.Components.Extensions.DNS.InternalEntry,
	).Destroy(ctx)
}

// MigrateExternalDNS destroys the external DNSEntry, DNSOwner, and DNSProvider resources,
// without removing the entry from the DNS provider.
func (b *Botanist) MigrateExternalDNS(ctx context.Context) error {
	return component.OpDestroy(
		b.Shoot.Components.Extensions.DNS.ExternalOwner,
		b.Shoot.Components.Extensions.DNS.ExternalProvider,
		b.Shoot.Components.Extensions.DNS.ExternalEntry,
	).Destroy(ctx)
}

// dnsRestoreDeployer implements special deploy logic for DNS providers, entries, and owners to be executed only
// during the restore phase.
type dnsRestoreDeployer struct {
	provider component.DeployWaiter
	entry    component.DeployWaiter
	owner    component.DeployWaiter
}

func (d dnsRestoreDeployer) Deploy(ctx context.Context) error {
	// Deploy the provider and wait for it to become ready
	if d.provider != nil {
		if err := d.provider.Deploy(ctx); err != nil {
			return err
		}
		if err := d.provider.Wait(ctx); err != nil {
			return err
		}
	}

	// Deploy the entry and wait for it to be reconciled, but ignore any errors due to Invalid or Error status
	// This is done in order to ensure that the entry exists and has been reconciled before the owner is reconciled
	if err := d.entry.Deploy(ctx); err != nil {
		return err
	}
	if err := d.entry.Wait(ctx); err != nil && !strings.Contains(err.Error(), "status=") {
		return err
	}

	// Deploy the owner and wait for it to become ready
	if err := d.owner.Deploy(ctx); err != nil {
		return err
	}
	if err := d.owner.Wait(ctx); err != nil {
		return err
	}

	// Wait for the entry to become ready
	if err := d.entry.Wait(ctx); err != nil {
		return err
	}

	return nil
}

func (d dnsRestoreDeployer) Destroy(ctx context.Context) error {
	return nil
}
