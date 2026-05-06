// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"fmt"
	"reflect"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gardencorehelper "github.com/gardener/gardener/pkg/api/core/helper"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	securityv1alpha1 "github.com/gardener/gardener/pkg/apis/security/v1alpha1"
	"github.com/gardener/gardener/pkg/utils/gardener"
	"github.com/gardener/gardener/pkg/utils/kubernetes"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apihelper "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	awsvalidation "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

var (
	specPath         = field.NewPath("spec")
	nwPath           = specPath.Child("networking")
	providerPath     = specPath.Child("provider")
	infraConfigPath  = providerPath.Child("infrastructureConfig")
	cpConfigPath     = providerPath.Child("controlPlaneConfig")
	workersPath      = providerPath.Child("workers")
	dnsProvidersPath = specPath.Child("dns").Child("providers")
)

// NewShootValidator returns a new instance of a shoot validator.
func NewShootValidator(mgr manager.Manager) extensionswebhook.Validator {
	return &shoot{
		client:         mgr.GetClient(),
		apiReader:      mgr.GetAPIReader(),
		decoder:        serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		lenientDecoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
	}
}

type shoot struct {
	client         client.Client
	apiReader      client.Reader
	decoder        runtime.Decoder
	lenientDecoder runtime.Decoder
}

// Validate validates the given shoot object.
func (s *shoot) Validate(ctx context.Context, newObj, old client.Object) error {
	shoot, ok := newObj.(*core.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", newObj)
	}

	// Skip if it's a workerless Shoot
	if gardencorehelper.IsWorkerless(shoot) {
		return nil
	}

	shootV1Beta1 := &gardencorev1beta1.Shoot{}
	err := gardencorev1beta1.Convert_core_Shoot_To_v1beta1_Shoot(shoot, shootV1Beta1, nil)
	if err != nil {
		return err
	}
	cloudProfile, err := gardener.GetCloudProfile(ctx, s.client, shootV1Beta1)
	if err != nil {
		return err
	}
	if cloudProfile == nil {
		return fmt.Errorf("cloudprofile could not be found")
	}

	if old != nil {
		oldShoot, ok := old.(*core.Shoot)
		if !ok {
			return fmt.Errorf("wrong object type %T for old object", old)
		}
		return s.validateShootUpdate(ctx, oldShoot, shoot, &cloudProfile.Spec)
	}

	return s.validateShootCreation(ctx, shoot, &cloudProfile.Spec)
}

func (s *shoot) validateShoot(ctx context.Context, shoot *core.Shoot) error {
	allErrs := field.ErrorList{}

	// Network validation
	if shoot.Spec.Networking != nil {
		allErrs = append(allErrs, awsvalidation.ValidateNetworking(shoot.Spec.Networking, nwPath)...)
	}

	// InfrastructureConfig
	if shoot.Spec.Provider.InfrastructureConfig == nil {
		return field.Required(infraConfigPath, "InfrastructureConfig must be set for AWS shoots")
	}

	infraConfig, err := decodeInfrastructureConfig(s.decoder, shoot.Spec.Provider.InfrastructureConfig, infraConfigPath)
	if err != nil {
		return err
	}

	allErrs = append(allErrs, awsvalidation.ValidateInfrastructureConfig(infraConfig, shoot.Spec.Networking.IPFamilies, shoot.Spec.Networking.Nodes, shoot.Spec.Networking.Pods, shoot.Spec.Networking.Services)...)

	// Cross-validate against seed config (if seed is known).
	// Only fetch seed config when needed: shoot has customRoutes, shoot-level TGW, or
	// seed has TGW enabled (for CIDR overlap validation).
	needsSeedConfig := len(infraConfig.Networks.CustomRoutes) > 0 ||
		(infraConfig.Networks.TransitGateway != nil && infraConfig.Networks.TransitGateway.Enabled)
	if shoot.Spec.SeedName != nil {
		seed := &gardencorev1beta1.Seed{}
		if err := s.client.Get(ctx, client.ObjectKey{Name: *shoot.Spec.SeedName}, seed); err == nil {
			if seedConfig, err := apihelper.SeedProviderConfigFromSeed(seed); err == nil && seedConfig != nil {
				// Seed has TGW — always need cross-validation for CIDR overlap.
				if seedConfig.TransitGateway != nil && seedConfig.TransitGateway.Enabled {
					needsSeedConfig = true
				}

				if needsSeedConfig {
					// Check shoot customRoutes don't conflict with seed globalCustomRoutes.
					if len(infraConfig.Networks.CustomRoutes) > 0 {
						allErrs = append(allErrs, awsvalidation.ValidateCustomRoutesAgainstGlobalRoutes(
							infraConfigPath.Child("networks", "customRoutes"),
							infraConfig.Networks.CustomRoutes,
							seedConfig.GlobalCustomRoutes,
						)...)
					}
					// Check shoot TGW ID doesn't duplicate seed TGW ID.
					if infraConfig.Networks.TransitGateway != nil && infraConfig.Networks.TransitGateway.Enabled &&
						infraConfig.Networks.TransitGateway.ID != nil &&
						seedConfig.TransitGateway != nil && seedConfig.TransitGateway.Enabled &&
						seedConfig.TransitGateway.ID != nil &&
						*infraConfig.Networks.TransitGateway.ID == *seedConfig.TransitGateway.ID {
						allErrs = append(allErrs, field.Forbidden(
							infraConfigPath.Child("networks", "transitGateway", "id"),
							"shoot-level TGW ID must differ from seed-level TGW ID (same TGW is already attached by the seed)"))
					}
				}

				// CIDR overlap validation: check shoot VPC CIDR against all reserved CIDRs
				// in the TGW routing domain (other shoots, globalVPCs, seed nodes, runtime VPC).
				// Only runs when the seed has TGW enabled.
				if seedConfig.TransitGateway != nil && seedConfig.TransitGateway.Enabled &&
					shoot.Spec.Networking != nil && shoot.Spec.Networking.Nodes != nil {
					existingShoots := s.listShootNodesCIDRsOnSeed(ctx, *shoot.Spec.SeedName)
					seedNodesCIDR := ""
					if seed.Spec.Networks.Nodes != nil {
						seedNodesCIDR = *seed.Spec.Networks.Nodes
					}
					// Look up the runtime VPC CIDR from the parent seed.
					// The seed shoot runs on a parent seed.
					// Find the parent by looking up which seed runs this seed's shoot.
					runtimeVPCCIDR := s.lookupRuntimeVPCCIDR(ctx, *shoot.Spec.SeedName)
					reserved := awsvalidation.BuildReservedCIDRs(
						*shoot.Spec.SeedName, seedConfig, seedNodesCIDR,
						runtimeVPCCIDR, existingShoots, shoot.Name,
					)
					// Phase 2: add reserved CIDRs from other TGW-enabled seeds.
					reserved = append(reserved, s.buildCrossSeedReservedCIDRs(ctx, *shoot.Spec.SeedName, shoot.Name)...)
					allErrs = append(allErrs, awsvalidation.ValidateShootCIDROverlap(
						nwPath.Child("nodes"),
						*shoot.Spec.Networking.Nodes,
						shoot.Name,
						infraConfig.Networks.CustomRoutes,
						reserved,
						seedConfig,
					)...)
				}
			}
		}
		// If seed lookup fails, skip cross-validation — reconciler will catch conflicts.
	}

	// ControlPlaneConfig
	if shoot.Spec.Provider.ControlPlaneConfig != nil {
		controlPlaneConfig, err := decodeControlPlaneConfig(s.decoder, shoot.Spec.Provider.ControlPlaneConfig, cpConfigPath)
		if err != nil {
			return err
		}

		allErrs = append(allErrs, awsvalidation.ValidateControlPlaneConfig(controlPlaneConfig, shoot.Spec.Kubernetes.Version, cpConfigPath)...)
	}

	// DNS validation
	allErrs = append(allErrs, s.validateDNS(ctx, shoot)...)

	for i, worker := range shoot.Spec.Provider.Workers {
		var workerConfig *api.WorkerConfig
		if worker.ProviderConfig != nil {
			wc, err := decodeWorkerConfig(s.decoder, worker.ProviderConfig, workersPath.Index(i).Child("providerConfig"))
			if err != nil {
				return err
			}
			workerConfig = wc
		}

		allErrs = append(allErrs, awsvalidation.ValidateWorker(worker, infraConfig.Networks.Zones, workerConfig, workersPath.Index(i))...)
	}

	return allErrs.ToAggregate()
}

func (s *shoot) validateShootUpdate(ctx context.Context, oldShoot, shoot *core.Shoot, cloudProfileSpec *gardencorev1beta1.CloudProfileSpec) error {
	if oldShoot.Spec.Provider.InfrastructureConfig == nil {
		return field.InternalError(infraConfigPath, fmt.Errorf("InfrastructureConfig is not available on old shoot"))
	}

	oldInfraConfig, err := decodeInfrastructureConfig(s.lenientDecoder, oldShoot.Spec.Provider.InfrastructureConfig, infraConfigPath)
	if err != nil {
		return err
	}

	awsCloudProfile, infraConfig, err := s.baseShootValidation(ctx, shoot, cloudProfileSpec, oldInfraConfig)
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(oldInfraConfig, infraConfig) {
		if errList := awsvalidation.ValidateInfrastructureConfigUpdate(oldInfraConfig, infraConfig); len(errList) != 0 {
			return errList.ToAggregate()
		}
	}

	if errList := awsvalidation.ValidateWorkersUpdate(oldShoot.Spec.Provider.Workers, shoot.Spec.Provider.Workers, workersPath); len(errList) != 0 {
		return errList.ToAggregate()
	}

	if shoot.DeletionTimestamp == nil {
		// If the Shoot is being deleted, we do not validate the workers against the cloud
		// profile, as the workers will be deleted anyway.
		if errList := awsvalidation.ValidateWorkersAgainstCloudProfileOnUpdate(oldShoot.Spec.Provider.Workers, shoot.Spec.Provider.Workers, shoot.Spec.Region, awsCloudProfile, cloudProfileSpec.MachineTypes, cloudProfileSpec.MachineCapabilities, workersPath); len(errList) != 0 {
			return errList.ToAggregate()
		}
	}

	return s.validateShoot(ctx, shoot)
}

func (s *shoot) validateShootCreation(ctx context.Context, shoot *core.Shoot, cloudProfileSpec *gardencorev1beta1.CloudProfileSpec) error {
	awsCloudProfile, _, err := s.baseShootValidation(ctx, shoot, cloudProfileSpec, nil)
	if err != nil {
		return err
	}

	if errList := awsvalidation.ValidateWorkersAgainstCloudProfileOnCreation(shoot.Spec.Provider.Workers, shoot.Spec.Region, awsCloudProfile, cloudProfileSpec.MachineTypes, cloudProfileSpec.MachineCapabilities, workersPath); len(errList) != 0 {
		return errList.ToAggregate()
	}

	return s.validateShoot(ctx, shoot)
}

func (s *shoot) baseShootValidation(ctx context.Context, shoot *core.Shoot, cloudProfileSpec *gardencorev1beta1.CloudProfileSpec, oldInfraConfig *api.InfrastructureConfig) (*api.CloudProfileConfig, *api.InfrastructureConfig, error) {
	if shoot.Spec.Provider.InfrastructureConfig == nil {
		return nil, nil, field.Required(infraConfigPath, "InfrastructureConfig must be set for AWS shoots")
	}

	infraConfig, err := decodeInfrastructureConfig(s.decoder, shoot.Spec.Provider.InfrastructureConfig, infraConfigPath)
	if err != nil {
		return nil, nil, err
	}

	if cloudProfileSpec == nil {
		return nil, nil, fmt.Errorf("shoot.spec.cloudprofile must not be nil <nil>")
	}
	awsCloudProfile, err := decodeCloudProfileConfig(s.decoder, cloudProfileSpec.ProviderConfig)
	if err != nil {
		return nil, nil, err
	}

	if err = s.validateAgainstCloudProfile(ctx, shoot, oldInfraConfig, infraConfig, cloudProfileSpec, infraConfigPath); err != nil {
		return nil, nil, err
	}

	return awsCloudProfile, infraConfig, nil
}

func (s *shoot) validateAgainstCloudProfile(_ context.Context, shoot *core.Shoot, oldInfraConfig, infraConfig *api.InfrastructureConfig, cloudProfileSpec *gardencorev1beta1.CloudProfileSpec, fldPath *field.Path) error {
	if errList := awsvalidation.ValidateInfrastructureConfigAgainstCloudProfile(oldInfraConfig, infraConfig, shoot, cloudProfileSpec, fldPath); len(errList) != 0 {
		return errList.ToAggregate()
	}

	return nil
}

// validateDNS validates all aws-dns provider entries in the Shoot spec.
func (s *shoot) validateDNS(ctx context.Context, shoot *core.Shoot) field.ErrorList {
	allErrs := field.ErrorList{}

	if shoot.Spec.DNS == nil {
		return allErrs
	}

	for i, p := range shoot.Spec.DNS.Providers {
		if p.Type == nil || *p.Type != aws.DNSType {
			continue
		}

		// Check if this is the primary provider
		if p.Primary == nil || !*p.Primary {
			continue // Skip non-primary providers
		}

		providerFldPath := dnsProvidersPath.Index(i)

		// TODO(vpnachev): Enable this validation once the extension does not support github.com/gardener/gardener < v1.135.0
		// if p.CredentialsRef == nil {
		// 	allErrs = append(allErrs, field.Required(providerFldPath.Child("credentialsRef"), "must be set"))
		// }

		if p.CredentialsRef != nil {
			credentialsFldPath := providerFldPath.Child("credentialsRef")

			credentials, err := kubernetes.GetCredentialsByCrossVersionObjectReference(ctx, s.apiReader, *p.CredentialsRef, shoot.GetNamespace())
			if err != nil {
				if apierrors.IsNotFound(err) {
					allErrs = append(allErrs, field.NotFound(credentialsFldPath, p.CredentialsRef.String()))
				} else {
					allErrs = append(allErrs, field.InternalError(credentialsFldPath, err))
				}
				continue
			}

			switch creds := credentials.(type) {
			case *securityv1alpha1.WorkloadIdentity:
				if err := ValidateWorkloadIdentity(creds, nil); err != nil {
					allErrs = append(allErrs, field.Invalid(credentialsFldPath, p.CredentialsRef.String(), err.Error()))
				}
			case *corev1.Secret:
				if err := ValidateSecret(creds, nil); err != nil {
					allErrs = append(allErrs, field.Invalid(credentialsFldPath, p.CredentialsRef.String(), err.Error()))
				}
			default:
				allErrs = append(allErrs, field.Invalid(credentialsFldPath, p.CredentialsRef.String(), "supported credentials types are Secret and WorkloadIdentity"))
			}
		} else { // TODO(vpnachev): Remove the else block once the extension does not support github.com/gardener/gardener < v1.135.0
			secretNameFldPath := providerFldPath.Child("secretName")
			if p.SecretName == nil || *p.SecretName == "" {
				allErrs = append(allErrs, field.Required(secretNameFldPath,
					fmt.Sprintf("secretName must be specified for %v provider", aws.DNSType)))
				continue
			}

			secret := &corev1.Secret{}
			key := client.ObjectKey{Namespace: shoot.Namespace, Name: *p.SecretName}
			if err := s.apiReader.Get(ctx, key, secret); err != nil {
				if apierrors.IsNotFound(err) {
					allErrs = append(allErrs, field.Invalid(secretNameFldPath,
						*p.SecretName, "referenced secret not found"))
				} else {
					allErrs = append(allErrs, field.InternalError(secretNameFldPath, err))
				}
				continue
			}

			if err := ValidateSecret(secret, nil); err != nil {
				allErrs = append(allErrs, field.Invalid(secretNameFldPath, p.SecretName, err.Error()))
			}
		}
	}

	return allErrs
}

// lookupRuntimeVPCCIDR finds the runtime VPC CIDR by looking up the parent seed.
// The managed seed is a shoot on a parent seed.
// The parent seed's nodes CIDR is the runtime VPC CIDR.
func (s *shoot) lookupRuntimeVPCCIDR(ctx context.Context, seedName string) string {
	// Find the shoot that became this seed (shoot name = seed name).
	seedShoot := &gardencorev1beta1.Shoot{}
	if err := s.client.Get(ctx, client.ObjectKey{Namespace: "garden", Name: seedName}, seedShoot); err != nil {
		return ""
	}
	if seedShoot.Spec.SeedName == nil {
		return ""
	}
	// Get the parent seed's nodes CIDR.
	parentSeed := &gardencorev1beta1.Seed{}
	if err := s.client.Get(ctx, client.ObjectKey{Name: *seedShoot.Spec.SeedName}, parentSeed); err != nil {
		return ""
	}
	if parentSeed.Spec.Networks.Nodes != nil {
		return *parentSeed.Spec.Networks.Nodes
	}
	return ""
}

// listShootNodesCIDRsOnSeed returns a map of shootName -> nodesCIDR for all shoots
// scheduled on the given seed. Uses field selector to filter server-side when available.
func (s *shoot) listShootNodesCIDRsOnSeed(ctx context.Context, seedName string) map[string]string {
	result := make(map[string]string)
	shootList := &gardencorev1beta1.ShootList{}
	// Use field selector to filter by seedName server-side (Gardener API supports this index).
	if err := s.client.List(ctx, shootList, client.MatchingFields{"spec.seedName": seedName}); err != nil {
		// Fallback: list all and filter client-side if field selector not supported.
		if err := s.client.List(ctx, shootList); err != nil {
			return result
		}
		for _, sh := range shootList.Items {
			if sh.Spec.SeedName != nil && *sh.Spec.SeedName == seedName {
				if sh.Spec.Networking != nil && sh.Spec.Networking.Nodes != nil {
					result[sh.Name] = *sh.Spec.Networking.Nodes
				}
			}
		}
		return result
	}
	for _, sh := range shootList.Items {
		if sh.Spec.Networking != nil && sh.Spec.Networking.Nodes != nil {
			result[sh.Name] = *sh.Spec.Networking.Nodes
		}
	}
	return result
}

// buildCrossSeedReservedCIDRs collects reserved CIDRs from ALL TGW-enabled seeds,
// not just the target seed. This prevents CIDR overlaps when multiple seeds share
// globalVPCs or TGW routing infrastructure.
func (s *shoot) buildCrossSeedReservedCIDRs(ctx context.Context, targetSeedName, currentShootName string) []awsvalidation.ReservedCIDR {
	var reserved []awsvalidation.ReservedCIDR

	seedList := &gardencorev1beta1.SeedList{}
	if err := s.client.List(ctx, seedList); err != nil {
		return reserved
	}

	for _, seed := range seedList.Items {
		if seed.Name == targetSeedName {
			continue // Target seed is already handled by BuildReservedCIDRs.
		}
		seedConfig, err := apihelper.SeedProviderConfigFromSeed(&seed)
		if err != nil || seedConfig == nil || seedConfig.TransitGateway == nil || !seedConfig.TransitGateway.Enabled {
			continue // Not a TGW-enabled seed.
		}

		// Add this seed's node CIDR — but skip if this seed IS the current shoot
		// (ManagedSeed shoots have the same name as their seed, and their VPC CIDR
		// equals the seed's spec.networks.nodes).
		if seed.Spec.Networks.Nodes != nil && seed.Name != currentShootName {
			reserved = append(reserved, awsvalidation.ReservedCIDR{
				CIDR:   *seed.Spec.Networks.Nodes,
				Owner:  seed.Name,
				Reason: "seed nodes (cross-seed)",
			})
		}

		// Add this seed's globalVPC CIDRs.
		for _, gvpc := range seedConfig.TransitGateway.GlobalVPCs {
			for _, cidr := range gvpc.CIDRs {
				reserved = append(reserved, awsvalidation.ReservedCIDR{
					CIDR:   cidr,
					Owner:  fmt.Sprintf("globalVPC %q on seed %s", gvpc.Name, seed.Name),
					Reason: "globalVPC (cross-seed)",
				})
			}
		}

		// Add shoots on this seed.
		existingShoots := s.listShootNodesCIDRsOnSeed(ctx, seed.Name)
		for shootName, cidr := range existingShoots {
			if shootName == currentShootName || cidr == "" {
				continue
			}
			reserved = append(reserved, awsvalidation.ReservedCIDR{
				CIDR:   cidr,
				Owner:  fmt.Sprintf("shoot %q on seed %s", shootName, seed.Name),
				Reason: "shoot VPC CIDR (cross-seed)",
			})
		}
	}

	return reserved
}
