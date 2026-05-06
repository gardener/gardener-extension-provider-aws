// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"fmt"
	"strings"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsvalidation "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

const (
	// AnnotationForceTGWDisable is the annotation on a Seed object that allows
	// disabling TGW even when child shoots are scheduled on the seed.
	AnnotationForceTGWDisable = "provider-aws.gardener.cloud/force-tgw-disable"
)

// seedValidator validates create and update operations on Seed resources,
// enforcing immutability of backup configurations and TGW disable safety.
type seedValidator struct {
	decoder        runtime.Decoder
	lenientDecoder runtime.Decoder
	apiReader      client.Reader
	gardenClient   client.Client
}

// NewSeedValidator returns a new instance of seed validator,
// to validate backupbucket configuration.
func NewSeedValidator(mgr manager.Manager) extensionswebhook.Validator {
	return &seedValidator{
		decoder:        serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		lenientDecoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
		apiReader:      mgr.GetAPIReader(),
		gardenClient:   mgr.GetClient(),
	}
}

// Validate validates the Seed resource during create or update operations.
// It enforces immutability policies on backup configurations to prevent
// disabling immutable settings, reducing retention periods, or changing retention types and mode.
func (s *seedValidator) Validate(ctx context.Context, newObj, oldObj client.Object) error {
	log.Log.WithName("aws-seed-validator").Info("Validate called", "type", fmt.Sprintf("%T", newObj), "name", newObj.GetName())

	newSeed, ok := newObj.(*core.Seed)
	if !ok {
		return fmt.Errorf("wrong object type %T for new object", newObj)
	}

	if oldObj != nil {
		oldSeed, ok := oldObj.(*core.Seed)
		if !ok {
			return fmt.Errorf("wrong object type %T for old object", oldObj)
		}
		return s.validateUpdate(ctx, oldSeed, newSeed).ToAggregate()
	}

	return s.validateCreate(newSeed).ToAggregate()
}

// validateCreate validates the Seed object upon creation.
// It checks if immutable settings are provided and if provided then it validates the immutable settings.
func (s *seedValidator) validateCreate(seed *core.Seed) field.ErrorList {
	var (
		allErrs = field.ErrorList{}
	)

	if seed.Spec.Backup != nil {
		backupPath := field.NewPath("spec", "backup")
		allErrs = append(allErrs, awsvalidation.ValidateBackupBucketCredentialsRef(seed.Spec.Backup.CredentialsRef, backupPath.Child("credentialsRef"))...)

		if seed.Spec.Backup.ProviderConfig != nil {
			allErrs = append(allErrs, awsvalidation.ValidateBackupBucketProviderConfigCreate(s.lenientDecoder, seed.Spec.Backup.ProviderConfig, backupPath.Child("providerConfig"))...)
		}
	}

	allErrs = append(allErrs, s.validateSeedProviderConfig(seed)...)

	return allErrs
}

// validateSeedProviderConfig decodes and validates the SeedProviderConfig from the seed's provider config.
func (s *seedValidator) validateSeedProviderConfig(seed *core.Seed) field.ErrorList {
	if seed.Spec.Provider.ProviderConfig == nil || seed.Spec.Provider.ProviderConfig.Raw == nil {
		return nil
	}
	seedConfig := &api.SeedProviderConfig{}
	if _, _, err := s.lenientDecoder.Decode(seed.Spec.Provider.ProviderConfig.Raw, nil, seedConfig); err != nil {
		// Not an AWS seed provider config — skip validation.
		return nil
	}
	return awsvalidation.ValidateSeedProviderConfig(seedConfig)
}

// validateUpdate validates updates to the Seed resource, ensuring that immutability settings for backup buckets
// are correctly managed and TGW disable safety is enforced.
func (s *seedValidator) validateUpdate(ctx context.Context, oldSeed, newSeed *core.Seed) field.ErrorList {
	var (
		allErrs    = field.ErrorList{}
		backupPath = field.NewPath("spec", "backup")

		oldBackupBucketConfig *runtime.RawExtension = nil
		newBackupBucketConfig *runtime.RawExtension = nil
	)

	if oldSeed.Spec.Backup != nil {
		oldBackupBucketConfig = oldSeed.Spec.Backup.ProviderConfig
	}

	if newSeed.Spec.Backup != nil {
		newBackupBucketConfig = newSeed.Spec.Backup.ProviderConfig
		allErrs = append(allErrs, awsvalidation.ValidateBackupBucketCredentialsRef(newSeed.Spec.Backup.CredentialsRef, backupPath.Child("credentialsRef"))...)
	}

	allErrs = append(allErrs, awsvalidation.ValidateBackupBucketProviderConfigUpdate(s.decoder, s.lenientDecoder, oldBackupBucketConfig, newBackupBucketConfig, backupPath.Child("providerConfig"))...)

	allErrs = append(allErrs, s.validateSeedProviderConfig(newSeed)...)

	// Validate TGW disable safety.
	allErrs = append(allErrs, s.validateTGWDisable(ctx, oldSeed, newSeed)...)

	// Validate TGW enable safety — check for CIDR overlaps among existing shoots.
	allErrs = append(allErrs, s.validateTGWEnable(ctx, oldSeed, newSeed)...)

	// Validate globalCustomRoutes don't conflict with existing shoot CIDRs.
	allErrs = append(allErrs, s.validateGlobalCustomRoutes(ctx, newSeed)...)

	return allErrs
}

// validateTGWDisable checks if TGW is being disabled (enabled: true → false) and
// rejects the change if child shoots are scheduled on this seed, unless the force
// annotation is present.
func (s *seedValidator) validateTGWDisable(ctx context.Context, oldSeed, newSeed *core.Seed) field.ErrorList {
	allErrs := field.ErrorList{}

	// Decode old and new SeedProviderConfigs.
	oldConfig := s.decodeSeedProviderConfig(oldSeed)
	newConfig := s.decodeSeedProviderConfig(newSeed)

	// Check if TGW is being disabled (was enabled, now disabled or removed).
	oldEnabled := oldConfig != nil && oldConfig.TransitGateway != nil && oldConfig.TransitGateway.Enabled
	newEnabled := newConfig != nil && newConfig.TransitGateway != nil && newConfig.TransitGateway.Enabled

	log.Log.WithName("aws-seed-validator").V(1).Info("validateTGWDisable", "oldEnabled", oldEnabled, "newEnabled", newEnabled, "seed", newSeed.Name)

	if !oldEnabled || newEnabled {
		return nil // Not disabling TGW — nothing to validate.
	}

	log.Log.WithName("aws-seed-validator").Info("TGW being disabled — checking for child shoots", "seed", newSeed.Name)

	// TGW is being disabled. Check if child shoots exist on this seed.
	// Use the internal core.ShootList type (admission uses internal API types).
	shootList := &gardencorev1beta1.ShootList{}
	if err := s.gardenClient.List(ctx, shootList); err != nil {
		log.Log.WithName("aws-seed-validator").Error(err, "Failed to list shoots for TGW disable validation")
		return nil
	}
	log.Log.WithName("aws-seed-validator").V(1).Info("Listed shoots", "count", len(shootList.Items))

	// Filter shoots scheduled on this seed.
	var shootsOnSeed []gardencorev1beta1.Shoot
	for _, shoot := range shootList.Items {
		if shoot.Spec.SeedName != nil && *shoot.Spec.SeedName == newSeed.Name {
			shootsOnSeed = append(shootsOnSeed, shoot)
		}
	}

	log.Log.WithName("aws-seed-validator").Info("Shoots on seed for TGW disable check", "seed", newSeed.Name, "count", len(shootsOnSeed))

	if len(shootsOnSeed) == 0 {
		return nil // No child shoots — safe to disable.
	}

	// Child shoots exist. Check for force annotation on the Seed.
	if newSeed.Annotations != nil && newSeed.Annotations[AnnotationForceTGWDisable] == "true" {
		return nil // Force annotation present — allow.
	}

	// Collect shoot names for the error message.
	shootNames := make([]string, 0, len(shootsOnSeed))
	for _, shoot := range shootsOnSeed {
		shootNames = append(shootNames, shoot.Name)
	}

	tgwPath := field.NewPath("spec", "provider", "providerConfig", "transitGateway", "enabled")
	allErrs = append(allErrs, field.Forbidden(tgwPath, fmt.Sprintf(
		"cannot disable transitGateway on seed %q: %d shoots are scheduled on this seed (%s). Delete all child shoots first, or annotate the seed with %s=true",
		newSeed.Name, len(shootsOnSeed), strings.Join(shootNames, ", "), AnnotationForceTGWDisable)))

	return allErrs
}

// validateTGWEnable checks if TGW is being enabled (false → true or new config added) and
// validates that existing shoots on this seed don't have overlapping VPC CIDRs.
// Prevents silent routing failures when a non-TGW seed is converted to TGW.
func (s *seedValidator) validateTGWEnable(ctx context.Context, oldSeed, newSeed *core.Seed) field.ErrorList {
	allErrs := field.ErrorList{}

	oldConfig := s.decodeSeedProviderConfig(oldSeed)
	newConfig := s.decodeSeedProviderConfig(newSeed)

	oldEnabled := oldConfig != nil && oldConfig.TransitGateway != nil && oldConfig.TransitGateway.Enabled
	newEnabled := newConfig != nil && newConfig.TransitGateway != nil && newConfig.TransitGateway.Enabled

	if oldEnabled || !newEnabled {
		return nil // Not enabling TGW — nothing to validate.
	}

	// TGW is being enabled. Check existing shoots for CIDR conflicts.
	shootList := &gardencorev1beta1.ShootList{}
	if err := s.gardenClient.List(ctx, shootList, client.MatchingFields{"spec.seedName": newSeed.Name}); err != nil {
		// Fallback to unfiltered list.
		if err := s.gardenClient.List(ctx, shootList); err != nil {
			return nil
		}
	}

	existingShoots := make(map[string]string)
	for _, sh := range shootList.Items {
		if sh.Spec.SeedName != nil && *sh.Spec.SeedName == newSeed.Name {
			if sh.Spec.Networking != nil && sh.Spec.Networking.Nodes != nil {
				existingShoots[sh.Name] = *sh.Spec.Networking.Nodes
			}
		}
	}

	if len(existingShoots) < 2 {
		return nil // 0 or 1 shoots — no possible overlap.
	}

	seedNodesCIDR := ""
	if newSeed.Spec.Networks.Nodes != nil {
		seedNodesCIDR = *newSeed.Spec.Networks.Nodes
	}

	// Look up runtime VPC CIDR from parent seed.
	runtimeVPCCIDR := ""
	seedShoot := &gardencorev1beta1.Shoot{}
	if err := s.gardenClient.Get(ctx, client.ObjectKey{Namespace: "garden", Name: newSeed.Name}, seedShoot); err == nil {
		if seedShoot.Spec.SeedName != nil {
			parentSeed := &gardencorev1beta1.Seed{}
			if err := s.gardenClient.Get(ctx, client.ObjectKey{Name: *seedShoot.Spec.SeedName}, parentSeed); err == nil {
				if parentSeed.Spec.Networks.Nodes != nil {
					runtimeVPCCIDR = *parentSeed.Spec.Networks.Nodes
				}
			}
		}
	}

	// Check each shoot's CIDR against all others + reserved CIDRs.
	tgwPath := field.NewPath("spec", "provider", "providerConfig", "transitGateway", "enabled")
	for shootName, shootCIDR := range existingShoots {
		reserved := awsvalidation.BuildReservedCIDRs(
			newSeed.Name, newConfig, seedNodesCIDR,
			runtimeVPCCIDR, existingShoots, shootName,
		)
		errs := awsvalidation.ValidateShootCIDROverlap(tgwPath, shootCIDR, shootName, nil, reserved, newConfig)
		if len(errs) > 0 {
			allErrs = append(allErrs, field.Forbidden(tgwPath,
				fmt.Sprintf("cannot enable transitGateway: existing shoots have overlapping CIDRs — %s", errs.ToAggregate().Error())))
			break // One conflict is enough to reject.
		}
	}

	return allErrs
}

// validateGlobalCustomRoutes checks that globalCustomRoutes destinations don't overlap
// with existing shoot VPC CIDRs on this seed. Prevents adding a globalCustomRoute that
// would conflict with an existing shoot's routing.
func (s *seedValidator) validateGlobalCustomRoutes(ctx context.Context, seed *core.Seed) field.ErrorList {
	allErrs := field.ErrorList{}

	config := s.decodeSeedProviderConfig(seed)
	if config == nil || config.TransitGateway == nil || !config.TransitGateway.Enabled {
		return nil
	}
	if len(config.GlobalCustomRoutes) == 0 {
		return nil
	}

	// List shoots on this seed.
	shootList := &gardencorev1beta1.ShootList{}
	if err := s.gardenClient.List(ctx, shootList, client.MatchingFields{"spec.seedName": seed.Name}); err != nil {
		if err := s.gardenClient.List(ctx, shootList); err != nil {
			return nil
		}
	}

	crPath := field.NewPath("spec", "provider", "providerConfig", "globalCustomRoutes")
	for i, route := range config.GlobalCustomRoutes {
		if route.DestinationCidrBlock == nil {
			continue
		}
		dest := *route.DestinationCidrBlock
		routePath := crPath.Index(i).Child("destinationCidrBlock")

		for _, sh := range shootList.Items {
			if sh.Spec.SeedName == nil || *sh.Spec.SeedName != seed.Name {
				continue
			}
			if sh.Spec.Networking != nil && sh.Spec.Networking.Nodes != nil {
				if awsvalidation.CIDRsOverlap(dest, *sh.Spec.Networking.Nodes) {
					allErrs = append(allErrs, field.Forbidden(routePath,
						fmt.Sprintf("globalCustomRoute destination %s overlaps with shoot %q VPC CIDR %s",
							dest, sh.Name, *sh.Spec.Networking.Nodes)))
				}
			}
		}
	}

	return allErrs
}

// decodeSeedProviderConfig decodes the SeedProviderConfig from a Seed, returning nil if
// the config is absent or not an AWS config.
func (s *seedValidator) decodeSeedProviderConfig(seed *core.Seed) *api.SeedProviderConfig {
	if seed.Spec.Provider.ProviderConfig == nil || seed.Spec.Provider.ProviderConfig.Raw == nil {
		return nil
	}
	config := &api.SeedProviderConfig{}
	if _, _, err := s.lenientDecoder.Decode(seed.Spec.Provider.ProviderConfig.Raw, nil, config); err != nil {
		return nil
	}
	return config
}
