// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"context"
	"fmt"
	"reflect"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	gardencorehelper "github.com/gardener/gardener/pkg/apis/core/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/utils/gardener"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
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

		if p.SecretName == nil || *p.SecretName == "" {
			allErrs = append(allErrs, field.Required(providerFldPath.Child("secretName"),
				fmt.Sprintf("secretName must be specified for %v provider", aws.DNSType)))
			continue
		}

		secret := &corev1.Secret{}
		key := client.ObjectKey{Namespace: shoot.Namespace, Name: *p.SecretName}
		if err := s.apiReader.Get(ctx, key, secret); err != nil {
			if apierrors.IsNotFound(err) {
				allErrs = append(allErrs, field.Invalid(providerFldPath.Child("secretName"),
					*p.SecretName, "referenced secret not found"))
			} else {
				allErrs = append(allErrs, field.InternalError(providerFldPath.Child("secretName"), err))
			}
			continue
		}

		allErrs = append(allErrs, awsvalidation.ValidateCloudProviderSecret(secret, providerFldPath, awsvalidation.SecretKindDns)...)
	}

	return allErrs
}
