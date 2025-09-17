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
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsvalidation "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
)

// NewShootValidator returns a new instance of a shoot validator.
func NewShootValidator(mgr manager.Manager) extensionswebhook.Validator {
	return &shoot{
		client:         mgr.GetClient(),
		decoder:        serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		lenientDecoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
	}
}

type shoot struct {
	client         client.Client
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

func (s *shoot) validateShoot(_ context.Context, shoot *core.Shoot) error {
	// Network validation
	if shoot.Spec.Networking != nil {
		if errList := awsvalidation.ValidateNetworking(shoot.Spec.Networking, field.NewPath("spec", "networking")); len(errList) != 0 {
			return errList.ToAggregate()
		}
	}

	// Provider validation
	fldPath := field.NewPath("spec", "provider")

	// InfrastructureConfig
	if shoot.Spec.Provider.InfrastructureConfig == nil {
		return field.Required(fldPath.Child("infrastructureConfig"), "InfrastructureConfig must be set for AWS shoots")
	}

	infraConfig, err := decodeInfrastructureConfig(s.decoder, shoot.Spec.Provider.InfrastructureConfig, fldPath.Child("infrastructureConfig"))
	if err != nil {
		return err
	}

	if shoot.Spec.Networking != nil {
		if errList := awsvalidation.ValidateInfrastructureConfig(infraConfig, shoot.Spec.Networking.IPFamilies, shoot.Spec.Networking.Nodes, shoot.Spec.Networking.Pods, shoot.Spec.Networking.Services); len(errList) != 0 {
			return errList.ToAggregate()
		}
	}

	// ControlPlaneConfig
	if shoot.Spec.Provider.ControlPlaneConfig != nil {
		controlPlaneConfig, err := decodeControlPlaneConfig(s.decoder, shoot.Spec.Provider.ControlPlaneConfig, fldPath.Child("controlPlaneConfig"))
		if err != nil {
			return err
		}

		if errList := awsvalidation.ValidateControlPlaneConfig(controlPlaneConfig, shoot.Spec.Kubernetes.Version, fldPath.Child("controlPlaneConfig")); len(errList) != 0 {
			return errList.ToAggregate()
		}
	}

	fldPath = fldPath.Child("workers")
	for i, worker := range shoot.Spec.Provider.Workers {
		var workerConfig *api.WorkerConfig
		if worker.ProviderConfig != nil {
			wc, err := decodeWorkerConfig(s.decoder, worker.ProviderConfig, fldPath.Index(i).Child("providerConfig"))
			if err != nil {
				return err
			}
			workerConfig = wc
		}

		if errList := awsvalidation.ValidateWorker(worker, infraConfig.Networks.Zones, workerConfig, fldPath.Index(i)); len(errList) != 0 {
			return errList.ToAggregate()
		}
	}

	return nil
}

func (s *shoot) validateShootUpdate(ctx context.Context, oldShoot, shoot *core.Shoot, cloudProfileSpec *gardencorev1beta1.CloudProfileSpec) error {
	var (
		fldPath            = field.NewPath("spec", "provider")
		infraConfigFldPath = fldPath.Child("infrastructureConfig")
	)

	if oldShoot.Spec.Provider.InfrastructureConfig == nil {
		return field.InternalError(infraConfigFldPath, fmt.Errorf("InfrastructureConfig is not available on old shoot"))
	}

	oldInfraConfig, err := decodeInfrastructureConfig(s.lenientDecoder, oldShoot.Spec.Provider.InfrastructureConfig, infraConfigFldPath)
	if err != nil {
		return err
	}

	awsCloudProfile, infraConfig, err := s.baseShootValidation(ctx, shoot, cloudProfileSpec, oldInfraConfig, fldPath)
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(oldInfraConfig, infraConfig) {
		if errList := awsvalidation.ValidateInfrastructureConfigUpdate(oldInfraConfig, infraConfig); len(errList) != 0 {
			return errList.ToAggregate()
		}
	}

	if errList := awsvalidation.ValidateWorkersUpdate(oldShoot.Spec.Provider.Workers, shoot.Spec.Provider.Workers, fldPath.Child("workers")); len(errList) != 0 {
		return errList.ToAggregate()
	}

	if shoot.DeletionTimestamp == nil {
		// If the Shoot is being deleted, we do not validate the workers against the cloud
		// profile, as the workers will be deleted anyway.
		if errList := awsvalidation.ValidateWorkersAgainstCloudProfileOnUpdate(oldShoot.Spec.Provider.Workers, shoot.Spec.Provider.Workers, shoot.Spec.Region, awsCloudProfile, cloudProfileSpec.MachineTypes, cloudProfileSpec.MachineCapabilities, fldPath.Child("workers")); len(errList) != 0 {
			return errList.ToAggregate()
		}
	}

	return s.validateShoot(ctx, shoot)
}

func (s *shoot) validateShootCreation(ctx context.Context, shoot *core.Shoot, cloudProfileSpec *gardencorev1beta1.CloudProfileSpec) error {
	var (
		fldPath = field.NewPath("spec", "provider")
	)

	awsCloudProfile, _, err := s.baseShootValidation(ctx, shoot, cloudProfileSpec, nil, fldPath)
	if err != nil {
		return err
	}

	if errList := awsvalidation.ValidateWorkersAgainstCloudProfileOnCreation(shoot.Spec.Provider.Workers, shoot.Spec.Region, awsCloudProfile, cloudProfileSpec.MachineTypes, cloudProfileSpec.MachineCapabilities, fldPath.Child("workers")); len(errList) != 0 {
		return errList.ToAggregate()
	}

	return s.validateShoot(ctx, shoot)
}

func (s *shoot) baseShootValidation(ctx context.Context, shoot *core.Shoot, cloudProfileSpec *gardencorev1beta1.CloudProfileSpec, oldInfraConfig *api.InfrastructureConfig, fldPath *field.Path) (*api.CloudProfileConfig, *api.InfrastructureConfig, error) {
	var (
		infraConfigFldPath = fldPath.Child("infrastructureConfig")
	)

	if shoot.Spec.Provider.InfrastructureConfig == nil {
		return nil, nil, field.Required(infraConfigFldPath, "InfrastructureConfig must be set for AWS shoots")
	}

	infraConfig, err := decodeInfrastructureConfig(s.decoder, shoot.Spec.Provider.InfrastructureConfig, fldPath.Child("infrastructureConfig"))
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

	if err = s.validateAgainstCloudProfile(ctx, shoot, oldInfraConfig, infraConfig, cloudProfileSpec, infraConfigFldPath); err != nil {
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
