// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
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
		scheme:         mgr.GetScheme(),
		decoder:        serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder(),
		lenientDecoder: serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
	}
}

type shoot struct {
	client         client.Client
	decoder        runtime.Decoder
	lenientDecoder runtime.Decoder
	scheme         *runtime.Scheme
}

// Validate validates the given shoot object.
func (s *shoot) Validate(ctx context.Context, new, old client.Object) error {
	shoot, ok := new.(*core.Shoot)
	if !ok {
		return fmt.Errorf("wrong object type %T", new)
	}

	// Skip if it's a workerless Shoot
	if gardencorehelper.IsWorkerless(shoot) {
		return nil
	}

	if old != nil {
		oldShoot, ok := old.(*core.Shoot)
		if !ok {
			return fmt.Errorf("wrong object type %T for old object", old)
		}
		return s.validateShootUpdate(ctx, oldShoot, shoot)
	}

	return s.validateShootCreation(ctx, shoot)
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
		if errList := awsvalidation.ValidateInfrastructureConfig(infraConfig, shoot.Spec.Networking.Nodes, shoot.Spec.Networking.Pods, shoot.Spec.Networking.Services); len(errList) != 0 {
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

func (s *shoot) validateShootUpdate(ctx context.Context, oldShoot, shoot *core.Shoot) error {
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

	awsCloudProfile, infraConfig, err := s.baseShootValidation(ctx, shoot, oldInfraConfig, fldPath)
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

	if errList := awsvalidation.ValidateWorkersAgainstCloudProfileOnUpdate(oldShoot.Spec.Provider.Workers, shoot.Spec.Provider.Workers, shoot.Spec.Region, awsCloudProfile, fldPath.Child("workers")); len(errList) != 0 {
		return errList.ToAggregate()
	}

	return s.validateShoot(ctx, shoot)
}

func (s *shoot) validateShootCreation(ctx context.Context, shoot *core.Shoot) error {
	var (
		fldPath = field.NewPath("spec", "provider")
	)

	awsCloudProfile, _, err := s.baseShootValidation(ctx, shoot, nil, fldPath)
	if err != nil {
		return err
	}

	if errList := awsvalidation.ValidateWorkersAgainstCloudProfileOnCreation(shoot.Spec.Provider.Workers, shoot.Spec.Region, awsCloudProfile, fldPath.Child("workers")); len(errList) != 0 {
		return errList.ToAggregate()
	}

	return s.validateShoot(ctx, shoot)
}

func (s *shoot) baseShootValidation(ctx context.Context, shoot *core.Shoot, oldInfraConfig *api.InfrastructureConfig, fldPath *field.Path) (*api.CloudProfileConfig, *api.InfrastructureConfig, error) {
	var (
		commonCloudProfile = &gardencorev1beta1.CloudProfile{}
		infraConfigFldPath = fldPath.Child("infrastructureConfig")
	)

	if shoot.Spec.Provider.InfrastructureConfig == nil {
		return nil, nil, field.Required(infraConfigFldPath, "InfrastructureConfig must be set for AWS shoots")
	}

	infraConfig, err := decodeInfrastructureConfig(s.decoder, shoot.Spec.Provider.InfrastructureConfig, fldPath.Child("infrastructureConfig"))
	if err != nil {
		return nil, nil, err
	}

	if shoot.Spec.CloudProfile == nil {
		return nil, nil, fmt.Errorf("shoot.spec.cloudprofile must not be nil <nil>")
	}

	if err := s.client.Get(ctx, client.ObjectKey{Name: shoot.Spec.CloudProfile.Name}, commonCloudProfile); err != nil {
		return nil, nil, err
	}

	awsCloudProfile, err := decodeCloudProfileConfig(s.decoder, commonCloudProfile.Spec.ProviderConfig)
	if err != nil {
		return nil, nil, err
	}

	if err = s.validateAgainstCloudProfile(ctx, shoot, oldInfraConfig, infraConfig, commonCloudProfile, infraConfigFldPath); err != nil {
		return nil, nil, err
	}

	return awsCloudProfile, infraConfig, nil
}

func (s *shoot) validateAgainstCloudProfile(_ context.Context, shoot *core.Shoot, oldInfraConfig, infraConfig *api.InfrastructureConfig, cloudProfile *gardencorev1beta1.CloudProfile, fldPath *field.Path) error {
	if errList := awsvalidation.ValidateInfrastructureConfigAgainstCloudProfile(oldInfraConfig, infraConfig, shoot, cloudProfile, fldPath); len(errList) != 0 {
		return errList.ToAggregate()
	}

	return nil
}
