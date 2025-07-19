// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"github.com/gardener/gardener/extensions/pkg/util"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/validation/field"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

func decodeWorkerConfig(decoder runtime.Decoder, worker *runtime.RawExtension, fldPath *field.Path) (*apisaws.WorkerConfig, error) {
	workerConfig := &apisaws.WorkerConfig{}
	if err := util.Decode(decoder, worker.Raw, workerConfig); err != nil {
		return nil, field.Invalid(fldPath, string(worker.Raw), "isn't a supported version")
	}

	return workerConfig, nil
}

func decodeControlPlaneConfig(decoder runtime.Decoder, cp *runtime.RawExtension, fldPath *field.Path) (*apisaws.ControlPlaneConfig, error) {
	controlPlaneConfig := &apisaws.ControlPlaneConfig{}
	if err := util.Decode(decoder, cp.Raw, controlPlaneConfig); err != nil {
		return nil, field.Invalid(fldPath, string(cp.Raw), "isn't a supported version")
	}

	return controlPlaneConfig, nil
}

func decodeInfrastructureConfig(decoder runtime.Decoder, infra *runtime.RawExtension, fldPath *field.Path) (*apisaws.InfrastructureConfig, error) {
	infraConfig := &apisaws.InfrastructureConfig{}
	if err := util.Decode(decoder, infra.Raw, infraConfig); err != nil {
		return nil, field.Invalid(fldPath, string(infra.Raw), "isn't a supported version")
	}

	return infraConfig, nil
}

func decodeCloudProfileConfig(decoder runtime.Decoder, config *runtime.RawExtension) (*apisaws.CloudProfileConfig, error) {
	cloudProfileConfig := &apisaws.CloudProfileConfig{}
	if err := util.Decode(decoder, config.Raw, cloudProfileConfig); err != nil {
		return nil, err
	}
	return cloudProfileConfig, nil
}
