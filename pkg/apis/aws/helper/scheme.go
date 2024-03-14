// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"fmt"

	"github.com/gardener/gardener/extensions/pkg/controller"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
)

var (
	// Scheme is a scheme with the types relevant for OpenStack actuators.
	Scheme *runtime.Scheme

	decoder runtime.Decoder
)

func init() {
	Scheme = runtime.NewScheme()
	utilruntime.Must(install.AddToScheme(Scheme))

	decoder = serializer.NewCodecFactory(Scheme, serializer.EnableStrict).UniversalDecoder()
}

// CloudProfileConfigFromCluster decodes the provider specific cloud profile configuration for a cluster
func CloudProfileConfigFromCluster(cluster *controller.Cluster) (*api.CloudProfileConfig, error) {
	var cloudProfileConfig *api.CloudProfileConfig
	if cluster != nil && cluster.CloudProfile != nil && cluster.CloudProfile.Spec.ProviderConfig != nil && cluster.CloudProfile.Spec.ProviderConfig.Raw != nil {
		cloudProfileConfig = &api.CloudProfileConfig{}
		if _, _, err := decoder.Decode(cluster.CloudProfile.Spec.ProviderConfig.Raw, nil, cloudProfileConfig); err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of cloudProfile for '%s': %w", kutil.ObjectName(cluster.CloudProfile), err)
		}
	}
	return cloudProfileConfig, nil
}

// InfrastructureConfigFromInfrastructure extracts the InfrastructureConfig from the
// ProviderConfig section of the given Infrastructure.
func InfrastructureConfigFromInfrastructure(infra *extensionsv1alpha1.Infrastructure) (*api.InfrastructureConfig, error) {
	config := &api.InfrastructureConfig{}
	if infra.Spec.ProviderConfig != nil {
		data, err := marshalRaw(infra.Spec.ProviderConfig)
		if err != nil {
			return nil, err
		}
		if data != nil {
			if _, _, err := decoder.Decode(data, nil, config); err != nil {
				return nil, err
			}
			return config, nil
		}
	}
	return nil, fmt.Errorf("provider config is not set on the infrastructure resource")
}

// InfrastructureStatusFromInfrastructure extracts the InfrastructureStatus from the
// ProviderConfig section of the given Infrastructure status.
func InfrastructureStatusFromInfrastructure(infra *extensionsv1alpha1.Infrastructure) (*api.InfrastructureStatus, error) {
	status := &api.InfrastructureStatus{}
	if infra.Status.ProviderStatus != nil {
		data, err := marshalRaw(infra.Status.ProviderStatus)
		if err != nil {
			return nil, err
		}

		if data != nil {
			if _, _, err := decoder.Decode(data, nil, status); err != nil {
				return nil, err
			}
			return status, nil
		}
	}
	return nil, fmt.Errorf("provider status is not set on the infrastructure resource")
}

func marshalRaw(raw *runtime.RawExtension) ([]byte, error) {
	data, err := raw.MarshalJSON()
	if err != nil {
		return nil, err
	}
	if string(data) == "null" {
		return nil, nil
	}

	return data, err
}
