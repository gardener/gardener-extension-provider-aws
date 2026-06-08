// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"encoding/json"
	"errors"
	"fmt"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/util"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
	apiv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

var (
	// Scheme is a Scheme with the types relevant for AWS actuators.
	Scheme *runtime.Scheme

	decoder runtime.Decoder

	lenientDecoder runtime.Decoder
)

func init() {
	Scheme = runtime.NewScheme()
	utilruntime.Must(install.AddToScheme(Scheme))

	decoder = serializer.NewCodecFactory(Scheme, serializer.EnableStrict).UniversalDecoder()
	lenientDecoder = serializer.NewCodecFactory(Scheme).UniversalDecoder()
}

// CloudProfileConfigFromCluster decodes the provider specific cloud profile configuration for a cluster
func CloudProfileConfigFromCluster(cluster *controller.Cluster) (*api.CloudProfileConfig, error) {
	var cloudProfileConfig *api.CloudProfileConfig
	if cluster != nil && cluster.CloudProfile != nil && cluster.CloudProfile.Spec.ProviderConfig != nil && cluster.CloudProfile.Spec.ProviderConfig.Raw != nil {
		cloudProfileSpecifier := fmt.Sprintf("cloudProfile '%q'", k8sclient.ObjectKeyFromObject(cluster.CloudProfile))
		if cluster.Shoot != nil && cluster.Shoot.Spec.CloudProfile != nil {
			cloudProfileSpecifier = fmt.Sprintf("%s '%s/%s'", cluster.Shoot.Spec.CloudProfile.Kind, cluster.Shoot.Namespace, cluster.Shoot.Spec.CloudProfile.Name)
		}
		cloudProfileConfig = &api.CloudProfileConfig{}
		if _, _, err := decoder.Decode(cluster.CloudProfile.Spec.ProviderConfig.Raw, nil, cloudProfileConfig); err != nil {
			return nil, fmt.Errorf("could not decode providerConfig of %s: %w", cloudProfileSpecifier, err)
		}
	}
	return cloudProfileConfig, nil
}

// InfrastructureConfigFromCluster decodes the infrastructure configuration for a cluster
func InfrastructureConfigFromCluster(cluster *controller.Cluster) (*api.InfrastructureConfig, error) {
	var infrastructureConfig *api.InfrastructureConfig
	if cluster != nil && cluster.Shoot != nil && cluster.Shoot.Spec.Provider.InfrastructureConfig != nil && cluster.Shoot.Spec.Provider.InfrastructureConfig.Raw != nil {
		infrastructureConfig = &api.InfrastructureConfig{}
		if _, _, err := decoder.Decode(cluster.Shoot.Spec.Provider.InfrastructureConfig.Raw, nil, infrastructureConfig); err != nil {
			return nil, fmt.Errorf("could not decode infrastructureConfig of shoot '%s': %w", k8sclient.ObjectKeyFromObject(cluster.Shoot), err)
		}
	}
	return infrastructureConfig, nil
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

// WorkloadIdentityConfigFromRaw extracts WorkloadIdentityConfig from the provided [runtime.RawExtension].
func WorkloadIdentityConfigFromRaw(raw *runtime.RawExtension) (*api.WorkloadIdentityConfig, error) {
	if raw == nil || raw.Raw == nil {
		return nil, errors.New("cannot parse WorkloadIdentityConfig from empty RawExtension")
	}
	return WorkloadIdentityConfigFromBytes(raw.Raw)
}

// WorkloadIdentityConfigFromBytes extracts WorkloadIdentityConfig from the provided byte array.
func WorkloadIdentityConfigFromBytes(config []byte) (*api.WorkloadIdentityConfig, error) {
	if len(config) == 0 {
		return nil, fmt.Errorf("cannot parse WorkloadIdentityConfig from empty config")
	}
	workloadIdentityConfig := &api.WorkloadIdentityConfig{}
	if err := util.Decode(decoder, config, workloadIdentityConfig); err != nil {
		return nil, err
	}
	return workloadIdentityConfig, nil
}

// HasFlowState returns true if the group version of the State field in the provided
// `extensionsv1alpha1.InfrastructureStatus` is aws.provider.extensions.gardener.cloud/v1alpha1.
func HasFlowState(status extensionsv1alpha1.InfrastructureStatus) (bool, error) {
	if status.State == nil {
		return true, nil
	}

	flowState := unstructured.Unstructured{}
	stateJson, err := status.State.MarshalJSON()
	if err != nil {
		return false, err
	}

	if err := json.Unmarshal(stateJson, &flowState); err != nil {
		return false, err
	}

	return flowState.GroupVersionKind() == schema.GroupVersionKind{
		Group:   apiv1alpha1.SchemeGroupVersion.Group,
		Version: apiv1alpha1.SchemeGroupVersion.Version,
		Kind:    "InfrastructureState",
	}, nil
}

// HasEFAWorkerPool returns true if any worker pool in the given list has at least one
// network interface configured with type "efa" or "efa-only" in its provider config.
// EFA-enabled worker pools require a self-referencing security group egress rule on the
// shoot's worker security group, since EFA's SRD traffic is not authorized by CIDR-based
// rules; see https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/efa-start.html#efa-start-security.
func HasEFAWorkerPool(workers []gardencorev1beta1.Worker) (bool, error) {
	for _, worker := range workers {
		if worker.ProviderConfig == nil || worker.ProviderConfig.Raw == nil {
			continue
		}
		workerConfig := &api.WorkerConfig{}
		if _, _, err := lenientDecoder.Decode(worker.ProviderConfig.Raw, nil, workerConfig); err != nil {
			return false, fmt.Errorf("could not decode providerConfig of worker pool %q: %w", worker.Name, err)
		}
		for _, ni := range workerConfig.NetworkInterfaces {
			if ni.Type == nil {
				continue
			}
			if *ni.Type == string(ec2types.NetworkInterfaceTypeEfa) || *ni.Type == string(ec2types.NetworkInterfaceTypeEfaOnly) {
				return true, nil
			}
		}
	}
	return false, nil
}

// InfrastructureStateFromRaw extracts the state from the Infrastructure. If no state was available, it returns a "zero" value InfrastructureState object.
func InfrastructureStateFromRaw(raw *runtime.RawExtension) (*api.InfrastructureState, error) {
	state := &api.InfrastructureState{}
	if raw != nil && raw.Raw != nil {
		if _, _, err := lenientDecoder.Decode(raw.Raw, nil, state); err != nil {
			return nil, err
		}
	}

	if state.Data == nil {
		state.Data = make(map[string]string)
	}

	return state, nil
}
