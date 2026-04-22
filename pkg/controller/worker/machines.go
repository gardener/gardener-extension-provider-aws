// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"math"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/extensions/pkg/controller/worker"
	genericworkeractuator "github.com/gardener/gardener/extensions/pkg/controller/worker/genericactuator"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/api/core/v1beta1/helper"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/api/extensions/v1alpha1/helper"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/controllerutils"
	"github.com/gardener/gardener/pkg/utils"
	"github.com/gardener/gardener/pkg/utils/flow"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	awsmachineapi "github.com/gardener/machine-controller-manager-provider-aws/pkg/aws/apis"
	machinev1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsapihelper "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
)

const (
	// CSIDriverTopologyKey is the legacy topology key used by the AWS CSI driver
	// we need to support it because old PVs use it as node affinity
	// see also: https://github.com/kubernetes-sigs/aws-ebs-csi-driver/issues/729#issuecomment-1942026577
	CSIDriverTopologyKey = "topology.ebs.csi.aws.com/zone"

	// maxConcurrentMachineTasks defines the maximum number of machine-related tasks that can run concurrently.
	// TODO(plkokanov): Use `genericworkeractuator.MaxConcurrentMachineTasks` introduced in https://github.com/gardener/gardener/pull/14220
	// when available.
	maxConcurrentMachineTasks = 50
)

// MachineClassKind yields the name of the machine class kind used by AWS provider.
func (w *WorkerDelegate) MachineClassKind() string {
	return "MachineClass"
}

// MachineClassList yields a newly initialized MachineClassList object.
func (w *WorkerDelegate) MachineClassList() client.ObjectList {
	return &machinev1alpha1.MachineClassList{}
}

// MachineClass yields a newly initialized MachineClass object.
func (w *WorkerDelegate) MachineClass() client.Object {
	return &machinev1alpha1.MachineClass{}
}

// DeployMachineClasses generates and creates the AWS specific machine classes.
func (w *WorkerDelegate) DeployMachineClasses(ctx context.Context) error {
	if len(w.machineClassToMutateFuncMap) == 0 || len(w.machineClassSecretToMutateFuncMap) == 0 {
		if err := w.generateMachineConfig(ctx); err != nil {
			return err
		}
	}

	var secretsTaskFns = make([]flow.TaskFn, 0, len(w.machineClassSecretToMutateFuncMap))
	for secret, mutateFn := range w.machineClassSecretToMutateFuncMap {
		secretsTaskFns = append(secretsTaskFns, func(ctx context.Context) error {
			if _, err := controllerutils.GetAndCreateOrMergePatch(ctx, w.client, secret, mutateFn); err != nil {
				return fmt.Errorf("could not deploy Secret '%s': %w", client.ObjectKeyFromObject(secret), err)
			}

			return nil
		})
	}
	if err := flow.ParallelN(maxConcurrentMachineTasks, secretsTaskFns...)(ctx); err != nil {
		return err
	}

	var machineClassesTaskFns = make([]flow.TaskFn, 0, len(w.machineClassToMutateFuncMap))
	for machineClass, mutateFn := range w.machineClassToMutateFuncMap {
		machineClassesTaskFns = append(machineClassesTaskFns, func(ctx context.Context) error {
			if _, err := controllerutils.GetAndCreateOrMergePatch(ctx, w.client, machineClass, mutateFn); err != nil {
				return fmt.Errorf("could not deploy MachineClass '%s':  %w", client.ObjectKeyFromObject(machineClass), err)
			}

			return nil
		})
	}

	return flow.ParallelN(maxConcurrentMachineTasks, machineClassesTaskFns...)(ctx)
}

// GenerateMachineDeployments generates the configuration for the desired machine deployments.
func (w *WorkerDelegate) GenerateMachineDeployments(ctx context.Context) (worker.MachineDeployments, error) {
	if w.machineDeployments == nil {
		if err := w.generateMachineConfig(ctx); err != nil {
			return nil, err
		}
	}
	return w.machineDeployments, nil
}

func (w *WorkerDelegate) generateMachineConfig(ctx context.Context) error {
	var (
		machineDeployments                = worker.MachineDeployments{}
		machineImages                     []awsapi.MachineImage
		machineClassToMutateFuncMap       = map[*machinev1alpha1.MachineClass]controllerutil.MutateFn{}
		machineClassSecretToMutateFuncMap = map[*corev1.Secret]controllerutil.MutateFn{}
	)

	// Normalize capability definitions once at the entry point.
	// This ensures all downstream code can assume capabilities are always present.
	capabilityDefinitions := awsapihelper.NormalizeCapabilityDefinitions(w.cluster.CloudProfile.Spec.MachineCapabilities)

	infrastructureStatus := &awsapi.InfrastructureStatus{}
	if _, _, err := w.decoder.Decode(w.worker.Spec.InfrastructureProviderStatus.Raw, nil, infrastructureStatus); err != nil {
		return err
	}

	nodesSecurityGroup, err := awsapihelper.FindSecurityGroupForPurpose(infrastructureStatus.VPC.SecurityGroups, awsapi.PurposeNodes)
	if err != nil {
		return err
	}

	for _, pool := range w.worker.Spec.Pools {
		workerConfig := &awsapi.WorkerConfig{}
		if pool.ProviderConfig != nil && pool.ProviderConfig.Raw != nil {
			if _, _, err := w.decoder.Decode(pool.ProviderConfig.Raw, nil, workerConfig); err != nil {
				return fmt.Errorf("could not decode provider config: %+v", err)
			}
		}

		workerPoolHash, err := w.generateWorkerPoolHash(pool, workerConfig)
		if err != nil {
			return err
		}

		machineTypeFromCloudProfile := gardencorev1beta1helper.FindMachineTypeByName(w.cluster.CloudProfile.Spec.MachineTypes, pool.MachineType)
		if machineTypeFromCloudProfile == nil {
			return fmt.Errorf("machine type %q not found in cloud profile %q", pool.MachineType, w.cluster.CloudProfile.Name)
		}

		workerArchitecture := ptr.Deref(pool.Architecture, v1beta1constants.ArchitectureAMD64)
		// Normalize machine type capabilities to include architecture
		machineTypeCapabilities := awsapihelper.NormalizeMachineTypeCapabilities(machineTypeFromCloudProfile.Capabilities, &workerArchitecture, capabilityDefinitions)
		machineImage, err := w.selectMachineImageForWorkerPool(pool.MachineImage.Name, pool.MachineImage.Version, w.worker.Spec.Region, &workerArchitecture, machineTypeCapabilities, capabilityDefinitions)
		if err != nil {
			return err
		}

		// use original MachineCapabilities as worker status must conform to different formats
		machineImages = EnsureUniformMachineImages(machineImages, w.cluster.CloudProfile.Spec.MachineCapabilities)
		machineImages = appendMachineImage(machineImages, *machineImage, w.cluster.CloudProfile.Spec.MachineCapabilities)

		blockDevices, err := w.computeBlockDevices(pool, workerConfig)
		if err != nil {
			return err
		}

		iamInstanceProfile, err := computeIAMInstanceProfile(workerConfig, infrastructureStatus)
		if err != nil {
			return err
		}

		instanceMetadataOptions, err := ComputeInstanceMetadataOptions(workerConfig, w.cluster.Shoot.Spec.Networking)
		if err != nil {
			return err
		}

		userData, err := worker.FetchUserData(ctx, w.client, w.worker.Namespace, pool)
		if err != nil {
			return err
		}

		zoneLen := int32(len(pool.Zones)) // #nosec: G115 - We do check if pool Zones exceeds max_int32.
		for zoneIndex, zone := range pool.Zones {
			zoneIdx := int32(zoneIndex) // #nosec: G115 - We do check if pool Zones exceeds max_int32.

			nodesSubnet, err := awsapihelper.FindSubnetForPurposeAndZone(infrastructureStatus.VPC.Subnets, awsapi.PurposeNodes, zone)
			if err != nil {
				return err
			}

			machineClassProviderSpec := &awsmachineapi.AWSProviderSpec{
				AMI:                    machineImage.AMI,
				Region:                 w.worker.Spec.Region,
				MachineType:            pool.MachineType,
				SrcAndDstChecksEnabled: ptr.To(false),
				IAM:                    iamInstanceProfile,
				NetworkInterfaces: []awsmachineapi.AWSNetworkInterfaceSpec{
					{
						SubnetID:         nodesSubnet.ID,
						SecurityGroupIDs: []string{nodesSecurityGroup.ID},
					},
				},
				Tags: utils.MergeStringMaps(
					map[string]string{
						fmt.Sprintf("kubernetes.io/cluster/%s", w.cluster.Shoot.Status.TechnicalID): "1",
						"kubernetes.io/role/node": "1",
					},
					pool.Labels,
				),
				BlockDevices:            blockDevices,
				InstanceMetadataOptions: instanceMetadataOptions,
			}

			networking := w.cluster.Shoot.Spec.Networking
			if networking != nil && infraflow.ContainsIPv6(networking.IPFamilies) {
				machineClassProviderSpec.NetworkInterfaces[0].Ipv6AddressCount = ptr.To[int32](1)
				machineClassProviderSpec.NetworkInterfaces[0].Ipv6PrefixCount = ptr.To[int32](1)
			}

			if len(infrastructureStatus.EC2.KeyName) > 0 {
				machineClassProviderSpec.KeyName = ptr.To(infrastructureStatus.EC2.KeyName)
			}

			nodeTemplate := &machinev1alpha1.NodeTemplate{
				Architecture: ptr.To("amd64"),
				Capacity: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("4"),
					"GPU":                 resource.MustParse("0"),
					corev1.ResourceMemory: resource.MustParse("16Gi"),
				},
				InstanceType: "m4.xlarge",
				Region:       "eu-west-1",
				Zone:         "eu-west-1a",
			}

			if pool.NodeTemplate != nil {
				nodeTemplate.Capacity = pool.NodeTemplate.Capacity
				nodeTemplate.VirtualCapacity = pool.NodeTemplate.VirtualCapacity
				nodeTemplate.InstanceType = pool.MachineType
				nodeTemplate.Region = w.worker.Spec.Region
				nodeTemplate.Zone = zone
				nodeTemplate.Architecture = &workerArchitecture
			}

			if workerConfig.NodeTemplate != nil {
				// Support providerConfig extended resources by copying into node template capacity and virtualCapacity
				maps.Copy(nodeTemplate.Capacity, workerConfig.NodeTemplate.Capacity)
				if nodeTemplate.VirtualCapacity == nil {
					nodeTemplate.VirtualCapacity = corev1.ResourceList{}
				}
				maps.Copy(nodeTemplate.VirtualCapacity, workerConfig.NodeTemplate.VirtualCapacity)
			}

			if cpuOptions := workerConfig.CpuOptions; cpuOptions != nil {
				machineClassProviderSpec.CPUOptions = &awsmachineapi.CPUOptions{
					AmdSevSnp:      cpuOptions.AmdSevSnp,
					CoreCount:      cpuOptions.CoreCount,
					ThreadsPerCore: cpuOptions.ThreadsPerCore,
				}
			}

			if workerConfig.CapacityReservation != nil {
				capacityReservationOpts := *workerConfig.CapacityReservation
				capacityReserverationCfg := &awsmachineapi.AWSCapacityReservationTargetSpec{
					CapacityReservationPreference:       ptr.Deref(capacityReservationOpts.CapacityReservationPreference, ""),
					CapacityReservationID:               capacityReservationOpts.CapacityReservationID,
					CapacityReservationResourceGroupArn: capacityReservationOpts.CapacityReservationResourceGroupARN,
				}

				machineClassProviderSpec.CapacityReservationTarget = capacityReserverationCfg
			}

			var (
				deploymentName = fmt.Sprintf("%s-%s-z%d", w.cluster.Shoot.Status.TechnicalID, pool.Name, zoneIndex+1)
				className      = fmt.Sprintf("%s-%s", deploymentName, workerPoolHash)
			)

			updateConfiguration := machinev1alpha1.UpdateConfiguration{
				MaxUnavailable: ptr.To(worker.DistributePositiveIntOrPercent(zoneIdx, pool.MaxUnavailable, zoneLen, pool.Minimum)),
				MaxSurge:       ptr.To(worker.DistributePositiveIntOrPercent(zoneIdx, pool.MaxSurge, zoneLen, pool.Maximum)),
			}

			machineDeploymentStrategy := machinev1alpha1.MachineDeploymentStrategy{
				Type: machinev1alpha1.RollingUpdateMachineDeploymentStrategyType,
				RollingUpdate: &machinev1alpha1.RollingUpdateMachineDeployment{
					UpdateConfiguration: updateConfiguration,
				},
			}

			if gardencorev1beta1helper.IsUpdateStrategyInPlace(pool.UpdateStrategy) {
				machineDeploymentStrategy = machinev1alpha1.MachineDeploymentStrategy{
					Type: machinev1alpha1.InPlaceUpdateMachineDeploymentStrategyType,
					InPlaceUpdate: &machinev1alpha1.InPlaceUpdateMachineDeployment{
						UpdateConfiguration: updateConfiguration,
						OrchestrationType:   machinev1alpha1.OrchestrationTypeAuto,
					},
				}

				if gardencorev1beta1helper.IsUpdateStrategyManualInPlace(pool.UpdateStrategy) {
					machineDeploymentStrategy.InPlaceUpdate.OrchestrationType = machinev1alpha1.OrchestrationTypeManual
				}
			}

			machineDeployments = append(machineDeployments, worker.MachineDeployment{
				Name:       deploymentName,
				ClassName:  className,
				SecretName: className,
				PoolName:   pool.Name,
				Minimum:    worker.DistributeOverZones(zoneIdx, pool.Minimum, zoneLen),
				Maximum:    worker.DistributeOverZones(zoneIdx, pool.Maximum, zoneLen),
				Strategy:   machineDeploymentStrategy,
				Priority:   pool.Priority,
				// add aws csi driver topology label if it's not specified
				Labels: utils.MergeStringMaps(pool.Labels, map[string]string{
					CSIDriverTopologyKey:     zone,
					corev1.LabelTopologyZone: zone,
				}),
				Annotations:                  pool.Annotations,
				Taints:                       pool.Taints,
				MachineConfiguration:         genericworkeractuator.ReadMachineConfiguration(pool),
				ClusterAutoscalerAnnotations: extensionsv1alpha1helper.GetMachineDeploymentClusterAutoscalerAnnotations(pool.ClusterAutoscaler),
			})

			var operatingSystemConfigLabels map[string]string
			if pool.MachineImage.Name != "" && pool.MachineImage.Version != "" {
				operatingSystemConfigLabels = map[string]string{
					"operatingSystemName":    pool.MachineImage.Name,
					"operatingSystemVersion": strings.ReplaceAll(pool.MachineImage.Version, "+", "_"),
				}
			}

			machineClass := &machinev1alpha1.MachineClass{
				ObjectMeta: metav1.ObjectMeta{
					Name:      className,
					Namespace: w.worker.Namespace,
				},
			}

			marshalledProviderSpec, err := json.Marshal(machineClassProviderSpec)
			if err != nil {
				return fmt.Errorf("could not marshal provider spec for MachineClass '%s' into json: %w", client.ObjectKeyFromObject(machineClass), err)
			}

			machineClassToMutateFuncMap[machineClass] = func() error {
				machineClass.Labels = utils.MergeStringMaps(operatingSystemConfigLabels, map[string]string{corev1.LabelZoneFailureDomain: zone})
				machineClass.NodeTemplate = nodeTemplate
				machineClass.ProviderSpec = runtime.RawExtension{
					Raw: marshalledProviderSpec,
				}
				machineClass.Provider = "AWS"
				machineClass.CredentialsSecretRef = &corev1.SecretReference{
					Name:      w.worker.Spec.SecretRef.Name,
					Namespace: w.worker.Spec.SecretRef.Namespace,
				}
				machineClass.SecretRef = &corev1.SecretReference{
					Name:      className,
					Namespace: w.worker.Namespace,
				}

				return nil
			}

			machineClassSecret := &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      className,
					Namespace: w.worker.Namespace,
				},
			}

			machineClassSecretToMutateFuncMap[machineClassSecret] = func() error {
				machineClassSecret.Labels = map[string]string{
					v1beta1constants.GardenerPurpose: v1beta1constants.GardenPurposeMachineClass,
				}
				machineClassSecret.Data = map[string][]byte{
					"userData": userData,
				}
				machineClassSecret.Type = corev1.SecretTypeOpaque

				return nil
			}
		}
	}

	w.machineDeployments = machineDeployments
	w.machineImages = machineImages
	w.machineClassToMutateFuncMap = machineClassToMutateFuncMap
	w.machineClassSecretToMutateFuncMap = machineClassSecretToMutateFuncMap

	return nil
}

func (w *WorkerDelegate) computeBlockDevices(pool extensionsv1alpha1.WorkerPool, workerConfig *awsapi.WorkerConfig) ([]awsmachineapi.AWSBlockDeviceMappingSpec, error) {
	var blockDevices []awsmachineapi.AWSBlockDeviceMappingSpec

	// handle root disk
	rootDisk, err := computeEBSForVolume(*pool.Volume)
	if err != nil {
		return nil, fmt.Errorf("error when computing EBS for root disk: %w", err)
	}
	if workerConfig.Volume != nil {
		if workerConfig.Volume.IOPS != nil {
			rootDisk.Iops = *workerConfig.Volume.IOPS
		}
		if workerConfig.Volume.Throughput != nil {
			rootDisk.Throughput = workerConfig.Volume.Throughput
		}
	}
	blockDevices = append(blockDevices, awsmachineapi.AWSBlockDeviceMappingSpec{Ebs: rootDisk})

	// handle data disks
	if dataVolumes := pool.DataVolumes; len(dataVolumes) > 0 {
		blockDevices[0].DeviceName = "/root"

		// sort data volumes for consistent device naming
		sort.Slice(dataVolumes, func(i, j int) bool {
			return dataVolumes[i].Name < dataVolumes[j].Name
		})

		for i, vol := range dataVolumes {
			dataDisk, err := computeEBSForDataVolume(vol)
			if err != nil {
				return nil, fmt.Errorf("error when computing EBS for %v: %w", vol, err)
			}
			if dvConfig := awsapihelper.FindDataVolumeByName(workerConfig.DataVolumes, vol.Name); dvConfig != nil {
				if dvConfig.IOPS != nil {
					dataDisk.Iops = *dvConfig.IOPS
				}
				if dvConfig.Throughput != nil {
					dataDisk.Throughput = dvConfig.Throughput
				}
				dataDisk.SnapshotID = dvConfig.SnapshotID
			}
			deviceName, err := computeEBSDeviceNameForIndex(i)
			if err != nil {
				return nil, fmt.Errorf("error when computing EBS device name for %v: %w", vol, err)
			}
			blockDevices = append(blockDevices, awsmachineapi.AWSBlockDeviceMappingSpec{
				DeviceName: deviceName,
				Ebs:        dataDisk,
			})
		}
	}

	return blockDevices, nil
}

func (w *WorkerDelegate) generateWorkerPoolHash(pool extensionsv1alpha1.WorkerPool, workerConfig *awsapi.WorkerConfig) (string, error) {
	v2HashData, err := ComputeAdditionalHashDataV2(pool, workerConfig)
	if err != nil {
		return "", err
	}
	return worker.WorkerPoolHash(pool, w.cluster, ComputeAdditionalHashDataV1(pool), v2HashData, ComputeAdditionalHashDataInPlace(pool))
}

func computeEBSForVolume(volume extensionsv1alpha1.Volume) (awsmachineapi.AWSEbsBlockDeviceSpec, error) {
	return computeEBS(volume.Size, volume.Type, volume.Encrypted)
}

func computeEBSForDataVolume(volume extensionsv1alpha1.DataVolume) (awsmachineapi.AWSEbsBlockDeviceSpec, error) {
	return computeEBS(volume.Size, volume.Type, volume.Encrypted)
}

func computeEBS(size string, volumeType *string, encrypted *bool) (awsmachineapi.AWSEbsBlockDeviceSpec, error) {
	volumeSize, err := worker.DiskSize(size)
	if err != nil {
		return awsmachineapi.AWSEbsBlockDeviceSpec{}, err
	}

	if volumeSize > math.MaxInt32 {
		return awsmachineapi.AWSEbsBlockDeviceSpec{}, fmt.Errorf("volume size cannot exceed %d", math.MaxInt32)
	}

	ebs := awsmachineapi.AWSEbsBlockDeviceSpec{
		VolumeSize:          int32(volumeSize), // #nosec: G115 - volumeSize is checked to not exceed max int32.
		Encrypted:           true,
		DeleteOnTermination: ptr.To(true),
	}

	if volumeType != nil {
		ebs.VolumeType = *volumeType
	}

	if encrypted != nil {
		ebs.Encrypted = *encrypted
	}

	return ebs, nil
}

// AWS device naming https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/device_naming.html
func computeEBSDeviceNameForIndex(index int) (string, error) {
	var (
		deviceNamePrefix = "/dev/sd"
		deviceNameSuffix = "fghijklmnop"
	)

	if index >= len(deviceNameSuffix) {
		return "", fmt.Errorf("unsupported data volume number")
	}

	return deviceNamePrefix + deviceNameSuffix[index:index+1], nil
}

// ComputeAdditionalHashDataV1 computes additional hash data for the worker pool. It returns a slice of strings containing the
// additional data used for hashing.
func ComputeAdditionalHashDataV1(pool extensionsv1alpha1.WorkerPool) []string {
	var additionalData []string

	if pool.Volume != nil && pool.Volume.Encrypted != nil {
		additionalData = append(additionalData, strconv.FormatBool(*pool.Volume.Encrypted))
	}

	for _, dv := range pool.DataVolumes {
		additionalData = append(additionalData, dv.Size)

		if dv.Type != nil {
			additionalData = append(additionalData, *dv.Type)
		}

		if dv.Encrypted != nil {
			additionalData = append(additionalData, strconv.FormatBool(*dv.Encrypted))
		}
	}

	return additionalData
}

// ComputeAdditionalHashDataV2 computes additional hash data for the worker pool. It returns a slice of strings containing the
// additional data used for hashing.
func ComputeAdditionalHashDataV2(pool extensionsv1alpha1.WorkerPool, workerConfig *awsapi.WorkerConfig) ([]string, error) {
	var (
		additionalData = ComputeAdditionalHashDataV1(pool)
		useNewHashData bool
	)
	if pool.KubernetesVersion != nil {
		poolK8sVersion, err := semver.NewVersion(*pool.KubernetesVersion)
		if err != nil {
			return nil, err
		}
		useNewHashData = versionutils.ConstraintK8sGreaterEqual134.Check(poolK8sVersion)
	}
	if useNewHashData && workerConfig != nil {
		additionalData = appendHashDataForWorkerConfig(additionalData, workerConfig)
		return additionalData, nil
	}

	// Addition or Change in VirtualCapacity should NOT cause existing hash to change to prevent trigger of rollout.
	if workerConfig != nil && workerConfig.NodeTemplate != nil && workerConfig.NodeTemplate.VirtualCapacity != nil {
		modifiedWorkerConfigJson := stripVirtualCapacity(pool.ProviderConfig.Raw)
		additionalData = append(additionalData, string(modifiedWorkerConfigJson))
		return additionalData, nil
	}

	// preserve legacy behaviour
	if pool.ProviderConfig != nil && pool.ProviderConfig.Raw != nil {
		additionalData = append(additionalData, string(pool.ProviderConfig.Raw))
	}

	return additionalData, nil
}

// ComputeAdditionalHashDataInPlace computes additional hash data for a worker pool with in-place update strategy.
func ComputeAdditionalHashDataInPlace(pool extensionsv1alpha1.WorkerPool) []string {
	var additionalData []string

	if pool.Volume != nil && pool.Volume.Encrypted != nil {
		additionalData = append(additionalData, strconv.FormatBool(*pool.Volume.Encrypted))
	}

	return additionalData
}

func computeIAMInstanceProfile(workerConfig *awsapi.WorkerConfig, infrastructureStatus *awsapi.InfrastructureStatus) (awsmachineapi.AWSIAMProfileSpec, error) {
	if workerConfig.IAMInstanceProfile == nil {
		nodesInstanceProfile, err := awsapihelper.FindInstanceProfileForPurpose(infrastructureStatus.IAM.InstanceProfiles, awsapi.PurposeNodes)
		if err != nil {
			return awsmachineapi.AWSIAMProfileSpec{}, err
		}

		return awsmachineapi.AWSIAMProfileSpec{
			Name: nodesInstanceProfile.Name,
		}, nil
	}

	if v := workerConfig.IAMInstanceProfile.Name; v != nil {
		return awsmachineapi.AWSIAMProfileSpec{
			Name: *v,
		}, nil
	}

	if v := workerConfig.IAMInstanceProfile.ARN; v != nil {
		return awsmachineapi.AWSIAMProfileSpec{
			ARN: *v,
		}, nil
	}

	return awsmachineapi.AWSIAMProfileSpec{}, fmt.Errorf("unable to compute IAM instance profile configuration")
}

// ComputeInstanceMetadataOptions calculates the InstanceMetadata options for a particular worker pool.
func ComputeInstanceMetadataOptions(workerConfig *awsapi.WorkerConfig, networking *gardencorev1beta1.Networking) (*awsmachineapi.InstanceMetadataOptions, error) {
	var instanceMetadataOptions = &awsmachineapi.InstanceMetadataOptions{}

	if networking != nil && gardencorev1beta1.IsIPv6SingleStack(networking.IPFamilies) {
		instanceMetadataOptions.HTTPProtocolIPv6 = string(ec2types.InstanceMetadataProtocolStateEnabled)
	}

	if workerConfig == nil || workerConfig.InstanceMetadataOptions == nil {
		instanceMetadataOptions.HTTPPutResponseHopLimit = ptr.To[int32](2)
		instanceMetadataOptions.HTTPTokens = string(awsapi.HTTPTokensRequired)

		return instanceMetadataOptions, nil
	}

	if workerConfig.InstanceMetadataOptions.HTTPPutResponseHopLimit != nil {
		instanceMetadataOptions.HTTPPutResponseHopLimit = workerConfig.InstanceMetadataOptions.HTTPPutResponseHopLimit
	}

	if workerConfig.InstanceMetadataOptions.HTTPTokens != nil {
		instanceMetadataOptions.HTTPTokens = string(*workerConfig.InstanceMetadataOptions.HTTPTokens)
	}

	return instanceMetadataOptions, nil
}

// EnsureUniformMachineImages ensures that all machine images are in the same format, either with or without Capabilities.
func EnsureUniformMachineImages(images []awsapi.MachineImage, definitions []gardencorev1beta1.CapabilityDefinition) []awsapi.MachineImage {
	var uniformMachineImages []awsapi.MachineImage

	if len(definitions) == 0 {
		// transform images that were added with Capabilities to the legacy format without Capabilities
		for _, img := range images {
			if len(img.Capabilities) == 0 {
				// image is already legacy format
				uniformMachineImages = appendMachineImage(uniformMachineImages, img, definitions)
				continue
			}
			// transform to legacy format by using the Architecture capability if it exists
			var architecture *string
			if len(img.Capabilities[v1beta1constants.ArchitectureName]) > 0 {
				architecture = &img.Capabilities[v1beta1constants.ArchitectureName][0]
			}
			uniformMachineImages = appendMachineImage(uniformMachineImages, awsapi.MachineImage{
				Name:         img.Name,
				Version:      img.Version,
				AMI:          img.AMI,
				Architecture: architecture,
			}, definitions)
		}
		return uniformMachineImages
	}

	// transform images that were added without Capabilities to contain a MachineImageFlavor with defaulted Architecture
	for _, img := range images {
		if len(img.Capabilities) > 0 {
			// image is already in the new format with Capabilities
			uniformMachineImages = appendMachineImage(uniformMachineImages, img, definitions)
		} else {
			// add image as a capability set with defaulted Architecture
			architecture := ptr.Deref(img.Architecture, v1beta1constants.ArchitectureAMD64)
			uniformMachineImages = appendMachineImage(uniformMachineImages, awsapi.MachineImage{
				Name:         img.Name,
				Version:      img.Version,
				AMI:          img.AMI,
				Capabilities: gardencorev1beta1.Capabilities{v1beta1constants.ArchitectureName: []string{architecture}},
			}, definitions)
		}
	}
	return uniformMachineImages
}

func appendHashDataForWorkerConfig(hashData []string, workerConfig *awsapi.WorkerConfig) []string {
	if workerConfig.NodeTemplate != nil {
		keys := slices.Sorted(maps.Keys(workerConfig.NodeTemplate.Capacity)) // ensure order
		for _, k := range keys {
			q := workerConfig.NodeTemplate.Capacity[k]
			hashData = append(hashData, fmt.Sprintf("%s=%d", k, q.Value()))
		}
	}
	if workerConfig.Volume != nil {
		if workerConfig.Volume.IOPS != nil {
			hashData = append(hashData, strconv.FormatInt(int64(*workerConfig.Volume.IOPS), 10))
		}
		if workerConfig.Volume.Throughput != nil {
			hashData = append(hashData, strconv.FormatInt(int64(*workerConfig.Volume.Throughput), 10))
		}
	}
	if workerConfig.DataVolumes != nil {
		for _, dv := range workerConfig.DataVolumes {
			hashData = append(hashData, dv.Name)
			if dv.IOPS != nil {
				hashData = append(hashData, strconv.FormatInt(int64(*dv.IOPS), 10))
			}
			if dv.Throughput != nil {
				hashData = append(hashData, strconv.FormatInt(int64(*dv.Throughput), 10))
			}
			if dv.SnapshotID != nil {
				hashData = append(hashData, *dv.SnapshotID)
			}
		}
	}
	if workerConfig.IAMInstanceProfile != nil {
		if workerConfig.IAMInstanceProfile.Name != nil {
			hashData = append(hashData, *workerConfig.IAMInstanceProfile.Name)
		}
		if workerConfig.IAMInstanceProfile.ARN != nil {
			hashData = append(hashData, *workerConfig.IAMInstanceProfile.ARN)
		}
	}

	if workerConfig.InstanceMetadataOptions != nil {
		if workerConfig.InstanceMetadataOptions.HTTPTokens != nil {
			hashData = append(hashData, string(*workerConfig.InstanceMetadataOptions.HTTPTokens))
		}
		if workerConfig.InstanceMetadataOptions.HTTPPutResponseHopLimit != nil {
			hashData = append(hashData, strconv.FormatInt(int64(*workerConfig.InstanceMetadataOptions.HTTPPutResponseHopLimit), 10))
		}
	}

	if workerConfig.CpuOptions != nil {
		if workerConfig.CpuOptions.CoreCount != nil {
			hashData = append(hashData, strconv.FormatInt(int64(*workerConfig.CpuOptions.CoreCount), 10))
		}
		if workerConfig.CpuOptions.ThreadsPerCore != nil {
			hashData = append(hashData, strconv.FormatInt(int64(*workerConfig.CpuOptions.ThreadsPerCore), 10))
		}
	}

	if workerConfig.CapacityReservation != nil {
		if workerConfig.CapacityReservation.CapacityReservationPreference != nil {
			hashData = append(hashData, *workerConfig.CapacityReservation.CapacityReservationPreference)
		}
		if workerConfig.CapacityReservation.CapacityReservationID != nil {
			hashData = append(hashData, *workerConfig.CapacityReservation.CapacityReservationID)
		}
		if workerConfig.CapacityReservation.CapacityReservationResourceGroupARN != nil {
			hashData = append(hashData, *workerConfig.CapacityReservation.CapacityReservationResourceGroupARN)
		}
	}
	return hashData
}
