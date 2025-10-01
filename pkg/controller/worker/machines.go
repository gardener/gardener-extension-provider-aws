// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/worker"
	genericworkeractuator "github.com/gardener/gardener/extensions/pkg/controller/worker/genericactuator"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	gardencorev1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	extensionsv1alpha1helper "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1/helper"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/utils"
	versionutils "github.com/gardener/gardener/pkg/utils/version"
	machinev1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/charts"
	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsapihelper "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
)

const (
	// CSIDriverTopologyKey is the legacy topology key used by the AWS CSI driver
	// we need to support it because old PVs use it as node affinity
	// see also: https://github.com/kubernetes-sigs/aws-ebs-csi-driver/issues/729#issuecomment-1942026577
	CSIDriverTopologyKey = "topology.ebs.csi.aws.com/zone"
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
	if w.machineClasses == nil {
		if err := w.generateMachineConfig(ctx); err != nil {
			return err
		}
	}

	return w.seedChartApplier.ApplyFromEmbeddedFS(ctx, charts.InternalChart, filepath.Join(charts.InternalChartsPath, "machineclass"), w.worker.Namespace, "machineclass", kubernetes.Values(map[string]interface{}{"machineClasses": w.machineClasses}))
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
		machineDeployments = worker.MachineDeployments{}
		machineClasses     []map[string]interface{}
		machineImages      []awsapi.MachineImage
	)

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

		workerPoolHash, err := w.generateWorkerPoolHash(pool)
		if err != nil {
			return err
		}

		arch := ptr.Deref(pool.Architecture, v1beta1constants.ArchitectureAMD64)
		machineTypeFromCloudProfile := gardencorev1beta1helper.FindMachineTypeByName(w.cluster.CloudProfile.Spec.MachineTypes, pool.MachineType)
		if machineTypeFromCloudProfile == nil {
			return fmt.Errorf("machine type %q not found in cloud profile %q", pool.MachineType, w.cluster.CloudProfile.Name)
		}

		machineImage, err := w.selectMachineImageForWorkerPool(pool.MachineImage.Name, pool.MachineImage.Version, w.worker.Spec.Region, &arch, machineTypeFromCloudProfile.Capabilities)
		if err != nil {
			return err
		}

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

		instanceMetadataOptions, err := ComputeInstanceMetadata(workerConfig, w.cluster)
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

			machineClassSpec := map[string]interface{}{
				"ami":                machineImage.AMI,
				"region":             w.worker.Spec.Region,
				"machineType":        pool.MachineType,
				"iamInstanceProfile": iamInstanceProfile,
				"networkInterfaces": []map[string]interface{}{
					{
						"subnetID":         nodesSubnet.ID,
						"securityGroupIDs": []string{nodesSecurityGroup.ID},
					},
				},
				"tags": utils.MergeStringMaps(
					map[string]string{
						fmt.Sprintf("kubernetes.io/cluster/%s", w.worker.Namespace): "1",
						"kubernetes.io/role/node":                                   "1",
					},
					pool.Labels,
				),
				"credentialsSecretRef": map[string]interface{}{
					"name":      w.worker.Spec.SecretRef.Name,
					"namespace": w.worker.Spec.SecretRef.Namespace,
				},
				"secret": map[string]interface{}{
					"cloudConfig": string(userData),
				},
				"blockDevices":            blockDevices,
				"instanceMetadataOptions": instanceMetadataOptions,
			}

			if isIPv6(w.cluster) {
				networkInterfaces, _ := machineClassSpec["networkInterfaces"].([]map[string]interface{})
				networkInterfaces[0]["ipv6AddressCount"] = 1
				networkInterfaces[0]["ipv6PrefixCount"] = 1
			}

			if len(infrastructureStatus.EC2.KeyName) > 0 {
				machineClassSpec["keyName"] = infrastructureStatus.EC2.KeyName
			}

			var nodeTemplate machinev1alpha1.NodeTemplate
			if pool.NodeTemplate != nil {
				nodeTemplate = machinev1alpha1.NodeTemplate{
					Capacity:     pool.NodeTemplate.Capacity,
					InstanceType: pool.MachineType,
					Region:       w.worker.Spec.Region,
					Zone:         zone,
					Architecture: &arch,
				}
			}
			if workerConfig.NodeTemplate != nil {
				// Support providerConfig extended resources by copying into node template capacity
				maps.Copy(nodeTemplate.Capacity, workerConfig.NodeTemplate.Capacity)
			}
			machineClassSpec["nodeTemplate"] = nodeTemplate

			if cpuOptions := workerConfig.CpuOptions; cpuOptions != nil {
				machineClassSpec["cpuOptions"] = map[string]int64{
					"coreCount":      *cpuOptions.CoreCount,
					"threadsPerCore": *cpuOptions.ThreadsPerCore,
				}
			}

			if pool.MachineImage.Name != "" && pool.MachineImage.Version != "" {
				machineClassSpec["operatingSystem"] = map[string]interface{}{
					"operatingSystemName":    pool.MachineImage.Name,
					"operatingSystemVersion": strings.ReplaceAll(pool.MachineImage.Version, "+", "_"),
				}
			}

			var (
				deploymentName = fmt.Sprintf("%s-%s-z%d", w.worker.Namespace, pool.Name, zoneIndex+1)
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

			machineClassSpec["name"] = className
			machineClassSpec["labels"] = map[string]string{corev1.LabelZoneFailureDomain: zone}
			machineClassSpec["secret"].(map[string]interface{})["labels"] = map[string]string{v1beta1constants.GardenerPurpose: v1beta1constants.GardenPurposeMachineClass}

			machineClasses = append(machineClasses, machineClassSpec)
		}
	}

	w.machineDeployments = machineDeployments
	w.machineClasses = machineClasses
	w.machineImages = machineImages

	return nil
}

func (w *WorkerDelegate) computeBlockDevices(pool extensionsv1alpha1.WorkerPool, workerConfig *awsapi.WorkerConfig) ([]map[string]interface{}, error) {
	var blockDevices []map[string]interface{}

	// handle root disk
	rootDisk, err := computeEBSForVolume(*pool.Volume)
	if err != nil {
		return nil, fmt.Errorf("error when computing EBS for root disk: %w", err)
	}
	if workerConfig.Volume != nil {
		if workerConfig.Volume.IOPS != nil {
			rootDisk["iops"] = *workerConfig.Volume.IOPS
		}
		if workerConfig.Volume.Throughput != nil {
			rootDisk["throughput"] = *workerConfig.Volume.Throughput
		}
	}
	blockDevices = append(blockDevices, map[string]interface{}{"ebs": rootDisk})

	// handle data disks
	if dataVolumes := pool.DataVolumes; len(dataVolumes) > 0 {
		blockDevices[0]["deviceName"] = "/root"

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
					dataDisk["iops"] = *dvConfig.IOPS
				}
				if dvConfig.SnapshotID != nil {
					dataDisk["snapshotID"] = *dvConfig.SnapshotID
				}
				if dvConfig.Throughput != nil {
					dataDisk["throughput"] = *dvConfig.Throughput
				}
			}
			deviceName, err := computeEBSDeviceNameForIndex(i)
			if err != nil {
				return nil, fmt.Errorf("error when computing EBS device name for %v: %w", vol, err)
			}
			blockDevices = append(blockDevices, map[string]interface{}{
				"deviceName": deviceName,
				"ebs":        dataDisk,
			})
		}
	}

	return blockDevices, nil
}

func (w *WorkerDelegate) generateWorkerPoolHash(pool extensionsv1alpha1.WorkerPool) (string, error) {
	return worker.WorkerPoolHash(pool, w.cluster, ComputeAdditionalHashDataV1(pool), ComputeAdditionalHashDataV2(pool), ComputeAdditionalHashDataInPlace(pool))
}

func computeEBSForVolume(volume extensionsv1alpha1.Volume) (map[string]interface{}, error) {
	return computeEBS(volume.Size, volume.Type, volume.Encrypted)
}

func computeEBSForDataVolume(volume extensionsv1alpha1.DataVolume) (map[string]interface{}, error) {
	return computeEBS(volume.Size, volume.Type, volume.Encrypted)
}

func computeEBS(size string, volumeType *string, encrypted *bool) (map[string]interface{}, error) {
	volumeSize, err := worker.DiskSize(size)
	if err != nil {
		return nil, err
	}

	ebs := map[string]interface{}{
		"volumeSize":          volumeSize,
		"encrypted":           true,
		"deleteOnTermination": true,
	}

	if volumeType != nil {
		ebs["volumeType"] = *volumeType
	}

	if encrypted != nil {
		ebs["encrypted"] = *encrypted
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
func ComputeAdditionalHashDataV2(pool extensionsv1alpha1.WorkerPool) []string {
	var additionalData = ComputeAdditionalHashDataV1(pool)

	// in the future, we may not calculate a hash for the whole ProviderConfig
	// for example volume IOPS changes could be done in place
	if pool.ProviderConfig != nil && pool.ProviderConfig.Raw != nil {
		additionalData = append(additionalData, string(pool.ProviderConfig.Raw))
	}

	return additionalData
}

// ComputeAdditionalHashDataInPlace computes additional hash data for a worker pool with in-place update strategy.
func ComputeAdditionalHashDataInPlace(pool extensionsv1alpha1.WorkerPool) []string {
	var additionalData []string

	if pool.Volume != nil && pool.Volume.Encrypted != nil {
		additionalData = append(additionalData, strconv.FormatBool(*pool.Volume.Encrypted))
	}

	return additionalData
}

func computeIAMInstanceProfile(workerConfig *awsapi.WorkerConfig, infrastructureStatus *awsapi.InfrastructureStatus) (map[string]interface{}, error) {
	if workerConfig.IAMInstanceProfile == nil {
		nodesInstanceProfile, err := awsapihelper.FindInstanceProfileForPurpose(infrastructureStatus.IAM.InstanceProfiles, awsapi.PurposeNodes)
		if err != nil {
			return nil, err
		}

		return map[string]interface{}{"name": nodesInstanceProfile.Name}, nil
	}

	if v := workerConfig.IAMInstanceProfile.Name; v != nil {
		return map[string]interface{}{"name": *v}, nil
	}

	if v := workerConfig.IAMInstanceProfile.ARN; v != nil {
		return map[string]interface{}{"arn": *v}, nil
	}

	return nil, fmt.Errorf("unable to compute IAM instance profile configuration")
}

// ComputeInstanceMetadata calculates the InstanceMetadata options for a particular worker pool.
func ComputeInstanceMetadata(workerConfig *awsapi.WorkerConfig, cluster *controller.Cluster) (map[string]interface{}, error) {
	res := make(map[string]interface{})

	// apply new defaults for k8s >= v1.30 to require the use of IMDSv2, unless explicitly opted out.
	if workerConfig == nil || workerConfig.InstanceMetadataOptions == nil {
		k8sVersion, err := semver.NewVersion(cluster.Shoot.Spec.Kubernetes.Version)
		if err != nil {
			return nil, err
		}

		if versionutils.ConstraintK8sGreaterEqual130.Check(k8sVersion) {
			res["httpPutResponseHopLimit"] = int64(2)
			res["httpTokens"] = string(awsapi.HTTPTokensRequired)
		}

		return res, nil
	}

	if workerConfig.InstanceMetadataOptions.HTTPPutResponseHopLimit != nil {
		res["httpPutResponseHopLimit"] = *workerConfig.InstanceMetadataOptions.HTTPPutResponseHopLimit
	}

	if workerConfig.InstanceMetadataOptions.HTTPTokens != nil {
		res["httpTokens"] = string(*workerConfig.InstanceMetadataOptions.HTTPTokens)
	}

	return res, nil
}

func isIPv6(c *controller.Cluster) bool {
	networking := c.Shoot.Spec.Networking
	if networking != nil {
		ipFamilies := networking.IPFamilies
		if ipFamilies != nil {
			if slices.Contains(ipFamilies, gardencorev1beta1.IPFamilyIPv6) {
				return true
			}
		}
	}
	return false
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
