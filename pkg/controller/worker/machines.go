// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package worker

import (
	"context"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsapihelper "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"

	"github.com/gardener/gardener/extensions/pkg/controller/csimigration"
	"github.com/gardener/gardener/extensions/pkg/controller/worker"
	genericworkeractuator "github.com/gardener/gardener/extensions/pkg/controller/worker/genericactuator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	"github.com/gardener/gardener/pkg/utils"
	machinev1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MachineClassKind yields the name of the machine class kind used by AWS provider.
func (w *workerDelegate) MachineClassKind() string {
	return "MachineClass"
}

// MachineClassList yields a newly initialized MachineClassList object.
func (w *workerDelegate) MachineClassList() client.ObjectList {
	return &machinev1alpha1.MachineClassList{}
}

// MachineClass yields a newly initialized MachineClass object.
func (w *workerDelegate) MachineClass() client.Object {
	return &machinev1alpha1.MachineClass{}
}

// DeployMachineClasses generates and creates the AWS specific machine classes.
func (w *workerDelegate) DeployMachineClasses(ctx context.Context) error {
	if w.machineClasses == nil {
		if err := w.generateMachineConfig(); err != nil {
			return err
		}
	}

	// Delete any older version of AWSMachineClass CRs.
	if err := w.Client().DeleteAllOf(ctx, &machinev1alpha1.AWSMachineClass{}, client.InNamespace(w.worker.Namespace)); err != nil {
		return errors.Wrapf(err, "cleaning up older version of AWS machine class CRs failed")
	}

	return w.seedChartApplier.Apply(ctx, filepath.Join(aws.InternalChartsPath, "machineclass"), w.worker.Namespace, "machineclass", kubernetes.Values(map[string]interface{}{"machineClasses": w.machineClasses}))
}

// GenerateMachineDeployments generates the configuration for the desired machine deployments.
func (w *workerDelegate) GenerateMachineDeployments(ctx context.Context) (worker.MachineDeployments, error) {
	if w.machineDeployments == nil {
		if err := w.generateMachineConfig(); err != nil {
			return nil, err
		}
	}
	return w.machineDeployments, nil
}

func (w *workerDelegate) generateMachineConfig() error {
	var (
		machineDeployments = worker.MachineDeployments{}
		machineClasses     []map[string]interface{}
		machineImages      []awsapi.MachineImage
	)

	infrastructureStatus := &awsapi.InfrastructureStatus{}
	if _, _, err := w.Decoder().Decode(w.worker.Spec.InfrastructureProviderStatus.Raw, nil, infrastructureStatus); err != nil {
		return err
	}

	nodesSecurityGroup, err := awsapihelper.FindSecurityGroupForPurpose(infrastructureStatus.VPC.SecurityGroups, awsapi.PurposeNodes)
	if err != nil {
		return err
	}

	csiEnabled, _, err := csimigration.CheckCSIConditions(w.cluster, aws.GetCSIMigrationKubernetesVersion(w.cluster))
	if err != nil {
		return err
	}

	for _, pool := range w.worker.Spec.Pools {
		zoneLen := int32(len(pool.Zones))

		workerConfig := &awsapi.WorkerConfig{}
		if pool.ProviderConfig != nil && pool.ProviderConfig.Raw != nil {
			if _, _, err := w.Decoder().Decode(pool.ProviderConfig.Raw, nil, workerConfig); err != nil {
				return fmt.Errorf("could not decode provider config: %+v", err)
			}
		}

		workerPoolHash, err := worker.WorkerPoolHash(pool, w.cluster, computeAdditionalHashData(pool)...)
		if err != nil {
			return err
		}

		ami, err := w.findMachineImage(pool.MachineImage.Name, pool.MachineImage.Version, w.worker.Spec.Region)
		if err != nil {
			return err
		}
		machineImages = appendMachineImage(machineImages, awsapi.MachineImage{
			Name:    pool.MachineImage.Name,
			Version: pool.MachineImage.Version,
			AMI:     ami,
		})

		blockDevices, err := w.computeBlockDevices(pool, workerConfig)
		if err != nil {
			return err
		}

		iamInstanceProfile, err := computeIAMInstanceProfile(workerConfig, infrastructureStatus)
		if err != nil {
			return err
		}

		for zoneIndex, zone := range pool.Zones {
			zoneIdx := int32(zoneIndex)

			nodesSubnet, err := awsapihelper.FindSubnetForPurposeAndZone(infrastructureStatus.VPC.Subnets, awsapi.PurposeNodes, zone)
			if err != nil {
				return err
			}

			machineClassSpec := map[string]interface{}{
				"ami":                ami,
				"region":             w.worker.Spec.Region,
				"machineType":        pool.MachineType,
				"iamInstanceProfile": iamInstanceProfile,
				"keyName":            infrastructureStatus.EC2.KeyName,
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
					"cloudConfig": string(pool.UserData),
				},
				"blockDevices": blockDevices,
			}

			var (
				deploymentName          = fmt.Sprintf("%s-%s-z%d", w.worker.Namespace, pool.Name, zoneIndex+1)
				className               = fmt.Sprintf("%s-%s", deploymentName, workerPoolHash)
				awsCSIDriverTopologyKey = "topology.ebs.csi.aws.com/zone"
			)

			machineDeployments = append(machineDeployments, worker.MachineDeployment{
				Name:           deploymentName,
				ClassName:      className,
				SecretName:     className,
				Minimum:        worker.DistributeOverZones(zoneIdx, pool.Minimum, zoneLen),
				Maximum:        worker.DistributeOverZones(zoneIdx, pool.Maximum, zoneLen),
				MaxSurge:       worker.DistributePositiveIntOrPercent(zoneIdx, pool.MaxSurge, zoneLen, pool.Maximum),
				MaxUnavailable: worker.DistributePositiveIntOrPercent(zoneIdx, pool.MaxUnavailable, zoneLen, pool.Minimum),
				Labels: func() map[string]string {
					if !csiEnabled {
						return pool.Labels
					}
					// TODO: remove the csi topology label when AWS CSI driver stops using the aws csi topology key - https://github.com/kubernetes-sigs/aws-ebs-csi-driver/issues/899
					// add aws csi driver topology label if its not specified
					return utils.MergeStringMaps(pool.Labels, map[string]string{awsCSIDriverTopologyKey: zone})
				}(),
				Annotations:          pool.Annotations,
				Taints:               pool.Taints,
				MachineConfiguration: genericworkeractuator.ReadMachineConfiguration(pool),
			})

			machineClassSpec["name"] = className
			machineClassSpec["labels"] = map[string]string{corev1.LabelZoneFailureDomain: zone}
			machineClassSpec["secret"].(map[string]interface{})["labels"] = map[string]string{v1beta1constants.GardenerPurpose: genericworkeractuator.GardenPurposeMachineClass}

			machineClasses = append(machineClasses, machineClassSpec)
		}
	}

	w.machineDeployments = machineDeployments
	w.machineClasses = machineClasses
	w.machineImages = machineImages

	return nil
}

func (w *workerDelegate) computeBlockDevices(pool extensionsv1alpha1.WorkerPool, workerConfig *awsapi.WorkerConfig) ([]map[string]interface{}, error) {
	var blockDevices []map[string]interface{}

	// handle root disk
	rootDisk, err := computeEBSForVolume(*pool.Volume)
	if err != nil {
		return nil, errors.Wrapf(err, "error when computing EBS for root disk")
	}
	if workerConfig.Volume != nil && workerConfig.Volume.IOPS != nil {
		rootDisk["iops"] = *workerConfig.Volume.IOPS
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
				return nil, errors.Wrapf(err, "error when computing EBS for %v", vol)
			}
			if dvConfig := awsapihelper.FindDataVolumeByName(workerConfig.DataVolumes, vol.Name); dvConfig != nil {
				if dvConfig.IOPS != nil {
					dataDisk["iops"] = *dvConfig.IOPS
				}
				if dvConfig.SnapshotID != nil {
					dataDisk["snapshotID"] = *dvConfig.SnapshotID
				}
			}
			deviceName, err := computeEBSDeviceNameForIndex(i)
			if err != nil {
				return nil, errors.Wrapf(err, "error when computing EBS device name for %v", vol)
			}
			blockDevices = append(blockDevices, map[string]interface{}{
				"deviceName": deviceName,
				"ebs":        dataDisk,
			})
		}
	}

	return blockDevices, nil
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

func computeAdditionalHashData(pool extensionsv1alpha1.WorkerPool) []string {
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
