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

package worker_test

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apiv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/worker"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/common"
	"github.com/gardener/gardener/extensions/pkg/controller/worker"
	genericworkeractuator "github.com/gardener/gardener/extensions/pkg/controller/worker/genericactuator"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	mockkubernetes "github.com/gardener/gardener/pkg/client/kubernetes/mock"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	"github.com/gardener/gardener/pkg/utils"
	machinev1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	ctx = context.TODO()
)

var _ = Describe("Machines", func() {
	var (
		ctrl         *gomock.Controller
		c            *mockclient.MockClient
		statusWriter *mockclient.MockStatusWriter
		chartApplier *mockkubernetes.MockChartApplier
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())

		c = mockclient.NewMockClient(ctrl)
		statusWriter = mockclient.NewMockStatusWriter(ctrl)
		chartApplier = mockkubernetes.NewMockChartApplier(ctrl)
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Context("workerDelegate", func() {
		workerDelegate, _ := NewWorkerDelegate(common.NewClientContext(nil, nil, nil), nil, "", nil, nil)

		Describe("#MachineClassKind", func() {
			It("should return the correct kind of the machine class", func() {
				Expect(workerDelegate.MachineClassKind()).To(Equal("MachineClass"))
			})
		})

		Describe("#MachineClassList", func() {
			It("should return the correct type for the machine class list", func() {
				Expect(workerDelegate.MachineClassList()).To(Equal(&machinev1alpha1.MachineClassList{}))
			})
		})

		Describe("#GenerateMachineDeployments, #DeployMachineClasses", func() {
			var (
				namespace        string
				cloudProfileName string
				region           string

				machineImageName    string
				machineImageVersion string
				machineImageAMI     string

				vpcID               string
				machineType         string
				userData            []byte
				instanceProfileName string
				securityGroupID     string
				keyName             string

				volumeType      string
				volumeSize      int
				volumeEncrypted bool
				volumeIOPS      int64

				dataVolume1Name      string
				dataVolume1Type      string
				dataVolume1Size      int
				dataVolume1IOPS      int64
				dataVolume1Encrypted bool

				dataVolume2Name       string
				dataVolume2Type       string
				dataVolume2Size       int
				dataVolume2Encrypted  bool
				dataVolume2SnapshotID string

				namePool1           string
				minPool1            int32
				maxPool1            int32
				maxSurgePool1       intstr.IntOrString
				maxUnavailablePool1 intstr.IntOrString

				namePool2           string
				minPool2            int32
				maxPool2            int32
				maxSurgePool2       intstr.IntOrString
				maxUnavailablePool2 intstr.IntOrString

				subnetZone1 string
				subnetZone2 string
				zone1       string
				zone2       string

				labels map[string]string

				machineConfiguration *machinev1alpha1.MachineConfiguration

				workerPoolHash1             string
				workerPoolHash2             string
				workerPoolWithCSIlabelHash1 string
				workerPoolWithCSIlabelHash2 string

				shootVersionMajorMinor string
				shootVersion           string
				scheme                 *runtime.Scheme
				decoder                runtime.Decoder
				clusterWithoutImages   *extensionscontroller.Cluster
				clusterk8s118          *extensionscontroller.Cluster
				cluster                *extensionscontroller.Cluster
				w                      *extensionsv1alpha1.Worker
			)

			BeforeEach(func() {
				namespace = "shoot--foobar--aws"
				cloudProfileName = "aws"

				region = "eu-west-1"

				machineImageName = "my-os"
				machineImageVersion = "123"
				machineImageAMI = "ami-123456"

				vpcID = "vpc-1234"
				machineType = "large"
				userData = []byte("some-user-data")
				instanceProfileName = "nodes-instance-prof"
				securityGroupID = "sg-12345"
				keyName = "my-ssh-key"

				volumeType = "normal"
				volumeSize = 20
				volumeEncrypted = true
				volumeIOPS = 400

				dataVolume1Name = "vol-1"
				dataVolume1Type = "foo"
				dataVolume1Size = 42
				dataVolume1IOPS = 567
				dataVolume1Encrypted = true

				dataVolume2Name = "vol-2"
				dataVolume2Type = "bar"
				dataVolume2Size = 43
				dataVolume2Encrypted = false
				dataVolume2SnapshotID = "snap-shot"

				namePool1 = "pool-1"
				minPool1 = 5
				maxPool1 = 10
				maxSurgePool1 = intstr.FromInt(3)
				maxUnavailablePool1 = intstr.FromInt(2)

				namePool2 = "pool-2"
				minPool2 = 30
				maxPool2 = 45
				maxSurgePool2 = intstr.FromInt(10)
				maxUnavailablePool2 = intstr.FromInt(15)

				subnetZone1 = "subnet-acbd1234"
				subnetZone2 = "subnet-4321dbca"
				zone1 = region + "a"
				zone2 = region + "b"

				labels = map[string]string{"component": "TiDB"}

				machineConfiguration = &machinev1alpha1.MachineConfiguration{}

				shootVersionMajorMinor = "1.2"
				shootVersion = shootVersionMajorMinor + ".3"

				clusterWithoutImages = &extensionscontroller.Cluster{
					Shoot: &gardencorev1beta1.Shoot{
						Spec: gardencorev1beta1.ShootSpec{
							Kubernetes: gardencorev1beta1.Kubernetes{
								Version: shootVersion,
							},
						},
					},
				}

				cloudProfileConfig := &apiv1alpha1.CloudProfileConfig{
					TypeMeta: metav1.TypeMeta{
						APIVersion: apiv1alpha1.SchemeGroupVersion.String(),
						Kind:       "CloudProfileConfig",
					},
					MachineImages: []apiv1alpha1.MachineImages{
						{
							Name: machineImageName,
							Versions: []apiv1alpha1.MachineImageVersion{
								{
									Version: machineImageVersion,
									Regions: []apiv1alpha1.RegionAMIMapping{
										{
											Name: region,
											AMI:  machineImageAMI,
										},
									},
								},
							},
						},
					},
				}
				cloudProfileConfigJSON, _ := json.Marshal(cloudProfileConfig)
				cluster = &extensionscontroller.Cluster{
					CloudProfile: &gardencorev1beta1.CloudProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name: cloudProfileName,
						},
						Spec: gardencorev1beta1.CloudProfileSpec{
							ProviderConfig: &runtime.RawExtension{
								Raw: cloudProfileConfigJSON,
							},
						},
					},
					Shoot: clusterWithoutImages.Shoot,
				}

				clusterk8s118 = &extensionscontroller.Cluster{
					CloudProfile: &gardencorev1beta1.CloudProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name: cloudProfileName,
						},
						Spec: gardencorev1beta1.CloudProfileSpec{
							ProviderConfig: &runtime.RawExtension{
								Raw: cloudProfileConfigJSON,
							},
						},
					},
					Shoot: &gardencorev1beta1.Shoot{
						Spec: gardencorev1beta1.ShootSpec{
							Kubernetes: gardencorev1beta1.Kubernetes{
								Version: "1.18.0",
							},
						},
					},
				}

				w = &extensionsv1alpha1.Worker{
					ObjectMeta: metav1.ObjectMeta{
						Namespace: namespace,
					},
					Spec: extensionsv1alpha1.WorkerSpec{
						SecretRef: corev1.SecretReference{
							Name:      "secret",
							Namespace: namespace,
						},
						Region: region,
						InfrastructureProviderStatus: &runtime.RawExtension{
							Raw: encode(&api.InfrastructureStatus{
								VPC: api.VPCStatus{
									ID: vpcID,
									Subnets: []api.Subnet{
										{
											ID:      subnetZone1,
											Purpose: "nodes",
											Zone:    zone1,
										},
										{
											ID:      subnetZone2,
											Purpose: "nodes",
											Zone:    zone2,
										},
									},
									SecurityGroups: []api.SecurityGroup{
										{
											ID:      securityGroupID,
											Purpose: "nodes",
										},
									},
								},
								IAM: api.IAM{
									InstanceProfiles: []api.InstanceProfile{
										{
											Name:    instanceProfileName,
											Purpose: "nodes",
										},
									},
								},
								EC2: api.EC2{
									KeyName: keyName,
								},
							}),
						},
						Pools: []extensionsv1alpha1.WorkerPool{
							{
								Name:           namePool1,
								Minimum:        minPool1,
								Maximum:        maxPool1,
								MaxSurge:       maxSurgePool1,
								MaxUnavailable: maxUnavailablePool1,
								MachineType:    machineType,
								MachineImage: extensionsv1alpha1.MachineImage{
									Name:    machineImageName,
									Version: machineImageVersion,
								},
								ProviderConfig: &runtime.RawExtension{
									Raw: encode(&api.WorkerConfig{
										Volume: &api.Volume{
											IOPS: &volumeIOPS,
										},
										DataVolumes: []api.DataVolume{
											{
												Name: dataVolume1Name,
												Volume: api.Volume{
													IOPS: &dataVolume1IOPS,
												},
											},
											{
												Name:       dataVolume2Name,
												SnapshotID: &dataVolume2SnapshotID,
											},
										},
									}),
								},
								UserData: userData,
								Volume: &extensionsv1alpha1.Volume{
									Type:      &volumeType,
									Size:      fmt.Sprintf("%dGi", volumeSize),
									Encrypted: &volumeEncrypted,
								},
								DataVolumes: []extensionsv1alpha1.DataVolume{
									{
										Name:      dataVolume1Name,
										Type:      &dataVolume1Type,
										Size:      fmt.Sprintf("%dGi", dataVolume1Size),
										Encrypted: &dataVolume1Encrypted,
									},
									{
										Name:      dataVolume2Name,
										Type:      &dataVolume2Type,
										Size:      fmt.Sprintf("%dGi", dataVolume2Size),
										Encrypted: &dataVolume2Encrypted,
									},
								},
								Zones: []string{
									zone1,
									zone2,
								},
								Labels: labels,
							},
							{
								Name:           namePool2,
								Minimum:        minPool2,
								Maximum:        maxPool2,
								MaxSurge:       maxSurgePool2,
								MaxUnavailable: maxUnavailablePool2,
								MachineType:    machineType,
								MachineImage: extensionsv1alpha1.MachineImage{
									Name:    machineImageName,
									Version: machineImageVersion,
								},
								UserData: userData,
								Volume: &extensionsv1alpha1.Volume{
									Type: &volumeType,
									Size: fmt.Sprintf("%dGi", volumeSize),
								},
								Zones: []string{
									zone1,
									zone2,
								},
								Labels: labels,
							},
						},
					},
				}

				scheme = runtime.NewScheme()
				_ = api.AddToScheme(scheme)
				_ = apiv1alpha1.AddToScheme(scheme)
				decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()

				workerPoolHash1, _ = worker.WorkerPoolHash(w.Spec.Pools[0], cluster, strconv.FormatBool(volumeEncrypted), fmt.Sprintf("%dGi", dataVolume1Size), dataVolume1Type, strconv.FormatBool(dataVolume1Encrypted), fmt.Sprintf("%dGi", dataVolume2Size), dataVolume2Type, strconv.FormatBool(dataVolume2Encrypted))
				workerPoolHash2, _ = worker.WorkerPoolHash(w.Spec.Pools[1], cluster)
				workerPoolWithCSIlabelHash1, _ = worker.WorkerPoolHash(w.Spec.Pools[0], clusterk8s118, strconv.FormatBool(volumeEncrypted), fmt.Sprintf("%dGi", dataVolume1Size), dataVolume1Type, strconv.FormatBool(dataVolume1Encrypted), fmt.Sprintf("%dGi", dataVolume2Size), dataVolume2Type, strconv.FormatBool(dataVolume2Encrypted))
				workerPoolWithCSIlabelHash2, _ = worker.WorkerPoolHash(w.Spec.Pools[1], clusterk8s118)

				workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, clusterWithoutImages)
			})

			Describe("machine images", func() {
				var (
					defaultMachineClass             map[string]interface{}
					machineDeployments              worker.MachineDeployments
					machineDeploymentsWithCSILabels worker.MachineDeployments
					machineClasses                  map[string]interface{}
				)

				BeforeEach(func() {
					ec2InstanceTags := utils.MergeStringMaps(
						map[string]string{
							fmt.Sprintf("kubernetes.io/cluster/%s", namespace): "1",
							"kubernetes.io/role/node":                          "1",
						},
						labels,
					)
					defaultMachineClass = map[string]interface{}{
						"secret": map[string]interface{}{
							"cloudConfig": string(userData),
						},
						"ami":         machineImageAMI,
						"region":      region,
						"machineType": machineType,
						"iamInstanceProfile": map[string]interface{}{
							"name": instanceProfileName,
						},
						"keyName": keyName,
						"tags":    ec2InstanceTags,
						"blockDevices": []map[string]interface{}{
							{
								"ebs": map[string]interface{}{
									"volumeSize":          volumeSize,
									"volumeType":          volumeType,
									"deleteOnTermination": true,
									"encrypted":           true,
								},
							},
						},
					}

					var (
						machineClassPool1Zone1 = addKeyValueToMap(defaultMachineClass, "networkInterfaces", []map[string]interface{}{
							{
								"subnetID":         subnetZone1,
								"securityGroupIDs": []string{securityGroupID},
							},
						})
						machineClassPool1Zone2 = addKeyValueToMap(defaultMachineClass, "networkInterfaces", []map[string]interface{}{
							{
								"subnetID":         subnetZone2,
								"securityGroupIDs": []string{securityGroupID},
							},
						})
						machineClassPool2Zone1 = addKeyValueToMap(defaultMachineClass, "networkInterfaces", []map[string]interface{}{
							{
								"subnetID":         subnetZone1,
								"securityGroupIDs": []string{securityGroupID},
							},
						})
						machineClassPool2Zone2 = addKeyValueToMap(defaultMachineClass, "networkInterfaces", []map[string]interface{}{
							{
								"subnetID":         subnetZone2,
								"securityGroupIDs": []string{securityGroupID},
							},
						})

						machineClassPool1BlockDevices = []map[string]interface{}{
							{
								"deviceName": "/root",
								"ebs": map[string]interface{}{
									"volumeSize":          volumeSize,
									"volumeType":          volumeType,
									"iops":                volumeIOPS,
									"deleteOnTermination": true,
									"encrypted":           volumeEncrypted,
								},
							},
							{
								"deviceName": "/dev/sdf",
								"ebs": map[string]interface{}{
									"volumeSize":          dataVolume1Size,
									"volumeType":          dataVolume1Type,
									"deleteOnTermination": true,
									"encrypted":           dataVolume1Encrypted,
									"iops":                dataVolume1IOPS,
								},
							},
							{
								"deviceName": "/dev/sdg",
								"ebs": map[string]interface{}{
									"volumeSize":          dataVolume2Size,
									"volumeType":          dataVolume2Type,
									"deleteOnTermination": true,
									"encrypted":           dataVolume2Encrypted,
									"snapshotID":          dataVolume2SnapshotID,
								},
							},
						}
					)

					machineClassPool1Zone1["blockDevices"] = machineClassPool1BlockDevices
					machineClassPool1Zone2["blockDevices"] = machineClassPool1BlockDevices

					machineClassPool1Zone1 = addKeyValueToMap(machineClassPool1Zone1, "labels", map[string]string{corev1.LabelZoneFailureDomain: zone1})
					machineClassPool1Zone2 = addKeyValueToMap(machineClassPool1Zone2, "labels", map[string]string{corev1.LabelZoneFailureDomain: zone2})
					machineClassPool2Zone1 = addKeyValueToMap(machineClassPool2Zone1, "labels", map[string]string{corev1.LabelZoneFailureDomain: zone1})
					machineClassPool2Zone2 = addKeyValueToMap(machineClassPool2Zone2, "labels", map[string]string{corev1.LabelZoneFailureDomain: zone2})

					var (
						machineClassNamePool1Zone1 = fmt.Sprintf("%s-%s-z1", namespace, namePool1)
						machineClassNamePool1Zone2 = fmt.Sprintf("%s-%s-z2", namespace, namePool1)
						machineClassNamePool2Zone1 = fmt.Sprintf("%s-%s-z1", namespace, namePool2)
						machineClassNamePool2Zone2 = fmt.Sprintf("%s-%s-z2", namespace, namePool2)

						machineClassWithHashPool1Zone1 = fmt.Sprintf("%s-%s", machineClassNamePool1Zone1, workerPoolHash1)
						machineClassWithHashPool1Zone2 = fmt.Sprintf("%s-%s", machineClassNamePool1Zone2, workerPoolHash1)
						machineClassWithHashPool2Zone1 = fmt.Sprintf("%s-%s", machineClassNamePool2Zone1, workerPoolHash2)
						machineClassWithHashPool2Zone2 = fmt.Sprintf("%s-%s", machineClassNamePool2Zone2, workerPoolHash2)

						machineClassWithHashPool1Zone1CSI = fmt.Sprintf("%s-%s", machineClassNamePool1Zone1, workerPoolWithCSIlabelHash1)
						machineClassWithHashPool1Zone2CSI = fmt.Sprintf("%s-%s", machineClassNamePool1Zone2, workerPoolWithCSIlabelHash1)
						machineClassWithHashPool2Zone1CSI = fmt.Sprintf("%s-%s", machineClassNamePool2Zone1, workerPoolWithCSIlabelHash2)
						machineClassWithHashPool2Zone2CSI = fmt.Sprintf("%s-%s", machineClassNamePool2Zone2, workerPoolWithCSIlabelHash2)
					)

					addNameAndSecretToMachineClass(machineClassPool1Zone1, machineClassWithHashPool1Zone1, w.Spec.SecretRef)
					addNameAndSecretToMachineClass(machineClassPool1Zone2, machineClassWithHashPool1Zone2, w.Spec.SecretRef)
					addNameAndSecretToMachineClass(machineClassPool2Zone1, machineClassWithHashPool2Zone1, w.Spec.SecretRef)
					addNameAndSecretToMachineClass(machineClassPool2Zone2, machineClassWithHashPool2Zone2, w.Spec.SecretRef)

					machineClasses = map[string]interface{}{"machineClasses": []map[string]interface{}{
						machineClassPool1Zone1,
						machineClassPool1Zone2,
						machineClassPool2Zone1,
						machineClassPool2Zone2,
					}}

					machineDeployments = worker.MachineDeployments{
						{
							Name:                 machineClassNamePool1Zone1,
							ClassName:            machineClassWithHashPool1Zone1,
							SecretName:           machineClassWithHashPool1Zone1,
							Minimum:              worker.DistributeOverZones(0, minPool1, 2),
							Maximum:              worker.DistributeOverZones(0, maxPool1, 2),
							MaxSurge:             worker.DistributePositiveIntOrPercent(0, maxSurgePool1, 2, maxPool1),
							MaxUnavailable:       worker.DistributePositiveIntOrPercent(0, maxUnavailablePool1, 2, minPool1),
							Labels:               labels,
							MachineConfiguration: machineConfiguration,
						},
						{
							Name:                 machineClassNamePool1Zone2,
							ClassName:            machineClassWithHashPool1Zone2,
							SecretName:           machineClassWithHashPool1Zone2,
							Minimum:              worker.DistributeOverZones(1, minPool1, 2),
							Maximum:              worker.DistributeOverZones(1, maxPool1, 2),
							MaxSurge:             worker.DistributePositiveIntOrPercent(1, maxSurgePool1, 2, maxPool1),
							MaxUnavailable:       worker.DistributePositiveIntOrPercent(1, maxUnavailablePool1, 2, minPool1),
							Labels:               labels,
							MachineConfiguration: machineConfiguration,
						},
						{
							Name:                 machineClassNamePool2Zone1,
							ClassName:            machineClassWithHashPool2Zone1,
							SecretName:           machineClassWithHashPool2Zone1,
							Minimum:              worker.DistributeOverZones(0, minPool2, 2),
							Maximum:              worker.DistributeOverZones(0, maxPool2, 2),
							MaxSurge:             worker.DistributePositiveIntOrPercent(0, maxSurgePool2, 2, maxPool2),
							MaxUnavailable:       worker.DistributePositiveIntOrPercent(0, maxUnavailablePool2, 2, minPool2),
							Labels:               labels,
							MachineConfiguration: machineConfiguration,
						},
						{
							Name:                 machineClassNamePool2Zone2,
							ClassName:            machineClassWithHashPool2Zone2,
							SecretName:           machineClassWithHashPool2Zone2,
							Minimum:              worker.DistributeOverZones(1, minPool2, 2),
							Maximum:              worker.DistributeOverZones(1, maxPool2, 2),
							MaxSurge:             worker.DistributePositiveIntOrPercent(1, maxSurgePool2, 2, maxPool2),
							MaxUnavailable:       worker.DistributePositiveIntOrPercent(1, maxUnavailablePool2, 2, minPool2),
							Labels:               labels,
							MachineConfiguration: machineConfiguration,
						},
					}

					machineDeploymentsWithCSILabels = worker.MachineDeployments{
						{
							Name:                 machineClassNamePool1Zone1,
							ClassName:            machineClassWithHashPool1Zone1CSI,
							SecretName:           machineClassWithHashPool1Zone1CSI,
							Minimum:              worker.DistributeOverZones(0, minPool1, 2),
							Maximum:              worker.DistributeOverZones(0, maxPool1, 2),
							MaxSurge:             worker.DistributePositiveIntOrPercent(0, maxSurgePool1, 2, maxPool1),
							MaxUnavailable:       worker.DistributePositiveIntOrPercent(0, maxUnavailablePool1, 2, minPool1),
							Labels:               utils.MergeStringMaps(labels, map[string]string{"topology.ebs.csi.aws.com/zone": zone1}),
							MachineConfiguration: machineConfiguration,
						},
						{
							Name:                 machineClassNamePool1Zone2,
							ClassName:            machineClassWithHashPool1Zone2CSI,
							SecretName:           machineClassWithHashPool1Zone2CSI,
							Minimum:              worker.DistributeOverZones(1, minPool1, 2),
							Maximum:              worker.DistributeOverZones(1, maxPool1, 2),
							MaxSurge:             worker.DistributePositiveIntOrPercent(1, maxSurgePool1, 2, maxPool1),
							MaxUnavailable:       worker.DistributePositiveIntOrPercent(1, maxUnavailablePool1, 2, minPool1),
							Labels:               utils.MergeStringMaps(labels, map[string]string{"topology.ebs.csi.aws.com/zone": zone2}),
							MachineConfiguration: machineConfiguration,
						},
						{
							Name:                 machineClassNamePool2Zone1,
							ClassName:            machineClassWithHashPool2Zone1CSI,
							SecretName:           machineClassWithHashPool2Zone1CSI,
							Minimum:              worker.DistributeOverZones(0, minPool2, 2),
							Maximum:              worker.DistributeOverZones(0, maxPool2, 2),
							MaxSurge:             worker.DistributePositiveIntOrPercent(0, maxSurgePool2, 2, maxPool2),
							MaxUnavailable:       worker.DistributePositiveIntOrPercent(0, maxUnavailablePool2, 2, minPool2),
							Labels:               utils.MergeStringMaps(labels, map[string]string{"topology.ebs.csi.aws.com/zone": zone1}),
							MachineConfiguration: machineConfiguration,
						},
						{
							Name:                 machineClassNamePool2Zone2,
							ClassName:            machineClassWithHashPool2Zone2CSI,
							SecretName:           machineClassWithHashPool2Zone2CSI,
							Minimum:              worker.DistributeOverZones(1, minPool2, 2),
							Maximum:              worker.DistributeOverZones(1, maxPool2, 2),
							MaxSurge:             worker.DistributePositiveIntOrPercent(1, maxSurgePool2, 2, maxPool2),
							MaxUnavailable:       worker.DistributePositiveIntOrPercent(1, maxUnavailablePool2, 2, minPool2),
							Labels:               utils.MergeStringMaps(labels, map[string]string{"topology.ebs.csi.aws.com/zone": zone2}),
							MachineConfiguration: machineConfiguration,
						},
					}
				})

				It("should return machine deployments with AWS CSI Label (k8s>=1.18)", func() {
					workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, clusterk8s118)
					result, err := workerDelegate.GenerateMachineDeployments(ctx)

					Expect(err).NotTo(HaveOccurred())
					Expect(result).To(Equal(machineDeploymentsWithCSILabels))
				})
				It("should return the expected machine deployments for profile image types", func() {
					workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

					// Test workerDelegate.DeployMachineClasses()

					gomock.InOrder(
						c.EXPECT().
							DeleteAllOf(context.TODO(), &machinev1alpha1.AWSMachineClass{}, client.InNamespace(namespace)),
						chartApplier.
							EXPECT().
							Apply(
								ctx,
								filepath.Join(aws.InternalChartsPath, "machineclass"),
								namespace,
								"machineclass",
								kubernetes.Values(machineClasses),
							),
					)

					err := workerDelegate.DeployMachineClasses(ctx)
					Expect(err).NotTo(HaveOccurred())

					// Test workerDelegate.UpdateMachineDeployments()
					expectedImages := &apiv1alpha1.WorkerStatus{
						TypeMeta: metav1.TypeMeta{
							APIVersion: apiv1alpha1.SchemeGroupVersion.String(),
							Kind:       "WorkerStatus",
						},
						MachineImages: []apiv1alpha1.MachineImage{
							{
								Name:    machineImageName,
								Version: machineImageVersion,
								AMI:     machineImageAMI,
							},
						},
					}

					workerWithExpectedImages := w.DeepCopy()
					workerWithExpectedImages.Status.ProviderStatus = &runtime.RawExtension{
						Object: expectedImages,
					}

					c.EXPECT().Get(ctx, gomock.Any(), gomock.AssignableToTypeOf(&extensionsv1alpha1.Worker{})).Return(nil)
					c.EXPECT().Status().Return(statusWriter)
					statusWriter.EXPECT().Update(ctx, workerWithExpectedImages).Return(nil)

					err = workerDelegate.UpdateMachineImagesStatus(ctx)
					Expect(err).NotTo(HaveOccurred())

					// Test workerDelegate.GenerateMachineDeployments()

					result, err := workerDelegate.GenerateMachineDeployments(ctx)
					Expect(err).NotTo(HaveOccurred())
					Expect(result).To(Equal(machineDeployments))
				})

				It("should delete the all old AWSMachineClasses", func() {
					workerDelegate, _ := NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)
					gomock.InOrder(
						c.EXPECT().
							DeleteAllOf(context.TODO(), &machinev1alpha1.AWSMachineClass{}, client.InNamespace(namespace)),
						chartApplier.
							EXPECT().
							Apply(
								ctx,
								filepath.Join(aws.InternalChartsPath, "machineclass"),
								namespace,
								"machineclass",
								kubernetes.Values(machineClasses),
							),
					)

					err := workerDelegate.DeployMachineClasses(context.TODO())
					Expect(err).NotTo(HaveOccurred())
				})

				Context("using workerConfig.iamInstanceProfile", func() {
					modifyExpectedMachineClasses := func(expectedIamInstanceProfile map[string]interface{}) {
						newHash, err := worker.WorkerPoolHash(w.Spec.Pools[1], cluster)
						Expect(err).NotTo(HaveOccurred())

						var (
							machineClassNamePool2Zone1     = fmt.Sprintf("%s-%s-z1", namespace, namePool2)
							machineClassNamePool2Zone2     = fmt.Sprintf("%s-%s-z2", namespace, namePool2)
							machineClassWithHashPool2Zone1 = fmt.Sprintf("%s-%s", machineClassNamePool2Zone1, newHash)
							machineClassWithHashPool2Zone2 = fmt.Sprintf("%s-%s", machineClassNamePool2Zone2, newHash)
						)

						machineClasses["machineClasses"].([]map[string]interface{})[2]["name"] = machineClassWithHashPool2Zone1
						machineClasses["machineClasses"].([]map[string]interface{})[2]["iamInstanceProfile"] = expectedIamInstanceProfile
						machineClasses["machineClasses"].([]map[string]interface{})[3]["name"] = machineClassWithHashPool2Zone2
						machineClasses["machineClasses"].([]map[string]interface{})[3]["iamInstanceProfile"] = expectedIamInstanceProfile
					}

					It("should deploy the correct machine class when using iamInstanceProfile.Name", func() {
						iamInstanceProfileName := "foo"
						w.Spec.Pools[1].ProviderConfig = &runtime.RawExtension{Raw: encode(&api.WorkerConfig{
							IAMInstanceProfile: &api.IAMInstanceProfile{
								Name: &iamInstanceProfileName,
							},
						})}
						modifyExpectedMachineClasses(map[string]interface{}{"name": iamInstanceProfileName})

						workerDelegate, _ := NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

						gomock.InOrder(
							c.EXPECT().
								DeleteAllOf(context.TODO(), &machinev1alpha1.AWSMachineClass{}, client.InNamespace(namespace)),
							chartApplier.
								EXPECT().
								Apply(
									ctx,
									filepath.Join(aws.InternalChartsPath, "machineclass"),
									namespace,
									"machineclass",
									kubernetes.Values(machineClasses),
								),
						)

						Expect(workerDelegate.DeployMachineClasses(context.TODO())).NotTo(HaveOccurred())
					})

					It("should deploy the correct machine class when using iamInstanceProfile.ARN", func() {
						iamInstanceProfileARN := "foo"
						w.Spec.Pools[1].ProviderConfig = &runtime.RawExtension{Raw: encode(&api.WorkerConfig{
							IAMInstanceProfile: &api.IAMInstanceProfile{
								ARN: &iamInstanceProfileARN,
							},
						})}
						modifyExpectedMachineClasses(map[string]interface{}{"arn": iamInstanceProfileARN})

						workerDelegate, _ := NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

						gomock.InOrder(
							c.EXPECT().
								DeleteAllOf(context.TODO(), &machinev1alpha1.AWSMachineClass{}, client.InNamespace(namespace)),
							chartApplier.
								EXPECT().
								Apply(
									ctx,
									filepath.Join(aws.InternalChartsPath, "machineclass"),
									namespace,
									"machineclass",
									kubernetes.Values(machineClasses),
								),
						)

						Expect(workerDelegate.DeployMachineClasses(context.TODO())).NotTo(HaveOccurred())
					})
				})

				It("should return err when the infrastructure provider status cannot be decoded", func() {
					// Deliberately setting InfrastructureProviderStatus to empty
					w.Spec.InfrastructureProviderStatus = &runtime.RawExtension{}
					workerDelegate, _ := NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

					err := workerDelegate.DeployMachineClasses(context.TODO())
					Expect(err).To(HaveOccurred())
				})

				It("should not delete the any of old AWSMachineClasses as DeleteAll call returns error", func() {
					workerDelegate, _ := NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

					c.EXPECT().
						DeleteAllOf(context.TODO(), &machinev1alpha1.AWSMachineClass{}, client.InNamespace(namespace)).
						Return(fmt.Errorf("fake error"))

					err := workerDelegate.DeployMachineClasses(context.TODO())
					Expect(err).To(HaveOccurred())
				})
			})

			It("should fail because the version is invalid", func() {
				clusterWithoutImages.Shoot.Spec.Kubernetes.Version = "invalid"
				workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the infrastructure status cannot be decoded", func() {
				w.Spec.InfrastructureProviderStatus = &runtime.RawExtension{}

				workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the nodes instance profile cannot be found", func() {
				w.Spec.InfrastructureProviderStatus = &runtime.RawExtension{
					Raw: encode(&api.InfrastructureStatus{}),
				}

				workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the security group cannot be found", func() {
				w.Spec.InfrastructureProviderStatus = &runtime.RawExtension{
					Raw: encode(&api.InfrastructureStatus{
						IAM: api.IAM{
							InstanceProfiles: []api.InstanceProfile{
								{
									Name:    instanceProfileName,
									Purpose: "nodes",
								},
							},
						},
					}),
				}

				workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the ami for this region cannot be found", func() {
				w.Spec.Region = "another-region"

				workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the subnet id cannot be found", func() {
				w.Spec.InfrastructureProviderStatus = &runtime.RawExtension{
					Raw: encode(&api.InfrastructureStatus{
						VPC: api.VPCStatus{
							Subnets: []api.Subnet{},
							SecurityGroups: []api.SecurityGroup{
								{
									ID:      securityGroupID,
									Purpose: "nodes",
								},
							},
						},
						IAM: api.IAM{
							InstanceProfiles: []api.InstanceProfile{
								{
									Name:    instanceProfileName,
									Purpose: "nodes",
								},
							},
						},
					}),
				}

				workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the volume size cannot be decoded", func() {
				w.Spec.Pools[0].Volume.Size = "not-decodeable"

				workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should set expected machineControllerManager settings on machine deployment", func() {
				testDrainTimeout := metav1.Duration{Duration: 10 * time.Minute}
				testHealthTimeout := metav1.Duration{Duration: 20 * time.Minute}
				testCreationTimeout := metav1.Duration{Duration: 30 * time.Minute}
				testMaxEvictRetries := int32(30)
				testNodeConditions := []string{"ReadonlyFilesystem", "KernelDeadlock", "DiskPressure"}
				w.Spec.Pools[0].MachineControllerManagerSettings = &gardencorev1beta1.MachineControllerManagerSettings{
					MachineDrainTimeout:    &testDrainTimeout,
					MachineCreationTimeout: &testCreationTimeout,
					MachineHealthTimeout:   &testHealthTimeout,
					MaxEvictRetries:        &testMaxEvictRetries,
					NodeConditions:         testNodeConditions,
				}

				workerDelegate, _ = NewWorkerDelegate(common.NewClientContext(c, scheme, decoder), chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				resultSettings := result[0].MachineConfiguration
				resultNodeConditions := strings.Join(testNodeConditions, ",")

				Expect(err).NotTo(HaveOccurred())
				Expect(resultSettings.MachineDrainTimeout).To(Equal(&testDrainTimeout))
				Expect(resultSettings.MachineCreationTimeout).To(Equal(&testCreationTimeout))
				Expect(resultSettings.MachineHealthTimeout).To(Equal(&testHealthTimeout))
				Expect(resultSettings.MaxEvictRetries).To(Equal(&testMaxEvictRetries))
				Expect(resultSettings.NodeConditions).To(Equal(&resultNodeConditions))
			})
		})
	})
})

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}

func addKeyValueToMap(class map[string]interface{}, key string, value interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(class)+1)

	for k, v := range class {
		out[k] = v
	}

	out[key] = value
	return out
}

func addNameAndSecretToMachineClass(class map[string]interface{}, name string, credentialsSecretRef corev1.SecretReference) {
	class["name"] = name
	class["credentialsSecretRef"] = map[string]interface{}{
		"name":      credentialsSecretRef.Name,
		"namespace": credentialsSecretRef.Namespace,
	}
	class["secret"].(map[string]interface{})["labels"] = map[string]string{v1beta1constants.GardenerPurpose: genericworkeractuator.GardenPurposeMachineClass}
}
