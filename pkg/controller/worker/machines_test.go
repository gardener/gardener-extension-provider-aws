// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package worker_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/worker"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/gardener/gardener/pkg/client/kubernetes"
	mockkubernetes "github.com/gardener/gardener/pkg/client/kubernetes/mock"
	"github.com/gardener/gardener/pkg/utils"
	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	machinev1alpha1 "github.com/gardener/machine-controller-manager/pkg/apis/machine/v1alpha1"
	"github.com/google/go-cmp/cmp"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/charts"
	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apiv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/worker"
)

var ctx = context.TODO()

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

	Context("WorkerDelegate", func() {
		workerDelegate, _ := NewWorkerDelegate(nil, nil, nil, nil, "", nil, nil)

		DescribeTableSubtree("#GenerateMachineDeployments, #DeployMachineClasses", func(isCapabilitiesCloudProfile bool) {
			var (
				namespace        string
				cloudProfileName string
				region           string

				machineImageName    string
				machineImageVersion string
				machineImageAMI     string

				vpcID                       string
				machineType, machineTypeArm string
				userData                    []byte
				userDataSecretName          string
				userDataSecretDataKey       string
				instanceProfileName         string
				securityGroupID             string
				keyName                     string

				archAMD  string
				archARM  string
				archFAKE string

				volumeType       string
				volumeSize       int
				volumeEncrypted  bool
				volumeIOPS       int64
				volumeThroughput int64

				dataVolume1Name       string
				dataVolume1Type       string
				dataVolume1Size       int
				dataVolume1IOPS       int64
				dataVolume1Throughput int64
				dataVolume1Encrypted  bool

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
				priorityPool2       int32
				maxSurgePool2       intstr.IntOrString
				maxUnavailablePool2 intstr.IntOrString

				namePool3 string

				subnetZone1 string
				subnetZone2 string
				zone1       string
				zone2       string

				labels map[string]string

				nodeCapacity           corev1.ResourceList
				nodeTemplatePool1Zone1 machinev1alpha1.NodeTemplate
				nodeTemplatePool2Zone1 machinev1alpha1.NodeTemplate
				nodeTemplatePool3Zone1 machinev1alpha1.NodeTemplate
				nodeTemplatePool1Zone2 machinev1alpha1.NodeTemplate
				nodeTemplatePool2Zone2 machinev1alpha1.NodeTemplate
				nodeTemplatePool3Zone2 machinev1alpha1.NodeTemplate

				machineConfiguration *machinev1alpha1.MachineConfiguration

				workerPoolHash1 string
				workerPoolHash2 string
				workerPoolHash3 string

				shootVersionMajorMinor           string
				shootVersion                     string
				scheme                           *runtime.Scheme
				decoder                          runtime.Decoder
				clusterWithoutImages             *extensionscontroller.Cluster
				cluster                          *extensionscontroller.Cluster
				infrastructureProviderStatus     *api.InfrastructureStatus
				w                                *extensionsv1alpha1.Worker
				capabilitiesAmd, capabilitiesArm gardencorev1beta1.Capabilities
				capabilityDefinitions            []gardencorev1beta1.CapabilityDefinition
			)

			BeforeEach(func() {
				if isCapabilitiesCloudProfile {
					capabilityDefinitions = []gardencorev1beta1.CapabilityDefinition{
						{Name: "some-capability", Values: []string{"a", "b", "c"}},
						{Name: v1beta1constants.ArchitectureName, Values: []string{"amd64", "arm64"}},
					}
					capabilitiesAmd = gardencorev1beta1.Capabilities{
						v1beta1constants.ArchitectureName: []string{"amd64"},
					}
					capabilitiesArm = gardencorev1beta1.Capabilities{
						v1beta1constants.ArchitectureName: []string{"arm64"},
					}
				}
				namespace = "shoot--foobar--aws"
				cloudProfileName = "aws"

				region = "eu-west-1"

				machineImageName = "my-os"
				machineImageVersion = "123.4.5-pre+build123"
				machineImageAMI = "ami-123456"

				vpcID = "vpc-1234"
				machineType = "large"
				machineTypeArm = "large-arm"
				userData = []byte("some-user-data")
				userDataSecretName = "userdata-secret-name"
				userDataSecretDataKey = "userdata-secret-key"
				instanceProfileName = "nodes-instance-prof"
				securityGroupID = "sg-12345"
				keyName = "my-ssh-key"

				archAMD = "amd64"
				archARM = "arm64"
				archFAKE = "fake"

				volumeType = "normal"
				volumeSize = 20
				volumeEncrypted = true
				volumeIOPS = 400
				volumeThroughput = 200

				dataVolume1Name = "vol-1"
				dataVolume1Type = "foo"
				dataVolume1Size = 42
				dataVolume1IOPS = 567
				dataVolume1Throughput = 300
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
				priorityPool2 = 100
				maxSurgePool2 = intstr.FromInt(10)
				maxUnavailablePool2 = intstr.FromInt(15)

				namePool3 = "pool-3"

				subnetZone1 = "subnet-acbd1234"
				subnetZone2 = "subnet-4321dbca"
				zone1 = region + "a"
				zone2 = region + "b"

				labels = map[string]string{"component": "TiDB"}

				nodeCapacity = corev1.ResourceList{
					"cpu":    resource.MustParse("8"),
					"gpu":    resource.MustParse("1"),
					"memory": resource.MustParse("128Gi"),
				}
				nodeTemplatePool1Zone1 = machinev1alpha1.NodeTemplate{
					Capacity:     nodeCapacity,
					InstanceType: machineType,
					Region:       region,
					Zone:         zone1,
					Architecture: &archAMD,
				}
				nodeTemplatePool1Zone2 = machinev1alpha1.NodeTemplate{
					Capacity:     nodeCapacity,
					InstanceType: machineType,
					Region:       region,
					Zone:         zone2,
					Architecture: &archAMD,
				}

				nodeTemplatePool2Zone1 = machinev1alpha1.NodeTemplate{
					Capacity:     nodeCapacity,
					InstanceType: machineTypeArm,
					Region:       region,
					Zone:         zone1,
					Architecture: &archARM,
				}
				nodeTemplatePool2Zone2 = machinev1alpha1.NodeTemplate{
					Capacity:     nodeCapacity,
					InstanceType: machineTypeArm,
					Region:       region,
					Zone:         zone2,
					Architecture: &archARM,
				}

				nodeTemplatePool3Zone1 = machinev1alpha1.NodeTemplate{
					Capacity:     nodeCapacity,
					InstanceType: machineTypeArm,
					Region:       region,
					Zone:         zone1,
					Architecture: &archARM,
				}
				nodeTemplatePool3Zone2 = machinev1alpha1.NodeTemplate{
					Capacity:     nodeCapacity,
					InstanceType: machineTypeArm,
					Region:       region,
					Zone:         zone2,
					Architecture: &archARM,
				}

				machineConfiguration = &machinev1alpha1.MachineConfiguration{}

				shootVersionMajorMinor = "1.29"
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

				machineImages := []apiv1alpha1.MachineImages{
					{
						Name: machineImageName,
						Versions: []apiv1alpha1.MachineImageVersion{
							{
								Version: machineImageVersion,
								CapabilityFlavors: []apiv1alpha1.MachineImageFlavor{
									{
										Capabilities: capabilitiesAmd,
										Regions: []apiv1alpha1.RegionAMIMapping{
											{
												Name: region,
												AMI:  machineImageAMI,
											},
										},
									},
									{
										Capabilities: capabilitiesArm,
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
					},
				}

				if !isCapabilitiesCloudProfile {
					machineImages = []apiv1alpha1.MachineImages{
						{
							Name: machineImageName,
							Versions: []apiv1alpha1.MachineImageVersion{
								{
									Version: machineImageVersion,
									Regions: []apiv1alpha1.RegionAMIMapping{
										{
											Name:         region,
											AMI:          machineImageAMI,
											Architecture: ptr.To(archAMD),
										},
									},
								},
							},
						}, {
							Name: machineImageName,
							Versions: []apiv1alpha1.MachineImageVersion{
								{
									Version: machineImageVersion,
									Regions: []apiv1alpha1.RegionAMIMapping{
										{
											Name:         region,
											AMI:          machineImageAMI,
											Architecture: ptr.To(archARM),
										},
									},
								},
							},
						},
					}
				}

				cloudProfileConfig := &apiv1alpha1.CloudProfileConfig{
					TypeMeta: metav1.TypeMeta{
						APIVersion: apiv1alpha1.SchemeGroupVersion.String(),
						Kind:       "CloudProfileConfig",
					},
					MachineImages: machineImages,
				}
				cloudProfileConfigJSON, _ := json.Marshal(cloudProfileConfig)
				cluster = &extensionscontroller.Cluster{
					CloudProfile: &gardencorev1beta1.CloudProfile{
						ObjectMeta: metav1.ObjectMeta{
							Name: cloudProfileName,
						},
						Spec: gardencorev1beta1.CloudProfileSpec{
							MachineCapabilities: capabilityDefinitions,
							MachineTypes: []gardencorev1beta1.MachineType{
								{
									Name:         machineType,
									Capabilities: capabilitiesAmd,
								},
								{
									Name:         machineTypeArm,
									Architecture: ptr.To(archARM),
									Capabilities: capabilitiesArm,
								},
							},
							ProviderConfig: &runtime.RawExtension{
								Raw: cloudProfileConfigJSON,
							},
						},
					},
					Shoot: clusterWithoutImages.Shoot,
				}

				infrastructureProviderStatus = &api.InfrastructureStatus{
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
							Raw: encode(infrastructureProviderStatus),
						},
						Pools: []extensionsv1alpha1.WorkerPool{
							{
								Name:           namePool1,
								Minimum:        minPool1,
								Maximum:        maxPool1,
								MaxSurge:       maxSurgePool1,
								MaxUnavailable: maxUnavailablePool1,
								MachineType:    machineType,
								Architecture:   ptr.To(archAMD),
								NodeTemplate: &extensionsv1alpha1.NodeTemplate{
									Capacity: nodeCapacity,
								},
								MachineImage: extensionsv1alpha1.MachineImage{
									Name:    machineImageName,
									Version: machineImageVersion,
								},
								KubernetesVersion: ptr.To("1.32.0"),
								ProviderConfig: &runtime.RawExtension{
									Raw: encode(&api.WorkerConfig{
										Volume: &api.Volume{
											IOPS:       &volumeIOPS,
											Throughput: &volumeThroughput,
										},
										DataVolumes: []api.DataVolume{
											{
												Name: dataVolume1Name,
												Volume: api.Volume{
													IOPS:       &dataVolume1IOPS,
													Throughput: &dataVolume1Throughput,
												},
											},
											{
												Name:       dataVolume2Name,
												SnapshotID: &dataVolume2SnapshotID,
											},
										},
									}),
								},
								UserDataSecretRef: corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: userDataSecretName},
									Key:                  userDataSecretDataKey,
								},
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
								Architecture:   ptr.To(archARM),
								Maximum:        maxPool2,
								Priority:       priorityPool2,
								MaxSurge:       maxSurgePool2,
								MaxUnavailable: maxUnavailablePool2,
								MachineType:    machineTypeArm,
								NodeTemplate: &extensionsv1alpha1.NodeTemplate{
									Capacity: nodeCapacity,
								},
								MachineImage: extensionsv1alpha1.MachineImage{
									Name:    machineImageName,
									Version: machineImageVersion,
								},
								KubernetesVersion: ptr.To("1.32.0"),
								UserDataSecretRef: corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: userDataSecretName},
									Key:                  userDataSecretDataKey,
								},
								Volume: &extensionsv1alpha1.Volume{
									Type: &volumeType,
									Size: fmt.Sprintf("%dGi", volumeSize),
								},
								Zones: []string{
									zone1,
									zone2,
								},
								Labels:         labels,
								UpdateStrategy: ptr.To(gardencorev1beta1.AutoInPlaceUpdate),
							},
							{
								Name:           namePool3,
								Minimum:        minPool2,
								Architecture:   ptr.To(archARM),
								Maximum:        maxPool2,
								Priority:       priorityPool2,
								MaxSurge:       maxSurgePool2,
								MaxUnavailable: maxUnavailablePool2,
								MachineType:    machineTypeArm,
								NodeTemplate: &extensionsv1alpha1.NodeTemplate{
									Capacity: nodeCapacity,
								},
								MachineImage: extensionsv1alpha1.MachineImage{
									Name:    machineImageName,
									Version: machineImageVersion,
								},
								KubernetesVersion: ptr.To("1.32.0"),
								UserDataSecretRef: corev1.SecretKeySelector{
									LocalObjectReference: corev1.LocalObjectReference{Name: userDataSecretName},
									Key:                  userDataSecretDataKey,
								},
								Volume: &extensionsv1alpha1.Volume{
									Type: &volumeType,
									Size: fmt.Sprintf("%dGi", volumeSize),
								},
								Zones: []string{
									zone1,
									zone2,
								},
								Labels:         labels,
								UpdateStrategy: ptr.To(gardencorev1beta1.ManualInPlaceUpdate),
							},
						},
					},
				}

				scheme = runtime.NewScheme()
				_ = api.AddToScheme(scheme)
				_ = apiv1alpha1.AddToScheme(scheme)
				decoder = serializer.NewCodecFactory(scheme, serializer.EnableStrict).UniversalDecoder()

				additionalData := []string{strconv.FormatBool(volumeEncrypted), fmt.Sprintf("%dGi", dataVolume1Size), dataVolume1Type, strconv.FormatBool(dataVolume1Encrypted), fmt.Sprintf("%dGi", dataVolume2Size), dataVolume2Type, strconv.FormatBool(dataVolume2Encrypted)}
				workerPoolHash1, _ = worker.WorkerPoolHash(w.Spec.Pools[0], cluster, additionalData, additionalData, nil)
				workerPoolHash2, _ = worker.WorkerPoolHash(w.Spec.Pools[1], cluster, nil, nil, nil)
				workerPoolHash3, _ = worker.WorkerPoolHash(w.Spec.Pools[2], cluster, nil, nil, nil)

				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, clusterWithoutImages)
			})

			expectedUserDataSecretRefRead := func() {
				c.EXPECT().Get(ctx, client.ObjectKey{Namespace: namespace, Name: userDataSecretName}, gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
					func(_ context.Context, _ client.ObjectKey, secret *corev1.Secret, _ ...client.GetOption) error {
						secret.Data = map[string][]byte{userDataSecretDataKey: userData}
						return nil
					},
				).AnyTimes()
			}

			Describe("machine images", func() {
				var (
					defaultMachineClass map[string]interface{}
					machineDeployments  worker.MachineDeployments
					machineClasses      map[string]interface{}
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
						"ami":    machineImageAMI,
						"region": region,
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
						"instanceMetadataOptions": map[string]interface{}{},
						"operatingSystem": map[string]interface{}{
							"operatingSystemName":    machineImageName,
							"operatingSystemVersion": strings.ReplaceAll(machineImageVersion, "+", "_"),
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
						machineClassPool3Zone1 = addKeyValueToMap(defaultMachineClass, "networkInterfaces", []map[string]interface{}{
							{
								"subnetID":         subnetZone1,
								"securityGroupIDs": []string{securityGroupID},
							},
						})
						machineClassPool3Zone2 = addKeyValueToMap(defaultMachineClass, "networkInterfaces", []map[string]interface{}{
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
									"throughput":          volumeThroughput,
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
									"throughput":          dataVolume1Throughput,
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
					machineClassPool1Zone1 = addKeyValueToMap(machineClassPool1Zone1, "machineType", machineType)

					machineClassPool1Zone2 = addKeyValueToMap(machineClassPool1Zone2, "labels", map[string]string{corev1.LabelZoneFailureDomain: zone2})
					machineClassPool1Zone2 = addKeyValueToMap(machineClassPool1Zone2, "machineType", machineType)

					machineClassPool2Zone1 = addKeyValueToMap(machineClassPool2Zone1, "labels", map[string]string{corev1.LabelZoneFailureDomain: zone1})
					machineClassPool2Zone1 = addKeyValueToMap(machineClassPool2Zone1, "machineType", machineTypeArm)

					machineClassPool2Zone2 = addKeyValueToMap(machineClassPool2Zone2, "labels", map[string]string{corev1.LabelZoneFailureDomain: zone2})
					machineClassPool2Zone2 = addKeyValueToMap(machineClassPool2Zone2, "machineType", machineTypeArm)

					machineClassPool3Zone1 = addKeyValueToMap(machineClassPool3Zone1, "labels", map[string]string{corev1.LabelZoneFailureDomain: zone1})
					machineClassPool3Zone1 = addKeyValueToMap(machineClassPool3Zone1, "machineType", machineTypeArm)

					machineClassPool3Zone2 = addKeyValueToMap(machineClassPool3Zone2, "labels", map[string]string{corev1.LabelZoneFailureDomain: zone2})
					machineClassPool3Zone2 = addKeyValueToMap(machineClassPool3Zone2, "machineType", machineTypeArm)

					var (
						machineClassNamePool1Zone1 = fmt.Sprintf("%s-%s-z1", namespace, namePool1)
						machineClassNamePool1Zone2 = fmt.Sprintf("%s-%s-z2", namespace, namePool1)
						machineClassNamePool2Zone1 = fmt.Sprintf("%s-%s-z1", namespace, namePool2)
						machineClassNamePool2Zone2 = fmt.Sprintf("%s-%s-z2", namespace, namePool2)
						machineClassNamePool3Zone1 = fmt.Sprintf("%s-%s-z1", namespace, namePool3)
						machineClassNamePool3Zone2 = fmt.Sprintf("%s-%s-z2", namespace, namePool3)

						machineClassWithHashPool1Zone1 = fmt.Sprintf("%s-%s", machineClassNamePool1Zone1, workerPoolHash1)
						machineClassWithHashPool1Zone2 = fmt.Sprintf("%s-%s", machineClassNamePool1Zone2, workerPoolHash1)
						machineClassWithHashPool2Zone1 = fmt.Sprintf("%s-%s", machineClassNamePool2Zone1, workerPoolHash2)
						machineClassWithHashPool2Zone2 = fmt.Sprintf("%s-%s", machineClassNamePool2Zone2, workerPoolHash2)
						machineClassWithHashPool3Zone1 = fmt.Sprintf("%s-%s", machineClassNamePool3Zone1, workerPoolHash3)
						machineClassWithHashPool3Zone2 = fmt.Sprintf("%s-%s", machineClassNamePool3Zone2, workerPoolHash3)
					)

					addNameAndSecretToMachineClass(machineClassPool1Zone1, machineClassWithHashPool1Zone1, w.Spec.SecretRef)
					addNameAndSecretToMachineClass(machineClassPool1Zone2, machineClassWithHashPool1Zone2, w.Spec.SecretRef)
					addNameAndSecretToMachineClass(machineClassPool2Zone1, machineClassWithHashPool2Zone1, w.Spec.SecretRef)
					addNameAndSecretToMachineClass(machineClassPool2Zone2, machineClassWithHashPool2Zone2, w.Spec.SecretRef)
					addNameAndSecretToMachineClass(machineClassPool3Zone1, machineClassWithHashPool3Zone1, w.Spec.SecretRef)
					addNameAndSecretToMachineClass(machineClassPool3Zone2, machineClassWithHashPool3Zone2, w.Spec.SecretRef)

					addNodeTemplateToMachineClass(machineClassPool1Zone1, nodeTemplatePool1Zone1)
					addNodeTemplateToMachineClass(machineClassPool1Zone2, nodeTemplatePool1Zone2)
					addNodeTemplateToMachineClass(machineClassPool2Zone1, nodeTemplatePool2Zone1)
					addNodeTemplateToMachineClass(machineClassPool2Zone2, nodeTemplatePool2Zone2)
					addNodeTemplateToMachineClass(machineClassPool3Zone1, nodeTemplatePool3Zone1)
					addNodeTemplateToMachineClass(machineClassPool3Zone2, nodeTemplatePool3Zone2)

					machineClasses = map[string]interface{}{"machineClasses": []map[string]interface{}{
						machineClassPool1Zone1,
						machineClassPool1Zone2,
						machineClassPool2Zone1,
						machineClassPool2Zone2,
						machineClassPool3Zone1,
						machineClassPool3Zone2,
					}}

					emptyClusterAutoscalerAnnotations := map[string]string{
						"autoscaler.gardener.cloud/max-node-provision-time":              "",
						"autoscaler.gardener.cloud/scale-down-gpu-utilization-threshold": "",
						"autoscaler.gardener.cloud/scale-down-unneeded-time":             "",
						"autoscaler.gardener.cloud/scale-down-unready-time":              "",
						"autoscaler.gardener.cloud/scale-down-utilization-threshold":     "",
					}

					machineDeployments = worker.MachineDeployments{
						{
							Name:       machineClassNamePool1Zone1,
							ClassName:  machineClassWithHashPool1Zone1,
							SecretName: machineClassWithHashPool1Zone1,
							Minimum:    worker.DistributeOverZones(0, minPool1, 2),
							Maximum:    worker.DistributeOverZones(0, maxPool1, 2),
							PoolName:   namePool1,
							Strategy: machinev1alpha1.MachineDeploymentStrategy{
								Type: machinev1alpha1.RollingUpdateMachineDeploymentStrategyType,
								RollingUpdate: &machinev1alpha1.RollingUpdateMachineDeployment{
									UpdateConfiguration: machinev1alpha1.UpdateConfiguration{
										MaxUnavailable: ptr.To(worker.DistributePositiveIntOrPercent(0, maxUnavailablePool1, 2, minPool1)),
										MaxSurge:       ptr.To(worker.DistributePositiveIntOrPercent(0, maxSurgePool1, 2, maxPool1)),
									},
								},
							},
							Labels: utils.MergeStringMaps(labels, map[string]string{
								CSIDriverTopologyKey:     zone1,
								corev1.LabelTopologyZone: zone1,
							}),
							MachineConfiguration:         machineConfiguration,
							ClusterAutoscalerAnnotations: emptyClusterAutoscalerAnnotations,
						},
						{
							Name:       machineClassNamePool1Zone2,
							ClassName:  machineClassWithHashPool1Zone2,
							SecretName: machineClassWithHashPool1Zone2,
							Minimum:    worker.DistributeOverZones(1, minPool1, 2),
							Maximum:    worker.DistributeOverZones(1, maxPool1, 2),
							PoolName:   namePool1,
							Strategy: machinev1alpha1.MachineDeploymentStrategy{
								Type: machinev1alpha1.RollingUpdateMachineDeploymentStrategyType,
								RollingUpdate: &machinev1alpha1.RollingUpdateMachineDeployment{
									UpdateConfiguration: machinev1alpha1.UpdateConfiguration{
										MaxUnavailable: ptr.To(worker.DistributePositiveIntOrPercent(1, maxUnavailablePool1, 2, minPool1)),
										MaxSurge:       ptr.To(worker.DistributePositiveIntOrPercent(1, maxSurgePool1, 2, maxPool1)),
									},
								},
							},
							Labels: utils.MergeStringMaps(labels, map[string]string{
								CSIDriverTopologyKey:     zone2,
								corev1.LabelTopologyZone: zone2,
							}),
							MachineConfiguration:         machineConfiguration,
							ClusterAutoscalerAnnotations: emptyClusterAutoscalerAnnotations,
						},
						{
							Name:       machineClassNamePool2Zone1,
							ClassName:  machineClassWithHashPool2Zone1,
							SecretName: machineClassWithHashPool2Zone1,
							Minimum:    worker.DistributeOverZones(0, minPool2, 2),
							Maximum:    worker.DistributeOverZones(0, maxPool2, 2),
							Priority:   priorityPool2,
							PoolName:   namePool2,
							Strategy: machinev1alpha1.MachineDeploymentStrategy{
								Type: machinev1alpha1.InPlaceUpdateMachineDeploymentStrategyType,
								InPlaceUpdate: &machinev1alpha1.InPlaceUpdateMachineDeployment{
									OrchestrationType: machinev1alpha1.OrchestrationTypeAuto,
									UpdateConfiguration: machinev1alpha1.UpdateConfiguration{
										MaxUnavailable: ptr.To(worker.DistributePositiveIntOrPercent(0, maxUnavailablePool2, 2, minPool2)),
										MaxSurge:       ptr.To(worker.DistributePositiveIntOrPercent(0, maxSurgePool2, 2, maxPool2)),
									},
								},
							},
							Labels: utils.MergeStringMaps(labels, map[string]string{
								CSIDriverTopologyKey:     zone1,
								corev1.LabelTopologyZone: zone1,
							}),
							MachineConfiguration:         machineConfiguration,
							ClusterAutoscalerAnnotations: emptyClusterAutoscalerAnnotations,
						},
						{
							Name:       machineClassNamePool2Zone2,
							ClassName:  machineClassWithHashPool2Zone2,
							SecretName: machineClassWithHashPool2Zone2,
							Minimum:    worker.DistributeOverZones(1, minPool2, 2),
							Maximum:    worker.DistributeOverZones(1, maxPool2, 2),
							Priority:   priorityPool2,
							PoolName:   namePool2,
							Strategy: machinev1alpha1.MachineDeploymentStrategy{
								Type: machinev1alpha1.InPlaceUpdateMachineDeploymentStrategyType,
								InPlaceUpdate: &machinev1alpha1.InPlaceUpdateMachineDeployment{
									OrchestrationType: machinev1alpha1.OrchestrationTypeAuto,
									UpdateConfiguration: machinev1alpha1.UpdateConfiguration{
										MaxUnavailable: ptr.To(worker.DistributePositiveIntOrPercent(1, maxUnavailablePool2, 2, minPool2)),
										MaxSurge:       ptr.To(worker.DistributePositiveIntOrPercent(1, maxSurgePool2, 2, maxPool2)),
									},
								},
							},
							Labels: utils.MergeStringMaps(labels, map[string]string{
								CSIDriverTopologyKey:     zone2,
								corev1.LabelTopologyZone: zone2,
							}),
							MachineConfiguration:         machineConfiguration,
							ClusterAutoscalerAnnotations: emptyClusterAutoscalerAnnotations,
						},
						{
							Name:       machineClassNamePool3Zone1,
							ClassName:  machineClassWithHashPool3Zone1,
							SecretName: machineClassWithHashPool3Zone1,
							Minimum:    worker.DistributeOverZones(0, minPool2, 2),
							Maximum:    worker.DistributeOverZones(0, maxPool2, 2),
							Priority:   priorityPool2,
							PoolName:   namePool3,
							Strategy: machinev1alpha1.MachineDeploymentStrategy{
								Type: machinev1alpha1.InPlaceUpdateMachineDeploymentStrategyType,
								InPlaceUpdate: &machinev1alpha1.InPlaceUpdateMachineDeployment{
									OrchestrationType: machinev1alpha1.OrchestrationTypeManual,
									UpdateConfiguration: machinev1alpha1.UpdateConfiguration{
										MaxUnavailable: ptr.To(worker.DistributePositiveIntOrPercent(0, maxUnavailablePool2, 2, minPool2)),
										MaxSurge:       ptr.To(worker.DistributePositiveIntOrPercent(0, maxSurgePool2, 2, maxPool2)),
									},
								},
							},
							Labels: utils.MergeStringMaps(labels, map[string]string{
								CSIDriverTopologyKey:     zone1,
								corev1.LabelTopologyZone: zone1,
							}),
							MachineConfiguration:         machineConfiguration,
							ClusterAutoscalerAnnotations: emptyClusterAutoscalerAnnotations,
						},
						{
							Name:       machineClassNamePool3Zone2,
							ClassName:  machineClassWithHashPool3Zone2,
							SecretName: machineClassWithHashPool3Zone2,
							Minimum:    worker.DistributeOverZones(1, minPool2, 2),
							Maximum:    worker.DistributeOverZones(1, maxPool2, 2),
							Priority:   priorityPool2,
							PoolName:   namePool3,
							Strategy: machinev1alpha1.MachineDeploymentStrategy{
								Type: machinev1alpha1.InPlaceUpdateMachineDeploymentStrategyType,
								InPlaceUpdate: &machinev1alpha1.InPlaceUpdateMachineDeployment{
									OrchestrationType: machinev1alpha1.OrchestrationTypeManual,
									UpdateConfiguration: machinev1alpha1.UpdateConfiguration{
										MaxUnavailable: ptr.To(worker.DistributePositiveIntOrPercent(1, maxUnavailablePool2, 2, minPool2)),
										MaxSurge:       ptr.To(worker.DistributePositiveIntOrPercent(1, maxSurgePool2, 2, maxPool2)),
									},
								},
							},
							Labels: utils.MergeStringMaps(labels, map[string]string{
								CSIDriverTopologyKey:     zone2,
								corev1.LabelTopologyZone: zone2,
							}),
							MachineConfiguration:         machineConfiguration,
							ClusterAutoscalerAnnotations: emptyClusterAutoscalerAnnotations,
						},
					}
				})

				It("should return machine deployments with AWS CSI Label", func() {
					workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

					expectedUserDataSecretRefRead()

					result, err := workerDelegate.GenerateMachineDeployments(ctx)

					Expect(err).NotTo(HaveOccurred())
					Expect(result).To(Equal(machineDeployments), "diff: %s", cmp.Diff(machineDeployments, result))
				})

				It("should return the expected machine deployments for profile image types", func() {
					workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

					expectedUserDataSecretRefRead()

					// Test WorkerDelegate.DeployMachineClasses()
					chartApplier.EXPECT().ApplyFromEmbeddedFS(
						ctx,
						charts.InternalChart,
						filepath.Join("internal", "machineclass"),
						namespace,
						"machineclass",
						kubernetes.Values(machineClasses),
					)

					err := workerDelegate.DeployMachineClasses(ctx)
					Expect(err).NotTo(HaveOccurred())

					machineImages := []apiv1alpha1.MachineImage{
						{
							Name:         machineImageName,
							Version:      machineImageVersion,
							AMI:          machineImageAMI,
							Capabilities: capabilitiesAmd,
						},
						{
							Name:         machineImageName,
							Version:      machineImageVersion,
							AMI:          machineImageAMI,
							Capabilities: capabilitiesArm,
						},
					}
					if !isCapabilitiesCloudProfile {
						machineImages = []apiv1alpha1.MachineImage{
							{
								Name:         machineImageName,
								Version:      machineImageVersion,
								AMI:          machineImageAMI,
								Architecture: ptr.To(archAMD),
							},
							{
								Name:         machineImageName,
								Version:      machineImageVersion,
								AMI:          machineImageAMI,
								Architecture: ptr.To(archARM),
							},
						}
					}

					// Test WorkerDelegate.UpdateMachineDeployments()
					expectedImages := &apiv1alpha1.WorkerStatus{
						TypeMeta: metav1.TypeMeta{
							APIVersion: apiv1alpha1.SchemeGroupVersion.String(),
							Kind:       "WorkerStatus",
						},
						MachineImages: machineImages,
					}

					workerWithExpectedImages := w.DeepCopy()
					workerWithExpectedImages.Status.ProviderStatus = &runtime.RawExtension{
						Object: expectedImages,
					}

					c.EXPECT().Status().Return(statusWriter)
					statusWriter.EXPECT().Patch(ctx, workerWithExpectedImages, gomock.Any()).Return(nil)

					err = workerDelegate.UpdateMachineImagesStatus(ctx)
					Expect(err).NotTo(HaveOccurred())

					// Test WorkerDelegate.GenerateMachineDeployments()

					result, err := workerDelegate.GenerateMachineDeployments(ctx)
					Expect(err).NotTo(HaveOccurred())
					Expect(result).To(Equal(machineDeployments))
				})

				It("should deploy the expected machine classes when infrastructureProviderStatus.EC2 is missing keyName", func() {
					infrastructureProviderStatus.EC2.KeyName = ""
					w.Spec.InfrastructureProviderStatus = &runtime.RawExtension{
						Raw: encode(infrastructureProviderStatus),
					}
					workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

					for _, machineClass := range machineClasses["machineClasses"].([]map[string]interface{}) {
						delete(machineClass, "keyName")
					}

					expectedUserDataSecretRefRead()

					// Test WorkerDelegate.DeployMachineClasses()
					chartApplier.EXPECT().ApplyFromEmbeddedFS(
						ctx,
						charts.InternalChart,
						filepath.Join("internal", "machineclass"),
						namespace,
						"machineclass",
						kubernetes.Values(machineClasses),
					)

					err := workerDelegate.DeployMachineClasses(ctx)
					Expect(err).NotTo(HaveOccurred())
				})

				Context("using workerConfig.iamInstanceProfile", func() {
					modifyExpectedMachineClasses := func(expectedIamInstanceProfile map[string]interface{}) {
						newHash, err := worker.WorkerPoolHash(w.Spec.Pools[1], cluster, nil, nil, nil)
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

						workerDelegate, _ := NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

						expectedUserDataSecretRefRead()

						chartApplier.EXPECT().ApplyFromEmbeddedFS(
							ctx,
							charts.InternalChart,
							filepath.Join("internal", "machineclass"),
							namespace,
							"machineclass",
							kubernetes.Values(machineClasses),
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

						workerDelegate, _ := NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

						expectedUserDataSecretRefRead()

						chartApplier.EXPECT().ApplyFromEmbeddedFS(
							ctx,
							charts.InternalChart,
							filepath.Join("internal", "machineclass"),
							namespace,
							"machineclass",
							kubernetes.Values(machineClasses),
						)

						Expect(workerDelegate.DeployMachineClasses(context.TODO())).NotTo(HaveOccurred())
					})
				})

				It("should return err when the infrastructure provider status cannot be decoded", func() {
					// Deliberately setting InfrastructureProviderStatus to empty
					w.Spec.InfrastructureProviderStatus = &runtime.RawExtension{}
					workerDelegate, _ := NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

					err := workerDelegate.DeployMachineClasses(context.TODO())
					Expect(err).To(HaveOccurred())
				})

				It("should return generate machine classes with core and extended resources in the nodeTemplate", func() {
					ephemeralStorageQuant := resource.MustParse("30Gi")
					dongleName := corev1.ResourceName("resources.com/dongle")
					dongleQuant := resource.MustParse("4")
					customResources := corev1.ResourceList{
						corev1.ResourceEphemeralStorage: ephemeralStorageQuant,
						dongleName:                      dongleQuant,
					}
					w.Spec.Pools[0].ProviderConfig = &runtime.RawExtension{
						Raw: encode(&api.WorkerConfig{
							NodeTemplate: &extensionsv1alpha1.NodeTemplate{
								Capacity: customResources,
							},
						}),
					}

					expectedCapacity := w.Spec.Pools[0].NodeTemplate.Capacity.DeepCopy()
					maps.Copy(expectedCapacity, customResources)

					wd, err := NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)
					Expect(err).NotTo(HaveOccurred())
					expectedUserDataSecretRefRead()
					_, err = wd.GenerateMachineDeployments(ctx)
					Expect(err).NotTo(HaveOccurred())
					workerDelegate := wd.(*WorkerDelegate)
					mClasses := workerDelegate.GetMachineClasses()
					for _, mClz := range mClasses {
						className := mClz["name"].(string)
						if strings.Contains(className, namePool1) {
							nt := mClz["nodeTemplate"].(machinev1alpha1.NodeTemplate)
							Expect(nt.Capacity).To(Equal(expectedCapacity))
						}
					}
				})
			})

			It("should fail because the version is invalid", func() {
				clusterWithoutImages.Shoot.Spec.Kubernetes.Version = "invalid"
				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the infrastructure status cannot be decoded", func() {
				w.Spec.InfrastructureProviderStatus = &runtime.RawExtension{}

				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the nodes instance profile cannot be found", func() {
				w.Spec.InfrastructureProviderStatus = &runtime.RawExtension{
					Raw: encode(&api.InfrastructureStatus{}),
				}

				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

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

				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the ami for this region cannot be found", func() {
				w.Spec.Region = "another-region"

				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the ami for this architecture cannot be found", func() {
				if isCapabilitiesCloudProfile {
					cluster.CloudProfile.Spec.MachineTypes[0].Capabilities[v1beta1constants.ArchitectureName] = []string{archFAKE}
				} else {
					w.Spec.Pools[0].Architecture = ptr.To(archFAKE)
				}

				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

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

				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

				expectedUserDataSecretRefRead()

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).To(HaveOccurred())
				Expect(result).To(BeNil())
			})

			It("should fail because the volume size cannot be decoded", func() {
				w.Spec.Pools[0].Volume.Size = "not-decodeable"

				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

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

				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

				expectedUserDataSecretRefRead()

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

			It("should set expected cluster-autoscaler annotations on the machine deployment", func() {
				w.Spec.Pools[0].ClusterAutoscaler = &extensionsv1alpha1.ClusterAutoscalerOptions{
					MaxNodeProvisionTime:             ptr.To(metav1.Duration{Duration: time.Minute}),
					ScaleDownGpuUtilizationThreshold: ptr.To("0.4"),
					ScaleDownUnneededTime:            ptr.To(metav1.Duration{Duration: 2 * time.Minute}),
					ScaleDownUnreadyTime:             ptr.To(metav1.Duration{Duration: 3 * time.Minute}),
					ScaleDownUtilizationThreshold:    ptr.To("0.5"),
				}
				w.Spec.Pools[1].ClusterAutoscaler = nil
				workerDelegate, _ = NewWorkerDelegate(c, decoder, scheme, chartApplier, "", w, cluster)

				expectedUserDataSecretRefRead()

				result, err := workerDelegate.GenerateMachineDeployments(ctx)
				Expect(err).NotTo(HaveOccurred())
				Expect(result).NotTo(BeNil())

				Expect(result[0].ClusterAutoscalerAnnotations).NotTo(BeNil())
				Expect(result[1].ClusterAutoscalerAnnotations).NotTo(BeNil())

				for k, v := range result[2].ClusterAutoscalerAnnotations {
					Expect(v).To(BeEmpty(), "entry for key %v is not empty", k)
				}
				for k, v := range result[3].ClusterAutoscalerAnnotations {
					Expect(v).To(BeEmpty(), "entry for key %v is not empty", k)
				}

				Expect(result[0].ClusterAutoscalerAnnotations[extensionsv1alpha1.MaxNodeProvisionTimeAnnotation]).To(Equal("1m0s"))
				Expect(result[0].ClusterAutoscalerAnnotations[extensionsv1alpha1.ScaleDownGpuUtilizationThresholdAnnotation]).To(Equal("0.4"))
				Expect(result[0].ClusterAutoscalerAnnotations[extensionsv1alpha1.ScaleDownUnneededTimeAnnotation]).To(Equal("2m0s"))
				Expect(result[0].ClusterAutoscalerAnnotations[extensionsv1alpha1.ScaleDownUnreadyTimeAnnotation]).To(Equal("3m0s"))
				Expect(result[0].ClusterAutoscalerAnnotations[extensionsv1alpha1.ScaleDownUtilizationThresholdAnnotation]).To(Equal("0.5"))

				Expect(result[1].ClusterAutoscalerAnnotations[extensionsv1alpha1.MaxNodeProvisionTimeAnnotation]).To(Equal("1m0s"))
				Expect(result[1].ClusterAutoscalerAnnotations[extensionsv1alpha1.ScaleDownGpuUtilizationThresholdAnnotation]).To(Equal("0.4"))
				Expect(result[1].ClusterAutoscalerAnnotations[extensionsv1alpha1.ScaleDownUnneededTimeAnnotation]).To(Equal("2m0s"))
				Expect(result[1].ClusterAutoscalerAnnotations[extensionsv1alpha1.ScaleDownUnreadyTimeAnnotation]).To(Equal("3m0s"))
				Expect(result[1].ClusterAutoscalerAnnotations[extensionsv1alpha1.ScaleDownUtilizationThresholdAnnotation]).To(Equal("0.5"))
			})

			Describe("Worker pool hash additional data calculation", func() {
				var pool extensionsv1alpha1.WorkerPool

				BeforeEach(func() {
					pool = extensionsv1alpha1.WorkerPool{
						Name: "pool1",
						Volume: &extensionsv1alpha1.Volume{
							Encrypted: ptr.To(true),
						},
						DataVolumes: []extensionsv1alpha1.DataVolume{
							{
								Name:      "data-volume-1",
								Encrypted: ptr.To(true),
								Size:      "10Gi",
								Type:      ptr.To("type1"),
							},
							{
								Name:      "data-volume-2",
								Encrypted: ptr.To(false),
								Size:      "20Gi",
								Type:      ptr.To("type2"),
							},
						},
					}
				})

				Describe("ComputeAdditionalHashDataV1", func() {
					It("should return the expected hash data for Rolling update strategy", func() {
						Expect(ComputeAdditionalHashDataV1(pool)).To(Equal([]string{
							"true",
							"10Gi",
							"type1",
							"true",
							"20Gi",
							"type2",
							"false",
						}))
					})
				})

				Describe("ComputeAdditionalHashDataV2", func() {
					var (
						workerConfig     api.WorkerConfig
						workerConfigData []byte
					)

					BeforeEach(func() {
						workerConfig = api.WorkerConfig{
							CpuOptions: &api.CpuOptions{
								CoreCount:      ptr.To(int64(4)),
								ThreadsPerCore: ptr.To(int64(2)),
							},
							IAMInstanceProfile: &api.IAMInstanceProfile{
								ARN:  ptr.To("arn"),
								Name: ptr.To("name1"),
							},
							InstanceMetadataOptions: &api.InstanceMetadataOptions{
								HTTPTokens:              ptr.To(api.HTTPTokensRequired),
								HTTPPutResponseHopLimit: ptr.To(int64(1)),
							},
						}
						workerConfigData = encode(&workerConfig)
						pool.ProviderConfig = &runtime.RawExtension{
							Raw: workerConfigData,
						}
					})

					It("should return the expected hash data for Rolling update strategy", func() {
						Expect(ComputeAdditionalHashDataV2(pool)).To(Equal([]string{
							"true",
							"10Gi",
							"type1",
							"true",
							"20Gi",
							"type2",
							"false",
							string(workerConfigData),
						}))
					})
				})

				Describe("ComputeAdditionalHashDataInPlace", func() {
					It("should return the expected hash data for InPlace update strategy", func() {
						Expect(ComputeAdditionalHashDataInPlace(pool)).To(Equal([]string{
							"true",
						}))
					})
				})
			})
		},
			Entry("with capabilities", true),
			Entry("without capabilities", false),
		)

		Describe("InstanceMetadata", func() {
			var (
				workerConfig *api.WorkerConfig
				cluster      *extensionscontroller.Cluster
			)
			BeforeEach(func() {
				cluster = &extensionscontroller.Cluster{
					Shoot: &gardencorev1beta1.Shoot{
						Spec: gardencorev1beta1.ShootSpec{
							Kubernetes: gardencorev1beta1.Kubernetes{
								Version: "1.29.0",
							},
						},
					},
				}
				workerConfig = &api.WorkerConfig{
					InstanceMetadataOptions: nil,
				}
			})
			It("should calculate correct IMDS for k8s <1.30", func() {
				res, err := ComputeInstanceMetadata(workerConfig, cluster)
				Expect(err).NotTo(HaveOccurred())
				Expect(res).To(BeEmpty())
			})
			It("should calculate correct IMDS for k8s >=1.30", func() {
				cluster.Shoot.Spec.Kubernetes.Version = "1.30.0"

				res, err := ComputeInstanceMetadata(workerConfig, cluster)
				Expect(err).NotTo(HaveOccurred())
				Expect(res).To(HaveKeyWithValue("httpPutResponseHopLimit", int64(2)))
				Expect(res).To(HaveKeyWithValue("httpTokens", "required"))
			})
			It("should calculate correct IMDS with user options", func() {
				workerConfig.InstanceMetadataOptions = &api.InstanceMetadataOptions{
					HTTPTokens:              ptr.To(api.HTTPTokensRequired),
					HTTPPutResponseHopLimit: ptr.To(int64(5)),
				}

				res, err := ComputeInstanceMetadata(workerConfig, cluster)
				Expect(err).NotTo(HaveOccurred())
				Expect(res).To(HaveKeyWithValue("httpPutResponseHopLimit", int64(5)))
				Expect(res).To(HaveKeyWithValue("httpTokens", "required"))
			})

		})
	})
	DescribeTable("EnsureUniformMachineImages", func(capabilityDefinitions []gardencorev1beta1.CapabilityDefinition, expectedImages []api.MachineImage) {
		machineImages := []api.MachineImage{
			// images with capability sets
			{
				Name:    "some-image",
				Version: "1.2.1",
				AMI:     "ami-for-arm64",
				Capabilities: gardencorev1beta1.Capabilities{
					v1beta1constants.ArchitectureName: []string{"arm64"},
				},
			},
			{
				Name:    "some-image",
				Version: "1.2.2",
				AMI:     "ami-for-amd64",
				Capabilities: gardencorev1beta1.Capabilities{
					v1beta1constants.ArchitectureName: []string{"amd64"},
				},
			},
			// legacy image entry without capability sets
			{
				Name:         "some-image",
				Version:      "1.2.3",
				AMI:          "ami-for-amd64",
				Architecture: ptr.To("amd64"),
			},
			{
				Name:         "some-image",
				Version:      "1.2.2",
				AMI:          "ami-for-amd64",
				Architecture: ptr.To("amd64"),
			},
			{
				Name:         "some-image",
				Version:      "1.2.1",
				AMI:          "ami-for-amd64",
				Architecture: ptr.To("amd64"),
			},
		}
		actualImages := EnsureUniformMachineImages(machineImages, capabilityDefinitions)
		Expect(actualImages).To(ContainElements(expectedImages))

	},
		Entry("should return images with Architecture", nil, []api.MachineImage{
			// images with capability sets
			{
				Name:         "some-image",
				Version:      "1.2.1",
				AMI:          "ami-for-arm64",
				Architecture: ptr.To("arm64"),
			},
			{
				Name:         "some-image",
				Version:      "1.2.2",
				AMI:          "ami-for-amd64",
				Architecture: ptr.To("amd64"),
			},
			// legacy image entry without capability sets
			{
				Name:         "some-image",
				Version:      "1.2.3",
				AMI:          "ami-for-amd64",
				Architecture: ptr.To("amd64"),
			},
			{
				Name:         "some-image",
				Version:      "1.2.1",
				AMI:          "ami-for-amd64",
				Architecture: ptr.To("amd64"),
			},
		}),
		Entry("should return images with Capabilities", []gardencorev1beta1.CapabilityDefinition{{
			Name:   v1beta1constants.ArchitectureName,
			Values: []string{"amd64", "arm64"},
		}}, []api.MachineImage{
			// images with capability sets
			{
				Name:    "some-image",
				Version: "1.2.1",
				AMI:     "ami-for-arm64",
				Capabilities: gardencorev1beta1.Capabilities{
					v1beta1constants.ArchitectureName: []string{"arm64"},
				},
			},
			{
				Name:    "some-image",
				Version: "1.2.2",
				AMI:     "ami-for-amd64",
				Capabilities: gardencorev1beta1.Capabilities{
					v1beta1constants.ArchitectureName: []string{"amd64"},
				},
			},
			// legacy image entry without capability sets
			{
				Name:    "some-image",
				Version: "1.2.3",
				AMI:     "ami-for-amd64",
				Capabilities: gardencorev1beta1.Capabilities{
					v1beta1constants.ArchitectureName: []string{"amd64"},
				}},
			{
				Name:    "some-image",
				Version: "1.2.1",
				AMI:     "ami-for-amd64",
				Capabilities: gardencorev1beta1.Capabilities{
					v1beta1constants.ArchitectureName: []string{"amd64"},
				},
			},
		}),
	)
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

func addNodeTemplateToMachineClass(class map[string]interface{}, nodeTemplate machinev1alpha1.NodeTemplate) {
	class["nodeTemplate"] = nodeTemplate
}

func addNameAndSecretToMachineClass(class map[string]interface{}, name string, credentialsSecretRef corev1.SecretReference) {
	class["name"] = name
	class["credentialsSecretRef"] = map[string]interface{}{
		"name":      credentialsSecretRef.Name,
		"namespace": credentialsSecretRef.Namespace,
	}
	class["secret"].(map[string]interface{})["labels"] = map[string]string{v1beta1constants.GardenerPurpose: v1beta1constants.GardenPurposeMachineClass}
}
