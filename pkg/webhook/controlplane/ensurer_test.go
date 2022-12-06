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

package controlplane

import (
	"context"
	"testing"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/test"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	"github.com/gardener/gardener/pkg/utils/version"

	"github.com/Masterminds/semver"
	"github.com/coreos/go-systemd/v22/unit"
	"github.com/golang/mock/gomock"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
)

const namespace = "test"

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ControlPlane Webhook Suite")
}

var _ = Describe("Ensurer", func() {
	var (
		ctrl *gomock.Controller
		ctx  = context.TODO()

		dummyContext   = gcontext.NewGardenContext(nil, nil)
		eContextK8s120 = gcontext.NewInternalGardenContext(
			&extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					Spec: gardencorev1beta1.ShootSpec{
						Kubernetes: gardencorev1beta1.Kubernetes{
							Version: "1.20.0",
						},
					},
				},
			},
		)
		eContextK8s121 = gcontext.NewInternalGardenContext(
			&extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					Spec: gardencorev1beta1.ShootSpec{
						Kubernetes: gardencorev1beta1.Kubernetes{
							Version: "1.21.0",
						},
					},
				},
			},
		)
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#EnsureKubeAPIServerDeployment", func() {
		var (
			client  *mockclient.MockClient
			dep     *appsv1.Deployment
			ensurer genericmutator.Ensurer
		)

		BeforeEach(func() {
			dep = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: v1beta1constants.DeploymentNameKubeAPIServer},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "kube-apiserver",
								},
							},
						},
					},
				},
			}
			client = mockclient.NewMockClient(ctrl)

			ensurer = NewEnsurer(logger)
			err := ensurer.(inject.Client).InjectClient(client)
			Expect(err).To(Not(HaveOccurred()))
		})

		It("should add missing elements to kube-apiserver deployment (k8s >= 1.18)", func() {
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, eContextK8s120, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeAPIServerDeployment(dep, "1.20.0")
		})

		It("should add missing elements to kube-apiserver deployment (k8s >= 1.21)", func() {
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, eContextK8s121, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeAPIServerDeployment(dep, "1.21.0")
		})

		It("should modify existing elements of kube-apiserver deployment", func() {
			dep = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: v1beta1constants.DeploymentNameKubeAPIServer},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "kube-apiserver",
									Command: []string{
										"--cloud-provider=?",
										"--cloud-config=?",
										"--enable-admission-plugins=Priority,NamespaceLifecycle",
										"--disable-admission-plugins=PersistentVolumeLabel",
									},
									Env: []corev1.EnvVar{
										{Name: "AWS_ACCESS_KEY_ID", Value: "?"},
										{Name: "AWS_SECRET_ACCESS_KEY", Value: "?"},
									},
									VolumeMounts: []corev1.VolumeMount{
										{Name: aws.CloudProviderConfigName, MountPath: "?"},
									},
								},
							},
							Volumes: []corev1.Volume{
								{Name: aws.CloudProviderConfigName},
							},
						},
					},
				},
			}

			err := ensurer.EnsureKubeAPIServerDeployment(ctx, eContextK8s120, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeAPIServerDeployment(dep, "1.20.0")
		})
	})

	Describe("#EnsureKubeControllerManagerDeployment", func() {
		var (
			client  *mockclient.MockClient
			dep     *appsv1.Deployment
			ensurer genericmutator.Ensurer
		)

		BeforeEach(func() {
			dep = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: v1beta1constants.DeploymentNameKubeControllerManager},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						ObjectMeta: metav1.ObjectMeta{
							Labels: map[string]string{
								v1beta1constants.LabelNetworkPolicyToBlockedCIDRs: v1beta1constants.LabelNetworkPolicyAllowed,
							},
						},
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "kube-controller-manager",
								},
							},
						},
					},
				},
			}
			client = mockclient.NewMockClient(ctrl)

			ensurer = NewEnsurer(logger)
			err := ensurer.(inject.Client).InjectClient(client)
			Expect(err).To(Not(HaveOccurred()))
		})

		It("should add missing elements to kube-controller-manager deployment (k8s >= 1.18 w/ CSI annotation)", func() {
			err := ensurer.EnsureKubeControllerManagerDeployment(ctx, eContextK8s120, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeControllerManagerDeployment(dep, "1.20.0")
		})

		It("should add missing elements to kube-controller-manager deployment (k8s >= 1.21 w/ CSI annotation)", func() {
			err := ensurer.EnsureKubeControllerManagerDeployment(ctx, eContextK8s121, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeControllerManagerDeployment(dep, "1.21.0")
		})

		It("should modify existing elements of kube-controller-manager deployment", func() {
			var (
				dep = &appsv1.Deployment{
					ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: v1beta1constants.DeploymentNameKubeControllerManager},
					Spec: appsv1.DeploymentSpec{
						Template: corev1.PodTemplateSpec{
							ObjectMeta: metav1.ObjectMeta{
								Labels: map[string]string{
									v1beta1constants.LabelNetworkPolicyToBlockedCIDRs: v1beta1constants.LabelNetworkPolicyAllowed,
								},
							},
							Spec: corev1.PodSpec{
								Containers: []corev1.Container{
									{
										Name: "kube-controller-manager",
										Command: []string{
											"--cloud-provider=?",
											"--cloud-config=?",
											"--external-cloud-volume-plugin=?",
										},
										Env: []corev1.EnvVar{
											{Name: "AWS_ACCESS_KEY_ID", Value: "?"},
											{Name: "AWS_SECRET_ACCESS_KEY", Value: "?"},
										},
										VolumeMounts: []corev1.VolumeMount{
											{Name: aws.CloudProviderConfigName, MountPath: "?"},
										},
									},
								},
								Volumes: []corev1.Volume{
									{Name: aws.CloudProviderConfigName},
								},
							},
						},
					},
				}
			)

			err := ensurer.EnsureKubeControllerManagerDeployment(ctx, eContextK8s120, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeControllerManagerDeployment(dep, "1.20.0")
		})
	})

	Describe("#EnsureKubeSchedulerDeployment", func() {
		var (
			dep     *appsv1.Deployment
			ensurer genericmutator.Ensurer
		)

		BeforeEach(func() {
			dep = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: v1beta1constants.DeploymentNameKubeScheduler},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "kube-scheduler",
								},
							},
						},
					},
				},
			}

			ensurer = NewEnsurer(logger)
		})

		It("should add missing elements to kube-scheduler deployment (k8s >= 1.18)", func() {
			err := ensurer.EnsureKubeSchedulerDeployment(ctx, eContextK8s120, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeSchedulerDeployment(dep, "1.20.0")
		})

		It("should add missing elements to kube-scheduler deployment (k8s >= 1.21)", func() {
			err := ensurer.EnsureKubeSchedulerDeployment(ctx, eContextK8s121, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeSchedulerDeployment(dep, "1.21.0")
		})
	})

	Describe("#EnsureClusterAutoscalerDeployment", func() {
		var (
			dep     *appsv1.Deployment
			ensurer genericmutator.Ensurer
		)

		BeforeEach(func() {
			dep = &appsv1.Deployment{
				ObjectMeta: metav1.ObjectMeta{Namespace: namespace, Name: v1beta1constants.DeploymentNameClusterAutoscaler},
				Spec: appsv1.DeploymentSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{
								{
									Name: "cluster-autoscaler",
								},
							},
						},
					},
				},
			}

			ensurer = NewEnsurer(logger)
		})

		It("should add missing elements to cluster-autoscaler deployment (k8s = 1.20)", func() {
			err := ensurer.EnsureClusterAutoscalerDeployment(ctx, eContextK8s120, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkClusterAutoscalerDeployment(dep, "1.20.0")
		})

		It("should add missing elements to cluster-autoscaler deployment (k8s >= 1.21)", func() {
			err := ensurer.EnsureClusterAutoscalerDeployment(ctx, eContextK8s121, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkClusterAutoscalerDeployment(dep, "1.21.0")
		})
	})

	Describe("#EnsureAdditionalUnits", func() {
		It("should add additional units to the current ones", func() {
			var (
				customMTUUnitContent = `[Unit]
Description=Apply a custom MTU to network interfaces
After=network.target
Wants=network.target

[Install]
WantedBy=kubelet.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/bin/mtu-customizer.sh
`

				command = "start"
				trueVar = true

				oldUnit        = extensionsv1alpha1.Unit{Name: "oldunit"}
				additionalUnit = extensionsv1alpha1.Unit{Name: "custom-mtu.service", Enable: &trueVar, Command: &command, Content: &customMTUUnitContent}

				units = []extensionsv1alpha1.Unit{oldUnit}
			)

			// Create ensurer
			ensurer := NewEnsurer(logger)

			// Call EnsureAdditionalUnits method and check the result
			err := ensurer.EnsureAdditionalUnits(ctx, dummyContext, &units, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(units).To(ConsistOf(oldUnit, additionalUnit))
		})
	})

	Describe("#EnsureAdditionalFiles", func() {
		It("should add additional files to the current ones", func() {
			var (
				permissions       int32 = 0755
				customFileContent       = `#!/bin/sh

for interface_path in $(find /sys/class/net  -type l -print)
do
	interface=$(basename ${interface_path})

	if ls -l ${interface_path} | grep -q virtual
	then
		echo skipping virtual interface: ${interface}
		continue
	fi

	echo changing mtu of non-virtual interface: ${interface}
	ip link set dev ${interface} mtu 1460
done
`

				filePath = "/opt/bin/mtu-customizer.sh"

				oldFile        = extensionsv1alpha1.File{Path: "oldpath"}
				additionalFile = extensionsv1alpha1.File{
					Path:        filePath,
					Permissions: &permissions,
					Content: extensionsv1alpha1.FileContent{
						Inline: &extensionsv1alpha1.FileContentInline{
							Encoding: "",
							Data:     customFileContent,
						},
					},
				}

				files = []extensionsv1alpha1.File{oldFile}
			)

			// Create ensurer
			ensurer := NewEnsurer(logger)

			// Call EnsureAdditionalFiles method and check the result
			err := ensurer.EnsureAdditionalFiles(ctx, dummyContext, &files, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(files).To(ConsistOf(oldFile, additionalFile))
		})

		It("should overwrite existing files of the current ones", func() {
			var (
				permissions       int32 = 0755
				customFileContent       = `#!/bin/sh

for interface_path in $(find /sys/class/net  -type l -print)
do
	interface=$(basename ${interface_path})

	if ls -l ${interface_path} | grep -q virtual
	then
		echo skipping virtual interface: ${interface}
		continue
	fi

	echo changing mtu of non-virtual interface: ${interface}
	ip link set dev ${interface} mtu 1460
done
`

				filePath = "/opt/bin/mtu-customizer.sh"

				oldFile        = extensionsv1alpha1.File{Path: "oldpath"}
				additionalFile = extensionsv1alpha1.File{
					Path:        filePath,
					Permissions: &permissions,
					Content: extensionsv1alpha1.FileContent{
						Inline: &extensionsv1alpha1.FileContentInline{
							Encoding: "",
							Data:     customFileContent,
						},
					},
				}

				files = []extensionsv1alpha1.File{oldFile, additionalFile}
			)

			// Create ensurer
			ensurer := NewEnsurer(logger)

			// Call EnsureAdditionalFiles method and check the result
			err := ensurer.EnsureAdditionalFiles(ctx, dummyContext, &files, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(files).To(ConsistOf(oldFile, additionalFile))
			Expect(files).To(HaveLen(2))
		})
	})

	Describe("#EnsureKubeletServiceUnitOptions", func() {
		var (
			ensurer               genericmutator.Ensurer
			oldUnitOptions        []*unit.UnitOption
			hostnamectlUnitOption *unit.UnitOption
		)

		BeforeEach(func() {
			ensurer = NewEnsurer(logger)
			oldUnitOptions = []*unit.UnitOption{
				{
					Section: "Service",
					Name:    "ExecStart",
					Value: `/opt/bin/hyperkube kubelet \
    --config=/var/lib/kubelet/config/kubelet`,
				},
			}
			hostnamectlUnitOption = &unit.UnitOption{
				Section: "Service",
				Name:    "ExecStartPre",
				Value:   `/bin/sh -c 'hostnamectl set-hostname $(hostname -f)'`,
			}
		})

		DescribeTable("should modify existing elements of kubelet.service unit options",
			func(gctx gcontext.GardenContext, kubeletVersion *semver.Version, cloudProvider string, withControllerAttachDetachFlag bool) {
				newUnitOptions := []*unit.UnitOption{
					{
						Section: "Service",
						Name:    "ExecStart",
						Value: `/opt/bin/hyperkube kubelet \
    --config=/var/lib/kubelet/config/kubelet`,
					},
					hostnamectlUnitOption,
				}

				if cloudProvider != "" {
					newUnitOptions[0].Value += ` \
    --cloud-provider=` + cloudProvider
				}

				if withControllerAttachDetachFlag {
					newUnitOptions[0].Value += ` \
    --enable-controller-attach-detach=true`
				}

				opts, err := ensurer.EnsureKubeletServiceUnitOptions(ctx, gctx, kubeletVersion, oldUnitOptions, nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(opts).To(Equal(newUnitOptions))
			},

			Entry("1.18 <= kubelet version < 1.23", eContextK8s120, semver.MustParse("1.20.0"), "external", true),
			Entry("kubelet version >= 1.23", eContextK8s120, semver.MustParse("1.23.0"), "external", false),
		)
	})

	Describe("#EnsureKubeletConfiguration", func() {
		var (
			ensurer          genericmutator.Ensurer
			oldKubeletConfig *kubeletconfigv1beta1.KubeletConfiguration
		)

		BeforeEach(func() {
			ensurer = NewEnsurer(logger)
			oldKubeletConfig = &kubeletconfigv1beta1.KubeletConfiguration{
				FeatureGates: map[string]bool{
					"Foo": true,
				},
			}
		})

		DescribeTable("should modify existing elements of kubelet configuration",
			func(gctx gcontext.GardenContext, kubeletVersion *semver.Version, withCSIFeatureGates bool, csiMigrationCompleteFeatureGate string, enableControllerAttachDetach *bool) {
				newKubeletConfig := &kubeletconfigv1beta1.KubeletConfiguration{
					FeatureGates: map[string]bool{
						"Foo": true,
					},
					EnableControllerAttachDetach: enableControllerAttachDetach,
				}
				kubeletConfig := *oldKubeletConfig

				if withCSIFeatureGates {
					newKubeletConfig.FeatureGates["CSIMigration"] = true
					newKubeletConfig.FeatureGates["CSIMigrationAWS"] = true
					newKubeletConfig.FeatureGates[csiMigrationCompleteFeatureGate] = true
				}

				err := ensurer.EnsureKubeletConfiguration(ctx, gctx, kubeletVersion, &kubeletConfig, nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(&kubeletConfig).To(Equal(newKubeletConfig))
			},

			Entry("1.18 <= kubelet < 1.21", eContextK8s120, semver.MustParse("1.18.0"), true, "CSIMigrationAWSComplete", nil),
			Entry("1.21 <= kubelet < 1.23", eContextK8s121, semver.MustParse("1.21.0"), true, "InTreePluginAWSUnregister", nil),
			Entry("kubelet >= 1.23", eContextK8s121, semver.MustParse("1.23.0"), true, "InTreePluginAWSUnregister", pointer.Bool(true)),
		)
	})

	Describe("#EnsureKubernetesGeneralConfiguration", func() {
		var ensurer genericmutator.Ensurer

		BeforeEach(func() {
			ensurer = NewEnsurer(logger)
		})

		It("should modify existing elements of kubernetes general configuration", func() {
			var (
				modifiedData = pointer.String("# Default Socket Send Buffer\n" +
					"net.core.wmem_max = 16777216\n" +
					"# AWS specific settings\n" +
					"# See https://github.com/kubernetes/kubernetes/issues/23395\n" +
					"net.ipv4.neigh.default.gc_thresh1 = 67" +
					"# For persistent HTTP connections\n" +
					"net.ipv4.tcp_slow_start_after_idle = 0")
				result = "# Default Socket Send Buffer\n" +
					"net.core.wmem_max = 16777216\n" +
					"# AWS specific settings\n" +
					"# See https://github.com/kubernetes/kubernetes/issues/23395\n" +
					"net.ipv4.neigh.default.gc_thresh1 = 0" +
					"# For persistent HTTP connections\n" +
					"net.ipv4.tcp_slow_start_after_idle = 0"
			)

			err := ensurer.EnsureKubernetesGeneralConfiguration(ctx, dummyContext, modifiedData, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(*modifiedData).To(Equal(result))
		})

		It("should add needed elements of kubernetes general configuration", func() {
			var (
				data   = pointer.String("# Default Socket Send Buffer\nnet.core.wmem_max = 16777216")
				result = "# Default Socket Send Buffer\n" +
					"net.core.wmem_max = 16777216\n" +
					"# AWS specific settings\n" +
					"# See https://github.com/kubernetes/kubernetes/issues/23395\n" +
					"net.ipv4.neigh.default.gc_thresh1 = 0"
			)

			err := ensurer.EnsureKubernetesGeneralConfiguration(ctx, dummyContext, data, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(*data).To(Equal(result))
		})
	})
})

func checkKubeAPIServerDeployment(dep *appsv1.Deployment, k8sVersion string) {
	k8sVersionAtLeast121, _ := version.CompareVersions(k8sVersion, ">=", "1.21")

	// Check that the kube-apiserver container still exists and contains all needed command line args,
	// env vars, and volume mounts
	c := extensionswebhook.ContainerWithName(dep.Spec.Template.Spec.Containers, "kube-apiserver")
	Expect(c).To(Not(BeNil()))

	if k8sVersionAtLeast121 {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,InTreePluginAWSUnregister=true"))
	} else {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,CSIMigrationAWSComplete=true"))
	}
	Expect(c.Command).NotTo(ContainElement("--cloud-provider=aws"))
	Expect(c.Command).NotTo(ContainElement("--cloud-config=/etc/kubernetes/cloudprovider/cloudprovider.conf"))
	Expect(c.Command).NotTo(test.ContainElementWithPrefixContaining("--enable-admission-plugins=", "PersistentVolumeLabel", ","))
	Expect(c.Command).To(test.ContainElementWithPrefixContaining("--disable-admission-plugins=", "PersistentVolumeLabel", ","))
	Expect(c.Env).NotTo(ContainElement(accessKeyIDEnvVar))
	Expect(c.Env).NotTo(ContainElement(secretAccessKeyEnvVar))
	Expect(c.VolumeMounts).NotTo(ContainElement(cloudProviderConfigVolumeMount))
	Expect(dep.Spec.Template.Spec.Volumes).NotTo(ContainElement(cloudProviderConfigVolume))
	Expect(dep.Spec.Template.Annotations).To(BeNil())
}

func checkKubeControllerManagerDeployment(dep *appsv1.Deployment, k8sVersion string) {
	k8sVersionAtLeast121, _ := version.CompareVersions(k8sVersion, ">=", "1.21")

	// Check that the kube-controller-manager container still exists and contains all needed command line args,
	// env vars, and volume mounts
	c := extensionswebhook.ContainerWithName(dep.Spec.Template.Spec.Containers, "kube-controller-manager")
	Expect(c).To(Not(BeNil()))

	if k8sVersionAtLeast121 {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,InTreePluginAWSUnregister=true"))
	} else {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,CSIMigrationAWSComplete=true"))
	}
	Expect(c.Command).To(ContainElement("--cloud-provider=external"))
	Expect(c.Command).NotTo(ContainElement("--cloud-config=/etc/kubernetes/cloudprovider/cloudprovider.conf"))
	Expect(c.Command).NotTo(ContainElement("--external-cloud-volume-plugin=aws"))
	Expect(c.Env).NotTo(ContainElement(accessKeyIDEnvVar))
	Expect(c.Env).NotTo(ContainElement(secretAccessKeyEnvVar))
	Expect(dep.Spec.Template.Labels).To(BeEmpty())
	Expect(dep.Spec.Template.Spec.Volumes).To(BeEmpty())
	Expect(c.VolumeMounts).NotTo(ContainElement(cloudProviderConfigVolumeMount))
	Expect(dep.Spec.Template.Spec.Volumes).NotTo(ContainElement(cloudProviderConfigVolume))
	Expect(c.VolumeMounts).NotTo(ContainElement(etcSSLVolumeMount))
	Expect(dep.Spec.Template.Spec.Volumes).NotTo(ContainElement(etcSSLVolume))
	Expect(c.VolumeMounts).NotTo(ContainElement(usrShareCaCertsVolumeMount))
	Expect(dep.Spec.Template.Spec.Volumes).NotTo(ContainElement(usrShareCaCertsVolume))
}

func checkKubeSchedulerDeployment(dep *appsv1.Deployment, k8sVersion string) {
	k8sVersionAtLeast121, _ := version.CompareVersions(k8sVersion, ">=", "1.21")

	// Check that the kube-scheduler container still exists and contains all needed command line args.
	c := extensionswebhook.ContainerWithName(dep.Spec.Template.Spec.Containers, "kube-scheduler")
	Expect(c).To(Not(BeNil()))

	if k8sVersionAtLeast121 {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,InTreePluginAWSUnregister=true"))
	} else {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,CSIMigrationAWSComplete=true"))
	}
}

func checkClusterAutoscalerDeployment(dep *appsv1.Deployment, k8sVersion string) {
	if k8sVersionAtLeast120, _ := version.CompareVersions(k8sVersion, ">=", "1.20"); !k8sVersionAtLeast120 {
		return
	}
	k8sVersionAtLeast121, _ := version.CompareVersions(k8sVersion, ">=", "1.21")

	// Check that the cluster-autoscaler container still exists and contains all needed command line args.
	c := extensionswebhook.ContainerWithName(dep.Spec.Template.Spec.Containers, "cluster-autoscaler")
	Expect(c).To(Not(BeNil()))

	if k8sVersionAtLeast121 {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,InTreePluginAWSUnregister=true"))
	} else {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,CSIMigrationAWSComplete=true"))
	}
}
