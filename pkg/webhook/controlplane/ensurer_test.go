// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package controlplane

import (
	"context"
	"testing"

	"github.com/Masterminds/semver/v3"
	"github.com/coreos/go-systemd/v22/unit"
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/test"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	imagevectorutils "github.com/gardener/gardener/pkg/utils/imagevector"
	testutils "github.com/gardener/gardener/pkg/utils/test"
	"github.com/gardener/gardener/pkg/utils/version"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
	vpaautoscalingv1 "k8s.io/autoscaler/vertical-pod-autoscaler/pkg/apis/autoscaling.k8s.io/v1"
	kubeletconfigv1beta1 "k8s.io/kubelet/config/v1beta1"
	"k8s.io/utils/pointer"
	"k8s.io/utils/ptr"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/imagevector"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const namespace = "test"

func TestController(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "ControlPlane Webhook Suite")
}

var _ = Describe("Ensurer", func() {
	var (
		ctrl *gomock.Controller
		c    *mockclient.MockClient
		ctx  = context.TODO()

		dummyContext   = gcontext.NewGardenContext(nil, nil)
		eContextK8s126 = gcontext.NewInternalGardenContext(
			&extensionscontroller.Cluster{
				Shoot: &gardencorev1beta1.Shoot{
					Spec: gardencorev1beta1.ShootSpec{
						Kubernetes: gardencorev1beta1.Kubernetes{
							Version: "1.26.1",
						},
					},
				},
			},
		)
		eContextK8s127 = gcontext.NewInternalGardenContext(
			&extensionscontroller.Cluster{
				ObjectMeta: metav1.ObjectMeta{
					Name: "shoot--project--foo",
				},
				Shoot: &gardencorev1beta1.Shoot{
					ObjectMeta: metav1.ObjectMeta{
						Name: "foo",
					},
					Spec: gardencorev1beta1.ShootSpec{
						Kubernetes: gardencorev1beta1.Kubernetes{
							Version: "1.27.1",
						},
					},
				},
			},
		)
		infraConfig    *v1alpha1.InfrastructureConfig
		infrastructure *extensionsv1alpha1.Infrastructure
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		c = mockclient.NewMockClient(ctrl)

		infraConfig = &v1alpha1.InfrastructureConfig{
			TypeMeta: metav1.TypeMeta{
				APIVersion: v1alpha1.SchemeGroupVersion.String(),
				Kind:       "InfrastructureConfig",
			},
		}
		infrastructure = &extensionsv1alpha1.Infrastructure{
			TypeMeta: metav1.TypeMeta{
				APIVersion: extensionsv1alpha1.SchemeGroupVersion.String(),
				Kind:       "Infrastructure",
			},
			Spec: extensionsv1alpha1.InfrastructureSpec{
				DefaultSpec: extensionsv1alpha1.DefaultSpec{
					Type: aws.Type,
					ProviderConfig: &runtime.RawExtension{
						Object: infraConfig,
					},
				},
			},
		}
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#EnsureKubeAPIServerDeployment", func() {
		var (
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

			ensurer = NewEnsurer(logger, c, true)
		})

		It("should add missing elements to kube-apiserver deployment (k8s < 1.27)", func() {
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, eContextK8s126, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeAPIServerDeployment(dep, "1.26.5")
		})

		It("should add missing elements to kube-apiserver deployment (k8s >= 1.27)", func() {
			err := ensurer.EnsureKubeAPIServerDeployment(ctx, eContextK8s127, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeAPIServerDeployment(dep, "1.27.1")
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

			err := ensurer.EnsureKubeAPIServerDeployment(ctx, eContextK8s127, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeAPIServerDeployment(dep, "1.27.5")
		})
	})

	Describe("#EnsureKubeControllerManagerDeployment", func() {
		var (
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

			ensurer = NewEnsurer(logger, c, true)
		})

		It("should add missing elements to kube-controller-manager deployment (k8s < 1.27)", func() {
			err := ensurer.EnsureKubeControllerManagerDeployment(ctx, eContextK8s126, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeControllerManagerDeployment(dep, "1.26.5")
		})

		It("should add missing elements to kube-controller-manager deployment (k8s >= 1.27 w/ CSI annotation)", func() {
			err := ensurer.EnsureKubeControllerManagerDeployment(ctx, eContextK8s127, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeControllerManagerDeployment(dep, "1.27.1")
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
									},
								},
							},
						},
					},
				}
			)

			err := ensurer.EnsureKubeControllerManagerDeployment(ctx, eContextK8s127, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeControllerManagerDeployment(dep, "1.27.5")
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

			ensurer = NewEnsurer(logger, c, true)
		})

		It("should add missing elements to kube-scheduler deployment (k8s < 1.27)", func() {
			err := ensurer.EnsureKubeSchedulerDeployment(ctx, eContextK8s126, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeSchedulerDeployment(dep, "1.26.5")
		})

		It("should add missing elements to kube-scheduler deployment (k8s >= 1.27)", func() {
			err := ensurer.EnsureKubeSchedulerDeployment(ctx, eContextK8s127, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkKubeSchedulerDeployment(dep, "1.27.1")
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

			ensurer = NewEnsurer(logger, c, true)
		})

		It("should add missing elements to cluster-autoscaler deployment (>= 1.27)", func() {
			err := ensurer.EnsureClusterAutoscalerDeployment(ctx, eContextK8s127, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkClusterAutoscalerDeployment(dep, "1.27.5")
		})
		It("should add missing elements to cluster-autoscaler deployment (< 1.27)", func() {
			err := ensurer.EnsureClusterAutoscalerDeployment(ctx, eContextK8s126, dep, nil)
			Expect(err).To(Not(HaveOccurred()))

			checkClusterAutoscalerDeployment(dep, "1.26.5")
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

				oldUnit        = extensionsv1alpha1.Unit{Name: "oldunit"}
				additionalUnit = extensionsv1alpha1.Unit{Name: "custom-mtu.service", Enable: pointer.Bool(true), Command: extensionsv1alpha1.UnitCommandPtr(extensionsv1alpha1.CommandStart), Content: &customMTUUnitContent}

				units = []extensionsv1alpha1.Unit{oldUnit}
			)

			// Create ensurer
			ensurer := NewEnsurer(logger, c, true)

			// Call EnsureAdditionalUnits method and check the result
			err := ensurer.EnsureAdditionalUnits(ctx, eContextK8s126, &units, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(units).To(ConsistOf(oldUnit, additionalUnit))
		})
	})

	Describe("#EnsureAdditionalFiles", func() {
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
			ecrConfig = `{"kind":"CredentialProviderConfig","apiVersion":"kubelet.config.k8s.io/v1","providers":[{"name":"ecr-credential-provider","matchImages":["*.dkr.ecr.*.amazonaws.com","*.dkr.ecr.*.amazonaws.com.cn","*.dkr.ecr-fips.*.amazonaws.com","*.dkr.ecr.us-iso-east-1.c2s.ic.gov","*.dkr.ecr.us-isob-east-1.sc2s.sgov.gov"],"defaultCacheDuration":"1h0m0s","apiVersion":"credentialprovider.kubelet.k8s.io/v1"}]}`
			filePath  = "/opt/bin/mtu-customizer.sh"
		)
		It("should add additional files to the current ones in k8s >=v1.27", func() {
			image, err := imagevector.ImageVector().FindImage(aws.ECRCredentialProviderImageName)
			Expect(err).NotTo(HaveOccurred())
			var (
				oldFile = extensionsv1alpha1.File{Path: "oldpath"}
				ecrBin  = extensionsv1alpha1.File{
					Path:        "/opt/bin/ecr-credential-provider",
					Permissions: ptr.To(int32(0755)),
					Content: extensionsv1alpha1.FileContent{
						ImageRef: &extensionsv1alpha1.FileContentImageRef{
							Image:           image.String(),
							FilePathInImage: "/bin/ecr-credential-provider",
						},
					},
				}
				ecrConfig = extensionsv1alpha1.File{
					Path:        "/opt/gardener/ecr-credential-provider-config.json",
					Permissions: ptr.To(int32(0755)),
					Content: extensionsv1alpha1.FileContent{
						Inline: &extensionsv1alpha1.FileContentInline{
							Data: ecrConfig,
						},
					},
				}

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

			c.EXPECT().Get(ctx, gomock.Any(), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).DoAndReturn(
				func(_ context.Context, _ k8sclient.ObjectKey, infra *extensionsv1alpha1.Infrastructure, _ ...k8sclient.GetOption) error {
					*infra = *infrastructure
					return nil
				},
			)

			// Create ensurer
			ensurer := NewEnsurer(logger, c, true)

			// Call EnsureAdditionalFiles method and check the result
			err = ensurer.EnsureAdditionalFiles(ctx, eContextK8s127, &files, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(files).To(ConsistOf(oldFile, additionalFile, ecrConfig, ecrBin))
		})

		It("should not add credential provider files to the current ones if k8s <= v1.26", func() {
			var (
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
			ensurer := NewEnsurer(logger, c, true)

			// Call EnsureAdditionalFiles method and check the result
			err := ensurer.EnsureAdditionalFiles(ctx, eContextK8s126, &files, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(files).To(ConsistOf(oldFile, additionalFile))
		})

		It("should not add credential provider files to the current ones if ECRAccess is disabled", func() {
			var (
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

			infraConfig.EnableECRAccess = ptr.To(false)
			c.EXPECT().Get(ctx, gomock.Any(), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).DoAndReturn(
				func(_ context.Context, _ k8sclient.ObjectKey, infra *extensionsv1alpha1.Infrastructure, _ ...k8sclient.GetOption) error {
					*infra = *infrastructure
					return nil
				},
			)

			// Create ensurer
			ensurer := NewEnsurer(logger, c, true)

			// Call EnsureAdditionalFiles method and check the result
			err := ensurer.EnsureAdditionalFiles(ctx, eContextK8s127, &files, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(files).To(ConsistOf(oldFile, additionalFile))
		})

		It("should add additional files to the current ones", func() {
			var (
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
			ensurer := NewEnsurer(logger, c, true)

			// Call EnsureAdditionalFiles method and check the result
			err := ensurer.EnsureAdditionalFiles(ctx, eContextK8s126, &files, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(files).To(ConsistOf(oldFile, additionalFile))
		})

		It("should overwrite existing files of the current ones", func() {
			var (
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
			ensurer := NewEnsurer(logger, c, true)

			// Call EnsureAdditionalFiles method and check the result
			err := ensurer.EnsureAdditionalFiles(ctx, eContextK8s126, &files, nil)
			Expect(err).To(Not(HaveOccurred()))
			Expect(files).To(ConsistOf(oldFile, additionalFile))
			Expect(files).To(HaveLen(2))
		})
	})

	Describe("#EnsureKubeletServiceUnitOptions", func() {
		var (
			ensurer               genericmutator.Ensurer
			oldUnitOptions        []*unit.UnitOption
			newUnitOptions        []*unit.UnitOption
			hostnamectlUnitOption *unit.UnitOption
		)

		BeforeEach(func() {
			ensurer = NewEnsurer(logger, c, true)
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

			newUnitOptions = []*unit.UnitOption{
				{
					Section: "Service",
					Name:    "ExecStart",
					Value: `/opt/bin/hyperkube kubelet \
    --config=/var/lib/kubelet/config/kubelet` + addCmdOption("--cloud-provider=external"),
				},
				hostnamectlUnitOption,
			}
		})

		Context("should modify existing elements of kubelet.service unit options", func() {
			It("kubelet version <= 1.26", func() {
				opts, err := ensurer.EnsureKubeletServiceUnitOptions(ctx, eContextK8s126, semver.MustParse("1.26.0"), oldUnitOptions, nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(opts).To(Equal(newUnitOptions))
			})

			It("kubelet version >= 1.27 without ECR access", func() {
				c.EXPECT().Get(ctx, gomock.Any(), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).DoAndReturn(
					func(_ context.Context, _ k8sclient.ObjectKey, infra *extensionsv1alpha1.Infrastructure, _ ...k8sclient.GetOption) error {
						*infra = *infrastructure

						infraConfig.EnableECRAccess = ptr.To(false)
						return nil
					},
				).AnyTimes()

				opts, err := ensurer.EnsureKubeletServiceUnitOptions(ctx, eContextK8s127, semver.MustParse("1.27.0"), oldUnitOptions, nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(opts).To(Equal(newUnitOptions))
			})

			It("kubelet version >= 1.27 with ECR Access", func() {
				newUnitOptions[0].Value += addCmdOption("--image-credential-provider-config=/opt/gardener/ecr-credential-provider-config.json")
				newUnitOptions[0].Value += addCmdOption("--image-credential-provider-bin-dir=/opt/bin/")

				c.EXPECT().Get(ctx, gomock.Any(), gomock.AssignableToTypeOf(&extensionsv1alpha1.Infrastructure{})).DoAndReturn(
					func(_ context.Context, _ k8sclient.ObjectKey, infra *extensionsv1alpha1.Infrastructure, _ ...k8sclient.GetOption) error {
						*infra = *infrastructure
						return nil
					},
				).AnyTimes()

				opts, err := ensurer.EnsureKubeletServiceUnitOptions(ctx, eContextK8s127, semver.MustParse("1.27.0"), oldUnitOptions, nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(opts).To(Equal(newUnitOptions))
			})
		})
	})

	Describe("#EnsureKubeletConfiguration", func() {
		var (
			ensurer          genericmutator.Ensurer
			oldKubeletConfig *kubeletconfigv1beta1.KubeletConfiguration
		)

		BeforeEach(func() {
			ensurer = NewEnsurer(logger, c, true)
			oldKubeletConfig = &kubeletconfigv1beta1.KubeletConfiguration{
				FeatureGates: map[string]bool{
					"Foo": true,
				},
			}
		})

		DescribeTable("should modify existing elements of kubelet configuration",
			func(gctx gcontext.GardenContext, kubeletVersion *semver.Version) {
				newKubeletConfig := &kubeletconfigv1beta1.KubeletConfiguration{
					FeatureGates: map[string]bool{
						"Foo": true,
					},
					EnableControllerAttachDetach: pointer.Bool(true),
				}
				kubeletConfig := *oldKubeletConfig

				if version.ConstraintK8sLess127.Check(kubeletVersion) {
					newKubeletConfig.FeatureGates["CSIMigration"] = true
					newKubeletConfig.FeatureGates["CSIMigrationAWS"] = true
				}
				newKubeletConfig.FeatureGates["InTreePluginAWSUnregister"] = true

				err := ensurer.EnsureKubeletConfiguration(ctx, nil, kubeletVersion, &kubeletConfig, nil)
				Expect(err).To(Not(HaveOccurred()))
				Expect(&kubeletConfig).To(Equal(newKubeletConfig))
			},

			Entry("kubelet < 1.26", eContextK8s126, semver.MustParse("1.26.0")),
			Entry("kubelet >= 1.27", eContextK8s127, semver.MustParse("1.27.1")),
		)
	})

	Describe("#EnsureKubernetesGeneralConfiguration", func() {
		var ensurer genericmutator.Ensurer

		BeforeEach(func() {
			ensurer = NewEnsurer(logger, c, true)
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

	Describe("#EnsureMachineControllerManagerDeployment", func() {
		var (
			ensurer    genericmutator.Ensurer
			deployment *appsv1.Deployment
		)

		BeforeEach(func() {
			deployment = &appsv1.Deployment{ObjectMeta: metav1.ObjectMeta{Namespace: "foo"}}
			ensurer = NewEnsurer(logger, c, true)
			DeferCleanup(testutils.WithVar(&ImageVector, imagevectorutils.ImageVector{{
				Name:       "machine-controller-manager-provider-aws",
				Repository: "foo",
				Tag:        pointer.String("bar"),
			}}))
		})

		It("should inject the sidecar container", func() {
			Expect(deployment.Spec.Template.Spec.Containers).To(BeEmpty())
			Expect(ensurer.EnsureMachineControllerManagerDeployment(context.TODO(), nil, deployment, nil)).To(BeNil())
			Expect(deployment.Spec.Template.Spec.Containers).To(ConsistOf(corev1.Container{
				Name:            "machine-controller-manager-provider-aws",
				Image:           "foo:bar",
				ImagePullPolicy: corev1.PullIfNotPresent,
				Command: []string{
					"./machine-controller",
					"--control-kubeconfig=inClusterConfig",
					"--machine-creation-timeout=20m",
					"--machine-drain-timeout=2h",
					"--machine-health-timeout=10m",
					"--machine-safety-apiserver-statuscheck-timeout=30s",
					"--machine-safety-apiserver-statuscheck-period=1m",
					"--machine-safety-orphan-vms-period=30m",
					"--namespace=" + deployment.Namespace,
					"--port=10259",
					"--target-kubeconfig=/var/run/secrets/gardener.cloud/shoot/generic-kubeconfig/kubeconfig",
					"--v=3",
				},
				LivenessProbe: &corev1.Probe{
					ProbeHandler: corev1.ProbeHandler{
						HTTPGet: &corev1.HTTPGetAction{
							Path:   "/healthz",
							Port:   intstr.FromInt(10259),
							Scheme: "HTTP",
						},
					},
					InitialDelaySeconds: 30,
					TimeoutSeconds:      5,
					PeriodSeconds:       10,
					SuccessThreshold:    1,
					FailureThreshold:    3,
				},
				VolumeMounts: []corev1.VolumeMount{{
					Name:      "kubeconfig",
					MountPath: "/var/run/secrets/gardener.cloud/shoot/generic-kubeconfig",
					ReadOnly:  true,
				}},
			}))
		})
	})

	Describe("#EnsureMachineControllerManagerVPA", func() {
		var (
			ensurer genericmutator.Ensurer
			vpa     *vpaautoscalingv1.VerticalPodAutoscaler
		)

		BeforeEach(func() {
			vpa = &vpaautoscalingv1.VerticalPodAutoscaler{}
			ensurer = NewEnsurer(logger, c, true)
		})

		It("should inject the sidecar container policy", func() {
			Expect(vpa.Spec.ResourcePolicy).To(BeNil())
			Expect(ensurer.EnsureMachineControllerManagerVPA(context.TODO(), nil, vpa, nil)).To(BeNil())

			ccv := vpaautoscalingv1.ContainerControlledValuesRequestsOnly
			Expect(vpa.Spec.ResourcePolicy.ContainerPolicies).To(ConsistOf(vpaautoscalingv1.ContainerResourcePolicy{
				ContainerName:    "machine-controller-manager-provider-aws",
				ControlledValues: &ccv,
				MinAllowed: corev1.ResourceList{
					corev1.ResourceMemory: resource.MustParse("64Mi"),
				},
				MaxAllowed: corev1.ResourceList{
					corev1.ResourceCPU:    resource.MustParse("2"),
					corev1.ResourceMemory: resource.MustParse("5G"),
				},
			}))
		})
	})
})

func checkKubeAPIServerDeployment(dep *appsv1.Deployment, k8sVersion string) {
	k8sVersionAtLeast127, _ := version.CompareVersions(k8sVersion, ">=", "1.27")

	// Check that the kube-apiserver container still exists and contains all needed command line args,
	// env vars, and volume mounts
	c := extensionswebhook.ContainerWithName(dep.Spec.Template.Spec.Containers, "kube-apiserver")
	Expect(c).To(Not(BeNil()))

	if k8sVersionAtLeast127 {
		Expect(c.Command).To(ContainElement("--feature-gates=InTreePluginAWSUnregister=true"))
	} else {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,InTreePluginAWSUnregister=true"))
	}
	Expect(c.Command).NotTo(ContainElement("--cloud-provider=aws"))
	Expect(c.Command).NotTo(ContainElement("--cloud-config=/etc/kubernetes/cloudprovider/cloudprovider.conf"))
	Expect(c.Command).NotTo(test.ContainElementWithPrefixContaining("--enable-admission-plugins=", "PersistentVolumeLabel", ","))
	Expect(c.Command).To(test.ContainElementWithPrefixContaining("--disable-admission-plugins=", "PersistentVolumeLabel", ","))
	Expect(c.Env).NotTo(ContainElement(accessKeyIDEnvVar))
	Expect(c.Env).NotTo(ContainElement(secretAccessKeyEnvVar))
	Expect(dep.Spec.Template.Annotations).To(BeNil())
	Expect(dep.Spec.Template.Labels).To(HaveKeyWithValue("networking.resources.gardener.cloud/to-csi-snapshot-validation-tcp-443", "allowed"))
	Expect(dep.Spec.Template.Labels).To(HaveKeyWithValue("networking.resources.gardener.cloud/to-aws-load-balancer-controller-webhook-service-tcp-9443", "allowed"))
}

func checkKubeControllerManagerDeployment(dep *appsv1.Deployment, k8sVersion string) {
	k8sVersionAtLeast127, _ := version.CompareVersions(k8sVersion, ">=", "1.27")

	// Check that the kube-controller-manager container still exists and contains all needed command line args,
	// env vars, and volume mounts
	c := extensionswebhook.ContainerWithName(dep.Spec.Template.Spec.Containers, "kube-controller-manager")
	Expect(c).To(Not(BeNil()))

	if k8sVersionAtLeast127 {
		Expect(c.Command).To(ContainElement("--feature-gates=InTreePluginAWSUnregister=true"))
	} else {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,InTreePluginAWSUnregister=true"))
	}
	Expect(c.Command).To(ContainElement("--cloud-provider=external"))
	Expect(c.Command).NotTo(ContainElement("--cloud-config=/etc/kubernetes/cloudprovider/cloudprovider.conf"))
	Expect(c.Command).NotTo(ContainElement("--external-cloud-volume-plugin=aws"))
	Expect(c.Env).NotTo(ContainElement(accessKeyIDEnvVar))
	Expect(c.Env).NotTo(ContainElement(secretAccessKeyEnvVar))
	Expect(dep.Spec.Template.Labels).To(BeEmpty())
	Expect(c.VolumeMounts).NotTo(ContainElement(etcSSLVolumeMount))
	Expect(dep.Spec.Template.Spec.Volumes).NotTo(ContainElement(etcSSLVolume))
	Expect(c.VolumeMounts).NotTo(ContainElement(usrShareCaCertsVolumeMount))
	Expect(dep.Spec.Template.Spec.Volumes).NotTo(ContainElement(usrShareCaCertsVolume))
	Expect(dep.Spec.Template.Spec.Volumes).To(BeEmpty())
}

func checkKubeSchedulerDeployment(dep *appsv1.Deployment, k8sVersion string) {
	k8sVersionAtLeast127, _ := version.CompareVersions(k8sVersion, ">=", "1.27")

	// Check that the kube-scheduler container still exists and contains all needed command line args.
	c := extensionswebhook.ContainerWithName(dep.Spec.Template.Spec.Containers, "kube-scheduler")
	Expect(c).To(Not(BeNil()))

	if k8sVersionAtLeast127 {
		Expect(c.Command).To(ContainElement("--feature-gates=InTreePluginAWSUnregister=true"))
	} else {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,InTreePluginAWSUnregister=true"))
	}
}

func checkClusterAutoscalerDeployment(dep *appsv1.Deployment, k8sVersion string) {
	k8sVersionAtLeast127, _ := version.CompareVersions(k8sVersion, ">=", "1.27")

	// Check that the cluster-autoscaler container still exists and contains all needed command line args.
	c := extensionswebhook.ContainerWithName(dep.Spec.Template.Spec.Containers, "cluster-autoscaler")
	Expect(c).To(Not(BeNil()))

	if k8sVersionAtLeast127 {
		Expect(c.Command).To(ContainElement("--feature-gates=InTreePluginAWSUnregister=true"))
	} else {
		Expect(c.Command).To(ContainElement("--feature-gates=CSIMigration=true,CSIMigrationAWS=true,InTreePluginAWSUnregister=true"))
	}
}

// add option adds 4 spaces to indent the input s.
func addCmdOption(s string) string {
	return ` \
    ` + s
}
