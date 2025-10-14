// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator_test

import (
	"context"

	"github.com/gardener/gardener/extensions/pkg/util"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/mutator"
	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

var _ = Describe("NamespacedCloudProfile Mutator", func() {
	var (
		fakeClient  client.Client
		fakeManager manager.Manager
		namespace   string
		ctx         = context.Background()
		decoder     runtime.Decoder

		namespacedCloudProfileMutator extensionswebhook.Mutator
		namespacedCloudProfile        *v1beta1.NamespacedCloudProfile
	)

	BeforeEach(func() {
		scheme := runtime.NewScheme()
		utilruntime.Must(install.AddToScheme(scheme))
		utilruntime.Must(v1beta1.AddToScheme(scheme))
		fakeClient = fakeclient.NewClientBuilder().WithScheme(scheme).Build()
		fakeManager = &test.FakeManager{
			Client: fakeClient,
			Scheme: scheme,
		}
		namespace = "garden-dev"
		decoder = serializer.NewCodecFactory(fakeManager.GetScheme(), serializer.EnableStrict).UniversalDecoder()

		namespacedCloudProfileMutator = mutator.NewNamespacedCloudProfileMutator(fakeManager)
		namespacedCloudProfile = &v1beta1.NamespacedCloudProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "profile-1",
				Namespace: namespace,
			},
		}
	})

	Describe("#Mutate", func() {
		It("should succeed for NamespacedCloudProfile without provider config", func() {
			Expect(namespacedCloudProfileMutator.Mutate(ctx, namespacedCloudProfile, nil)).To(Succeed())
		})

		It("should skip if NamespacedCloudProfile is in deletion phase", func() {
			namespacedCloudProfile.DeletionTimestamp = ptr.To(metav1.Now())
			expectedProfile := namespacedCloudProfile.DeepCopy()

			Expect(namespacedCloudProfileMutator.Mutate(ctx, namespacedCloudProfile, nil)).To(Succeed())

			Expect(namespacedCloudProfile).To(DeepEqual(expectedProfile))
		})

		Describe("merge the provider configurations from a NamespacedCloudProfile and the parent CloudProfile", func() {
			It("should correctly merge extended machineImages", func() {
				namespacedCloudProfile.Status.CloudProfileSpec.ProviderConfig = &runtime.RawExtension{Raw: []byte(`{
"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1",
"kind":"CloudProfileConfig",
"machineImages":[
  {"name":"image-1","versions":[{"version":"1.0","regions":[{"name":"eu1","ami":"ami-123"}]}]}
]}`)}
				namespacedCloudProfile.Spec.ProviderConfig = &runtime.RawExtension{Raw: []byte(`{
"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1",
"kind":"CloudProfileConfig",
"machineImages":[
  {"name":"image-1","versions":[{"version":"1.1","regions":[{"name":"eu2","ami":"ami-124","architecture":"arm64"}]}]},
  {"name":"image-2","versions":[{"version":"2.0","regions":[{"name":"eu3","ami":"ami-125"}]}]}
]}`)}

				Expect(namespacedCloudProfileMutator.Mutate(ctx, namespacedCloudProfile, nil)).To(Succeed())

				mergedConfig, err := decodeCloudProfileConfig(decoder, namespacedCloudProfile.Status.CloudProfileSpec.ProviderConfig)
				Expect(err).ToNot(HaveOccurred())
				Expect(mergedConfig.MachineImages).To(ConsistOf(
					MatchFields(IgnoreExtras, Fields{
						"Name": Equal("image-1"),
						"Versions": ContainElements(
							api.MachineImageVersion{Version: "1.0", Regions: []api.RegionAMIMapping{{Name: "eu1", AMI: "ami-123", Architecture: ptr.To("amd64")}}},
							api.MachineImageVersion{Version: "1.1", Regions: []api.RegionAMIMapping{{Name: "eu2", AMI: "ami-124", Architecture: ptr.To("arm64")}}},
						),
					}),
					MatchFields(IgnoreExtras, Fields{
						"Name":     Equal("image-2"),
						"Versions": ContainElements(api.MachineImageVersion{Version: "2.0", Regions: []api.RegionAMIMapping{{Name: "eu3", AMI: "ami-125", Architecture: ptr.To("amd64")}}}),
					}),
				))
			})
			It("should correctly merge extended machineImages using capabilities ", func() {
				namespacedCloudProfile.Status.CloudProfileSpec.MachineCapabilities = []v1beta1.CapabilityDefinition{{
					Name:   "architecture",
					Values: []string{"amd64", "arm64"},
				}}
				namespacedCloudProfile.Status.CloudProfileSpec.ProviderConfig = &runtime.RawExtension{Raw: []byte(`{
"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1",
"kind":"CloudProfileConfig",
"machineImages":[
  {"name":"image-1","versions":[{"version":"1.0","capabilityFlavors":[
{"capabilities":{"architecture":["amd64"]},"regions":[{"name":"eu1","ami":"ami-123"}]}
]}]}
]}`)}
				namespacedCloudProfile.Spec.ProviderConfig = &runtime.RawExtension{Raw: []byte(`{
"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1",
"kind":"CloudProfileConfig",
"machineImages":[
  {"name":"image-1","versions":[{"version":"1.1","capabilityFlavors":[
{"capabilities":{"architecture":["arm64"]},"regions":[{"name":"eu2","ami":"ami-124"}]}
]}]},
  {"name":"image-2","versions":[{"version":"2.0","capabilityFlavors":[
{"capabilities":{"architecture":["amd64"]},"regions":[{"name":"eu3","ami":"ami-125"}]}
]}]}
]}`)}

				Expect(namespacedCloudProfileMutator.Mutate(ctx, namespacedCloudProfile, nil)).To(Succeed())

				mergedConfig, err := decodeCloudProfileConfig(decoder, namespacedCloudProfile.Status.CloudProfileSpec.ProviderConfig)
				Expect(err).ToNot(HaveOccurred())
				Expect(mergedConfig.MachineImages).To(ConsistOf(
					MatchFields(IgnoreExtras, Fields{
						"Name": Equal("image-1"),
						"Versions": ContainElements(
							api.MachineImageVersion{Version: "1.0",
								CapabilityFlavors: []api.MachineImageFlavor{{
									Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}},
									Regions:      []api.RegionAMIMapping{{Name: "eu1", AMI: "ami-123", Architecture: ptr.To("ignore")}},
								}},
							},
							api.MachineImageVersion{Version: "1.1",
								CapabilityFlavors: []api.MachineImageFlavor{{
									Capabilities: v1beta1.Capabilities{"architecture": []string{"arm64"}},
									Regions:      []api.RegionAMIMapping{{Name: "eu2", AMI: "ami-124", Architecture: ptr.To("ignore")}},
								}},
							},
						),
					}),
					MatchFields(IgnoreExtras, Fields{
						"Name": Equal("image-2"),
						"Versions": ContainElements(
							api.MachineImageVersion{Version: "2.0",
								CapabilityFlavors: []api.MachineImageFlavor{{
									Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}},
									Regions:      []api.RegionAMIMapping{{Name: "eu3", AMI: "ami-125", Architecture: ptr.To("ignore")}},
								}},
							}),
					}),
				))
			})
		})
	})

	Describe("#TransformProviderConfigToParentFormat", func() {
		var (
			capabilityDefinitions []v1beta1.CapabilityDefinition
		)

		BeforeEach(func() {
			capabilityDefinitions = []v1beta1.CapabilityDefinition{{
				Name:   "architecture",
				Values: []string{"amd64", "arm64"},
			}}
		})

		Context("when config is empty", func() {
			It("should return empty config", func() {
				result := mutator.TransformProviderConfigToParentFormat(nil, capabilityDefinitions)

				Expect(result).NotTo(BeNil())
				Expect(result.MachineImages).To(BeEmpty())
			})

			It("should return empty config with proper structure", func() {
				config := &v1alpha1.CloudProfileConfig{}
				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				Expect(result).NotTo(BeNil())
				Expect(result.MachineImages).To(BeEmpty())
				Expect(result.TypeMeta).To(Equal(config.TypeMeta))
			})
		})

		Context("when transforming to capability format", func() {
			It("should transform legacy format with single architecture to capability format", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name: "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "20.04",
									Regions: []v1alpha1.RegionAMIMapping{
										{Name: "eu-west-1", AMI: "ami-123", Architecture: ptr.To("amd64")},
										{Name: "us-east-1", AMI: "ami-456", Architecture: ptr.To("amd64")},
									},
								},
							},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				Expect(result.MachineImages).To(HaveLen(1))
				Expect(result.MachineImages[0].Name).To(Equal("ubuntu"))
				Expect(result.MachineImages[0].Versions).To(HaveLen(1))

				version := result.MachineImages[0].Versions[0]
				Expect(version.Version).To(Equal("20.04"))
				Expect(version.Regions).To(BeEmpty()) // Should be empty in capability format
				Expect(version.CapabilityFlavors).To(HaveLen(1))

				flavor := version.CapabilityFlavors[0]
				Expect(flavor.Capabilities).To(Equal(v1beta1.Capabilities{"architecture": []string{"amd64"}}))
				Expect(flavor.Regions).To(ConsistOf(
					v1alpha1.RegionAMIMapping{Name: "eu-west-1", AMI: "ami-123"},
					v1alpha1.RegionAMIMapping{Name: "us-east-1", AMI: "ami-456"},
				))
			})

			It("should transform legacy format with multiple architectures to capability format", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name: "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "20.04",
									Regions: []v1alpha1.RegionAMIMapping{
										{Name: "eu-west-1", AMI: "ami-123", Architecture: ptr.To("amd64")},
										{Name: "eu-west-1", AMI: "ami-124", Architecture: ptr.To("arm64")},
										{Name: "us-east-1", AMI: "ami-456", Architecture: ptr.To("amd64")},
									},
								},
							},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				Expect(result.MachineImages).To(HaveLen(1))
				version := result.MachineImages[0].Versions[0]
				Expect(version.CapabilityFlavors).To(HaveLen(2))

				// Check both architecture flavors are present
				var amd64Flavor, arm64Flavor *v1alpha1.MachineImageFlavor
				for i := range version.CapabilityFlavors {
					switch version.CapabilityFlavors[i].Capabilities["architecture"][0] {
					case "amd64":
						amd64Flavor = &version.CapabilityFlavors[i]
					case "arm64":
						arm64Flavor = &version.CapabilityFlavors[i]
					}
				}

				Expect(amd64Flavor).NotTo(BeNil())
				Expect(amd64Flavor.Regions).To(ConsistOf(
					v1alpha1.RegionAMIMapping{Name: "eu-west-1", AMI: "ami-123"},
					v1alpha1.RegionAMIMapping{Name: "us-east-1", AMI: "ami-456"},
				))

				Expect(arm64Flavor).NotTo(BeNil())
				Expect(arm64Flavor.Regions).To(ConsistOf(
					v1alpha1.RegionAMIMapping{Name: "eu-west-1", AMI: "ami-124"},
				))
			})

			It("should default to amd64 when architecture is not specified", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name: "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "20.04",
									Regions: []v1alpha1.RegionAMIMapping{
										{Name: "eu-west-1", AMI: "ami-123"}, // No architecture specified
									},
								},
							},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				version := result.MachineImages[0].Versions[0]
				Expect(version.CapabilityFlavors).To(HaveLen(1))
				Expect(version.CapabilityFlavors[0].Capabilities).To(Equal(v1beta1.Capabilities{"architecture": []string{"amd64"}}))
			})

			It("should preserve already capability-formatted data", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name: "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "20.04",
									CapabilityFlavors: []v1alpha1.MachineImageFlavor{
										{
											Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}},
											Regions:      []v1alpha1.RegionAMIMapping{{Name: "eu-west-1", AMI: "ami-123"}},
										},
									},
								},
							},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				version := result.MachineImages[0].Versions[0]
				Expect(version.CapabilityFlavors).To(HaveLen(1))
				Expect(version.CapabilityFlavors[0].Capabilities).To(Equal(v1beta1.Capabilities{"architecture": []string{"amd64"}}))
				Expect(version.CapabilityFlavors[0].Regions).To(ConsistOf(
					v1alpha1.RegionAMIMapping{Name: "eu-west-1", AMI: "ami-123"},
				))
			})
		})

		Context("when transforming to legacy format", func() {
			BeforeEach(func() {
				capabilityDefinitions = nil // No capability definitions means legacy format
			})

			It("should transform capability format to legacy format", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name: "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "20.04",
									CapabilityFlavors: []v1alpha1.MachineImageFlavor{
										{
											Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}},
											Regions:      []v1alpha1.RegionAMIMapping{{Name: "eu-west-1", AMI: "ami-123"}},
										},
										{
											Capabilities: v1beta1.Capabilities{"architecture": []string{"arm64"}},
											Regions:      []v1alpha1.RegionAMIMapping{{Name: "eu-west-1", AMI: "ami-124"}},
										},
									},
								},
							},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				version := result.MachineImages[0].Versions[0]
				Expect(version.CapabilityFlavors).To(BeEmpty()) // Should be empty in legacy format
				Expect(version.Regions).To(HaveLen(2))
				Expect(version.Regions).To(ConsistOf(
					v1alpha1.RegionAMIMapping{Name: "eu-west-1", AMI: "ami-123", Architecture: ptr.To("amd64")},
					v1alpha1.RegionAMIMapping{Name: "eu-west-1", AMI: "ami-124", Architecture: ptr.To("arm64")},
				))
			})

			It("should preserve already legacy-formatted data", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name: "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "20.04",
									Regions: []v1alpha1.RegionAMIMapping{
										{Name: "eu-west-1", AMI: "ami-123", Architecture: ptr.To("amd64")},
									},
								},
							},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				version := result.MachineImages[0].Versions[0]
				Expect(version.Regions).To(HaveLen(1))
				Expect(version.Regions[0]).To(Equal(v1alpha1.RegionAMIMapping{
					Name: "eu-west-1", AMI: "ami-123", Architecture: ptr.To("amd64"),
				}))
			})

			It("should default to amd64 when no architecture capability is found", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name: "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "20.04",
									CapabilityFlavors: []v1alpha1.MachineImageFlavor{
										{
											Capabilities: v1beta1.Capabilities{"other": []string{"value"}},
											Regions:      []v1alpha1.RegionAMIMapping{{Name: "eu-west-1", AMI: "ami-123"}},
										},
									},
								},
							},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				version := result.MachineImages[0].Versions[0]
				Expect(version.Regions).To(HaveLen(1))
				Expect(version.Regions[0].Architecture).To(Equal(ptr.To("amd64")))
			})
		})

		Context("when handling edge cases", func() {
			It("should handle empty machine images list", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				Expect(result.MachineImages).To(BeEmpty())
			})

			It("should handle machine image with no versions", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name:     "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				Expect(result.MachineImages).To(HaveLen(1))
				Expect(result.MachineImages[0].Name).To(Equal("ubuntu"))
				Expect(result.MachineImages[0].Versions).To(BeEmpty())
			})

			It("should handle version with no regions or capability flavors", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name: "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "20.04",
									// No regions or capability flavors
								},
							},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				version := result.MachineImages[0].Versions[0]
				Expect(version.Version).To(Equal("20.04"))
				Expect(version.Regions).To(BeEmpty())
				Expect(version.CapabilityFlavors).To(BeEmpty())
			})

			It("should handle multiple machine images", func() {
				config := &v1alpha1.CloudProfileConfig{
					MachineImages: []v1alpha1.MachineImages{
						{
							Name: "ubuntu",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "20.04",
									Regions: []v1alpha1.RegionAMIMapping{{Name: "eu-west-1", AMI: "ami-123"}},
								},
							},
						},
						{
							Name: "rhel",
							Versions: []v1alpha1.MachineImageVersion{
								{
									Version: "8.5",
									Regions: []v1alpha1.RegionAMIMapping{{Name: "us-east-1", AMI: "ami-456"}},
								},
							},
						},
					},
				}

				result := mutator.TransformProviderConfigToParentFormat(config, capabilityDefinitions)

				Expect(result.MachineImages).To(HaveLen(2))

				ubuntuImg := result.MachineImages[0]
				if ubuntuImg.Name != "ubuntu" {
					ubuntuImg = result.MachineImages[1]
				}
				Expect(ubuntuImg.Name).To(Equal("ubuntu"))

				rhelImg := result.MachineImages[0]
				if rhelImg.Name != "rhel" {
					rhelImg = result.MachineImages[1]
				}
				Expect(rhelImg.Name).To(Equal("rhel"))
			})
		})
	})
})

func decodeCloudProfileConfig(decoder runtime.Decoder, config *runtime.RawExtension) (*api.CloudProfileConfig, error) {
	cloudProfileConfig := &api.CloudProfileConfig{}
	if err := util.Decode(decoder, config.Raw, cloudProfileConfig); err != nil {
		return nil, err
	}
	return cloudProfileConfig, nil
}
