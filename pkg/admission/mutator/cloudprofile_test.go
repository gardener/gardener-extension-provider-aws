// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package mutator_test

import (
	"context"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	"github.com/gardener/gardener/pkg/utils/test"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/mutator"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/install"
)

var _ = Describe("CloudProfile Mutator", func() {
	var (
		fakeClient  client.Client
		fakeManager manager.Manager
		ctx         = context.Background()

		cloudProfileMutator extensionswebhook.Mutator
		cloudProfile        *v1beta1.CloudProfile
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

		cloudProfileMutator = mutator.NewCloudProfileMutator(fakeManager)

		imageVersion := "1.0.0"
		latestImageVersion := "1.0.1"
		imageName := "os-1"

		machineImages := []v1beta1.MachineImage{
			{
				Name: imageName,
				Versions: []v1beta1.MachineImageVersion{{
					ExpirableVersion: v1beta1.ExpirableVersion{
						Version: imageVersion,
					},
				}, {
					ExpirableVersion: v1beta1.ExpirableVersion{
						Version: latestImageVersion,
					},
				},
				},
			},
		}

		cloudProfile = &v1beta1.CloudProfile{
			ObjectMeta: metav1.ObjectMeta{
				Name: "aws",
			},
			Spec: v1beta1.CloudProfileSpec{
				MachineImages: machineImages,
			},
		}
	})

	Describe("#Mutate", func() {
		Context("CloudProfile without machineCapabilities", func() {
			BeforeEach(func() {
				cloudProfile.Spec.ProviderConfig = nil
			})

			It("should succeed and not modify the CloudProfile", func() {
				cloudProfile.Spec.ProviderConfig = &runtime.RawExtension{Raw: []byte(`{
"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1",
"kind":"CloudProfileConfig",
"machineImages":[
  {"name":"image-1","versions":[{"version":"1.1","regions":[{"name":"eu2","ami":"ami-124","architecture":"armhf"}]}]}
]}`)}
				expectedProfileSpec := cloudProfile.Spec.DeepCopy()
				Expect(cloudProfileMutator.Mutate(ctx, cloudProfile, nil)).To(Succeed())

				Expect(cloudProfile.Spec.MachineImages).To(Equal(expectedProfileSpec.MachineImages))
			})
		})

		Context("CloudProfile with machineCapabilities", func() {
			BeforeEach(func() {
				cloudProfile.Spec.MachineCapabilities = []v1beta1.CapabilityDefinition{{
					Name:   "architecture",
					Values: []string{"amd64", "arm64", "armhf"},
				}, {
					Name:   "gpu",
					Values: []string{"true", "false"},
				}}
			})
			It("should succeed for CloudProfile without provider config", func() {
				expectedProfile := cloudProfile.DeepCopy()
				Expect(cloudProfileMutator.Mutate(ctx, cloudProfile, nil)).To(Succeed())
				Expect(cloudProfile).To(Equal(expectedProfile))

			})

			It("should skip if CloudProfile is in deletion phase", func() {
				cloudProfile.DeletionTimestamp = ptr.To(metav1.Now())
				expectedProfile := cloudProfile.DeepCopy()

				Expect(cloudProfileMutator.Mutate(ctx, cloudProfile, nil)).To(Succeed())

				Expect(cloudProfile).To(Equal(expectedProfile))
			})

			It("should fill capabilityFlavors based on provider config", func() {
				image1AmiMappings := `"capabilityFlavors":[
{"capabilities":{"architecture":["arm64"]},"regions":[{"name":"image-region-1","ami":"id-img-reg-1"}]},
{"capabilities":{"architecture":["amd64"]},"regions":[{"name":"image-region-2","ami":"id-img-reg-2"}]}
]`
				image1FallbackMappings := `"capabilityFlavors":[
{"capabilities":{"architecture":["amd64"]},"regions":[{"name":"image-region-2","ami":"id-img-reg-2"}]}
]`

				cloudProfile.Spec.ProviderConfig = &runtime.RawExtension{Raw: []byte(fmt.Sprintf(`{
"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1",
"kind":"CloudProfileConfig",
"machineImages":[
  {"name":"os-1","versions":[
	{"version":"1.0.0",%s},
    {"version":"1.0.1",%s}
  ]}
]}`, image1AmiMappings, image1FallbackMappings))}
				Expect(cloudProfileMutator.Mutate(ctx, cloudProfile, nil)).To(Succeed())
				Expect(cloudProfile.Spec.MachineImages).To(Equal([]v1beta1.MachineImage{
					{
						Name: "os-1",
						Versions: []v1beta1.MachineImageVersion{
							{
								ExpirableVersion: v1beta1.ExpirableVersion{Version: "1.0.0"},
								CapabilityFlavors: []v1beta1.MachineImageFlavor{
									{Capabilities: v1beta1.Capabilities{"architecture": []string{"arm64"}}},
									{Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}}},
								},
							},
							{
								ExpirableVersion: v1beta1.ExpirableVersion{Version: "1.0.1"},
								CapabilityFlavors: []v1beta1.MachineImageFlavor{
									{Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}}},
								},
							},
						},
					},
				}))
			})

			It("should overwrite capabilityFlavors when some versions already have them", func() {
				twoFlavors := `"capabilityFlavors":[
{"capabilities":{"architecture":["arm64"]},"regions":[{"name":"image-region-1","ami":"id-img-reg-1"}]},
{"capabilities":{"architecture":["amd64"]},"regions":[{"name":"image-region-2","ami":"id-img-reg-2"}]}
]`
				oneFlavors := `"capabilityFlavors":[
{"capabilities":{"architecture":["amd64"]},"regions":[{"name":"image-region-2","ami":"id-img-reg-2"}]}
]`
				cloudProfile.Spec.MachineImages = []v1beta1.MachineImage{
					{
						Name: "os-1",
						Versions: []v1beta1.MachineImageVersion{
							{
								ExpirableVersion: v1beta1.ExpirableVersion{Version: "1.0.0"},
								CapabilityFlavors: []v1beta1.MachineImageFlavor{
									{Capabilities: v1beta1.Capabilities{"architecture": []string{"not-existing"}}},
									{Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}}},
								},
							},
							{ExpirableVersion: v1beta1.ExpirableVersion{Version: "1.0.1"}},
						},
					},
					{
						Name: "os-2",
						Versions: []v1beta1.MachineImageVersion{
							{ExpirableVersion: v1beta1.ExpirableVersion{Version: "1.0.0"}},
							{ExpirableVersion: v1beta1.ExpirableVersion{Version: "1.0.1"}},
						},
					},
				}
				cloudProfile.Spec.ProviderConfig = &runtime.RawExtension{Raw: []byte(fmt.Sprintf(`{
"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1",
"kind":"CloudProfileConfig",
"machineImages":[
  {"name":"os-1","versions":[
	{"version":"1.0.0",%s},
	{"version":"1.0.1",%s}
  ]},
 {"name":"os-2","versions":[
	{"version":"1.0.0",%s},
	{"version":"1.0.1",%s}
  ]}
]}`, twoFlavors, oneFlavors, oneFlavors, twoFlavors))}
				Expect(cloudProfileMutator.Mutate(ctx, cloudProfile, nil)).To(Succeed())
				Expect(cloudProfile.Spec.MachineImages).To(HaveLen(2))
				Expect(cloudProfile.Spec.MachineImages[0].Name).To(Equal("os-1"))
				Expect(cloudProfile.Spec.MachineImages[0].Versions).To(HaveLen(2))
				Expect(cloudProfile.Spec.MachineImages[0].Versions[0].Version).To(Equal("1.0.0"))
				// the existing capabilityFlavors should be overwritten.
				Expect(cloudProfile.Spec.MachineImages[0].Versions[0].CapabilityFlavors).To(ConsistOf([]v1beta1.MachineImageFlavor{
					{Capabilities: v1beta1.Capabilities{"architecture": []string{"arm64"}}},
					{Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}}},
				}))
				Expect(cloudProfile.Spec.MachineImages[0].Versions[1].Version).To(Equal("1.0.1"))
				Expect(cloudProfile.Spec.MachineImages[0].Versions[1].CapabilityFlavors).To(ConsistOf([]v1beta1.MachineImageFlavor{
					{Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}}},
				}))
				// The second machine image should be added completely.
				Expect(cloudProfile.Spec.MachineImages[1].Versions).To(HaveLen(2))
				Expect(cloudProfile.Spec.MachineImages[1].Versions[0].Version).To(Equal("1.0.0"))
				Expect(cloudProfile.Spec.MachineImages[1].Versions[0].CapabilityFlavors).To(ConsistOf([]v1beta1.MachineImageFlavor{
					{Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}}},
				}))
				Expect(cloudProfile.Spec.MachineImages[1].Versions[1].Version).To(Equal("1.0.1"))
				Expect(cloudProfile.Spec.MachineImages[1].Versions[1].CapabilityFlavors).To(ConsistOf([]v1beta1.MachineImageFlavor{
					{Capabilities: v1beta1.Capabilities{"architecture": []string{"arm64"}}},
					{Capabilities: v1beta1.Capabilities{"architecture": []string{"amd64"}}},
				}))

			})
		})

	})
})
