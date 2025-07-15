// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator_test

import (
	"context"
	"encoding/json"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	core "github.com/gardener/gardener/pkg/apis/core"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"go.uber.org/mock/gomock"
	"k8s.io/apimachinery/pkg/runtime"

	"github.com/gardener/gardener-extension-provider-aws/pkg/admission/validator"
	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	apisawsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

var _ = Describe("Seed Validator", func() {
	var (
		ctrl          *gomock.Controller
		mgr           *mockmanager.MockManager
		c             *mockclient.MockClient
		seedValidator extensionswebhook.Validator
		scheme        *runtime.Scheme
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())

		scheme = runtime.NewScheme()
		Expect(core.AddToScheme(scheme)).To(Succeed())
		Expect(apisaws.AddToScheme(scheme)).To(Succeed())
		Expect(apisawsv1alpha1.AddToScheme(scheme)).To(Succeed())
		Expect(gardencorev1beta1.AddToScheme(scheme)).To(Succeed())
		c = mockclient.NewMockClient(ctrl)

		mgr = mockmanager.NewMockManager(ctrl)
		mgr.EXPECT().GetScheme().Return(scheme).AnyTimes()
		mgr.EXPECT().GetClient().Return(c).AnyTimes()
		seedValidator = validator.NewSeedValidator(mgr)
	})

	// Helper function to generate Seed objects
	generateSeed := func(retentionType, retentionPeriod string, mode string, isImmutableConfigured bool) *core.Seed {
		var config *runtime.RawExtension
		if isImmutableConfigured {

			immutability := make(map[string]interface{})
			if retentionType != "" {
				immutability["retentionType"] = retentionType
			}
			if retentionPeriod != "" {
				immutability["retentionPeriod"] = retentionPeriod
				immutability["mode"] = mode
			}

			backupBucketConfig := map[string]interface{}{
				"apiVersion":   "aws.provider.extensions.gardener.cloud/v1alpha1",
				"kind":         "BackupBucketConfig",
				"immutability": immutability,
			}
			raw, err := json.Marshal(backupBucketConfig)
			Expect(err).NotTo(HaveOccurred())
			config = &runtime.RawExtension{
				Raw: raw,
			}
		} else {
			config = nil
		}

		var backup *core.Backup
		if config != nil {
			backup = &core.Backup{
				ProviderConfig: config,
			}
		}

		return &core.Seed{
			Spec: core.SeedSpec{
				Backup: backup,
			},
		}
	}

	Describe("ValidateUpdate", func() {
		DescribeTable("Valid update scenarios",
			func(oldSeed, newSeed *core.Seed) {
				err := seedValidator.Validate(context.Background(), newSeed, oldSeed)
				Expect(err).NotTo(HaveOccurred())
			},
			Entry("Immutable settings unchanged",
				generateSeed("bucket", "96h", "governance", true),
				generateSeed("bucket", "96h", "governance", true),
			),
			Entry("Immutable settings change the mode: governance to compliance",
				generateSeed("bucket", "24h", "governance", true),
				generateSeed("bucket", "24h", "compliance", true),
			),
			Entry("Retention period increased with mode: governance",
				generateSeed("bucket", "24h", "governance", true),
				generateSeed("bucket", "48h", "governance", true),
			),
			Entry("Retention period increased with mode: compliance",
				generateSeed("bucket", "24h", "compliance", true),
				generateSeed("bucket", "48h", "compliance", true),
			),
			Entry("Retention period decreased with mode: governance",
				generateSeed("bucket", "96h", "governance", true),
				generateSeed("bucket", "48h", "governance", true),
			),
			// TODO: @ishan16696 to be remove this test case, once immutability can't be disable
			Entry("Disabling immutability",
				generateSeed("bucket", "96h", "governance", true),
				generateSeed("", "", "", false),
			),
			Entry("Backup not configured",
				generateSeed("", "", "", false),
				generateSeed("", "", "", false),
			),
		)

		DescribeTable("Invalid update scenarios",
			func(oldSeed, newSeed *core.Seed, expectedError string) {
				err := seedValidator.Validate(context.Background(), newSeed, oldSeed)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedError))
			},
			Entry("Reducing retention period in compliance mode is not allowed",
				generateSeed("bucket", "96h", "compliance", true),
				generateSeed("bucket", "48h", "compliance", true),
				"reducing the retention period from",
			),
			Entry("Changing the mode from compliance to governance is not allowed",
				generateSeed("bucket", "96h", "compliance", true),
				generateSeed("bucket", "96h", "governance", true),
				"mode can't be change to governance once it is compliance",
			),
			Entry("Changing retentionType is not allowed",
				generateSeed("bucket", "96h", "compliance", true),
				generateSeed("object", "96h", "compliance", true),
				"must be 'bucket'",
			),
			Entry("Retention period below minimum in any mode is not allowed",
				generateSeed("bucket", "96h", "compliance", true),
				generateSeed("bucket", "23h", "compliance", true),
				"it can't be less than 24hour",
			),
			Entry("Retention period not multiple of 24hours is not allowed",
				generateSeed("bucket", "96h", "compliance", true),
				generateSeed("bucket", "100h", "compliance", true),
				"must be a multiple of 24hour",
			),
			Entry("Invalid retention period format is not allowed",
				generateSeed("bucket", "96h", "compliance", true),
				generateSeed("bucket", "invalid", "compliance", true),
				"invalid duration",
			),
		)
	})

	Describe("ValidateCreate", func() {
		DescribeTable("Valid creation scenarios",
			func(newSeed *core.Seed) {
				err := seedValidator.Validate(context.Background(), newSeed, nil)
				Expect(err).NotTo(HaveOccurred())
			},
			Entry("Creation with valid immutable settings",
				generateSeed("bucket", "96h", "compliance", true),
			),
			Entry("Creation without immutable settings",
				generateSeed("", "", "", false),
			),
			Entry("Creation with compliance mode immutable settings",
				generateSeed("bucket", "96h", "compliance", true),
			),
			Entry("Retention period exactly at minimum (24h) with mode: governance",
				generateSeed("bucket", "24h", "governance", true),
			),
			Entry("Retention period of 3 days i.e 72h",
				generateSeed("bucket", "72h", "governance", true),
			),
			Entry("Backup not configured",
				generateSeed("", "", "", false),
			),
		)

		DescribeTable("Invalid creation scenarios",
			func(newSeed *core.Seed, expectedError string) {
				err := seedValidator.Validate(context.Background(), newSeed, nil)
				Expect(err).To(HaveOccurred())
				Expect(err.Error()).To(ContainSubstring(expectedError))
			},
			Entry("Invalid retention type",
				generateSeed("invalid", "96h", "governance", true),
				"must be 'bucket'",
			),
			Entry("Invalid retention period format",
				&core.Seed{
					Spec: core.SeedSpec{
						Backup: &core.Backup{
							ProviderConfig: &runtime.RawExtension{
								Raw: []byte(`{
									"apiVersion": "aws.provider.extensions.gardener.cloud/v1alpha1",
									"kind": "BackupBucketConfig",
									"immutability":{
										"retentionType": "bucket",
										"retentionPeriod": "invalid",
										"mode": "compliance"
									}
								}`),
							},
						},
					},
				},
				"invalid duration",
			),
			Entry("Negative retention period",
				generateSeed("bucket", "-96h", "compliance", true),
				"can't be less than 24hour",
			),
			Entry("Retention period below minimum retention period",
				generateSeed("bucket", "23h", "compliance", true),
				"can't be less than 24hour",
			),
			Entry("Retention period not multiple of 24h",
				generateSeed("bucket", "100h", "compliance", true),
				"must be a multiple of 24hour",
			),
			Entry("Invalid mode",
				generateSeed("bucket", "72h", "invalid", true),
				"should be either compliance mode or governance mode",
			),
			Entry("Invalid retention period format",
				generateSeed("bucket", "invalid", "compliance", true),
				"invalid duration",
			),
		)
	})
})
