// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation_test

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/validation/field"

	. "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/validation"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

var _ = Describe("Secret validation", func() {
	Describe("#ValidateCloudProviderSecret", func() {
		const (
			namespace  = "test-namespace"
			secretName = "test-secret"
		)

		var (
			secret  *corev1.Secret
			fldPath *field.Path

			validAccessKeyID     = "AKIAIOSFODNN7EXAMPLE"                     // exactly 20 chars, uppercase alphanumeric
			validSecretAccessKey = "wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY" // exactly 40 chars, base64
		)

		BeforeEach(func() {
			secret = &corev1.Secret{
				ObjectMeta: metav1.ObjectMeta{
					Name:      secretName,
					Namespace: namespace,
				},
			}
			fldPath = field.NewPath("secret")
		})

		Context("Standard keys (camelCase)", func() {
			It("should pass with valid credentials", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass with valid credentials and region", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
					aws.Region:          []byte("us-east-1"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should fail when accessKeyID is missing", func() {
				secret.Data = map[string][]byte{
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("secret.data[accessKeyID]"),
				}))))
			})

			It("should fail when accessKeyID is empty", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(""),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("secret.data[accessKeyID]"),
				}))))
			})

			It("should fail when secretAccessKey is missing", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID: []byte(validAccessKeyID),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("secret.data[secretAccessKey]"),
				}))))
			})

			It("should fail when secretAccessKey is empty", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(""),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("secret.data[secretAccessKey]"),
				}))))
			})
		})

		Context("DNS keys (capitalized)", func() {
			It("should pass with valid credentials", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass with valid credentials and region", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte("eu-west-2"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should fail when AWS_ACCESS_KEY_ID is missing", func() {
				secret.Data = map[string][]byte{
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("secret.data[accessKeyID]"),
				}))))
			})

			It("should fail when AWS_ACCESS_KEY_ID is empty", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(""),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("secret.data[AWS_ACCESS_KEY_ID]"),
				}))))
			})

			It("should fail when AWS_SECRET_ACCESS_KEY is missing", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID: []byte(validAccessKeyID),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("secret.data[secretAccessKey]"),
				}))))
			})

			It("should fail when AWS_SECRET_ACCESS_KEY is empty", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(""),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeRequired),
					"Field": Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
				}))))
			})
		})

		Context("Mixed keys", func() {
			It("should pass when mixing standard accessKeyID with DNS secretAccessKey", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:        []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass when mixing DNS accessKeyID with standard secretAccessKey", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:  []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass when mixing standard credentials with DNS region", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:       []byte("us-west-2"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass when mixing DNS credentials with standard region", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.Region:             []byte("ap-southeast-1"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})
		})

		Context("Duplicate keys", func() {
			It("should fail when both standard and DNS accessKeyID are present", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.DNSAccessKeyID:  []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type": Equal(field.ErrorTypeInvalid),
				}))))
			})

			It("should fail when both standard and DNS secretAccessKey are present", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:        []byte(validAccessKeyID),
					aws.SecretAccessKey:    []byte(validSecretAccessKey),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type": Equal(field.ErrorTypeInvalid),
				}))))
			})

			It("should fail when both standard and DNS region are present", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
					aws.Region:          []byte("us-east-1"),
					aws.DNSRegion:       []byte("us-west-2"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type": Equal(field.ErrorTypeInvalid),
				}))))
			})

			It("should fail when all credential keys are duplicated", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:        []byte(validAccessKeyID),
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey:    []byte(validSecretAccessKey),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(Not(BeEmpty()))
				Expect(errs).To(HaveLen(2)) // Two duplicate errors
			})

			It("should fail when all keys including region are duplicated", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:        []byte(validAccessKeyID),
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey:    []byte(validSecretAccessKey),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.Region:             []byte("us-east-1"),
					aws.DNSRegion:          []byte("us-west-2"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(Not(BeEmpty()))
				Expect(errs).To(HaveLen(3)) // Three duplicate errors
			})
		})

		Context("AccessKeyID validation", func() {
			It("should fail when accessKeyID is too short", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL"), // 19 chars
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[accessKeyID]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when accessKeyID is too long", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPLE1"), // 21 chars
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[accessKeyID]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when accessKeyID contains lowercase characters", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNn7EXAMPLE"), // 20 chars but has lowercase 'n'
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[accessKeyID]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when accessKeyID contains invalid special characters", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"), // 20 chars but has underscore
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[accessKeyID]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when AWS_ACCESS_KEY_ID is too short", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL"), // 19 chars
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[AWS_ACCESS_KEY_ID]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when AWS_ACCESS_KEY_ID is too long", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte("AKIAIOSFODNN7EXAMPLE1"), // 21 chars
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[AWS_ACCESS_KEY_ID]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when AWS_ACCESS_KEY_ID contains lowercase characters", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte("AKIAIOSFODNn7EXAMPLE"), // 20 chars but has lowercase 'n'
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[AWS_ACCESS_KEY_ID]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when AWS_ACCESS_KEY_ID contains invalid special characters", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"), // 20 chars but has underscore
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[AWS_ACCESS_KEY_ID]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})
		})

		Context("SecretAccessKey validation", func() {
			It("should fail when secretAccessKey is too short", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEK"), // 38 chars, valid characters
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[secretAccessKey]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when secretAccessKey is too long", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY1"), // 41 chars, valid characters
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[secretAccessKey]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when secretAccessKey contains invalid characters", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI!K7MDENG#bPxRfiCYEXAMPLEKEY"), // 40 chars but has ! and #
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[secretAccessKey]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when AWS_SECRET_ACCESS_KEY is too short", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEK"), // 38 chars, valid characters
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when AWS_SECRET_ACCESS_KEY is too long", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY1"), // 41 chars, valid characters
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when AWS_SECRET_ACCESS_KEY contains invalid characters", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte("wJalrXUtnFEMI!K7MDENG#bPxRfiCYEXAMPLEKEY"), // 40 chars but has ! and #
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
					"BadValue": Equal("(hidden)"),
				}))))
			})

			It("should fail when both credentials are invalid", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("invalid123456789012_"),                     // 20 chars but has lowercase and underscore
					aws.SecretAccessKey: []byte("invalid12345678901234567890123456789012!"), // 40 chars but has ! and lowercase
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(Not(BeEmpty()))
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Field": Equal("secret.data[accessKeyID]"),
				}))))
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Field": Equal("secret.data[secretAccessKey]"),
				}))))
			})
		})

		Context("Region validation", func() {
			It("should pass with valid standard region", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
					aws.Region:          []byte("us-east-1"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass with valid DNS region", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte("eu-west-2"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass with valid GovCloud region", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte("us-gov-west-1"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass with valid multi-zone region", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte("ap-southeast-3"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass with valid EU sovereign cloud region", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte("eusc-de-east-1"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass when region field is empty", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte(""),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should pass when region field is missing", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(BeEmpty())
			})

			It("should fail when region format is invalid - missing zone number", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte("invalid-region"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("secret.data[AWS_REGION]"),
				}))))
			})

			It("should fail when region has uppercase characters", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte("US-EAST-1"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("secret.data[AWS_REGION]"),
				}))))
			})

			It("should fail when region is too long", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte("us-extremely-long-region-name-33c"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("secret.data[AWS_REGION]"),
				}))))
			})

			It("should fail when region contains invalid characters - underscore", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					aws.DNSRegion:          []byte("us_east_1"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("secret.data[AWS_REGION]"),
				}))))
			})

			It("should fail when region using camelCase key is invalid", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
					aws.Region:          []byte("invalid_region"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("secret.data[region]"),
				}))))
			})
		})

		Context("Unexpected keys", func() {
			It("should fail when unexpected key is present with standard keys", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
					"unexpectedKey":     []byte("someValue"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("secret.data[unexpectedKey]"),
				}))))
			})

			It("should fail when unexpected key is present with DNS keys", func() {
				secret.Data = map[string][]byte{
					aws.DNSAccessKeyID:     []byte(validAccessKeyID),
					aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					"unexpectedKey":        []byte("someValue"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("secret.data[unexpectedKey]"),
				}))))
			})

			It("should fail when multiple unexpected keys are present", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
					"unexpectedKey1":    []byte("someValue"),
					"unexpectedKey2":    []byte("anotherValue"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath)
				Expect(errs).To(HaveLen(2))
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type": Equal(field.ErrorTypeForbidden),
				}))))
			})
		})
	})
})
