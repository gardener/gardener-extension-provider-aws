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

		Context("Infrastructure Secrets", func() {
			It("should pass with valid complete AWS credentials", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(BeEmpty())
			})

			It("should fail when accessKeyID field is missing", func() {
				secret.Data = map[string][]byte{
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
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

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("secret.data[accessKeyID]"),
				}))))
			})

			It("should fail when accessKeyID is too short", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL"), // 19 chars
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[accessKeyID]"),
					"BadValue": Equal("AKIAIOSFODNN7EXAMPL"),
				}))))
			})

			It("should fail when accessKeyID is too long", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPLE1"), // 21 chars
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[accessKeyID]"),
					"BadValue": Equal("AKIAIOSFODNN7EXAMPLE1"),
				}))))
			})

			It("should fail when accessKeyID contains lowercase characters", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNn7EXAMPLE"), // 20 chars but has lowercase 'n'
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[accessKeyID]"),
					"BadValue": Equal("AKIAIOSFODNn7EXAMPLE"),
				}))))
			})

			It("should fail when accessKeyID contains invalid special characters", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"), // 20 chars but has underscore
					aws.SecretAccessKey: []byte(validSecretAccessKey),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[accessKeyID]"),
					"BadValue": Equal("AKIAIOSFODNN7EXAMPL_"),
				}))))
			})

			It("should fail when secretAccessKey field is missing", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID: []byte(validAccessKeyID),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
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

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("secret.data[secretAccessKey]"),
				}))))
			})

			It("should fail when secretAccessKey is too short", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKE"), // 39 chars
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[secretAccessKey]"),
					"BadValue": Equal("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKE"),
				}))))
			})

			It("should fail when secretAccessKey is too long", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY1"), // 41 chars
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[secretAccessKey]"),
					"BadValue": Equal("wJalrXUtnFEMI/K7MDEN+/=PxRfiCYEXAMPLEKEY1"),
				}))))
			})

			It("should fail when secretAccessKey contains invalid characters", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfi!#EXAMPLEKEY"), // 40 chars but has ! and #
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("secret.data[secretAccessKey]"),
					"BadValue": Equal("wJalrXUtnFEMI/K7MDEN+/=PxRfi!#EXAMPLEKEY"),
				}))))
			})

			It("should fail when both fields are invalid", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte("invalid1234567890123"),                     // 20 chars but invalid
					aws.SecretAccessKey: []byte("invalid12345678901234567890123456789012!"), // 40 chars but invalid
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(Not(BeEmpty()))
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Field": Equal("secret.data[accessKeyID]"),
				}))))
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Field": Equal("secret.data[secretAccessKey]"),
				}))))
			})

			It("should fail when unexpected key is present", func() {
				secret.Data = map[string][]byte{
					aws.AccessKeyID:     []byte(validAccessKeyID),
					aws.SecretAccessKey: []byte(validSecretAccessKey),
					"unexpectedKey":     []byte("someValue"),
				}

				errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindInfrastructure)
				Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
					"Type":  Equal(field.ErrorTypeForbidden),
					"Field": Equal("secret.data[unexpectedKey]"),
				}))))
			})
		})

		Context("DNS Secrets", func() {
			Context("with capitalized keys", func() {
				It("should pass with valid complete DNS credentials", func() {
					secret.Data = map[string][]byte{
						aws.DNSAccessKeyID:     []byte(validAccessKeyID),
						aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(BeEmpty())
				})

				It("should fail when AWS_ACCESS_KEY_ID field is missing", func() {
					secret.Data = map[string][]byte{
						aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
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

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeInvalid),
						"Field": Equal("secret.data[AWS_ACCESS_KEY_ID]"),
					}))))
				})

				It("should fail when AWS_ACCESS_KEY_ID is too short", func() {
					secret.Data = map[string][]byte{
						aws.DNSAccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL"), // 19 chars
						aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":     Equal(field.ErrorTypeInvalid),
						"Field":    Equal("secret.data[AWS_ACCESS_KEY_ID]"),
						"BadValue": Equal("AKIAIOSFODNN7EXAMPL"),
					}))))
				})

				It("should fail when AWS_ACCESS_KEY_ID is invalid", func() {
					secret.Data = map[string][]byte{
						aws.DNSAccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"), // 20 chars but invalid char
						aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":     Equal(field.ErrorTypeInvalid),
						"Field":    Equal("secret.data[AWS_ACCESS_KEY_ID]"),
						"BadValue": Equal("AKIAIOSFODNN7EXAMPL_"),
					}))))
				})

				It("should fail when AWS_SECRET_ACCESS_KEY field is missing", func() {
					secret.Data = map[string][]byte{
						aws.DNSAccessKeyID: []byte(validAccessKeyID),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
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

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeInvalid),
						"Field": Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
					}))))
				})

				It("should fail when AWS_SECRET_ACCESS_KEY is too short", func() {
					secret.Data = map[string][]byte{
						aws.DNSAccessKeyID:     []byte(validAccessKeyID),
						aws.DNSSecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfi!#EXAMPLEKE"), // 39 chars
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":     Equal(field.ErrorTypeInvalid),
						"Field":    Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
						"BadValue": Equal("wJalrXUtnFEMI/K7MDEN+/=PxRfi!#EXAMPLEKE"),
					}))))
				})

				It("should fail when AWS_SECRET_ACCESS_KEY is invalid", func() {
					secret.Data = map[string][]byte{
						aws.DNSAccessKeyID:     []byte(validAccessKeyID),
						aws.DNSSecretAccessKey: []byte("wJalrXUtnFEMI!K7MDENG#bPxRfiCYEXAMPLEKEY"), // 40 chars but invalid chars
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":     Equal(field.ErrorTypeInvalid),
						"Field":    Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
						"BadValue": Equal("wJalrXUtnFEMI!K7MDENG#bPxRfiCYEXAMPLEKEY"),
					}))))
				})

				It("should fail when unexpected key is present", func() {
					secret.Data = map[string][]byte{
						aws.DNSAccessKeyID:     []byte(validAccessKeyID),
						aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
						"unexpectedKey":        []byte("someValue"),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeForbidden),
						"Field": Equal("secret.data[unexpectedKey]"),
					}))))
				})
			})

			Context("with camelCase keys (fallback)", func() {
				It("should pass with valid complete DNS credentials using camelCase keys", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:     []byte(validAccessKeyID),
						aws.SecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(BeEmpty())
				})

				It("should fail when accessKeyID field is missing", func() {
					secret.Data = map[string][]byte{
						aws.SecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("secret.data[accessKeyID]"),
					}))))
				})

				It("should fail when accessKeyID is too short", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL"), // 19 chars
						aws.SecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":     Equal(field.ErrorTypeInvalid),
						"Field":    Equal("secret.data[accessKeyID]"),
						"BadValue": Equal("AKIAIOSFODNN7EXAMPL"),
					}))))
				})

				It("should fail when accessKeyID is invalid", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:     []byte("AKIAIOSFODNN7EXAMPL_"), // 20 chars but invalid char
						aws.SecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":     Equal(field.ErrorTypeInvalid),
						"Field":    Equal("secret.data[accessKeyID]"),
						"BadValue": Equal("AKIAIOSFODNN7EXAMPL_"),
					}))))
				})

				It("should fail when secretAccessKey field is missing", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID: []byte(validAccessKeyID),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeRequired),
						"Field": Equal("secret.data[secretAccessKey]"),
					}))))
				})

				It("should fail when secretAccessKey is too short", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:     []byte(validAccessKeyID),
						aws.SecretAccessKey: []byte("wJalrXUtnFEMI/K7MDEN+/=PxRfi!#EXAMPLEKE"), // 39 chars
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":     Equal(field.ErrorTypeInvalid),
						"Field":    Equal("secret.data[secretAccessKey]"),
						"BadValue": Equal("wJalrXUtnFEMI/K7MDEN+/=PxRfi!#EXAMPLEKE"),
					}))))
				})

				It("should fail when secretAccessKey is invalid", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:     []byte(validAccessKeyID),
						aws.SecretAccessKey: []byte("wJalrXUtnFEMI!K7MDENG#bPxRfiCYEXAMPLEKEY"), // 40 chars but invalid chars
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":     Equal(field.ErrorTypeInvalid),
						"Field":    Equal("secret.data[secretAccessKey]"),
						"BadValue": Equal("wJalrXUtnFEMI!K7MDENG#bPxRfiCYEXAMPLEKEY"),
					}))))
				})

				It("should fail when unexpected key is present", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:     []byte(validAccessKeyID),
						aws.SecretAccessKey: []byte(validSecretAccessKey),
						"unexpectedKey":     []byte("someValue"),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeForbidden),
						"Field": Equal("secret.data[unexpectedKey]"),
					}))))
				})
			})

			Context("with mixed keys", func() {
				It("should fail when both standard and DNS alias keys are present for accessKeyID", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:     []byte(validAccessKeyID),
						aws.DNSAccessKeyID:  []byte(validAccessKeyID),
						aws.SecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeForbidden),
						"Field": Equal("secret.data[AWS_ACCESS_KEY_ID]"),
					}))))
				})

				It("should fail when both standard and DNS alias keys are present for secretAccessKey", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:        []byte(validAccessKeyID),
						aws.SecretAccessKey:    []byte(validSecretAccessKey),
						aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeForbidden),
						"Field": Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
					}))))
				})

				It("should fail when mixing one standard key with one DNS alias key", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:        []byte(validAccessKeyID),
						aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeForbidden),
						"Field": Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
					}))))
				})

				It("should fail when all four keys are present", func() {
					secret.Data = map[string][]byte{
						aws.AccessKeyID:        []byte(validAccessKeyID),
						aws.DNSAccessKeyID:     []byte(validAccessKeyID),
						aws.SecretAccessKey:    []byte(validSecretAccessKey),
						aws.DNSSecretAccessKey: []byte(validSecretAccessKey),
					}

					errs := ValidateCloudProviderSecret(secret, fldPath, SecretKindDns)
					Expect(errs).To(Not(BeEmpty()))
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeForbidden),
						"Field": Equal("secret.data[AWS_ACCESS_KEY_ID]"),
					}))))
					Expect(errs).To(ContainElement(PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeForbidden),
						"Field": Equal("secret.data[AWS_SECRET_ACCESS_KEY]"),
					}))))
				})
			})
		})

		Context("Invalid Secret Kind", func() {
			It("should fail with unsupported secret kind", func() {
				errs := ValidateCloudProviderSecret(secret, fldPath, "invalid-kind")

				Expect(errs).To(ConsistOf(
					PointTo(MatchFields(IgnoreExtras, Fields{
						"Type":  Equal(field.ErrorTypeInvalid),
						"Field": Equal("secret"),
					})),
				))
			})
		})
	})
})
