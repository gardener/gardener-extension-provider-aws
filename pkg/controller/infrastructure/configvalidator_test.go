// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go/aws/awserr"
	"github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	mockclient "github.com/gardener/gardener/pkg/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/pkg/mock/controller-runtime/manager"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gstruct"
	gomegatypes "github.com/onsi/gomega/types"
	"go.uber.org/mock/gomock"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"
	"k8s.io/utils/pointer"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure"
)

const (
	name      = "infrastructure"
	namespace = "shoot--foobar--aws"
	region    = "eu-west-1"
	vpcID     = "vpc-123456"

	accessKeyID     = "accessKeyID"
	secretAccessKey = "secretAccessKey"
)

var _ = Describe("ConfigValidator", func() {
	var (
		ctrl             *gomock.Controller
		c                *mockclient.MockClient
		awsClientFactory *mockawsclient.MockFactory
		awsClient        *mockawsclient.MockInterface
		ctx              context.Context
		logger           logr.Logger
		cv               infrastructure.ConfigValidator
		infra            *extensionsv1alpha1.Infrastructure
		secret           *corev1.Secret

		mgr *mockmanager.MockManager
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())

		c = mockclient.NewMockClient(ctrl)
		awsClientFactory = mockawsclient.NewMockFactory(ctrl)
		awsClient = mockawsclient.NewMockInterface(ctrl)

		ctx = context.TODO()
		logger = log.Log.WithName("test")

		mgr = mockmanager.NewMockManager(ctrl)
		mgr.EXPECT().GetClient().Return(c)

		cv = NewConfigValidator(mgr, awsClientFactory, logger)

		infra = &extensionsv1alpha1.Infrastructure{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Spec: extensionsv1alpha1.InfrastructureSpec{
				DefaultSpec: extensionsv1alpha1.DefaultSpec{
					Type: aws.Type,
					ProviderConfig: &runtime.RawExtension{
						Raw: encode(&apisaws.InfrastructureConfig{
							Networks: apisaws.Networks{
								VPC: apisaws.VPC{
									ID: pointer.String(vpcID),
								},
							},
						}),
					},
				},
				Region: region,
				SecretRef: corev1.SecretReference{
					Name:      name,
					Namespace: namespace,
				},
			},
		}
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      name,
				Namespace: namespace,
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				aws.AccessKeyID:     []byte(accessKeyID),
				aws.SecretAccessKey: []byte(secretAccessKey),
			},
		}
	})

	AfterEach(func() {
		ctrl.Finish()
	})

	Describe("#Validate", func() {
		var (
			validDHCPOptions map[string]string
		)

		BeforeEach(func() {
			c.EXPECT().Get(ctx, kutil.Key(namespace, name), gomock.AssignableToTypeOf(&corev1.Secret{})).DoAndReturn(
				func(_ context.Context, _ client.ObjectKey, obj *corev1.Secret, _ ...client.GetOption) error {
					*obj = *secret
					return nil
				},
			)
			awsClientFactory.EXPECT().NewClient(accessKeyID, secretAccessKey, region).Return(awsClient, nil)

			validDHCPOptions = map[string]string{
				"domain-name": region + ".compute.internal",
			}
		})

		It("should forbid VPC that doesn't exist", func() {
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, "enableDnsSupport").Return(false, awserr.New("InvalidVpcID.NotFound", "", nil))

			errorList := cv.Validate(ctx, infra)
			Expect(errorList).To(ConsistOfFields(Fields{
				"Type":  Equal(field.ErrorTypeNotFound),
				"Field": Equal("networks.vpc.id"),
			}))
		})

		It("should forbid VPC that exists but has wrong attribute values or no attached internet gateway", func() {
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, "enableDnsSupport").Return(false, nil)
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, "enableDnsHostnames").Return(false, nil)
			awsClient.EXPECT().GetVPCInternetGateway(ctx, vpcID).Return("", nil)
			awsClient.EXPECT().GetDHCPOptions(ctx, vpcID).Return(validDHCPOptions, nil)

			errorList := cv.Validate(ctx, infra)
			Expect(errorList).To(ConsistOfFields(Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("networks.vpc.id"),
				"Detail": Equal("VPC attribute enableDnsSupport must be set to true"),
			}, Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("networks.vpc.id"),
				"Detail": Equal("VPC attribute enableDnsHostnames must be set to true"),
			}, Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("networks.vpc.id"),
				"Detail": Equal("no attached internet gateway found"),
			}))
		})

		It("should allow VPC that exists and has correct attribute values and an attached internet gateway", func() {
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, "enableDnsSupport").Return(true, nil)
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, "enableDnsHostnames").Return(true, nil)
			awsClient.EXPECT().GetVPCInternetGateway(ctx, vpcID).Return(vpcID, nil)
			awsClient.EXPECT().GetDHCPOptions(ctx, vpcID).Return(validDHCPOptions, nil)

			errorList := cv.Validate(ctx, infra)
			Expect(errorList).To(BeEmpty())
		})

		It("should fail with InternalError if getting VPC attributes failed", func() {
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, "enableDnsSupport").Return(false, errors.New("test"))

			errorList := cv.Validate(ctx, infra)
			Expect(errorList).To(ConsistOfFields(Fields{
				"Type":   Equal(field.ErrorTypeInternal),
				"Field":  Equal("networks.vpc.id"),
				"Detail": Equal(fmt.Sprintf("could not get VPC attribute enableDnsSupport for VPC %s: test", vpcID)),
			}))
		})

		DescribeTable("validate DHCP options", func(newRegion string, mapping map[string]string, err error, matcher gomegatypes.GomegaMatcher) {
			if newRegion != "" {
				infra.Spec.Region = newRegion
				awsClientFactory.NewClient(accessKeyID, secretAccessKey, region) //nolint:errcheck
				awsClientFactory.EXPECT().NewClient(accessKeyID, secretAccessKey, newRegion).Return(awsClient, nil)
			}

			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, "enableDnsSupport").Return(true, nil)
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, "enableDnsHostnames").Return(true, nil)
			awsClient.EXPECT().GetVPCInternetGateway(ctx, vpcID).Return(vpcID, nil)
			awsClient.EXPECT().GetDHCPOptions(ctx, vpcID).Return(mapping, err)

			errorList := cv.Validate(ctx, infra)
			Expect(errorList).To(matcher)
		},
			Entry("should allow VPC with correctly configurated DHCP options", "", map[string]string{
				"domain-name": region + ".compute.internal",
			}, nil, BeEmpty()),
			Entry("should allow VPC with correctly configurated DHCP options and domain-name 'us-east-1`", "us-east-1", map[string]string{
				"domain-name": "ec2.internal",
			}, nil, BeEmpty()),
			Entry("should fail with InternalError if getting DHCP options failed", "", nil, fmt.Errorf("test"), ConsistOfFields(Fields{
				"Type":   Equal(field.ErrorTypeInternal),
				"Field":  Equal("networks.vpc.id"),
				"Detail": Equal(fmt.Sprintf("could not get DHCP options for VPC %s: test", vpcID)),
			})),
			Entry("should fail with DHCP options that do not contain domain-name", "", map[string]string{}, nil, ConsistOfFields(Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("networks.vpc.id"),
				"Detail": Equal("missing domain-name value in DHCP options used by the VPC"),
			})),
			Entry("should fail with invalid DHCP options for domain-name", "", map[string]string{
				"domain-name": "ec2.test",
			}, nil, ConsistOfFields(Fields{
				"Type":   Equal(field.ErrorTypeInvalid),
				"Field":  Equal("networks.vpc.id"),
				"Detail": Equal("invalid domain-name specified in DHCP options used by VPC: ec2.test"),
			})),
		)

		Describe("validate Elastic IP addresses", func() {
			BeforeEach(func() {
				infra.Spec.ProviderConfig.Raw = encode(&apisaws.InfrastructureConfig{
					Networks: apisaws.Networks{
						VPC: apisaws.VPC{},
						Zones: []apisaws.Zone{
							{
								ElasticIPAllocationID: pointer.String("eipalloc-0e2669d4b46150ee4"),
							},
							{
								ElasticIPAllocationID: pointer.String("eipalloc-0e2669d4b46150ee5"),
							},
							{
								ElasticIPAllocationID: pointer.String("eipalloc-0e2669d4b46150ee6"),
							},
						},
					},
				})
			})

			It("should succeed - no EIPs configured", func() {
				infra.Spec.ProviderConfig.Raw = encode(&apisaws.InfrastructureConfig{
					Networks: apisaws.Networks{
						VPC: apisaws.VPC{},
					},
				})
				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(BeEmpty())
			})

			It("should succeed - all EIPs exist and are already associated to the Shoot's NAT Gateways", func() {
				mapping := map[string]*string{
					"eipalloc-0e2669d4b46150ee4": pointer.String("eipassoc-0f8ff66536587824b"),
					"eipalloc-0e2669d4b46150ee5": pointer.String("eipassoc-0f8ff66536587824c"),
					"eipalloc-0e2669d4b46150ee6": pointer.String("eipassoc-0f8ff66536587824d"),
				}
				awsClient.EXPECT().GetElasticIPsAssociationIDForAllocationIDs(ctx, gomock.Any()).Return(mapping, nil)
				awsClient.EXPECT().GetNATGatewayAddressAllocations(ctx, infra.Namespace).Return(sets.New[string]("eipalloc-0e2669d4b46150ee4", "eipalloc-0e2669d4b46150ee5", "eipalloc-0e2669d4b46150ee6"), nil)

				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(BeEmpty())
			})

			It("should succeed - all EIPs exist, but are not associated to any resource yet", func() {
				mapping := map[string]*string{
					"eipalloc-0e2669d4b46150ee4": nil,
					"eipalloc-0e2669d4b46150ee5": nil,
					"eipalloc-0e2669d4b46150ee6": nil,
				}
				awsClient.EXPECT().GetElasticIPsAssociationIDForAllocationIDs(ctx, gomock.Any()).Return(mapping, nil)

				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(BeEmpty())
			})

			It("should fail - the Elastic IP Address for the given allocation ID does not exist", func() {
				empty := make(map[string]*string)
				awsClient.EXPECT().GetElasticIPsAssociationIDForAllocationIDs(ctx, []string{"eipalloc-0e2669d4b46150ee4", "eipalloc-0e2669d4b46150ee5", "eipalloc-0e2669d4b46150ee6"}).Return(empty, nil)

				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("networks.zones[].elasticIPAllocationID"),
					"BadValue": Equal("eipalloc-0e2669d4b46150ee4"),
					"Detail":   ContainSubstring("cannot be used as it does not exist"),
				}, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("networks.zones[].elasticIPAllocationID"),
					"BadValue": Equal("eipalloc-0e2669d4b46150ee5"),
					"Detail":   ContainSubstring("cannot be used as it does not exist"),
				}, Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("networks.zones[].elasticIPAllocationID"),
					"BadValue": Equal("eipalloc-0e2669d4b46150ee6"),
					"Detail":   ContainSubstring("cannot be used as it does not exist"),
				},
				))
			})

			It("should fail - some of the Elastic IP Addresses exist, some do not", func() {
				mapping := map[string]*string{
					"eipalloc-0e2669d4b46150ee4": pointer.String("eipassoc-0f8ff66536587824b"),
					"eipalloc-0e2669d4b46150ee5": pointer.String("eipassoc-0f8ff66536587824c"),
				}
				awsClient.EXPECT().GetElasticIPsAssociationIDForAllocationIDs(ctx, gomock.Any()).Return(mapping, nil)
				awsClient.EXPECT().GetNATGatewayAddressAllocations(ctx, infra.Namespace).Return(sets.New[string]("eipalloc-0e2669d4b46150ee4", "eipalloc-0e2669d4b46150ee5"), nil)

				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("networks.zones[].elasticIPAllocationID"),
					"BadValue": Equal("eipalloc-0e2669d4b46150ee6"),
					"Detail":   ContainSubstring("cannot be used as it does not exist"),
				}))
			})

			It("should fail - Elastic IP Addresses exist are already associated with another resource", func() {
				mapping := map[string]*string{
					"eipalloc-0e2669d4b46150ee4": pointer.String("eipassoc-0f8ff66536587824b"),
					"eipalloc-0e2669d4b46150ee5": pointer.String("eipassoc-0f8ff66536587824c"),
					"eipalloc-0e2669d4b46150ee6": pointer.String("eipassoc-0f8ff66536587824d"),
				}
				awsClient.EXPECT().GetElasticIPsAssociationIDForAllocationIDs(ctx, gomock.Any()).Return(mapping, nil)
				awsClient.EXPECT().GetNATGatewayAddressAllocations(ctx, infra.Namespace).Return(sets.New[string]("eipalloc-0e2669d4b46150ee4", "eipalloc-0e2669d4b46150ee5"), nil)

				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":     Equal(field.ErrorTypeInvalid),
					"Field":    Equal("networks.zones[].elasticIPAllocationID"),
					"BadValue": Equal("eipalloc-0e2669d4b46150ee6"),
					"Detail":   ContainSubstring("cannot be attached to the clusters NAT Gateway(s) as it is already associated"),
				}))
			})
		})
	})
})

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}
