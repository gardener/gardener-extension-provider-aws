// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	mockclient "github.com/gardener/gardener/third_party/mock/controller-runtime/client"
	mockmanager "github.com/gardener/gardener/third_party/mock/controller-runtime/manager"
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
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"

	apisaws "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	mockawsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client/mock"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure"
)

const (
	name            = "infrastructure"
	namespace       = "shoot--foobar--aws"
	region          = "eu-west-1"
	vpcID           = "vpc-123456"
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
		authConfig       awsclient.AuthConfig
	)

	BeforeEach(func() {
		ctrl = gomock.NewController(GinkgoT())
		c = mockclient.NewMockClient(ctrl)
		awsClientFactory = mockawsclient.NewMockFactory(ctrl)
		awsClient = mockawsclient.NewMockInterface(ctrl)
		ctx = context.TODO()
		logger = log.Log.WithName("test")

		mgr := mockmanager.NewMockManager(ctrl)
		mgr.EXPECT().GetClient().Return(c)
		cv = NewConfigValidator(mgr, awsClientFactory, logger)

		// shared infra + secret setup
		infra = baseInfra(region, ptr.To(vpcID))
		secret, authConfig = baseSecretAuth(accessKeyID, secretAccessKey, region)

		c.EXPECT().Get(ctx, client.ObjectKey{Namespace: infra.Namespace, Name: infra.Name}, gomock.AssignableToTypeOf(&corev1.Secret{})).
			DoAndReturn(func(_ context.Context, _ client.ObjectKey, obj *corev1.Secret, _ ...client.GetOption) error {
				*obj = *secret
				return nil
			})
		awsClientFactory.EXPECT().NewClient(authConfig).Return(awsClient, nil)
	})

	AfterEach(func() { ctrl.Finish() })

	Context("VPC validation", func() {
		It("allows existing VPC with correct attributes and IGW", func() {
			expectValidVPCAttributes(ctx, awsClient, vpcID)
			expectValidDHCPOptions(ctx, awsClient, vpcID, region)
			expectGetVpc(ctx, awsClient, vpcID, "")

			Expect(cv.Validate(ctx, infra)).To(BeEmpty())
		})

		It("fails when VPC attribute retrieval errors", func() {
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, ec2types.VpcAttributeNameEnableDnsSupport).
				Return(false, errors.New("test"))
			Expect(cv.Validate(ctx, infra)).To(ConsistOfFields(Fields{
				"Type":   Equal(field.ErrorTypeInternal),
				"Field":  Equal("networks.vpc.id"),
				"Detail": Equal(fmt.Sprintf("could not get VPC attribute enableDnsSupport for VPC %s: test", vpcID)),
			}))
		})

		It("should forbid VPC that exists but has wrong attribute values or no attached internet gateway", func() {
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, ec2types.VpcAttributeNameEnableDnsSupport).Return(false, nil)
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, ec2types.VpcAttributeNameEnableDnsHostnames).Return(false, nil)
			awsClient.EXPECT().GetVPCInternetGateway(ctx, vpcID).Return("", nil)
			expectValidDHCPOptions(ctx, awsClient, vpcID, region)
			expectGetVpc(ctx, awsClient, vpcID, "")

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

		DescribeTable("validate DHCP options", func(newRegion string, mapping map[string]string,
			err error, matcher gomegatypes.GomegaMatcher) {
			if newRegion != "" {
				infra.Spec.Region = newRegion
				awsClientFactory.NewClient(authConfig) //nolint:errcheck
				newAuthConfig := awsclient.AuthConfig{
					AccessKey: &awsclient.AccessKey{
						ID:     authConfig.AccessKey.ID,
						Secret: authConfig.AccessKey.Secret,
					},
					Region: newRegion,
				}
				awsClientFactory.EXPECT().NewClient(newAuthConfig).Return(awsClient, nil)
			}

			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, ec2types.VpcAttributeNameEnableDnsSupport).Return(true, nil)
			awsClient.EXPECT().GetVPCAttribute(ctx, vpcID, ec2types.VpcAttributeNameEnableDnsHostnames).Return(true, nil)
			awsClient.EXPECT().GetVPCInternetGateway(ctx, vpcID).Return(vpcID, nil)
			awsClient.EXPECT().GetDHCPOptions(ctx, vpcID).Return(mapping, err)
			if err == nil {
				awsClient.EXPECT().GetVpc(ctx, vpcID).Return(&awsclient.VPC{}, nil)
			}

			errorList := cv.Validate(ctx, infra)
			Expect(errorList).To(matcher)
		},
			Entry("should allow VPC with correctly configured DHCP options", "", map[string]string{
				"domain-name": region + ".compute.internal",
			}, nil, BeEmpty()),
			Entry("should allow VPC with correctly configured DHCP options and domain-name 'us-east-1'", "us-east-1", map[string]string{
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

		Context("Validate subnet CIDRs are subset of VPC CIDR", func() {
			It("should succeed - all subnet CIDRs are subset of the VPC CIDR", func() {
				infra.Spec.ProviderConfig.Raw = encode(&apisaws.InfrastructureConfig{
					Networks: apisaws.Networks{
						VPC: apisaws.VPC{
							ID: ptr.To(vpcID),
						},
						Zones: []apisaws.Zone{
							{
								Workers:  "10.251.127.0/26",
								Public:   "10.251.125.0/26",
								Internal: "10.251.126.0/26",
							},
						},
					},
				})
				expectValidVPCAttributes(ctx, awsClient, vpcID)
				expectValidDHCPOptions(ctx, awsClient, vpcID, region)
				awsClient.EXPECT().GetVpc(ctx, vpcID).Return(&awsclient.VPC{
					CidrBlock: "10.251.0.0/16",
				}, nil)

				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(BeEmpty())
			})

			It("should fail - a subnet CIDR is not a subset of the VPC cidr", func() {
				infra.Spec.ProviderConfig.Raw = encode(&apisaws.InfrastructureConfig{
					Networks: apisaws.Networks{
						VPC: apisaws.VPC{
							ID: ptr.To(vpcID),
						},
						Zones: []apisaws.Zone{
							{
								// outside the VPC CIDR on purpose
								Workers:  "192.168.0.0/24",
								Public:   "10.252.125.0/26",
								Internal: "10.250.126.0/26",
							},
						},
					},
				})
				expectValidVPCAttributes(ctx, awsClient, vpcID)
				expectValidDHCPOptions(ctx, awsClient, vpcID, region)
				awsClient.EXPECT().GetVpc(ctx, vpcID).Return(&awsclient.VPC{CidrBlock: "10.251.0.0/16"}, nil)

				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networking.nodes"), // workers -> nodes in validator
				}, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networking.public"),
				}, Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networking.internal"),
				}))
			})

			It("should succeed - in a multi-zone scenario", func() {
				infra.Spec.ProviderConfig.Raw = encode(&apisaws.InfrastructureConfig{
					Networks: apisaws.Networks{
						VPC: apisaws.VPC{
							ID: ptr.To(vpcID),
						},
						Zones: []apisaws.Zone{
							{
								Workers:  "10.251.125.0/26",
								Public:   "10.251.126.0/26",
								Internal: "10.251.127.0/26",
							},
							{
								Workers:  "10.251.128.0/26",
								Public:   "10.251.129.0/26",
								Internal: "10.251.130.0/26",
							},
						},
					},
				})
				expectValidVPCAttributes(ctx, awsClient, vpcID)
				expectValidDHCPOptions(ctx, awsClient, vpcID, region)
				awsClient.EXPECT().GetVpc(ctx, vpcID).Return(&awsclient.VPC{CidrBlock: "10.251.0.0/16"}, nil)

				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(BeEmpty())
			})

			It("should fail - in a multi-zone scenario", func() {
				infra.Spec.ProviderConfig.Raw = encode(&apisaws.InfrastructureConfig{
					Networks: apisaws.Networks{
						VPC: apisaws.VPC{
							ID: ptr.To(vpcID),
						},
						Zones: []apisaws.Zone{
							{
								Workers:  "10.251.125.0/26",
								Public:   "10.251.126.0/26",
								Internal: "10.251.127.0/26",
							},
							{
								Workers:  "192.168.0.0/24", // outside the VPC CIDR
								Public:   "10.251.129.0/26",
								Internal: "10.251.130.0/26",
							},
						},
					},
				})
				expectValidVPCAttributes(ctx, awsClient, vpcID)
				expectValidDHCPOptions(ctx, awsClient, vpcID, region)
				awsClient.EXPECT().GetVpc(ctx, vpcID).Return(&awsclient.VPC{CidrBlock: "10.251.0.0/16"}, nil)

				errorList := cv.Validate(ctx, infra)
				Expect(errorList).To(ConsistOfFields(Fields{
					"Type":  Equal(field.ErrorTypeInvalid),
					"Field": Equal("networking.nodes"),
				}))
			})
		})
	})

	Context("Elastic IPs", func() {
		BeforeEach(func() {
			infra.Spec.ProviderConfig.Raw = encode(&apisaws.InfrastructureConfig{
				Networks: apisaws.Networks{
					VPC: apisaws.VPC{},
					Zones: []apisaws.Zone{
						{ElasticIPAllocationID: ptr.To("eipalloc-0e2669d4b46150ee4")},
						{ElasticIPAllocationID: ptr.To("eipalloc-0e2669d4b46150ee5")},
						{ElasticIPAllocationID: ptr.To("eipalloc-0e2669d4b46150ee6")},
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
				"eipalloc-0e2669d4b46150ee4": ptr.To("eipassoc-0f8ff66536587824b"),
				"eipalloc-0e2669d4b46150ee5": ptr.To("eipassoc-0f8ff66536587824c"),
				"eipalloc-0e2669d4b46150ee6": ptr.To("eipassoc-0f8ff66536587824d"),
			}
			awsClient.EXPECT().GetElasticIPsAssociationIDForAllocationIDs(ctx, gomock.Any()).Return(mapping, nil)
			awsClient.EXPECT().GetNATGatewayAddressAllocations(ctx, infra.Namespace).
				Return(sets.New[string](
					"eipalloc-0e2669d4b46150ee4",
					"eipalloc-0e2669d4b46150ee5",
					"eipalloc-0e2669d4b46150ee6"), nil)

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
			awsClient.EXPECT().GetElasticIPsAssociationIDForAllocationIDs(ctx, []string{
				"eipalloc-0e2669d4b46150ee4",
				"eipalloc-0e2669d4b46150ee5",
				"eipalloc-0e2669d4b46150ee6"}).Return(empty, nil)

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
				"eipalloc-0e2669d4b46150ee4": ptr.To("eipassoc-0f8ff66536587824b"),
				"eipalloc-0e2669d4b46150ee5": ptr.To("eipassoc-0f8ff66536587824c"),
			}
			awsClient.EXPECT().GetElasticIPsAssociationIDForAllocationIDs(ctx, gomock.Any()).Return(mapping, nil)
			awsClient.EXPECT().GetNATGatewayAddressAllocations(ctx, infra.Namespace).Return(sets.New[string](
				"eipalloc-0e2669d4b46150ee4", "eipalloc-0e2669d4b46150ee5"), nil)

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
				"eipalloc-0e2669d4b46150ee4": ptr.To("eipassoc-0f8ff66536587824b"),
				"eipalloc-0e2669d4b46150ee5": ptr.To("eipassoc-0f8ff66536587824c"),
				"eipalloc-0e2669d4b46150ee6": ptr.To("eipassoc-0f8ff66536587824d"),
			}
			awsClient.EXPECT().GetElasticIPsAssociationIDForAllocationIDs(ctx, gomock.Any()).Return(mapping, nil)
			awsClient.EXPECT().GetNATGatewayAddressAllocations(ctx, infra.Namespace).Return(sets.New[string](
				"eipalloc-0e2669d4b46150ee4", "eipalloc-0e2669d4b46150ee5"), nil)

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

// helpers
func baseInfra(region string, vpcID *string) *extensionsv1alpha1.Infrastructure {
	return &extensionsv1alpha1.Infrastructure{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Spec: extensionsv1alpha1.InfrastructureSpec{
			DefaultSpec: extensionsv1alpha1.DefaultSpec{
				Type: aws.Type,
				ProviderConfig: &runtime.RawExtension{Raw: encode(&apisaws.InfrastructureConfig{
					Networks: apisaws.Networks{VPC: apisaws.VPC{ID: vpcID}},
				})},
			},
			Region:    region,
			SecretRef: corev1.SecretReference{Name: name, Namespace: namespace},
		},
	}
}

func baseSecretAuth(id, secret, region string) (*corev1.Secret, awsclient.AuthConfig) {
	s := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: namespace},
		Type:       corev1.SecretTypeOpaque,
		Data:       map[string][]byte{aws.AccessKeyID: []byte(id), aws.SecretAccessKey: []byte(secret)},
	}
	return s, awsclient.AuthConfig{AccessKey: &awsclient.AccessKey{ID: id, Secret: secret}, Region: region}
}

// nolint:unparam
func expectValidVPCAttributes(ctx context.Context, m *mockawsclient.MockInterface, vpcID string) {
	m.EXPECT().GetVPCAttribute(ctx, vpcID, ec2types.VpcAttributeNameEnableDnsSupport).Return(true, nil)
	m.EXPECT().GetVPCAttribute(ctx, vpcID, ec2types.VpcAttributeNameEnableDnsHostnames).Return(true, nil)
	m.EXPECT().GetVPCInternetGateway(ctx, vpcID).Return(vpcID, nil)
}

// nolint:unparam
func expectValidDHCPOptions(ctx context.Context, m *mockawsclient.MockInterface, vpcID, region string) {
	m.EXPECT().GetDHCPOptions(ctx, vpcID).Return(map[string]string{
		"domain-name": region + ".compute.internal",
	}, nil)
}

func expectGetVpc(ctx context.Context, m *mockawsclient.MockInterface, vpcID, cidr string) {
	m.EXPECT().GetVpc(ctx, vpcID).Return(&awsclient.VPC{CidrBlock: cidr}, nil)
}

func encode(obj runtime.Object) []byte {
	data, _ := json.Marshal(obj)
	return data
}
