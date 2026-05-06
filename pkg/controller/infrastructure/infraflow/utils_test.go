package infraflow_test

import (
	"context"
	"errors"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	awsv1alpha1 "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

var _ = Describe("FindExisting", func() {
	var (
		ctx       context.Context
		fakeStore map[string]struct {
			id   string
			tags awsclient.Tags
		}

		//nolint:unparam
		getter = func(_ context.Context, key string) (*string, error) {
			return ptr.To(fakeStore[key].id), nil
		}
		//nolint:unparam
		finder = func(_ context.Context, tags awsclient.Tags) ([]*string, error) {
			var res []*string
			for _, fakeEntry := range fakeStore {
				func() {
					for tagKey, tagValue := range tags {
						if v, ok := fakeEntry.tags[tagKey]; !ok || v != tagValue {
							return
						}
					}
					res = append(res, ptr.To(fakeEntry.id))
				}()
			}
			return res, nil
		}
	)

	BeforeEach(func() {
		ctx = context.Background()
		fakeStore = map[string]struct {
			id   string
			tags awsclient.Tags
		}{
			"key1": {
				id: "foo",
				tags: map[string]string{
					"tag1": "value1",
					"tag2": "value2",
				},
			},
			"key2": {
				id: "bar",
				tags: map[string]string{
					"tag3": "value3",
					"tag4": "value4",
				},
			},
			"key3": {
				id: "baz",
				tags: map[string]string{
					"tag4": "value5",
				},
			},
			"key4": {
				id: "baz-copy",
				tags: map[string]string{
					"tag4": "value5",
				},
			},
		}
	})

	Context("using getter", func() {
		It("should find existing", func() {
			res, err := FindExisting(ctx, ptr.To("key1"), nil, getter, finder)
			Expect(err).NotTo(HaveOccurred())
			Expect(res).NotTo(BeNil())
			Expect(*res).To(Equal("foo"))
		})
	})

	Context("using finder", func() {
		It("should succeed", func() {
			res, err := FindExisting(ctx, nil, map[string]string{
				"tag3": "value3",
				"tag4": "value4",
			}, getter, finder)
			Expect(err).NotTo(HaveOccurred())
			Expect(res).NotTo(BeNil())
			Expect(*res).To(Equal("bar"))
		})

		It("should fail to find matching tags", func() {
			res, err := FindExisting(ctx, nil, map[string]string{
				"key2":    "value2",
				"cluster": "foo",
			}, getter, finder)
			Expect(err).NotTo(HaveOccurred())
			Expect(res).To(BeNil())
		})

		It("should find return an error if multiple matches found", func() {
			_, err := FindExisting(ctx, nil, map[string]string{
				"tag4": "value5",
			}, getter, finder)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrorMultipleMatches)).To(BeTrue())
		})
		Context("using selector", func() {
			It("should find return an error if multiple matches found", func() {
				_, err := FindExisting(ctx, nil, map[string]string{
					"tag4": "value5",
				}, getter, finder, func(item *string) bool {
					return strings.Contains(ptr.Deref(item, ""), "baz")
				})
				Expect(err).To(HaveOccurred())
				Expect(errors.Is(err, ErrorMultipleMatches)).To(BeTrue())
			})

			It("should find target", func() {
				res, err := FindExisting(ctx, nil, map[string]string{
					"tag4": "value5",
				}, getter, finder, func(item *string) bool {
					return strings.Contains(ptr.Deref(item, ""), "copy")
				})
				Expect(err).NotTo(HaveOccurred())
				Expect(res).NotTo(BeNil())
				Expect(*res).To(Equal("baz-copy"))
			})
		})
	})
})

var _ = Describe("BuildInfrastructureStatus", func() {
	It("should not set TransitGateway when no TGW state keys exist", func() {
		wb := shared.NewWhiteboard()
		wb.Set(IdentifierVPC, "vpc-123")

		status := BuildInfrastructureStatus(wb, nil)
		Expect(status.TransitGateway).To(BeNil())
	})

	It("should populate TransitGateway when TGW ID exists in state", func() {
		wb := shared.NewWhiteboard()
		wb.Set(IdentifierVPC, "vpc-123")
		wb.Set(IdentifierTransitGatewayID, "tgw-123")
		wb.Set(IdentifierTransitGatewayHubRouteTable, "tgw-rtb-hub")
		wb.Set(IdentifierTransitGatewaySpokeRouteTable, "tgw-rtb-spoke")
		wb.Set(IdentifierTransitGatewayAttachment, "tgw-attach-1")

		status := BuildInfrastructureStatus(wb, nil)
		Expect(status.TransitGateway).NotTo(BeNil())
		Expect(*status.TransitGateway.ID).To(Equal("tgw-123"))
		Expect(*status.TransitGateway.HubRouteTableID).To(Equal("tgw-rtb-hub"))
		Expect(*status.TransitGateway.SpokeRouteTableID).To(Equal("tgw-rtb-spoke"))
		Expect(*status.TransitGateway.AttachmentID).To(Equal("tgw-attach-1"))
		Expect(status.TransitGateway.ShootAttachmentID).To(BeNil())
	})

	It("should populate ShootAttachmentID when present", func() {
		wb := shared.NewWhiteboard()
		wb.Set(IdentifierVPC, "vpc-123")
		wb.Set(IdentifierShootTransitGatewayAttachment, "tgw-attach-shoot")

		status := BuildInfrastructureStatus(wb, nil)
		Expect(status.TransitGateway).NotTo(BeNil())
		Expect(*status.TransitGateway.ShootAttachmentID).To(Equal("tgw-attach-shoot"))
	})

	It("should populate TransitGateway when only route tables exist", func() {
		wb := shared.NewWhiteboard()
		wb.Set(IdentifierVPC, "vpc-123")
		wb.Set(IdentifierTransitGatewayHubRouteTable, "tgw-rtb-hub")

		status := BuildInfrastructureStatus(wb, nil)
		Expect(status.TransitGateway).NotTo(BeNil())
		Expect(*status.TransitGateway.HubRouteTableID).To(Equal("tgw-rtb-hub"))
	})

	It("should include correct TypeMeta", func() {
		wb := shared.NewWhiteboard()
		status := BuildInfrastructureStatus(wb, nil)
		Expect(status.TypeMeta.APIVersion).To(Equal(awsv1alpha1.SchemeGroupVersion.String()))
		Expect(status.TypeMeta.Kind).To(Equal("InfrastructureStatus"))
	})
})
