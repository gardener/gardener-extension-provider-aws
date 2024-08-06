package infraflow_test

import (
	"context"
	"errors"
	"fmt"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	. "github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow"
)

var _ = Describe("FindExisting", func() {
	var (
		ctx       context.Context
		fakeStore map[string]struct {
			id   string
			tags awsclient.Tags
		}

		getter = func(_ context.Context, key string) (*string, error) {
			return ptr.To(fakeStore[key].id), nil
		}
		finder = func(_ context.Context, tags awsclient.Tags) ([]*string, error) {
			res := []*string{}
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

	Context("foo", func() {
		It("should find existing by getter", func() {
			res, err := FindExisting(ctx, ptr.To("key1"), nil, getter, finder)
			Expect(err).NotTo(HaveOccurred())
			Expect(res).NotTo(BeNil())
			Expect(*res).To(Equal("foo"))
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
		})

		It("should find return an error if multiple matches found", func() {
			_, err := FindExisting(ctx, nil, map[string]string{
				"tag4": "value5",
			}, getter, finder)
			Expect(err).To(HaveOccurred())
			Expect(errors.Is(err, ErrorMultipleMatches)).To(BeTrue())
			fmt.Print(err)
		})
	})
})
