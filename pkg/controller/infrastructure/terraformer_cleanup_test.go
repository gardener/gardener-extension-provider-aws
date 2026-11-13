// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure_test

import (
	"context"
	"errors"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	testutils "github.com/gardener/gardener/pkg/utils/test"
	. "github.com/gardener/gardener/pkg/utils/test/matchers"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure"
)

var _ = Describe("Legacy Terraformer artifact cleanup", func() {
	const finalizer = "gardener.cloud/terraformer"

	var (
		ctx       context.Context
		c         client.WithWatch
		infra     *extensionsv1alpha1.Infrastructure
		cluster   *extensionscontroller.Cluster
		artifacts []client.Object
	)

	BeforeEach(func() {
		ctx = context.Background()
		infra = &extensionsv1alpha1.Infrastructure{
			ObjectMeta: metav1.ObjectMeta{Namespace: "shoot--test--aws", Name: "infrastructure"},
			Spec: extensionsv1alpha1.InfrastructureSpec{
				Region: "eu-west-1",
				SecretRef: corev1.SecretReference{
					Namespace: "shoot--test--aws",
					Name:      "cloudprovider",
				},
				DefaultSpec: extensionsv1alpha1.DefaultSpec{
					ProviderConfig: &runtime.RawExtension{Raw: []byte(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","kind":"InfrastructureConfig","networks":{"vpc":{}}}`)},
				},
			},
		}
		cluster = &extensionscontroller.Cluster{Shoot: &gardencorev1beta1.Shoot{}}
		// An empty flow state lets Delete complete without making AWS API calls.
		infra.Status.State = &runtime.RawExtension{Raw: []byte(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","kind":"InfrastructureState","data":{}}`)}
		c = fakeclient.NewClientBuilder().WithObjects(&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Namespace: infra.Namespace, Name: infra.Spec.SecretRef.Name},
			Data: map[string][]byte{
				aws.AccessKeyID:     []byte("test-access-key"),
				aws.SecretAccessKey: []byte("test-secret-key"),
			},
		}).Build()
		artifacts = []client.Object{
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: infra.Namespace, Name: "infrastructure.infra.tf-state", Finalizers: []string{finalizer}}},
			&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: infra.Namespace, Name: "infrastructure.infra.tf-vars", Finalizers: []string{finalizer}}},
			&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: infra.Namespace, Name: "infrastructure.infra.tf-config", Finalizers: []string{finalizer}}},
		}
	})

	for _, operation := range []string{"Delete", "Migrate"} {
		Describe(operation, func() {
			run := func() error {
				actuator := infrastructure.NewActuator(&testutils.FakeManager{Client: c})
				if operation == "Delete" {
					return actuator.Delete(ctx, logr.Discard(), infra, cluster)
				}
				return actuator.Migrate(ctx, logr.Discard(), infra, cluster)
			}

			DescribeTable("should delete legacy artifacts and tolerate repeated cleanup", func(withFinalizer, deleting bool) {
				for _, obj := range artifacts {
					if !withFinalizer {
						obj.SetFinalizers(nil)
					}
					Expect(c.Create(ctx, obj)).To(Succeed())
					if deleting {
						Expect(c.Delete(ctx, obj)).To(Succeed())
					}
				}

				before := infra.DeepCopy()
				Expect(run()).To(Succeed())
				for _, obj := range artifacts {
					Expect(c.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(BeNotFoundError())
				}
				Expect(infra).To(Equal(before))
				Expect(run()).To(Succeed())
			},
				Entry("with Terraformer finalizers", true, false),
				Entry("without finalizers", false, false),
				Entry("already marked for deletion", true, true),
			)

			It("should preserve unrelated finalizers", func() {
				for _, obj := range artifacts {
					obj.SetFinalizers(append(obj.GetFinalizers(), "example.com/other-controller"))
					Expect(c.Create(ctx, obj)).To(Succeed())
				}

				Expect(run()).To(Succeed())
				for _, obj := range artifacts {
					Expect(c.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
					Expect(obj.GetFinalizers()).To(ConsistOf("example.com/other-controller"))
					Expect(obj.GetDeletionTimestamp()).NotTo(BeNil())
				}
			})

			It("should only clean artifacts for this infrastructure and namespace", func() {
				unrelated := []client.Object{
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: infra.Namespace, Name: "other.infra.tf-state", Finalizers: []string{finalizer}}},
					&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: infra.Namespace, Name: "infrastructure.other.tf-vars", Finalizers: []string{finalizer}}},
					&corev1.ConfigMap{ObjectMeta: metav1.ObjectMeta{Namespace: "other-namespace", Name: "infrastructure.infra.tf-config", Finalizers: []string{finalizer}}},
				}
				for _, obj := range unrelated {
					Expect(c.Create(ctx, obj)).To(Succeed())
				}

				Expect(run()).To(Succeed())
				for _, obj := range unrelated {
					Expect(c.Get(ctx, client.ObjectKeyFromObject(obj), obj)).To(Succeed())
					Expect(obj.GetFinalizers()).To(ConsistOf(finalizer))
					Expect(obj.GetDeletionTimestamp()).To(BeNil())
				}
				Expect(c.Get(ctx, client.ObjectKey{Namespace: infra.Namespace, Name: infra.Spec.SecretRef.Name}, &corev1.Secret{})).To(Succeed())
			})

			DescribeTable("should propagate cleanup failures for retry", func(failingOperation string) {
				for _, obj := range artifacts {
					Expect(c.Create(ctx, obj)).To(Succeed())
				}
				fakeErr := errors.New("API unavailable")
				c = interceptor.NewClient(c, interceptor.Funcs{
					Get: func(ctx context.Context, c client.WithWatch, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
						if failingOperation == "get" && key.Name == "infrastructure.infra.tf-state" {
							return fakeErr
						}
						return c.Get(ctx, key, obj, opts...)
					},
					Patch: func(ctx context.Context, c client.WithWatch, obj client.Object, patch client.Patch, opts ...client.PatchOption) error {
						if failingOperation == "patch" {
							return fakeErr
						}
						return c.Patch(ctx, obj, patch, opts...)
					},
					Delete: func(ctx context.Context, c client.WithWatch, obj client.Object, opts ...client.DeleteOption) error {
						if failingOperation == "delete" {
							return fakeErr
						}
						return c.Delete(ctx, obj, opts...)
					},
				})

				Expect(run()).To(MatchError(ContainSubstring(fakeErr.Error())))
			},
				Entry("getting artifacts", "get"),
				Entry("removing finalizers", "patch"),
				Entry("deleting artifacts", "delete"),
			)
		})
	}
})
