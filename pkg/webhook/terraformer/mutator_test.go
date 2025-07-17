// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package terraformer_test

import (
	"context"

	"github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/go-logr/logr"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	fakeclient "sigs.k8s.io/controller-runtime/pkg/client/fake"

	"github.com/gardener/gardener-extension-provider-aws/pkg/webhook/terraformer"
)

var _ = Describe("Mutator", func() {
	var (
		ctx         = context.TODO()
		fakeClient  client.Client
		pod         *corev1.Pod
		expectedPod *corev1.Pod
		secret      *corev1.Secret
		mutator     webhook.Mutator
	)

	BeforeEach(func() {
		fakeClient = fakeclient.NewClientBuilder().Build()
		pod = &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "terraformer",
				Namespace: "foo",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{
						Name: "terraform",
					},
				},
			},
		}
		expectedPod = pod.DeepCopy()
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cloudprovider",
				Namespace: "foo",
				Labels: map[string]string{
					"security.gardener.cloud/purpose": "workload-identity-token-requestor",
				},
			},
		}
		mutator = terraformer.New(fakeClient, logr.Discard())
	})

	It("should add the required volume to the pod", func() {
		Expect(fakeClient.Create(ctx, secret)).To(Succeed())
		Expect(mutator.Mutate(ctx, pod, nil)).To(Succeed())
		expectedPod.Spec.Volumes = []corev1.Volume{
			{
				Name: "workload-identity",
				VolumeSource: corev1.VolumeSource{
					Projected: &corev1.ProjectedVolumeSource{
						Sources: []corev1.VolumeProjection{
							{
								Secret: &corev1.SecretProjection{
									LocalObjectReference: corev1.LocalObjectReference{
										Name: "cloudprovider",
									},
									Items: []corev1.KeyToPath{
										{
											Key:  "token",
											Path: "token",
										},
									},
								},
							},
						},
					},
				},
			},
		}
		expectedPod.Spec.Containers[0].VolumeMounts = []corev1.VolumeMount{
			{
				Name:      "workload-identity",
				MountPath: "/var/run/secrets/gardener.cloud/workload-identity",
			},
		}
		Expect(pod).To(Equal(expectedPod))
	})

	It("should error because of missing cloudprovider secret", func() {
		err := mutator.Mutate(ctx, pod, nil)
		Expect(apierrors.IsNotFound(err)).To(BeTrue())
		Expect(err.Error()).To(ContainSubstring("cloudprovider"))
	})

	It("should not mutate the pod because the cloudprovider secret is not labeled properly", func() {
		secret.Labels = nil
		Expect(fakeClient.Create(ctx, secret)).To(Succeed())
		Expect(mutator.Mutate(ctx, pod, nil)).To(Succeed())
		Expect(pod).To(Equal(expectedPod))
	})
})
