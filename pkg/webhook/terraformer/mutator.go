// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package terraformer

import (
	"context"
	"errors"
	"fmt"
	"slices"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	securityv1alpha1constants "github.com/gardener/gardener/pkg/apis/security/v1alpha1/constants"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

type mutator struct {
	logger logr.Logger
	client client.Client
}

const (
	containerName = "terraform"
	volumeName    = "workload-identity"
)

// New returns a new Terraformer mutator that uses mutateFunc to perform the mutation.
func New(c client.Client, logger logr.Logger) extensionswebhook.Mutator {
	return &mutator{
		client: c,
		logger: logger,
	}
}

// Mutate mutates the pod attaches the workload identity token to it.
func (m *mutator) Mutate(ctx context.Context, new, old client.Object) error {
	if old != nil || new.GetDeletionTimestamp() != nil {
		return nil
	}

	pod, ok := new.(*corev1.Pod)
	if !ok {
		return errors.New("object is not of type corev1.Pod")
	}

	cloudProviderSecret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      v1beta1constants.SecretNameCloudProvider,
			Namespace: pod.Namespace,
		},
	}
	if err := m.client.Get(ctx, client.ObjectKeyFromObject(cloudProviderSecret), cloudProviderSecret); err != nil {
		return fmt.Errorf("failed getting cloudprovider secret: %w", err)
	}

	if cloudProviderSecret.Labels[securityv1alpha1constants.LabelPurpose] != securityv1alpha1constants.LabelPurposeWorkloadIdentityTokenRequestor {
		return nil
	}

	idx := slices.IndexFunc(pod.Spec.Containers, func(c corev1.Container) bool {
		return c.Name == containerName
	})

	if idx == -1 {
		return fmt.Errorf("found no container with name %q", containerName)
	}

	pod.Spec.Volumes = append(
		pod.Spec.Volumes,
		corev1.Volume{
			Name: volumeName,
			VolumeSource: corev1.VolumeSource{
				Projected: &corev1.ProjectedVolumeSource{
					Sources: []corev1.VolumeProjection{
						{
							Secret: &corev1.SecretProjection{
								LocalObjectReference: corev1.LocalObjectReference{
									Name: v1beta1constants.SecretNameCloudProvider,
								},
								Items: []corev1.KeyToPath{
									{
										Key:  securityv1alpha1constants.DataKeyToken,
										Path: "token",
									},
								},
							},
						},
					},
				},
			},
		},
	)

	pod.Spec.Containers[idx].VolumeMounts = append(
		pod.Spec.Containers[idx].VolumeMounts,
		corev1.VolumeMount{
			Name:      volumeName,
			MountPath: aws.WorkloadIdentityMountPath,
		},
	)

	return nil
}
