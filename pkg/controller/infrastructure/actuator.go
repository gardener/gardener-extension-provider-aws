// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"time"

	"github.com/gardener/gardener/extensions/pkg/controller/infrastructure"
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/imagevector"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

type actuator struct {
	client                     client.Client
	decoder                    runtime.Decoder
	restConfig                 *rest.Config
	disableProjectedTokenMount bool
}

// NewActuator creates a new Actuator that updates the status of the handled Infrastructure resources.
func NewActuator(mgr manager.Manager, disableProjectedTokenMount bool) infrastructure.Actuator {
	return &actuator{
		client:                     mgr.GetClient(),
		decoder:                    serializer.NewCodecFactory(mgr.GetScheme()).UniversalDecoder(),
		restConfig:                 mgr.GetConfig(),
		disableProjectedTokenMount: disableProjectedTokenMount,
	}
}

// Helper functions

func newTerraformer(
	logger logr.Logger,
	restConfig *rest.Config,
	purpose string,
	infra *extensionsv1alpha1.Infrastructure,
	disableProjectedTokenMount bool,
) (
	terraformer.Terraformer,
	error,
) {
	tf, err := terraformer.NewForConfig(logger, restConfig, purpose, infra.Namespace, infra.Name, imagevector.TerraformerImage())
	if err != nil {
		return nil, err
	}

	owner := metav1.NewControllerRef(infra, extensionsv1alpha1.SchemeGroupVersion.WithKind(extensionsv1alpha1.InfrastructureResource))
	return tf.
		UseProjectedTokenMount(!disableProjectedTokenMount).
		SetTerminationGracePeriodSeconds(630).
		SetDeadlineCleaning(5 * time.Minute).
		SetDeadlinePod(15 * time.Minute).
		SetOwnerRef(owner), nil
}

func generateTerraformerEnvVars(secretRef corev1.SecretReference) []corev1.EnvVar {
	return []corev1.EnvVar{{
		Name: "TF_VAR_ACCESS_KEY_ID",
		ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: secretRef.Name,
			},
			Key: aws.AccessKeyID,
		}},
	}, {
		Name: "TF_VAR_SECRET_ACCESS_KEY",
		ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{
				Name: secretRef.Name,
			},
			Key: aws.SecretAccessKey,
		}},
	}}
}
