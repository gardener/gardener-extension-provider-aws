// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/pkg/apis/core"
	"github.com/gardener/gardener/pkg/apis/security"
	securityv1alpha1 "github.com/gardener/gardener/pkg/apis/security/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	// Name is a name for a validation webhook.
	Name = "validator"
	// SecretsValidatorName is the name of the secrets validator.
	SecretsValidatorName = "secrets." + Name
)

var logger = log.Log.WithName("aws-validator-webhook")

// New creates a new webhook that validates Shoot, CloudProfile, NamespacedCloudProfile, SecretBinding and CredentialsBinding resources.
func New(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Setting up webhook", "name", Name)

	return extensionswebhook.New(mgr, extensionswebhook.Args{
		Provider: aws.Type,
		Name:     Name,
		Path:     "/webhooks/validate",
		Validators: map[extensionswebhook.Validator][]extensionswebhook.Type{
			NewShootValidator(mgr):                  {{Obj: &core.Shoot{}}},
			NewCloudProfileValidator(mgr):           {{Obj: &core.CloudProfile{}}},
			NewNamespacedCloudProfileValidator(mgr): {{Obj: &core.NamespacedCloudProfile{}}},
			NewSecretBindingValidator(mgr):          {{Obj: &core.SecretBinding{}}},
			NewCredentialsBindingValidator(mgr):     {{Obj: &security.CredentialsBinding{}}},
			NewSeedValidator(mgr):                   {{Obj: &core.Seed{}}},
			NewBackupBucketValidator(mgr):           {{Obj: &core.BackupBucket{}}},
			NewWorkloadIdentityValidator(serializer.NewCodecFactory(mgr.GetScheme(), serializer.EnableStrict).UniversalDecoder()): {{Obj: &securityv1alpha1.WorkloadIdentity{}}},
		},
		Target: extensionswebhook.TargetSeed,
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"provider.extensions.gardener.cloud/aws": "true"},
		},
	})
}

// NewSecretsWebhook creates a new validation webhook for Secrets.
func NewSecretsWebhook(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Setting up webhook", "name", SecretsValidatorName)

	return extensionswebhook.New(mgr, extensionswebhook.Args{
		Provider: aws.Type,
		Name:     SecretsValidatorName,
		Path:     "/webhooks/validate/secrets",
		Validators: map[extensionswebhook.Validator][]extensionswebhook.Type{
			NewSecretValidator(): {{Obj: &corev1.Secret{}}},
		},
		Target: extensionswebhook.TargetSeed,
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{"provider.shoot.gardener.cloud/aws": "true"},
		},
	})
}
