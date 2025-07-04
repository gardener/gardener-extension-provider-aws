// SPDX-FileCopyrightText: 2025 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupbucket

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	// WebhookName is the used for the BackupBucket webhook.
	WebhookName = "backupbucket"
	webhookPath = "backupbucket"
)

var logger = log.Log.WithName("backupbucket-webhook")

// AddToManager creates an BackupBucket webhook and adds it to the manager.
func AddToManager(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Adding webhook to manager")

	types := []extensionswebhook.Type{
		{Obj: &extensionsv1alpha1.BackupBucket{}},
	}

	handler, err := extensionswebhook.NewBuilder(mgr, logger).WithValidator(New(mgr), types...).Build()
	if err != nil {
		return nil, err
	}

	logger.Info("Creating webhook")
	return &extensionswebhook.Webhook{
		Name:     WebhookName,
		Target:   extensionswebhook.TargetSeed,
		Provider: aws.Type,
		Types:    types,
		Webhook:  &admission.Webhook{Handler: handler, RecoverPanic: ptr.To(true)},
		Path:     webhookPath,
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{v1beta1constants.LabelExtensionProviderTypePrefix + aws.Type: "true"},
		},
	}, nil
}
