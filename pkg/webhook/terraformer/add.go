// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package terraformer

import (
	"github.com/gardener/gardener/extensions/pkg/terraformer"
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	// WebhookName is the used for the terraformer webhook.
	WebhookName = "terraformer"
	webhookPath = "terraformer"
)

var logger = log.Log.WithName("terraformer-webhook")

// AddToManager creates an terraformer webhook adds the webhook to the manager.
func AddToManager(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Adding webhook to manager")

	types := []extensionswebhook.Type{
		{Obj: &corev1.Pod{}},
	}

	handler, err := extensionswebhook.NewBuilder(mgr, logger).WithMutator(New(mgr.GetClient(), logger), types...).Build()
	if err != nil {
		return nil, err
	}

	logger.Info("Creating webhook")
	return &extensionswebhook.Webhook{
		Name:              WebhookName,
		Target:            extensionswebhook.TargetSeed,
		Provider:          aws.Type,
		Types:             types,
		Webhook:           &admission.Webhook{Handler: handler, RecoverPanic: ptr.To(true)},
		Path:              webhookPath,
		NamespaceSelector: buildNamespaceSelector(aws.Type),
		ObjectSelector:    buildObjectSelector(),
	}, nil
}

func buildNamespaceSelector(provider string) *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      v1beta1constants.LabelShootProvider,
				Operator: metav1.LabelSelectorOpIn,
				Values:   []string{provider},
			},
		},
	}
}

func buildObjectSelector() *metav1.LabelSelector {
	return &metav1.LabelSelector{
		MatchExpressions: []metav1.LabelSelectorRequirement{
			{
				Key:      terraformer.LabelKeyName,
				Operator: metav1.LabelSelectorOpExists,
			},
			{
				Key:      terraformer.LabelKeyPurpose,
				Operator: metav1.LabelSelectorOpExists,
			},
		},
	}
}
