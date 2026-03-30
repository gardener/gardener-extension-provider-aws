// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootpvca

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	pvcautoscalingv1alpha1 "github.com/gardener/pvc-autoscaler/api/autoscaling/v1alpha1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	// WebhookName is the name of the webhook.
	WebhookName = "shoot-pvca"
)

var (
	// DefaultAddOptions are the default AddOptions for AddToManager.
	DefaultAddOptions = AddOptions{}
)

// AddOptions are options to apply when adding the AWS shoot webhook to the manager.
type AddOptions struct{}

// AddToManagerWithOptions creates a webhook with the given options and adds it to the manager.
func AddToManagerWithOptions(mgr manager.Manager, _ AddOptions) (*extensionswebhook.Webhook, error) {
	logger := log.Log.WithName("aws-shoot-pvca-webhook")
	logger.Info("Adding webhook for PersistentVolumeClaimAutoscaler to manager")

	if err := pvcautoscalingv1alpha1.AddToScheme(mgr.GetScheme()); err != nil {
		return nil, err
	}

	types := []extensionswebhook.Type{{Obj: &pvcautoscalingv1alpha1.PersistentVolumeClaimAutoscaler{}}}
	handler, err := extensionswebhook.NewBuilder(mgr, logger).WithMutator(NewMutator(logger), types...).Build()
	if err != nil {
		return nil, err
	}

	// This webhook should apply to all namespaces in the shoot cluster.
	return &extensionswebhook.Webhook{
		Name:              WebhookName,
		Target:            extensionswebhook.TargetSeed,
		Provider:          aws.Type,
		Types:             types,
		Webhook:           &admission.Webhook{Handler: handler, RecoverPanic: ptr.To(true)},
		Path:              WebhookName,
		NamespaceSelector: nil,
	}, nil
}

// AddToManager creates a webhook with the default options and adds it to the manager.
func AddToManager(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	return AddToManagerWithOptions(mgr, DefaultAddOptions)
}
