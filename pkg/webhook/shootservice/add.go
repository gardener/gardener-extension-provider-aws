// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootservice

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/shoot"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	WebhookName           = "shoot-service"
	KubeSystemWebhookName = "shoot-service-kube-system"
)

var (
	// DefaultAddOptions are the default AddOptions for AddToManager.
	DefaultAddOptions = AddOptions{}
)

// AddOptions are options to apply when adding the AWS shoot webhook to the manager.
type AddOptions struct{}

var logger = log.Log.WithName("aws-shoot-service-webhook")

// AddToManagerWithOptions creates a webhook with the given options and adds it to the manager.
func AddToManagerWithOptions(mgr manager.Manager, _ AddOptions) (*extensionswebhook.Webhook, error) {
	logger.Info("Adding webhook to manager")
	wb, err := shoot.New(mgr, shoot.Args{
		Types: []extensionswebhook.Type{
			{Obj: &corev1.Service{}},
		},
		MutatorWithShootClient: NewMutatorWithShootClient(),
		ObjectSelector: &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "resources.gardener.cloud/managed-by",
					Operator: metav1.LabelSelectorOpDoesNotExist,
					Values:   []string{},
				},
			},
		},
	})
	if err != nil {
		return nil, err
	}
	wb.NamespaceSelector = nil
	wb.Name = WebhookName
	wb.Path = WebhookName
	return wb, nil
}

// AddToManager creates a webhook with the default options and adds it to the manager.
func AddToManager(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	return AddToManagerWithOptions(mgr, DefaultAddOptions)
}

// AddToManagerForKubeSystem creates a webhook for the kube-system namespace and adds it to the manager.
// The webhook specifically targets the nginx-ingress because it is the only resource managed by the
// Gardener resource manager that needs to be mutated.
func AddToManagerForKubeSystem(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Adding webhook for kube-system to manager")
	wb, err := shoot.New(mgr, shoot.Args{
		Types: []extensionswebhook.Type{
			{Obj: &corev1.Service{}},
		},
		MutatorWithShootClient: NewMutatorWithShootClient(),
		ObjectSelector: &metav1.LabelSelector{
			MatchLabels: map[string]string{
				"app":       "nginx-ingress",
				"component": "controller",
				"release":   "addons",
			},
		},
	})
	if err != nil {
		return nil, err
	}
	wb.Name = KubeSystemWebhookName
	wb.Path = KubeSystemWebhookName
	return wb, nil
}
