// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shootconfigmap

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/gardener/gardener/extensions/pkg/webhook/shoot"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

const (
	WebhookName = "shoot-configmap"
)

var (
	// DefaultAddOptions are the default AddOptions for AddToManager.
	DefaultAddOptions = AddOptions{}
)

// AddOptions are options to apply when adding the AWS shoot webhook to the manager.
type AddOptions struct{}

// AddToManagerWithOptions creates a webhook with the given options and adds it to the manager.
func AddToManagerWithOptions(mgr manager.Manager, _ AddOptions) (*extensionswebhook.Webhook, error) {
	logger := log.Log.WithName("aws-shoot-nginx-ingress-configmap-webhook")
	logger.Info("Adding webhook for nginx-ingress ConfigMap to manager")
	wb, err := shoot.New(mgr, shoot.Args{
		Types: []extensionswebhook.Type{
			{Obj: &corev1.ConfigMap{}},
		},
		Mutator: NewMutator(logger),
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
	wb.Name = WebhookName
	wb.Path = WebhookName
	return wb, nil
}

// AddToManager creates a webhook with the default options and adds it to the manager.
func AddToManager(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	return AddToManagerWithOptions(mgr, DefaultAddOptions)
}
