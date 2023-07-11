// Copyright (c) 2022 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package infrastructure

import (
	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	// WebhookName is the used for the Infrastructure webhook.
	WebhookName = "infrastructure"
	webhookPath = "infrastructure"
)

var logger = log.Log.WithName("infrastructure-webhook")

// AddToManager creates an Infrastructure webhook adds the webhook to the manager.
func AddToManager(mgr manager.Manager) (*extensionswebhook.Webhook, error) {
	logger.Info("Adding webhook to manager")

	types := []extensionswebhook.Type{
		{Obj: &extensionsv1alpha1.Infrastructure{}},
	}

	handler, err := extensionswebhook.NewBuilder(mgr, logger).WithMutator(New(mgr, logger), types...).Build()
	if err != nil {
		return nil, err
	}

	logger.Info("Creating webhook")
	return &extensionswebhook.Webhook{
		Name:     WebhookName,
		Target:   extensionswebhook.TargetSeed,
		Provider: aws.Type,
		Types:    types,
		Webhook:  &admission.Webhook{Handler: handler, RecoverPanic: true},
		Path:     webhookPath,
		Selector: buildSelector(aws.Type),
	}, nil
}

func buildSelector(provider string) *metav1.LabelSelector {
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
