// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package shoot

import (
	"context"

	corev1 "k8s.io/api/core/v1"
)

func (m *mutator) mutateNginxIngressControllerConfigMap(_ context.Context, configMap *corev1.ConfigMap) error {
	if configMap.Data == nil {
		configMap.Data = make(map[string]string, 1)
	}

	configMap.Data["use-proxy-protocol"] = "true"

	return nil
}
