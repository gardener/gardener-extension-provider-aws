// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"context"
	"encoding/json"
	"fmt"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	k8sclient "sigs.k8s.io/controller-runtime/pkg/client"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

func (w *WorkerDelegate) decodeWorkerProviderStatus() (*api.WorkerStatus, error) {
	workerStatus := &api.WorkerStatus{}

	if w.worker.Status.ProviderStatus == nil {
		return workerStatus, nil
	}

	if _, _, err := w.decoder.Decode(w.worker.Status.ProviderStatus.Raw, nil, workerStatus); err != nil {
		return nil, fmt.Errorf("could not decode WorkerStatus '%s': %w", k8sclient.ObjectKeyFromObject(w.worker), err)
	}

	return workerStatus, nil
}

func (w *WorkerDelegate) updateWorkerProviderStatus(ctx context.Context, workerStatus *api.WorkerStatus) error {
	var workerStatusV1alpha1 = &v1alpha1.WorkerStatus{
		TypeMeta: metav1.TypeMeta{
			APIVersion: v1alpha1.SchemeGroupVersion.String(),
			Kind:       "WorkerStatus",
		},
	}

	if err := w.scheme.Convert(workerStatus, workerStatusV1alpha1, nil); err != nil {
		return err
	}

	patch := k8sclient.MergeFrom(w.worker.DeepCopy())
	w.worker.Status.ProviderStatus = &runtime.RawExtension{Object: workerStatusV1alpha1}
	return w.client.Status().Patch(ctx, w.worker, patch)
}

// rewriteWorkerConfigForBackwardCompatibleHash ensures that addition or change in providerConfig.nodeTemplate.virtualCapacity should NOT
// cause existing hash to change to prevent trigger of rollout.
func rewriteWorkerConfigForBackwardCompatibleHash(workerConfig *api.WorkerConfig) ([]byte, error) {
	// Step 1: get copy of workerConfig and set NodeTemplate.VirtualCapacity set to nil
	workerConfigCopy := workerConfig.DeepCopy()
	if workerConfigCopy.NodeTemplate != nil {
		workerConfigCopy.NodeTemplate.VirtualCapacity = nil
	}

	if workerConfigCopy.NodeTemplate != nil && workerConfigCopy.NodeTemplate.Capacity == nil {
		// Need the same hash if WorkerConfig was present, but nodeTemplate was NOT set and subsequently nodeTemplate.virtualCapacity was just added.
		workerConfigCopy.NodeTemplate = nil
	}

	// Step 2: wrap and inject apiVersion & kind
	// needs an explicit set of APIVersion and Kind in exact order so we don't to differ from the previous `string(pool.ProviderConfig.Raw)`
	// In https://github.com/gardener/gardener-extension-provider-aws/blob/master/docs/usage/usage.md, we mention apiVersion and then kind,
	// which is what customers copy-paste to the shoot spec and then use.
	// cannot use either std json nor api machinery json to directly serialize WorkerConfig since they serialize to kind first followed by apiVersion which
	// would be different from previous `string(pool.ProviderConfig.Raw)` used as hash for the machine class suffix.
	wrapper := workerConfigWrapper{
		APIVersion:   "aws.provider.extensions.gardener.cloud/v1alpha1",
		Kind:         "WorkerConfig",
		WorkerConfig: workerConfigCopy,
	}
	// Step 3: marshal back to JSON
	return json.Marshal(wrapper)
}

// workerConfigWrapper is used by rewriteWorkerConfigForBackwardCompatibleHash so that APIVersion comes before Kind
type workerConfigWrapper struct {
	APIVersion        string `json:"apiVersion"`
	Kind              string `json:"kind"`
	*api.WorkerConfig `json:",inline"`
}
