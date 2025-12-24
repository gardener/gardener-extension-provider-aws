// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"bytes"
	"context"
	"fmt"
	"regexp"

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

// Precompiled regexes used by stripVirtualCapacity for efficiency
var (
	// reOnlyVirtualCapacity matches the entire providerConfig.nodeTemplate object when it contains
	// ONLY the virtualCapacity field. The match is done regardless of whitespace and newlines.
	// Example of Matched structure:
	//     "nodeTemplate": {
	//         "virtualCapacity" : { ...simple map contents... }
	//     }
	reOnlyVirtualCapacity = regexp.MustCompile(
		`(?s)"nodeTemplate"\s*:\s*\{\s*"virtualCapacity"\s*:\s*\{[^{}]*\}\s*\}\s*,?`,
	)

	// reTrailingVirtualCapacity matches only the virtualCapacity field when it is the last field inside providerConfig.nodeTemplate and "capacity" appears before it.
	// Example of matched structure:
	//      ,"virtualCapacity": { ... simple map contents ... }
	reTrailingVirtualCapacity = regexp.MustCompile(
		`(?s),\s*"virtualCapacity"\s*:\s*\{[^{}]*\}\s*`,
	)

	// reDanglingComma removes any comma followed by optional whitespace followed by closing brace
	reDanglingComma = regexp.MustCompile(`,\s*}`)
)

// stripVirtualCapacity removes virtualCapacity (and optionally nodeTemplate)
// from the given inProviderConfig using regex logic under strict structural assumptions.
//
// Assumptions:
//   - nodeTemplate contains only "capacity" and/or "virtualCapacity"
//   - Both fields are simple maps { key: int/string }
//   - virtualCapacity is either:
//     B) the last field
//     C) the only field
//   - No nested objects inside these maps.
//
// It preserves all whitespace, indentation, newlines, and key ordering. A final cleanup step removes any illegal trailing ",}" created when removing the
// last field inside an object.
func stripVirtualCapacity(inProviderConfig []byte) (outProviderConfig []byte) {
	outProviderConfig = inProviderConfig

	// Case A: virtualCapacity is the only field -> remove entire nodeTemplate
	outProviderConfig = reOnlyVirtualCapacity.ReplaceAll(outProviderConfig, []byte(""))

	// Case B: virtualCapacity is the last field -> remove only the virtualCapacity field
	outProviderConfig = reTrailingVirtualCapacity.ReplaceAll(outProviderConfig, []byte(""))

	// fix any dangling commas after nodeTemplate removal
	outProviderConfig = reDanglingComma.ReplaceAll(outProviderConfig, []byte("}"))

	return bytes.TrimSpace(outProviderConfig)
}
