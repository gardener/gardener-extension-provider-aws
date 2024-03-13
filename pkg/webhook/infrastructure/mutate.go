// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"context"
	"fmt"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	extensionscontextwebhook "github.com/gardener/gardener/extensions/pkg/webhook/context"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

type mutator struct {
	logger logr.Logger
	client client.Client
}

// New returns a new Infrastructure mutator that uses mutateFunc to perform the mutation.
func New(mgr manager.Manager, logger logr.Logger) extensionswebhook.Mutator {
	return &mutator{
		client: mgr.GetClient(),
		logger: logger,
	}
}

// Mutate mutates the given object on creation and adds the annotation `aws.provider.extensions.gardener.cloud/use-flow=true`
// if the seed has the label `aws.provider.extensions.gardener.cloud/use-flow` == `new`.
func (m *mutator) Mutate(ctx context.Context, new, old client.Object) error {
	if old != nil || new.GetDeletionTimestamp() != nil {
		return nil
	}

	newInfra, ok := new.(*extensionsv1alpha1.Infrastructure)
	if !ok {
		return fmt.Errorf("could not mutate: object is not of type Infrastructure")
	}

	gctx := extensionscontextwebhook.NewGardenContext(m.client, new)
	cluster, err := gctx.GetCluster(ctx)
	if err != nil {
		return err
	}

	if cluster.Seed.Labels[aws.SeedLabelKeyUseFlow] == aws.SeedLabelUseFlowValueNew {
		if newInfra.Annotations == nil {
			newInfra.Annotations = map[string]string{}
		}
		newInfra.Annotations[aws.AnnotationKeyUseFlow] = "true"
	}

	return nil
}
