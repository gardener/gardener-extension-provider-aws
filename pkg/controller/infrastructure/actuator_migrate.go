// Copyright (c) 2020 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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
	"context"
	"fmt"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"k8s.io/client-go/rest"
)

// Migrate deletes only the ConfigMaps and Secrets of the Terraformer.
func (a *actuator) Migrate(ctx context.Context, log logr.Logger, infrastructure *extensionsv1alpha1.Infrastructure, _ *extensionscontroller.Cluster) error {
	return migrate(ctx, log, a.RESTConfig(), infrastructure, a.disableProjectedTokenMount)
}

func migrate(
	ctx context.Context,
	logger logr.Logger,
	restConfig *rest.Config,
	infrastructure *extensionsv1alpha1.Infrastructure,
	disableProjectedTokenMount bool,
) error {
	tf, err := newTerraformer(logger, restConfig, aws.TerraformerPurposeInfra, infrastructure, disableProjectedTokenMount)
	if err != nil {
		return helper.DetermineError(fmt.Errorf("could not create the Terraformer: %+v", err))
	}

	if err := tf.CleanupConfiguration(ctx); err != nil {
		return helper.DetermineError(err)
	}

	if err := tf.RemoveTerraformerFinalizerFromConfig(ctx); err != nil {
		return helper.DetermineError(err)
	}

	return nil
}
