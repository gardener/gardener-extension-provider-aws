// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package controlplane

import (
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/imagevector"
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/controlplane"
	"github.com/gardener/gardener/extensions/pkg/controller/controlplane/genericactuator"
	"github.com/gardener/gardener/extensions/pkg/util"
	"github.com/gardener/gardener/pkg/utils/version"

	admissionregistrationv1beta1 "k8s.io/api/admissionregistration/v1beta1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
)

var (
	// DefaultAddOptions are the default AddOptions for AddToManager.
	DefaultAddOptions = AddOptions{}

	logger = log.Log.WithName("aws-controlplane-controller")
)

// AddOptions are options to apply when adding the AWS controlplane controller to the manager.
type AddOptions struct {
	// Controller are the controller.Options.
	Controller controller.Options
	// IgnoreOperationAnnotation specifies whether to ignore the operation annotation or not.
	IgnoreOperationAnnotation bool
	// ShootWebhooks specifies the list of desired Shoot MutatingWebhooks.
	ShootWebhooks []admissionregistrationv1beta1.MutatingWebhook
}

// AddToManagerWithOptions adds a controller with the given Options to the given manager.
// The opts.Reconciler is being set with a newly instantiated actuator.
func AddToManagerWithOptions(mgr manager.Manager, opts AddOptions) error {
	objectKeys := []client.ObjectKey{
		{Name: "volumesnapshots.snapshot.storage.k8s.io"},
		{Name: "volumesnapshotcontents.snapshot.storage.k8s.io"},
		{Name: "volumesnapshotclasses.snapshot.storage.k8s.io"},
	}
	needsMigrationFunc := func(cluster *extensionscontroller.Cluster) bool {
		csiEnabled, err := version.CompareVersions(cluster.Shoot.Spec.Kubernetes.Version, ">=", "1.18")
		if err != nil {
			return false
		}
		return csiEnabled
	}

	return controlplane.Add(mgr, controlplane.AddArgs{
		Actuator: genericactuator.NewShootCRDsMigrator(genericactuator.NewActuator(aws.Name, controlPlaneSecrets, controlPlaneExposureSecrets, configChart, controlPlaneChart, controlPlaneShootChart, controlPlaneShootCRDsChart,
			storageClassChart, cpExposureChart, NewValuesProvider(logger), extensionscontroller.ChartRendererFactoryFunc(util.NewChartRendererForShoot),
			imagevector.ImageVector(), aws.CloudProviderConfigName, opts.ShootWebhooks, mgr.GetWebhookServer().Port, logger), objectKeys, needsMigrationFunc, logger),
		ControllerOptions: opts.Controller,
		Predicates:        controlplane.DefaultPredicates(opts.IgnoreOperationAnnotation),
		Type:              aws.Type,
	})
}

// AddToManager adds a controller with the default Options.
func AddToManager(mgr manager.Manager) error {
	return AddToManagerWithOptions(mgr, DefaultAddOptions)
}
