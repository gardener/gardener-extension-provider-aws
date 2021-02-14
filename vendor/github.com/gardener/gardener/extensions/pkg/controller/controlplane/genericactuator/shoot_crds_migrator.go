// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package genericactuator

import (
	"context"

	resourcesv1alpha1 "github.com/gardener/gardener-resource-manager/pkg/apis/resources/v1alpha1"
	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	"github.com/gardener/gardener/extensions/pkg/controller/controlplane"
	"github.com/gardener/gardener/extensions/pkg/util"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/gardener/gardener/pkg/utils/managedresources"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1beta1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1beta1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/runtime/inject"
)

// NewClientForShoot is a function to create a new client for shoots.
var NewClientForShoot = util.NewClientForShoot

// NewShootCRDsMigrator returns a new controlplane.Actuator that migrates the Shoot CRDs to a separate ManagedResource.
func NewShootCRDsMigrator(a controlplane.Actuator, objectKeys []client.ObjectKey, needsMigrationFunc NeedsMigrationFunc, logger logr.Logger) controlplane.Actuator {
	return &shootCRDsMigrator{
		Actuator:           a,
		objectKeys:         objectKeys,
		needsMigrationFunc: needsMigrationFunc,
		logger:             logger.WithName("shoot-crds-migrator"),
	}
}

// shootCRDsMigrator is a controlplane.Actuator interface wrapper.
type shootCRDsMigrator struct {
	controlplane.Actuator
	client             client.Client
	objectKeys         []client.ObjectKey
	needsMigrationFunc NeedsMigrationFunc
	logger             logr.Logger
}

// NeedsMigrationFunc is used to determine whether the given cluster needs Shoot CRDs migration.
type NeedsMigrationFunc = func(*extensionscontroller.Cluster) bool

// InjectFunc enables injecting Kubernetes dependencies into actuator's dependencies.
func (m *shootCRDsMigrator) InjectFunc(f inject.Func) error {
	return f(m.Actuator)
}

// InjectClient injects the controller runtime client into the migrator.
func (m *shootCRDsMigrator) InjectClient(client client.Client) error {
	m.client = client
	return nil
}

// Reconcile intercepts the Reconcile func to add a migration logic for moving Shoot CRDs into a separate ManagedResource.
func (m *shootCRDsMigrator) Reconcile(
	ctx context.Context,
	cp *extensionsv1alpha1.ControlPlane,
	cluster *extensionscontroller.Cluster,
) (bool, error) {

	var shootClient client.Client

	shouldMigrate, err := m.shouldMigrate(ctx, cp, cluster)
	if err != nil {
		return false, err
	}
	m.logger.Info("Checked whether Shoot CRDs should be migrated", "controlplane", kutil.ObjectName(cp), "shouldMigrate", shouldMigrate)

	if shouldMigrate {
		_, shootClient, err = NewClientForShoot(ctx, m.client, cp.Namespace, client.Options{})
		if err != nil {
			return false, err
		}

		for _, objectKey := range m.objectKeys {
			crd := &apiextensionsv1beta1.CustomResourceDefinition{}
			if err := shootClient.Get(ctx, objectKey, crd); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}

				return false, err
			}

			m.logger.Info("Adding annotation to CustomResourceDefinition", "controlplane", kutil.ObjectName(cp), "crd-name", crd.Name, "annotation", resourcesv1alpha1.KeepObject)
			if err := extensionscontroller.AddAnnotation(ctx, shootClient, crd, resourcesv1alpha1.KeepObject, "true"); err != nil {
				return false, err
			}
		}
	}

	m.logger.Info("Calling Reconcile func of the underlying actuator")
	requeue, err := m.Actuator.Reconcile(ctx, cp, cluster)
	if err != nil {
		return requeue, err
	}

	if shouldMigrate {
		for _, objectKey := range m.objectKeys {
			ref := &corev1.ObjectReference{
				APIVersion: "apiextensions.k8s.io/v1beta1",
				Kind:       "CustomResourceDefinition",
				Name:       objectKey.Name,
			}

			m.logger.Info("Waiting until CustomResourceDefinition is removed from old ManagedResource status", "controlplane", kutil.ObjectName(cp), "crd-name", objectKey.Name)
			if err := managedresources.WaitUntilObjectsAreRemovedFromManagedResourceStatus(ctx, m.client, cp.Namespace, ControlPlaneShootChartResourceName, ref); err != nil {
				return false, err
			}
		}

		for _, objectKey := range m.objectKeys {
			crd := &apiextensionsv1beta1.CustomResourceDefinition{}
			if err := shootClient.Get(ctx, objectKey, crd); err != nil {
				if apierrors.IsNotFound(err) {
					continue
				}

				return false, err
			}

			m.logger.Info("Removing annotation from CustomResourceDefinition", "controlplane", kutil.ObjectName(cp), "crd-name", crd.Name, "annotation", resourcesv1alpha1.KeepObject)
			if err := extensionscontroller.RemoveAnnotation(ctx, shootClient, crd, resourcesv1alpha1.KeepObject); err != nil {
				return false, err
			}
		}

		m.logger.Info("Successfully completed migration of Shoot CRDs to separate ManagedResource", "name", cluster.ObjectMeta.Name)
	}

	return false, nil
}

func (m *shootCRDsMigrator) shouldMigrate(ctx context.Context, cp *extensionsv1alpha1.ControlPlane, cluster *extensionscontroller.Cluster) (bool, error) {
	if extensionscontroller.IsHibernated(cluster) {
		m.logger.Info("The cluster is hibernated, hence skipping migration for it", "cluster", cluster.ObjectMeta.Name)
		return false, nil
	}

	return m.needsShootCRDsMigration(ctx, cp, cluster)
}

func (m *shootCRDsMigrator) needsShootCRDsMigration(ctx context.Context, cp *extensionsv1alpha1.ControlPlane, cluster *extensionscontroller.Cluster) (bool, error) {
	// Exit early if the given Cluster does not need migration
	if m.needsMigrationFunc != nil && !m.needsMigrationFunc(cluster) {
		m.logger.Info("The cluster does not need migration", "cluster", cluster.ObjectMeta.Name)
		return false, nil
	}

	controlPlaneShootChart := &resourcesv1alpha1.ManagedResource{}
	if err := m.client.Get(ctx, client.ObjectKey{Name: ControlPlaneShootChartResourceName, Namespace: cp.Namespace}, controlPlaneShootChart); err != nil {
		if apierrors.IsNotFound(err) {
			m.logger.Info("ManagedResource 'extension-controlplane-shoot' does not exist, assuming that the Shoot is in process of creation", "controlplane", kutil.ObjectName(cp))
			return false, nil
		}

		return false, err
	}

	return containsAnyOfCRDs(controlPlaneShootChart, m.objectKeys), nil
}

func containsAnyOfCRDs(mr *resourcesv1alpha1.ManagedResource, objectKeys []client.ObjectKey) bool {
	for _, objectKey := range objectKeys {
		ref := &corev1.ObjectReference{
			APIVersion: "apiextensions.k8s.io/v1beta1",
			Kind:       "CustomResourceDefinition",
			Name:       objectKey.Name,
		}

		if managedresources.ContainsResource(mr, ref) {
			return true
		}
	}

	return false
}
