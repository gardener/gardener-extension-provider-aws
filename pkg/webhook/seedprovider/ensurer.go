// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package seedprovider

import (
	"context"

	druidcorev1alpha1 "github.com/gardener/etcd-druid/api/core/v1alpha1"
	gcontext "github.com/gardener/gardener/extensions/pkg/webhook/context"
	"github.com/gardener/gardener/extensions/pkg/webhook/controlplane/genericmutator"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	"github.com/go-logr/logr"
	"k8s.io/apimachinery/pkg/api/resource"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/config"
)

// NewEnsurer creates a new seedprovider ensurer.
func NewEnsurer(etcdStorage *config.ETCDStorage, logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		etcdStorage: etcdStorage,
		logger:      logger.WithName("aws-seedprovider-ensurer"),
	}
}

type ensurer struct {
	genericmutator.NoopEnsurer
	etcdStorage *config.ETCDStorage
	logger      logr.Logger
}

// EnsureETCD ensures that the etcd conform to the provider requirements.
func (e *ensurer) EnsureETCD(_ context.Context, _ gcontext.GardenContext, newObj, oldObj *druidcorev1alpha1.Etcd) error {
	capacity := resource.MustParse("10Gi")
	class := ""

	// for newly created Etcds
	if newObj.Name == v1beta1constants.ETCDMain && e.etcdStorage != nil {
		if e.etcdStorage.Capacity != nil {
			capacity = *e.etcdStorage.Capacity
		}
		if e.etcdStorage.ClassName != nil {
			class = *e.etcdStorage.ClassName
		}
	}

	// ensure old Etcds which are created are not resized
	if oldObj != nil && oldObj.Name == v1beta1constants.ETCDMain && e.etcdStorage != nil {
		if oldObj.Spec.StorageClass != nil {
			class = *oldObj.Spec.StorageClass
		} else if e.etcdStorage.ClassName != nil {
			class = *e.etcdStorage.ClassName
		}
		if oldObj.Spec.StorageCapacity != nil {
			capacity = *oldObj.Spec.StorageCapacity
		} else if e.etcdStorage.Capacity != nil {
			capacity = *e.etcdStorage.Capacity
		}
	}

	newObj.Spec.StorageClass = &class
	newObj.Spec.StorageCapacity = &capacity

	return nil
}
