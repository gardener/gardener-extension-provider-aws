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

package controlplaneexposure

import (
	"context"

	druidv1alpha1 "github.com/gardener/etcd-druid/api/v1alpha1"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/config"
	extensionswebhook "github.com/gardener/gardener-extensions/pkg/webhook"
	"github.com/gardener/gardener-extensions/pkg/webhook/controlplane/genericmutator"

	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	v1beta1helper "github.com/gardener/gardener/pkg/apis/core/v1beta1/helper"
	"github.com/go-logr/logr"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/resource"
)

// NewEnsurer creates a new controlplaneexposure ensurer.
func NewEnsurer(etcdStorage *config.ETCDStorage, logger logr.Logger) genericmutator.Ensurer {
	return &ensurer{
		etcdStorage: etcdStorage,
		logger:      logger.WithName("aws-controlplaneexposure-ensurer"),
	}
}

type ensurer struct {
	genericmutator.NoopEnsurer
	etcdStorage *config.ETCDStorage
	logger      logr.Logger
}

// EnsureKubeAPIServerService ensures that the kube-apiserver service conforms to the provider requirements.
func (e *ensurer) EnsureKubeAPIServerService(ctx context.Context, ectx genericmutator.EnsurerContext, new, old *corev1.Service) error {
	if v1beta1helper.IsAPIServerExposureManaged(new) {
		return nil
	}

	if new.Annotations == nil {
		new.Annotations = make(map[string]string)
	}
	new.Annotations["service.beta.kubernetes.io/aws-load-balancer-connection-idle-timeout"] = "3600"
	new.Annotations["service.beta.kubernetes.io/aws-load-balancer-backend-protocol"] = "ssl"
	new.Annotations["service.beta.kubernetes.io/aws-load-balancer-ssl-ports"] = "443"
	new.Annotations["service.beta.kubernetes.io/aws-load-balancer-healthcheck-timeout"] = "5"
	new.Annotations["service.beta.kubernetes.io/aws-load-balancer-healthcheck-interval"] = "30"
	new.Annotations["service.beta.kubernetes.io/aws-load-balancer-healthcheck-healthy-threshold"] = "2"
	new.Annotations["service.beta.kubernetes.io/aws-load-balancer-healthcheck-unhealthy-threshold"] = "2"
	new.Annotations["service.beta.kubernetes.io/aws-load-balancer-ssl-negotiation-policy"] = "ELBSecurityPolicy-TLS-1-2-2017-01"
	return nil
}

// EnsureKubeAPIServerDeployment ensures that the kube-apiserver deployment conforms to the provider requirements.
func (e *ensurer) EnsureKubeAPIServerDeployment(ctx context.Context, ectx genericmutator.EnsurerContext, new, old *appsv1.Deployment) error {
	if v1beta1helper.IsAPIServerExposureManaged(new) {
		return nil
	}

	if c := extensionswebhook.ContainerWithName(new.Spec.Template.Spec.Containers, "kube-apiserver"); c != nil {
		c.Command = extensionswebhook.EnsureStringWithPrefix(c.Command, "--endpoint-reconciler-type=", "none")
	}
	return nil
}

// EnsureETCD ensures that the etcd conform to the provider requirements.
func (e *ensurer) EnsureETCD(ctx context.Context, ectx genericmutator.EnsurerContext, new, old *druidv1alpha1.Etcd) error {
	capacity := resource.MustParse("10Gi")
	class := ""

	if new.Name == v1beta1constants.ETCDMain && e.etcdStorage != nil {
		if e.etcdStorage.Capacity != nil {
			capacity = *e.etcdStorage.Capacity
		}
		if e.etcdStorage.ClassName != nil {
			class = *e.etcdStorage.ClassName
		}
	}

	new.Spec.StorageClass = &class
	new.Spec.StorageCapacity = &capacity

	return nil
}
