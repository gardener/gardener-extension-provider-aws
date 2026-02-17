// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain m copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package shootservice

import (
	"context"
	"fmt"
	"slices"

	extensionswebhook "github.com/gardener/gardener/extensions/pkg/webhook"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
)

// Annotation and value constants moved to pkg/apis/aws/const.go

type mutator struct {
	logger           logr.Logger
	wantsShootClient bool
}

// NewMutatorWithShootClient creates a new Mutator that mutates resources in the shoot cluster.
func NewMutatorWithShootClient(logger logr.Logger) extensionswebhook.Mutator {
	return &mutator{logger, true}
}

// WantsShootClient indicates that this mutator wants the shoot client to be injected into the context.
// The corresponding client can be found in the passed context via the ShootClientContextKey.
func (m *mutator) WantsShootClient() bool {
	return m.wantsShootClient
}

// Mutate mutates resources.
func (m *mutator) Mutate(ctx context.Context, newObj, oldObj client.Object) error {
	service, ok := newObj.(*corev1.Service)
	if !ok {
		return fmt.Errorf("could not mutate: object is not of type corev1.Service")
	}

	log := m.logger.WithValues("service", client.ObjectKeyFromObject(service))

	// If the object does have a deletion timestamp then we don't want to mutate anything.
	if service.GetDeletionTimestamp() != nil {
		return nil
	}

	if service.Spec.Type != corev1.ServiceTypeLoadBalancer {
		return nil
	}

	shootClient, ok := ctx.Value(extensionswebhook.ShootClientContextKey{}).(client.Client)
	if !ok {
		return fmt.Errorf("could not mutate: no shoot client found in context")
	}

	kubeDNSService := &corev1.Service{}
	if err := shootClient.Get(ctx, types.NamespacedName{Name: "kube-dns", Namespace: "kube-system"}, kubeDNSService); err != nil {
		log.Error(err, "Failed to get kube-dns service")
		return err
	}

	// Early return if not dualstack (no IPv6)
	if !slices.Contains(kubeDNSService.Spec.IPFamilies, corev1.IPv6Protocol) {
		return nil
	}

	// For existing services, check if we should add the ignore annotation
	if oldObj != nil {
		oldService, ok := oldObj.(*corev1.Service)
		if !ok {
			return fmt.Errorf("oldObj is not of type corev1.Service")
		}

		hasIgnoreAnnotation := metav1.HasAnnotation(service.ObjectMeta, aws.AnnotationIgnoreLoadBalancer) &&
			service.Annotations[aws.AnnotationIgnoreLoadBalancer] == aws.ValueTrue
		hadIgnoreAnnotation := metav1.HasAnnotation(oldService.ObjectMeta, aws.AnnotationIgnoreLoadBalancer) &&
			oldService.Annotations[aws.AnnotationIgnoreLoadBalancer] == aws.ValueTrue
		hasDualStackAnnotation := metav1.HasAnnotation(service.ObjectMeta, aws.AnnotationAWSLBIPType) &&
			service.Annotations[aws.AnnotationAWSLBIPType] == aws.ValueDualStack

		if !hasIgnoreAnnotation && !hasDualStackAnnotation {
			// If old version didn't have it either, add it (preserve existing services)
			if !hadIgnoreAnnotation {
				log.Info("Adding ignore annotation to existing service to preserve current behavior")
				metav1.SetMetaDataAnnotation(&service.ObjectMeta, aws.AnnotationIgnoreLoadBalancer, aws.ValueTrue)
				return nil
			}
			// If old version had it but new doesn't, user explicitly removed it -> proceed with mutation
			log.Info("User removed ignore annotation, proceeding with mutation")
		}
	}

	// Check if mutation should be skipped based on annotations
	if metav1.HasAnnotation(service.ObjectMeta, aws.AnnotationAWSLBScheme) &&
		service.Annotations[aws.AnnotationAWSLBScheme] == aws.ValueInternal ||
		metav1.HasAnnotation(service.ObjectMeta, aws.AnnotationAWSLBInternal) &&
			service.Annotations[aws.AnnotationAWSLBInternal] == aws.ValueTrue ||
		metav1.HasAnnotation(service.ObjectMeta, aws.AnnotationIgnoreLoadBalancer) &&
			service.Annotations[aws.AnnotationIgnoreLoadBalancer] == aws.ValueTrue {
		return nil
	}

	log.Info("Setting dualstack annotations for IPv6-enabled cluster")
	metav1.SetMetaDataAnnotation(&service.ObjectMeta, aws.AnnotationAWSLBIPType, aws.ValueDualStack)
	metav1.SetMetaDataAnnotation(&service.ObjectMeta, aws.AnnotationAWSLBScheme, aws.ValueInternetFacing)
	metav1.SetMetaDataAnnotation(&service.ObjectMeta, aws.AnnotationAWSLBNLBTargetType, aws.ValueInstance)
	metav1.SetMetaDataAnnotation(&service.ObjectMeta, aws.AnnotationAWSLBType, aws.ValueExternal)

	return nil
}
