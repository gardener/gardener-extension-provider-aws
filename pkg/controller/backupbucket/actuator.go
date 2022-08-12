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

package backupbucket

import (
	"context"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
	"github.com/gardener/gardener/extensions/pkg/controller/backupbucket"

	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	"github.com/go-logr/logr"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type actuator struct {
	backupbucket.Actuator
	client client.Client
}

func newActuator() backupbucket.Actuator {
	return &actuator{}
}

func (a *actuator) InjectClient(client client.Client) error {
	a.client = client
	return nil
}

func (a *actuator) Reconcile(ctx context.Context, _ logr.Logger, bb *extensionsv1alpha1.BackupBucket) error {
	awsClient, err := aws.NewClientFromSecretRef(ctx, a.client, bb.Spec.SecretRef, bb.Spec.Region)
	if err != nil {
		return err
	}

	return awsClient.CreateBucketIfNotExists(ctx, bb.Name, bb.Spec.Region)
}

func (a *actuator) Delete(ctx context.Context, _ logr.Logger, bb *extensionsv1alpha1.BackupBucket) error {
	awsClient, err := aws.NewClientFromSecretRef(ctx, a.client, bb.Spec.SecretRef, bb.Spec.Region)
	if err != nil {
		return err
	}

	return awsClient.DeleteBucketIfExists(ctx, bb.Name)
}
