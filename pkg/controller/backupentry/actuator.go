// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package backupentry

import (
	"context"
	"fmt"
	"strings"

	"github.com/gardener/gardener/extensions/pkg/controller/backupentry/genericactuator"
	"github.com/gardener/gardener/extensions/pkg/util"
	v1beta1constants "github.com/gardener/gardener/pkg/apis/core/v1beta1/constants"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	securityv1alpha1constants "github.com/gardener/gardener/pkg/apis/security/v1alpha1/constants"
	kutil "github.com/gardener/gardener/pkg/utils/kubernetes"
	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

type actuator struct {
	client client.Client
}

var _ genericactuator.BackupEntryDelegate = (*actuator)(nil)

func newActuator(mgr manager.Manager) genericactuator.BackupEntryDelegate {
	return &actuator{
		client: mgr.GetClient(),
	}
}

func (a *actuator) GetETCDSecretData(ctx context.Context, _ logr.Logger, be *extensionsv1alpha1.BackupEntry, backupSecretData map[string][]byte) (map[string][]byte, error) {
	backupSecretData[aws.Region] = []byte(be.Spec.Region)
	if err := a.injectWorkloadIdentityData(ctx, be, backupSecretData); err != nil {
		return nil, err
	}
	return backupSecretData, nil
}

func (a *actuator) Delete(ctx context.Context, _ logr.Logger, be *extensionsv1alpha1.BackupEntry) error {
	awsClient, err := aws.NewClientFromSecretRef(ctx, a.client, be.Spec.SecretRef, be.Spec.Region)
	if err != nil {
		return util.DetermineError(err, helper.KnownCodes)
	}
	entryName := strings.TrimPrefix(be.Name, v1beta1constants.BackupSourcePrefix+"-")
	return util.DetermineError(awsClient.DeleteObjectsWithPrefix(ctx, be.Spec.BucketName, fmt.Sprintf("%s/", entryName)), helper.KnownCodes)
}

func (a *actuator) injectWorkloadIdentityData(ctx context.Context, be *extensionsv1alpha1.BackupEntry, data map[string][]byte) error {
	entrySecret := &corev1.Secret{}
	if err := a.client.Get(ctx, kutil.ObjectKeyFromSecretRef(be.Spec.SecretRef), entrySecret); err != nil {
		return err
	}
	if entrySecret.Labels[securityv1alpha1constants.LabelPurpose] != securityv1alpha1constants.LabelPurposeWorkloadIdentityTokenRequestor {
		return nil
	}
	wi, err := helper.WorkloadIdentityConfigFromBytes(entrySecret.Data[securityv1alpha1constants.DataKeyConfig])
	if err != nil {
		return err
	}

	data[aws.RoleARN] = []byte(wi.RoleARN)
	return nil
}
