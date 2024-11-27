// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	"context"
	"fmt"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	securityv1alpha1constants "github.com/gardener/gardener/pkg/apis/security/v1alpha1/constants"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

type staticTokenRetriever struct {
	token []byte
}

func (s *staticTokenRetriever) GetIdentityToken() ([]byte, error) {
	return s.token, nil
}

// GetCredentialsFromSecretRef reads the secret given by the the secret reference and returns the read Credentials
// object.
func GetCredentialsFromSecretRef(ctx context.Context, client client.Client, secretRef corev1.SecretReference, allowDNSKeys bool) (*awsclient.AuthConfig, error) {
	secret, err := extensionscontroller.GetSecretByReference(ctx, client, &secretRef)
	if err != nil {
		return nil, err
	}
	return ReadCredentialsSecret(secret, allowDNSKeys)
}

// ReadCredentialsSecret reads a secret containing credentials.
func ReadCredentialsSecret(secret *corev1.Secret, allowDNSKeys bool) (*awsclient.AuthConfig, error) {
	if secret.Data == nil {
		return nil, fmt.Errorf("secret does not contain any data")
	}

	var altAccessKeyIDKey, altSecretAccessKeyKey, altRegionKey *string
	if allowDNSKeys {
		altAccessKeyIDKey, altSecretAccessKeyKey, altRegionKey = ptr.To(DNSAccessKeyID), ptr.To(DNSSecretAccessKey), ptr.To(DNSRegion)
	}

	authConfig := &awsclient.AuthConfig{}

	accessKeyID, err := getSecretDataValue(secret, AccessKeyID, altAccessKeyIDKey, false)
	if err != nil {
		return nil, err
	}
	if len(accessKeyID) != 0 {
		secretAccessKey, err := getSecretDataValue(secret, SecretAccessKey, altSecretAccessKeyKey, true)
		if err != nil {
			return nil, err
		}
		authConfig.AccessKey = &awsclient.AccessKey{
			ID:     string(accessKeyID),
			Secret: string(secretAccessKey),
		}
	} else {
		// If access key data does not exist then we require that the secret contains
		// information for workload identity authentication
		if _, ok := secret.Data[securityv1alpha1constants.DataKeyToken]; !ok {
			return nil, fmt.Errorf("missing %q field in secret", securityv1alpha1constants.DataKeyToken)
		}
		if _, ok := secret.Data[RoleARN]; !ok {
			return nil, fmt.Errorf("missing %q field in secret", RoleARN)
		}
		authConfig.WorkloadIdentity = &awsclient.WorkloadIdentity{
			TokenRetriever: &staticTokenRetriever{token: secret.Data[securityv1alpha1constants.DataKeyToken]},
			RoleARN:        string(secret.Data[RoleARN]),
		}
	}

	region, _ := getSecretDataValue(secret, Region, altRegionKey, false)
	authConfig.Region = string(region)

	return authConfig, nil
}

// NewClientFromSecretRef creates a new Client for the given AWS credentials from given k8s <secretRef> and
// the AWS region <region>.
func NewClientFromSecretRef(ctx context.Context, client client.Client, secretRef corev1.SecretReference, region string) (awsclient.Interface, error) {
	authConfig, err := GetCredentialsFromSecretRef(ctx, client, secretRef, false)
	if err != nil {
		return nil, err
	}
	authConfig.Region = region
	return awsclient.NewClient(*authConfig)
}

func getSecretDataValue(secret *corev1.Secret, key string, altKey *string, required bool) ([]byte, error) {
	if value, ok := secret.Data[key]; ok {
		return value, nil
	}
	if altKey != nil {
		if value, ok := secret.Data[*altKey]; ok {
			return value, nil
		}
	}
	if required {
		if altKey != nil {
			return nil, fmt.Errorf("missing %q (or %q) field in secret", key, *altKey)
		}
		return nil, fmt.Errorf("missing %q field in secret", key)
	}
	return nil, nil
}
