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

package aws

import (
	"context"
	"fmt"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"

	extensionscontroller "github.com/gardener/gardener/extensions/pkg/controller"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// GetCredentialsFromSecretRef reads the secret given by the the secret reference and returns the read Credentials
// object.
func GetCredentialsFromSecretRef(ctx context.Context, client client.Client, secretRef corev1.SecretReference, useDNSKeys bool) (*Credentials, error) {
	secret, err := extensionscontroller.GetSecretByReference(ctx, client, &secretRef)
	if err != nil {
		return nil, err
	}
	return ReadCredentialsSecret(secret, useDNSKeys)
}

// ReadCredentialsSecret reads a secret containing credentials.
func ReadCredentialsSecret(secret *corev1.Secret, useDNSKeys bool) (*Credentials, error) {
	if secret.Data == nil {
		return nil, fmt.Errorf("secret does not contain any data")
	}

	accessKeyIDKey, secretAccessKeyKey, regionKey := AccessKeyID, SecretAccessKey, Region
	if useDNSKeys {
		accessKeyIDKey, secretAccessKeyKey, regionKey = DNSAccessKeyID, DNSSecretAccessKey, DNSRegion
	}

	accessKeyID, ok := secret.Data[accessKeyIDKey]
	if !ok {
		return nil, fmt.Errorf("missing %q field in secret", accessKeyIDKey)
	}

	secretAccessKey, ok := secret.Data[secretAccessKeyKey]
	if !ok {
		return nil, fmt.Errorf("missing %q field in secret", secretAccessKeyKey)
	}

	region := secret.Data[regionKey]

	return &Credentials{
		AccessKeyID:     accessKeyID,
		SecretAccessKey: secretAccessKey,
		Region:          region,
	}, nil
}

// NewClientFromSecretRef creates a new Client for the given AWS credentials from given k8s <secretRef> and
// the AWS region <region>.
func NewClientFromSecretRef(ctx context.Context, client client.Client, secretRef corev1.SecretReference, region string) (awsclient.Interface, error) {
	credentials, err := GetCredentialsFromSecretRef(ctx, client, secretRef, false)
	if err != nil {
		return nil, err
	}
	return awsclient.NewClient(string(credentials.AccessKeyID), string(credentials.SecretAccessKey), region)
}

// NewClientFromDNSSecretRef creates a new Client for the given AWS credentials from given k8s <secretRef> and
// the AWS region <region>, using the DNS keys instead of the regular ones.
func NewClientFromDNSSecretRef(ctx context.Context, client client.Client, secretRef corev1.SecretReference, region *string) (awsclient.Interface, error) {
	credentials, err := GetCredentialsFromSecretRef(ctx, client, secretRef, true)
	if err != nil {
		return nil, err
	}
	return awsclient.NewClient(string(credentials.AccessKeyID), string(credentials.SecretAccessKey), getDNSRegion(region, credentials))
}

func getDNSRegion(region *string, credentials *Credentials) string {
	switch {
	case region != nil:
		return *region
	case credentials.Region != nil:
		return string(credentials.Region)
	default:
		return DefaultDNSRegion
	}
}
