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

package validation

import (
	"fmt"
	"regexp"

	corev1 "k8s.io/api/core/v1"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

const (
	accessKeyMinLen       = 16
	accessKeyMaxLen       = 128
	secretAccessKeyMinLen = 40
)

var (
	accessKeyRegex       = regexp.MustCompile(`^\w+$`)
	secretAccessKeyRegex = regexp.MustCompile(`^[A-Za-z0-9/+=]+$`)
)

// ValidateCloudProviderSecret checks whether the given secret contains a valid AWS access keys.
func ValidateCloudProviderSecret(secret *corev1.Secret) error {
	secretRef := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)

	// accessKeyID must have length between 16 and 128 and only contain alphanumeric characters,
	// see https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html
	accessKeyID, ok := secret.Data[aws.AccessKeyID]
	if !ok {
		return fmt.Errorf("missing %q field in secret %s", aws.AccessKeyID, secretRef)
	}
	if len(accessKeyID) < accessKeyMinLen {
		return fmt.Errorf("field %q in secret %s must have at least %d characters", aws.AccessKeyID, secretRef, accessKeyMinLen)
	}
	if len(accessKeyID) > accessKeyMaxLen {
		return fmt.Errorf("field %q in secret %s cannot be longer than %d characters", aws.AccessKeyID, secretRef, accessKeyMaxLen)
	}
	if !accessKeyRegex.Match(accessKeyID) {
		return fmt.Errorf("field %q in secret %s must only contain alphanumeric characters", aws.AccessKeyID, secretRef)
	}

	// secretAccessKey must have a minimum length of 40 and only contain base64 characters,
	// see https://docs.aws.amazon.com/IAM/latest/APIReference/API_AccessKey.html and https://aws.amazon.com/blogs/security/a-safer-way-to-distribute-aws-credentials-to-ec2/
	secretAccessKey, ok := secret.Data[aws.SecretAccessKey]
	if !ok {
		return fmt.Errorf("missing %q field in secret %s", aws.SecretAccessKey, secretRef)
	}
	if len(secretAccessKey) < secretAccessKeyMinLen {
		return fmt.Errorf("field %q in secret %s must have at least %d characters", aws.SecretAccessKey, secretRef, secretAccessKeyMinLen)
	}
	if !secretAccessKeyRegex.Match(secretAccessKey) {
		return fmt.Errorf("field %q in secret %s must only contain base64 characters", aws.SecretAccessKey, secretRef)
	}

	return nil
}
