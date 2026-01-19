// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"

	securityv1alpha1constants "github.com/gardener/gardener/pkg/apis/security/v1alpha1/constants"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/apimachinery/pkg/util/validation/field"

	"github.com/gardener/gardener-extension-provider-aws/pkg/aws"
)

// SecretKind determines whether the secret is of type infrastructure or dns
type SecretKind string

const (
	// SecretKindInfrastructure denotes an infrastructure secret referenced e.g. in a credentialsBinding
	SecretKindInfrastructure SecretKind = "infrastructure"
	// SecretKindDns denotes a dns secret referenced in the dns section of a shoot spec
	SecretKindDns SecretKind = "dns"
)

var supportedSecretKinds = []string{
	string(SecretKindInfrastructure),
	string(SecretKindDns),
}

// ValidateCloudProviderSecret checks whether the given secret contains valid AWS access keys.
func ValidateCloudProviderSecret(secret *corev1.Secret, fldPath *field.Path, kind SecretKind) field.ErrorList {
	allErrs := field.ErrorList{}
	dataPath := fldPath.Child("data")
	secretRef := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)

	var accessKeyIDKey, secretAccessKeyKey string
	var accessKeyID, secretAccessKey []byte
	var accessKeyIDExists, secretAccessKeyExists bool

	switch kind {
	case SecretKindInfrastructure:
		accessKeyIDKey = aws.AccessKeyID
		secretAccessKeyKey = aws.SecretAccessKey
		accessKeyID, accessKeyIDExists = secret.Data[accessKeyIDKey]
		secretAccessKey, secretAccessKeyExists = secret.Data[secretAccessKeyKey]

		// Validate no unexpected keys exist
		allErrs = append(allErrs, validateNoUnexpectedKeys(secret.Data, dataPath, secretRef,
			aws.AccessKeyID, aws.SecretAccessKey, aws.Region,
			aws.SharedCredentialsFile, securityv1alpha1constants.DataKeyConfig,
			aws.RoleARN, aws.WorkloadIdentityTokenFileKey)...)

	case SecretKindDns:
		// For DNS secrets, check for DNS-specific key aliases first, then fall back to
		// standard infrastructure keys
		accessKeyID, accessKeyIDExists = secret.Data[aws.DNSAccessKeyID]
		if accessKeyIDExists {
			accessKeyIDKey = aws.DNSAccessKeyID
		} else {
			accessKeyID, accessKeyIDExists = secret.Data[aws.AccessKeyID]
			accessKeyIDKey = aws.AccessKeyID
		}

		secretAccessKey, secretAccessKeyExists = secret.Data[aws.DNSSecretAccessKey]
		if secretAccessKeyExists {
			secretAccessKeyKey = aws.DNSSecretAccessKey
		} else {
			secretAccessKey, secretAccessKeyExists = secret.Data[aws.SecretAccessKey]
			secretAccessKeyKey = aws.SecretAccessKey
		}

		// Validate no unexpected keys exist
		// For DNS, we allow either the standard infrastructure keys or the DNS-specific alias keys, but not a mix
		// Prefer standard keys if any are present
		_, hasStandardAccessKey := secret.Data[aws.AccessKeyID]
		_, hasStandardSecretKey := secret.Data[aws.SecretAccessKey]

		if hasStandardAccessKey || hasStandardSecretKey {
			allErrs = append(allErrs, validateNoUnexpectedKeys(secret.Data, dataPath, secretRef,
				aws.AccessKeyID, aws.SecretAccessKey, aws.Region)...)
		} else {
			allErrs = append(allErrs, validateNoUnexpectedKeys(secret.Data, dataPath, secretRef,
				aws.DNSAccessKeyID, aws.DNSSecretAccessKey, aws.DNSRegion)...)
		}

	default:
		return field.ErrorList{
			field.NotSupported(fldPath, kind, supportedSecretKinds),
		}
	}

	// Validate accessKeyID
	if !accessKeyIDExists {
		allErrs = append(allErrs, field.Required(dataPath.Key(accessKeyIDKey),
			fmt.Sprintf("missing required field %q in secret %s", accessKeyIDKey, secretRef)))
	} else if len(accessKeyID) == 0 {
		allErrs = append(allErrs, field.Required(dataPath.Key(accessKeyIDKey),
			fmt.Sprintf("field %q cannot be empty in secret %s", accessKeyIDKey, secretRef)))
	} else {
		allErrs = append(allErrs, validateAccessKeyID(string(accessKeyID), dataPath.Key(accessKeyIDKey))...)
	}

	// Validate secretAccessKey
	if !secretAccessKeyExists {
		allErrs = append(allErrs, field.Required(dataPath.Key(secretAccessKeyKey),
			fmt.Sprintf("missing required field %q in secret %s", secretAccessKeyKey, secretRef)))
	} else if len(secretAccessKey) == 0 {
		allErrs = append(allErrs, field.Required(dataPath.Key(secretAccessKeyKey),
			fmt.Sprintf("field %q cannot be empty in secret %s", secretAccessKeyKey, secretRef)))
	} else {
		allErrs = append(allErrs, validateSecretAccessKey(string(secretAccessKey), dataPath.Key(secretAccessKeyKey))...)
	}

	return allErrs
}

// validateNoUnexpectedKeys checks that the secret data contains only the expected keys
func validateNoUnexpectedKeys(data map[string][]byte, dataPath *field.Path, secretRef string, expectedKeys ...string) field.ErrorList {
	allErrs := field.ErrorList{}

	expected := sets.NewString(expectedKeys...)

	for key := range data {
		if !expected.Has(key) {
			allErrs = append(allErrs, field.Forbidden(dataPath.Key(key),
				fmt.Sprintf("unexpected field %q in secret %s", key, secretRef)))
		}
	}

	return allErrs
}
