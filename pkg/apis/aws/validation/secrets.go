// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package validation

import (
	"fmt"

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

// ValidateCloudProviderSecret checks whether the given secret contains valid AWS credentials
func ValidateCloudProviderSecret(secret *corev1.Secret, fldPath *field.Path, kind SecretKind) field.ErrorList {
	allErrs := field.ErrorList{}
	dataPath := fldPath.Child("data")
	secretRef := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)

	var accessKeyIDKey, secretAccessKeyKey, regionKey string
	var accessKeyID, secretAccessKey, region []byte
	var accessKeyIDExists, secretAccessKeyExists, regionExists bool

	// Check for duplicate keys (both standard and DNS-specific for the same field)
	_, hasStandardAccessKey := secret.Data[aws.AccessKeyID]
	_, hasDNSAccessKey := secret.Data[aws.DNSAccessKeyID]
	_, hasStandardSecretKey := secret.Data[aws.SecretAccessKey]
	_, hasDNSSecretKey := secret.Data[aws.DNSSecretAccessKey]

	if hasStandardAccessKey && hasDNSAccessKey {
		allErrs = append(allErrs, field.Invalid(dataPath, "(multiple keys)",
			fmt.Sprintf("cannot have both %q and %q in secret %s", aws.AccessKeyID, aws.DNSAccessKeyID, secretRef)))
	}

	if hasStandardSecretKey && hasDNSSecretKey {
		allErrs = append(allErrs, field.Invalid(dataPath, "(multiple keys)",
			fmt.Sprintf("cannot have both %q and %q in secret %s", aws.SecretAccessKey, aws.DNSSecretAccessKey, secretRef)))
	}

	// Check for DNS-specific keys first, then fall back to standard keys
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

	switch kind {
	case SecretKindInfrastructure:
		// Allow both standard and DNS-specific keys
		allErrs = append(allErrs, validateNoUnexpectedKeys(secret.Data, dataPath, secretRef,
			aws.AccessKeyID, aws.SecretAccessKey,
			aws.DNSAccessKeyID, aws.DNSSecretAccessKey)...)

	case SecretKindDns:
		// Check for duplicate region keys
		_, hasStandardRegion := secret.Data[aws.Region]
		_, hasDNSRegion := secret.Data[aws.DNSRegion]

		if hasStandardRegion && hasDNSRegion {
			allErrs = append(allErrs, field.Invalid(dataPath, "(multiple keys)",
				fmt.Sprintf("cannot have both %q and %q in secret %s", aws.Region, aws.DNSRegion, secretRef)))
		}

		// Allow both standard and DNS-specific keys
		allErrs = append(allErrs, validateNoUnexpectedKeys(secret.Data, dataPath, secretRef,
			aws.AccessKeyID, aws.SecretAccessKey, aws.Region,
			aws.DNSAccessKeyID, aws.DNSSecretAccessKey, aws.DNSRegion)...)

		region, regionExists = secret.Data[aws.DNSRegion]
		if regionExists {
			regionKey = aws.DNSRegion
		} else {
			region, regionExists = secret.Data[aws.Region]
			regionKey = aws.Region
		}

		if regionExists && len(region) > 0 {
			allErrs = append(allErrs, validateRegion(string(region), dataPath.Key(regionKey))...)
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
