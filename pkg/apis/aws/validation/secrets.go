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

// ValidateCloudProviderSecret checks whether the given secret contains valid AWS credentials
func ValidateCloudProviderSecret(secret *corev1.Secret, fldPath *field.Path) field.ErrorList {
	allErrs := field.ErrorList{}
	dataPath := fldPath.Child("data")
	secretRef := fmt.Sprintf("%s/%s", secret.Namespace, secret.Name)

	// Check for duplicate keys
	allErrs = append(allErrs, validateNoDuplicateKey(secret.Data, dataPath, secretRef, aws.AccessKeyID, aws.DNSAccessKeyID)...)
	allErrs = append(allErrs, validateNoDuplicateKey(secret.Data, dataPath, secretRef, aws.SecretAccessKey, aws.DNSSecretAccessKey)...)
	allErrs = append(allErrs, validateNoDuplicateKey(secret.Data, dataPath, secretRef, aws.Region, aws.DNSRegion)...)

	// Allow all possible keys
	allErrs = append(allErrs, validateNoUnexpectedKeys(secret.Data, dataPath, secretRef,
		aws.AccessKeyID, aws.SecretAccessKey, aws.Region,
		aws.DNSAccessKeyID, aws.DNSSecretAccessKey, aws.DNSRegion)...)

	// Validate required credentials
	accessKeyID, accessKeyIDKey, accessKeyIDExists := getCredential(secret.Data, aws.DNSAccessKeyID, aws.AccessKeyID)
	allErrs = append(allErrs, validateRequiredCredential(accessKeyIDExists, accessKeyID, accessKeyIDKey, dataPath, secretRef, validateAccessKeyID)...)

	secretAccessKey, secretAccessKeyKey, secretAccessKeyExists := getCredential(secret.Data, aws.DNSSecretAccessKey, aws.SecretAccessKey)
	allErrs = append(allErrs, validateRequiredCredential(secretAccessKeyExists, secretAccessKey, secretAccessKeyKey, dataPath, secretRef, validateSecretAccessKey)...)

	// Validate optional region
	region, regionKey, regionExists := getCredential(secret.Data, aws.DNSRegion, aws.Region)
	if regionExists && len(region) > 0 {
		allErrs = append(allErrs, validateRegion(string(region), dataPath.Key(regionKey))...)
	}

	return allErrs
}

// validateNoDuplicateKey checks if both standard and DNS-specific keys exist
func validateNoDuplicateKey(data map[string][]byte, dataPath *field.Path, secretRef, standardKey, dnsKey string) field.ErrorList {
	_, hasStandard := data[standardKey]
	_, hasDNS := data[dnsKey]

	if hasStandard && hasDNS {
		return field.ErrorList{field.Invalid(dataPath, "(multiple keys)",
			fmt.Sprintf("cannot have both %q and %q in secret %s", standardKey, dnsKey, secretRef))}
	}
	return nil
}

// getCredential returns the credential value, key name, and existence flag, preferring DNS-specific keys
func getCredential(data map[string][]byte, dnsKey, standardKey string) ([]byte, string, bool) {
	if val, exists := data[dnsKey]; exists {
		return val, dnsKey, true
	}
	if val, exists := data[standardKey]; exists {
		return val, standardKey, true
	}
	return nil, standardKey, false
}

// validateRequiredCredential validates a required credential field
func validateRequiredCredential(exists bool, value []byte, key string, dataPath *field.Path, secretRef string, validatorFn validateFunc[string]) field.ErrorList {
	if !exists {
		return field.ErrorList{field.Required(dataPath.Key(key),
			fmt.Sprintf("missing required field %q in secret %s", key, secretRef))}
	}
	if len(value) == 0 {
		return field.ErrorList{field.Required(dataPath.Key(key),
			fmt.Sprintf("field %q cannot be empty in secret %s", key, secretRef))}
	}
	return validatorFn(string(value), dataPath.Key(key))
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
