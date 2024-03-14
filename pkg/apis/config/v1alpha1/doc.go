// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

// +k8s:deepcopy-gen=package
// +k8s:conversion-gen=github.com/gardener/gardener-extension-provider-aws/pkg/apis/config
// +k8s:openapi-gen=true
// +k8s:defaulter-gen=TypeMeta

//go:generate sh -c "gen-crd-api-reference-docs -api-dir . -config ../../../../hack/api-reference/config.json -template-dir $GARDENER_HACK_DIR/api-reference/template -out-file ../../../../hack/api-reference/config.md"

// Package v1alpha1 contains the AWS provider configuration API resources.
// +groupName=aws.provider.extensions.config.gardener.cloud
package v1alpha1 // import "github.com/gardener/gardener-extension-provider-aws/pkg/apis/config/v1alpha1"
