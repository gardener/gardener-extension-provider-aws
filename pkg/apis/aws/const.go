// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws

const (
	// AnnotationKeyUseFlow is the annotation key used to enable reconciliation with flow instead of terraformer.
	AnnotationKeyUseFlow = "aws.provider.extensions.gardener.cloud/use-flow"
	// SeedLabelKeyUseFlow is the label for seeds to enable flow reconciliation for all of its shoots if value is `true`
	// or for new shoots only with value `new`
	SeedLabelKeyUseFlow = AnnotationKeyUseFlow
	// SeedLabelUseFlowValueNew is the value to restrict flow reconciliation to new shoot clusters
	SeedLabelUseFlowValueNew = "new"
	// AnnotationKeyIPStack is the annotation key to set the IP stack for a DNSRecord.
	AnnotationKeyIPStack = "dns.gardener.cloud/ip-stack"
)
