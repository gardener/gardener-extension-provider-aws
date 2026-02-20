// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws

const (
	// AnnotationKeyIPStack is the annotation key to set the IP stack for a DNSRecord.
	AnnotationKeyIPStack = "dns.gardener.cloud/ip-stack"

	// AnnotationIgnoreLoadBalancer is the annotation key to ignore load balancer mutation for a service.
	AnnotationIgnoreLoadBalancer = "extensions.gardener.cloud/ignore-load-balancer"
	// AnnotationAWSLBIPType is the annotation key for AWS load balancer IP address type.
	AnnotationAWSLBIPType = "service.beta.kubernetes.io/aws-load-balancer-ip-address-type"
	// AnnotationAWSLBScheme is the annotation key for AWS load balancer scheme.
	AnnotationAWSLBScheme = "service.beta.kubernetes.io/aws-load-balancer-scheme"
	// AnnotationAWSLBInternal is the annotation key for AWS internal load balancer.
	AnnotationAWSLBInternal = "service.beta.kubernetes.io/aws-load-balancer-internal"
	// AnnotationAWSLBNLBTargetType is the annotation key for AWS NLB target type.
	AnnotationAWSLBNLBTargetType = "service.beta.kubernetes.io/aws-load-balancer-nlb-target-type"
	// AnnotationAWSLBType is the annotation key for AWS load balancer type.
	AnnotationAWSLBType = "service.beta.kubernetes.io/aws-load-balancer-type"

	// ValueTrue is the string value "true" for annotation values.
	ValueTrue = "true"
	// ValueInternal is the string value "internal" for annotation values.
	ValueInternal = "internal"
	// ValueDualStack is the string value "dualstack" for annotation values.
	ValueDualStack = "dualstack"
	// ValueInternetFacing is the string value "internet-facing" for annotation values.
	ValueInternetFacing = "internet-facing"
	// ValueInstance is the string value "instance" for annotation values.
	ValueInstance = "instance"
	// ValueExternal is the string value "external" for annotation values.
	ValueExternal = "external"
)
