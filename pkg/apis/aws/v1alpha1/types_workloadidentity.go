// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkloadIdentityConfig contains configuration settings for workload identity.
type WorkloadIdentityConfig struct {
	metav1.TypeMeta

	// RoleARN is the identifier of the role that the workload identity will assume.
	RoleARN string `json:"roleARN,omitempty"`
}
