// SPDX-FileCopyrightText: Contributors to the Gardener project
//
// SPDX-License-Identifier: Apache-2.0

package helper_test

import (
	"testing"

	. "github.com/onsi/gomega"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"

	api "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/helper"
	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws/v1alpha1"
)

func TestInfrastructureStateFromRaw(t *testing.T) {
	nativeState := &v1alpha1.InfrastructureState{
		TypeMeta: metav1.TypeMeta{APIVersion: v1alpha1.SchemeGroupVersion.String(), Kind: "InfrastructureState"},
		Data: map[string]string{
			"VPC":                   "vpc-test",
			"MigratedFromTerraform": "true",
		},
	}
	for _, tc := range []struct {
		name    string
		raw     *runtime.RawExtension
		data    map[string]string
		wantErr bool
	}{
		{name: "absent state", data: map[string]string{}},
		{name: "empty raw extension", raw: &runtime.RawExtension{}, data: map[string]string{}},
		{name: "empty raw bytes", raw: &runtime.RawExtension{Raw: []byte{}}, data: map[string]string{}},
		{
			name: "raw state preserves data and ignores unknown fields",
			raw:  &runtime.RawExtension{Raw: []byte(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","kind":"InfrastructureState","data":{"VPC":"vpc-test","MigratedFromTerraform":"true"},"futureField":true}`)},
			data: nativeState.Data,
		},
		{name: "object-backed state preserves data", raw: &runtime.RawExtension{Object: nativeState}, data: nativeState.Data},
		{
			name: "raw bytes take precedence over object",
			raw: &runtime.RawExtension{
				Raw:    []byte(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","kind":"InfrastructureState","data":{"VPC":"vpc-raw"}}`),
				Object: nativeState,
			},
			data: map[string]string{"VPC": "vpc-raw"},
		},
		{name: "native state without data", raw: &runtime.RawExtension{Raw: []byte(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","kind":"InfrastructureState"}`)}, data: map[string]string{}},
		{name: "invalid JSON", raw: &runtime.RawExtension{Raw: []byte(`invalid`)}, wantErr: true},
		{name: "object cannot be marshalled", raw: &runtime.RawExtension{Object: &runtime.Unknown{Raw: []byte(`invalid`)}}, wantErr: true},
		{name: "missing kind", raw: &runtime.RawExtension{Raw: []byte(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","data":{"VPC":"vpc-test"}}`)}, wantErr: true},
		{name: "missing API version", raw: &runtime.RawExtension{Raw: []byte(`{"kind":"InfrastructureState","data":{"VPC":"vpc-test"}}`)}, wantErr: true},
		{name: "legacy Terraform state", raw: &runtime.RawExtension{Raw: []byte(`{"data":"{}","encoding":"none"}`)}, wantErr: true},
		{name: "unsupported API version", raw: &runtime.RawExtension{Raw: []byte(`{"apiVersion":"example.com/v1","kind":"InfrastructureState"}`)}, wantErr: true},
		{name: "different registered kind", raw: &runtime.RawExtension{Raw: []byte(`{"apiVersion":"aws.provider.extensions.gardener.cloud/v1alpha1","kind":"InfrastructureConfig"}`)}, wantErr: true},
		{
			name: "different registered object kind",
			raw: &runtime.RawExtension{Object: &v1alpha1.InfrastructureConfig{
				TypeMeta: metav1.TypeMeta{APIVersion: v1alpha1.SchemeGroupVersion.String(), Kind: "InfrastructureConfig"},
			}},
			wantErr: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := NewWithT(t)
			state, err := helper.InfrastructureStateFromRaw(tc.raw)
			if tc.wantErr {
				g.Expect(err).To(HaveOccurred())
				g.Expect(state).To(BeNil())
			} else {
				g.Expect(err).NotTo(HaveOccurred())
				g.Expect(state).To(Equal(&api.InfrastructureState{Data: tc.data}))
			}
		})
	}
}
