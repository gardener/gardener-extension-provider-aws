// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infrastructure

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/validation/field"

	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

func TestValidateNodesCIDRInSubnet(t *testing.T) {
	fldPath := field.NewPath("networks", "zones").Index(0).Child("workersSubnetID")

	tests := []struct {
		name       string
		subnetCIDR string
		nodesCIDRs []string
		expectErr  bool
	}{
		{
			name:       "nodes CIDR contained in subnet",
			subnetCIDR: "10.0.0.0/16",
			nodesCIDRs: []string{"10.0.0.0/19"},
			expectErr:  false,
		},
		{
			name:       "nodes CIDR equals subnet (exact match)",
			subnetCIDR: "10.0.0.0/19",
			nodesCIDRs: []string{"10.0.0.0/19"},
			expectErr:  false,
		},
		{
			name:       "nodes CIDR larger than subnet (not contained)",
			subnetCIDR: "10.0.0.0/24",
			nodesCIDRs: []string{"10.0.0.0/16"},
			expectErr:  true,
		},
		{
			name:       "nodes CIDR outside subnet range",
			subnetCIDR: "10.0.0.0/24",
			nodesCIDRs: []string{"192.168.0.0/24"},
			expectErr:  true,
		},
		{
			name:       "nodes CIDR partially overlaps but not contained",
			subnetCIDR: "10.0.0.0/24",
			nodesCIDRs: []string{"10.0.0.128/23"},
			expectErr:  true,
		},
		{
			name:       "empty nodes CIDRs (no check)",
			subnetCIDR: "10.0.0.0/24",
			nodesCIDRs: nil,
			expectErr:  false,
		},
		{
			name:       "IPv6 nodes CIDR is skipped",
			subnetCIDR: "10.0.0.0/24",
			nodesCIDRs: []string{"2001:db8::/48"},
			expectErr:  false,
		},
		{
			name:       "empty subnet CIDR (IPv6-native, skip check)",
			subnetCIDR: "",
			nodesCIDRs: []string{"10.0.0.0/24"},
			expectErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			subnet := &awsclient.Subnet{
				SubnetId:  "subnet-test",
				CidrBlock: tt.subnetCIDR,
			}
			errs := validateNodesCIDRInSubnet(subnet, fldPath, "subnet-test", tt.nodesCIDRs)
			if tt.expectErr && len(errs) == 0 {
				t.Errorf("expected validation error, got none")
			}
			if !tt.expectErr && len(errs) > 0 {
				t.Errorf("unexpected validation error: %v", errs)
			}
		})
	}
}
