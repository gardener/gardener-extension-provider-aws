// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	"github.com/gardener/gardener/pkg/apis/core/v1beta1"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	awsapi "github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

var _ = Describe("getSubnetKey", func() {
	const (
		zoneName = "eu-west-1a"
		ns       = "shoot--test--cluster"
		suffix   = "z1"
	)

	newFC := func(ipFamilies []v1beta1.IPFamily, zones []awsapi.Zone, stateSubnets map[string]string) *FlowContext {
		state := shared.NewWhiteboard()
		zoneChild := state.GetChild(ChildIdZones).GetChild(zoneName)
		zoneChild.Set(IdentifierZoneSuffix, suffix)
		for k, v := range stateSubnets {
			zoneChild.Set(k, v)
		}
		return &FlowContext{
			namespace:  ns,
			state:      state,
			config:     &awsapi.InfrastructureConfig{Networks: awsapi.Networks{Zones: zones}},
			networking: &v1beta1.Networking{IPFamilies: ipFamilies},
		}
	}

	var (
		ipv4Only  = []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}
		ipv6Only  = []v1beta1.IPFamily{v1beta1.IPFamilyIPv6}
		dualStack = []v1beta1.IPFamily{v1beta1.IPFamilyIPv4, v1beta1.IPFamilyIPv6}

		ipv4Zones = []awsapi.Zone{{Name: zoneName, Workers: ptr.To("10.0.0.0/19"), Public: ptr.To("10.0.48.0/20"), Internal: ptr.To("10.0.112.0/22")}}
		byoZones  = []awsapi.Zone{{Name: zoneName, WorkersSubnetID: ptr.To("subnet-workers"), PublicSubnetID: ptr.To("subnet-public"), InternalSubnetID: ptr.To("subnet-internal")}}
		ipv6Zones = []awsapi.Zone{{Name: zoneName}}

		byoState  = map[string]string{IdentifierZoneSubnetWorkers: "subnet-workers", IdentifierZoneSubnetPublic: "subnet-public", IdentifierZoneSubnetPrivate: "subnet-internal"}
		ipv6State = map[string]string{IdentifierZoneSubnetWorkers: "subnet-workers-ipv6", IdentifierZoneSubnetPublic: "subnet-public-ipv6", IdentifierZoneSubnetPrivate: "subnet-internal-ipv6"}
	)

	DescribeTable("resolves subnet key correctly",
		func(ipFamilies []v1beta1.IPFamily, zones []awsapi.Zone, stateSubnets map[string]string, subnet *awsclient.Subnet, expectedKey string, expectErr bool) {
			fc := newFC(ipFamilies, zones, stateSubnets)
			_, key, err := fc.getSubnetKey(subnet)
			if expectErr {
				Expect(err).To(HaveOccurred())
			} else {
				Expect(err).NotTo(HaveOccurred())
				Expect(key).To(Equal(expectedKey))
			}
		},
		// IPv4 managed: CIDR-based matching
		Entry("IPv4 workers subnet matched by CIDR",
			ipv4Only, ipv4Zones, nil,
			&awsclient.Subnet{SubnetId: "subnet-aaa", CidrBlock: "10.0.0.0/19", AvailabilityZone: zoneName},
			IdentifierZoneSubnetWorkers, false),
		Entry("IPv4 public subnet matched by CIDR",
			ipv4Only, ipv4Zones, nil,
			&awsclient.Subnet{SubnetId: "subnet-bbb", CidrBlock: "10.0.48.0/20", AvailabilityZone: zoneName},
			IdentifierZoneSubnetPublic, false),
		Entry("IPv4 internal subnet matched by CIDR",
			ipv4Only, ipv4Zones, nil,
			&awsclient.Subnet{SubnetId: "subnet-ccc", CidrBlock: "10.0.112.0/22", AvailabilityZone: zoneName},
			IdentifierZoneSubnetPrivate, false),
		Entry("IPv4 unknown CIDR returns error",
			ipv4Only, ipv4Zones, nil,
			&awsclient.Subnet{SubnetId: "subnet-xxx", CidrBlock: "10.99.0.0/24", AvailabilityZone: zoneName},
			"", true),

		// BYO dual-stack: ID-based matching from state
		Entry("BYO dual-stack workers subnet matched by ID",
			dualStack, byoZones, byoState,
			&awsclient.Subnet{SubnetId: "subnet-workers", AvailabilityZone: zoneName},
			IdentifierZoneSubnetWorkers, false),
		Entry("BYO dual-stack public subnet matched by ID",
			dualStack, byoZones, byoState,
			&awsclient.Subnet{SubnetId: "subnet-public", AvailabilityZone: zoneName},
			IdentifierZoneSubnetPublic, false),
		Entry("BYO dual-stack internal subnet matched by ID",
			dualStack, byoZones, byoState,
			&awsclient.Subnet{SubnetId: "subnet-internal", AvailabilityZone: zoneName},
			IdentifierZoneSubnetPrivate, false),
		Entry("BYO dual-stack unknown subnet ID returns error",
			dualStack, byoZones, byoState,
			&awsclient.Subnet{SubnetId: "subnet-unknown", AvailabilityZone: zoneName},
			"", true),

		// IPv6-only managed: ID-based matching from state
		Entry("IPv6-only workers subnet matched by ID from state",
			ipv6Only, ipv6Zones, ipv6State,
			&awsclient.Subnet{SubnetId: "subnet-workers-ipv6", AvailabilityZone: zoneName},
			IdentifierZoneSubnetWorkers, false),
		Entry("IPv6-only public subnet matched by ID from state",
			ipv6Only, ipv6Zones, ipv6State,
			&awsclient.Subnet{SubnetId: "subnet-public-ipv6", AvailabilityZone: zoneName},
			IdentifierZoneSubnetPublic, false),
		Entry("IPv6-only internal subnet matched by ID from state",
			ipv6Only, ipv6Zones, ipv6State,
			&awsclient.Subnet{SubnetId: "subnet-internal-ipv6", AvailabilityZone: zoneName},
			IdentifierZoneSubnetPrivate, false),

		// IPv6-only managed: name tag matching (fallback when ID not in state)
		Entry("IPv6-only workers subnet matched by name tag",
			ipv6Only, ipv6Zones, nil,
			&awsclient.Subnet{SubnetId: "subnet-workers-ipv6", AvailabilityZone: zoneName, Tags: awsclient.Tags{TagKeyName: ns + "-nodes-" + suffix}},
			IdentifierZoneSubnetWorkers, false),
		Entry("IPv6-only public subnet matched by name tag",
			ipv6Only, ipv6Zones, nil,
			&awsclient.Subnet{SubnetId: "subnet-public-ipv6", AvailabilityZone: zoneName, Tags: awsclient.Tags{TagKeyName: ns + "-public-utility-" + suffix}},
			IdentifierZoneSubnetPublic, false),
		Entry("IPv6-only internal subnet matched by name tag",
			ipv6Only, ipv6Zones, nil,
			&awsclient.Subnet{SubnetId: "subnet-internal-ipv6", AvailabilityZone: zoneName, Tags: awsclient.Tags{TagKeyName: ns + "-private-utility-" + suffix}},
			IdentifierZoneSubnetPrivate, false),
		Entry("IPv6-only unknown subnet returns error",
			ipv6Only, ipv6Zones, nil,
			&awsclient.Subnet{SubnetId: "subnet-unknown", AvailabilityZone: zoneName},
			"", true),

		// Contract test (Gap G): BYO with empty state must error. The caller
		// contract is that ensureBYOZones populates zone state before any code
		// path that calls getSubnetKey. Verify a regression in that ordering
		// (e.g., someone moves getSubnetKey earlier in the graph) is caught by
		// this test. Both `stateSubnets: nil` and no name tags => nothing to
		// match against => error.
		Entry("BYO workers subnet with empty state returns error (state-write-first contract)",
			dualStack, byoZones, nil,
			&awsclient.Subnet{SubnetId: "subnet-workers", AvailabilityZone: zoneName},
			"", true),
		Entry("BYO public subnet with empty state returns error",
			dualStack, byoZones, nil,
			&awsclient.Subnet{SubnetId: "subnet-public", AvailabilityZone: zoneName},
			"", true),
		Entry("BYO internal subnet with empty state returns error",
			dualStack, byoZones, nil,
			&awsclient.Subnet{SubnetId: "subnet-internal", AvailabilityZone: zoneName},
			"", true),
	)
})
