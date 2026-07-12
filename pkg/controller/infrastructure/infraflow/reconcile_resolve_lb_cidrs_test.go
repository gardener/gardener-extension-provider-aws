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
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

var _ = Describe("resolveZoneLBCIDRs", func() {
	const (
		zoneName = "eu-west-1a"
		// A representative VPC /56 the derived offsets are computed from in managed mode.
		vpcIPv6 = "2001:db8:1234:5600::/56"
		// The expected /64s the managed derivation produces at index 0.
		// cidrSubnet(vpcIPv6, 64, 2) -> 2nd /64 == 2001:db8:1234:5602::/64
		// cidrSubnet(vpcIPv6, 64, 3) -> 3rd /64 == 2001:db8:1234:5603::/64
		derivedInternalV6Idx0 = "2001:db8:1234:5602::/64"
		derivedPublicV6Idx0   = "2001:db8:1234:5603::/64"
	)

	newFC := func(ipFamilies []v1beta1.IPFamily, isBYO bool, zoneState map[string]string, vpcIpv6State string) *FlowContext {
		state := shared.NewWhiteboard()
		if vpcIpv6State != "" {
			state.Set(IdentifierVpcIPv6CidrBlock, vpcIpv6State)
		}
		zoneChild := state.GetChild(ChildIdZones).GetChild(zoneName)
		for k, v := range zoneState {
			zoneChild.Set(k, v)
		}
		zones := []awsapi.Zone{{Name: zoneName}}
		if isBYO {
			zones[0].WorkersSubnetID = ptr.To("subnet-workers")
		}
		return &FlowContext{
			state:      state,
			config:     &awsapi.InfrastructureConfig{Networks: awsapi.Networks{Zones: zones}},
			networking: &v1beta1.Networking{IPFamilies: ipFamilies},
		}
	}

	var (
		ipv4Only  = []v1beta1.IPFamily{v1beta1.IPFamilyIPv4}
		dualStack = []v1beta1.IPFamily{v1beta1.IPFamilyIPv4, v1beta1.IPFamilyIPv6}
	)

	Context("managed mode", func() {
		It("returns config CIDRs for IPv4", func() {
			fc := newFC(ipv4Only, false, nil, "")
			zone := &awsapi.Zone{Name: zoneName, Internal: ptr.To("10.0.112.0/22"), Public: ptr.To("10.0.48.0/20")}
			iV4, iV6, pV4, pV6, err := fc.resolveZoneLBCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(iV4).To(Equal("10.0.112.0/22"))
			Expect(iV6).To(BeEmpty())
			Expect(pV4).To(Equal("10.0.48.0/20"))
			Expect(pV6).To(BeEmpty())
		})

		It("derives IPv6 CIDRs from the VPC block for dual-stack", func() {
			fc := newFC(dualStack, false, nil, vpcIPv6)
			zone := &awsapi.Zone{Name: zoneName, Internal: ptr.To("10.0.112.0/22"), Public: ptr.To("10.0.48.0/20")}
			iV4, iV6, pV4, pV6, err := fc.resolveZoneLBCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(iV4).To(Equal("10.0.112.0/22"))
			Expect(iV6).To(Equal(derivedInternalV6Idx0))
			Expect(pV4).To(Equal("10.0.48.0/20"))
			Expect(pV6).To(Equal(derivedPublicV6Idx0))
		})

		It("returns empty IPv6 CIDRs when VPC IPv6 block is not in state", func() {
			fc := newFC(dualStack, false, nil, "")
			zone := &awsapi.Zone{Name: zoneName, Internal: ptr.To("10.0.112.0/22"), Public: ptr.To("10.0.48.0/20")}
			_, iV6, _, pV6, err := fc.resolveZoneLBCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(iV6).To(BeEmpty())
			Expect(pV6).To(BeEmpty())
		})

		It("returns empty IPv4 CIDRs when zone.Internal/zone.Public are nil", func() {
			fc := newFC(ipv4Only, false, nil, "")
			zone := &awsapi.Zone{Name: zoneName}
			iV4, _, pV4, _, err := fc.resolveZoneLBCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(iV4).To(BeEmpty())
			Expect(pV4).To(BeEmpty())
		})
	})

	Context("BYO mode", func() {
		It("reads all four CIDRs from state (dual-stack)", func() {
			byoState := map[string]string{
				IdentifierZoneSubnetPublicCIDR:      "10.1.0.0/24",
				IdentifierZoneSubnetPublicIPv6CIDR:  "2001:db8:1234:5677::/64",
				IdentifierZoneSubnetPrivateCIDR:     "10.1.1.0/24",
				IdentifierZoneSubnetPrivateIPv6CIDR: "2001:db8:1234:5678::/64",
			}
			// vpcIPv6 is set in state but must NOT be used in BYO mode — assert we
			// do not derive from it.
			fc := newFC(dualStack, true, byoState, vpcIPv6)
			zone := &awsapi.Zone{Name: zoneName, WorkersSubnetID: ptr.To("subnet-workers")}
			iV4, iV6, pV4, pV6, err := fc.resolveZoneLBCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(iV4).To(Equal("10.1.1.0/24"))
			Expect(iV6).To(Equal("2001:db8:1234:5678::/64"))
			Expect(pV4).To(Equal("10.1.0.0/24"))
			Expect(pV6).To(Equal("2001:db8:1234:5677::/64"))
			// Explicitly assert we did NOT derive from the VPC block.
			Expect(iV6).NotTo(Equal(derivedInternalV6Idx0))
			Expect(pV6).NotTo(Equal(derivedPublicV6Idx0))
		})

		It("returns empty LB CIDRs when state has no LB subnet CIDRs (pre-tagged discovery case)", func() {
			// State only has workers CIDR; no public/internal LB subnets configured.
			byoState := map[string]string{
				IdentifierZoneSubnetWorkersCIDR:     "10.1.0.0/16",
				IdentifierZoneSubnetWorkersIPv6CIDR: "2001:db8:1234:5610::/64",
			}
			fc := newFC(dualStack, true, byoState, vpcIPv6)
			zone := &awsapi.Zone{Name: zoneName, WorkersSubnetID: ptr.To("subnet-workers")}
			iV4, iV6, pV4, pV6, err := fc.resolveZoneLBCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(iV4).To(BeEmpty())
			Expect(iV6).To(BeEmpty())
			Expect(pV4).To(BeEmpty())
			Expect(pV6).To(BeEmpty())
		})

		It("returns empty IPv6 LB CIDRs when only IPv4 CIDRs are in state (IPv4-only BYO)", func() {
			byoState := map[string]string{
				IdentifierZoneSubnetPublicCIDR:  "10.1.0.0/24",
				IdentifierZoneSubnetPrivateCIDR: "10.1.1.0/24",
			}
			fc := newFC(ipv4Only, true, byoState, "")
			zone := &awsapi.Zone{Name: zoneName, WorkersSubnetID: ptr.To("subnet-workers")}
			iV4, iV6, pV4, pV6, err := fc.resolveZoneLBCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(iV4).To(Equal("10.1.1.0/24"))
			Expect(iV6).To(BeEmpty())
			Expect(pV4).To(Equal("10.1.0.0/24"))
			Expect(pV6).To(BeEmpty())
		})

		It("ignores zone.Internal / zone.Public from config in BYO (they are nil anyway, but assert we do not read them)", func() {
			// BYO with LB CIDRs from state but also (hypothetically) non-nil zone.Internal/Public.
			// The BYO branch must not fall back to config.
			byoState := map[string]string{
				IdentifierZoneSubnetPublicCIDR:  "192.168.1.0/24",
				IdentifierZoneSubnetPrivateCIDR: "192.168.2.0/24",
			}
			fc := newFC(ipv4Only, true, byoState, "")
			// Intentionally pass a zone with config CIDRs that would win if the BYO
			// branch accidentally fell through.
			zone := &awsapi.Zone{
				Name:             zoneName,
				WorkersSubnetID:  ptr.To("subnet-workers"),
				Internal:         ptr.To("10.9.9.0/24"),
				Public:           ptr.To("10.9.8.0/24"),
				PublicSubnetID:   ptr.To("subnet-public"),
				InternalSubnetID: ptr.To("subnet-internal"),
			}
			iV4, _, pV4, _, err := fc.resolveZoneLBCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(iV4).To(Equal("192.168.2.0/24"), "internal CIDR must come from state, not config")
			Expect(pV4).To(Equal("192.168.1.0/24"), "public CIDR must come from state, not config")
		})
	})
})
