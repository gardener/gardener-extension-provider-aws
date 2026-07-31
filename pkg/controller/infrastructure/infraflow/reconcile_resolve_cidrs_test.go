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

var _ = Describe("resolveZoneCIDRs", func() {
	const (
		zoneName = "eu-west-1a"
		// A representative VPC /56 the derived offsets are computed from in managed mode.
		vpcIPv6 = "2001:db8:1234:5600::/56"
		// Expected /64 values at zone index 0.
		//   cidrSubnet(vpcIPv6, 64, 0) -> 2001:db8:1234:5600::/64   (workers, correct)
		//   cidrSubnet(vpcIPv6, 64, 2) -> 2001:db8:1234:5602::/64   (internal, buggy — see Gap N)
		//   cidrSubnet(vpcIPv6, 64, 3) -> 2001:db8:1234:5603::/64   (public,   buggy — see Gap N)
		derivedWorkersV6Idx0  = "2001:db8:1234:5600::/64"
		derivedInternalV6Idx0 = "2001:db8:1234:5602::/64" // Gap N: should be offset 1 (5601::/64)
		derivedPublicV6Idx0   = "2001:db8:1234:5603::/64" // Gap N: should be offset 2 (5602::/64)
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
			zone := &awsapi.Zone{Name: zoneName, Workers: ptr.To("10.0.0.0/19"), Internal: ptr.To("10.0.112.0/22"), Public: ptr.To("10.0.48.0/20")}
			r, err := fc.resolveZoneCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.WorkersV4).To(Equal("10.0.0.0/19"))
			Expect(r.WorkersV6).To(BeEmpty())
			Expect(r.InternalV4).To(Equal("10.0.112.0/22"))
			Expect(r.InternalV6).To(BeEmpty())
			Expect(r.PublicV4).To(Equal("10.0.48.0/20"))
			Expect(r.PublicV6).To(BeEmpty())
		})

		It("derives IPv6 CIDRs from the VPC block for dual-stack", func() {
			fc := newFC(dualStack, false, nil, vpcIPv6)
			zone := &awsapi.Zone{Name: zoneName, Workers: ptr.To("10.0.0.0/19"), Internal: ptr.To("10.0.112.0/22"), Public: ptr.To("10.0.48.0/20")}
			r, err := fc.resolveZoneCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.WorkersV4).To(Equal("10.0.0.0/19"))
			Expect(r.WorkersV6).To(Equal(derivedWorkersV6Idx0), "workers IPv6 offset 0+3*index matches ensureManagedZones layout")
			Expect(r.InternalV4).To(Equal("10.0.112.0/22"))
			Expect(r.InternalV6).To(Equal(derivedInternalV6Idx0), "internal IPv6 offset preserves pre-existing Gap N bug")
			Expect(r.PublicV4).To(Equal("10.0.48.0/20"))
			Expect(r.PublicV6).To(Equal(derivedPublicV6Idx0), "public IPv6 offset preserves pre-existing Gap N bug")
		})

		It("returns empty IPv6 CIDRs when VPC IPv6 block is not in state", func() {
			fc := newFC(dualStack, false, nil, "")
			zone := &awsapi.Zone{Name: zoneName, Workers: ptr.To("10.0.0.0/19"), Internal: ptr.To("10.0.112.0/22"), Public: ptr.To("10.0.48.0/20")}
			r, err := fc.resolveZoneCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.WorkersV6).To(BeEmpty())
			Expect(r.InternalV6).To(BeEmpty())
			Expect(r.PublicV6).To(BeEmpty())
		})

		It("returns empty IPv4 CIDRs when zone.Workers/Internal/Public are nil", func() {
			fc := newFC(ipv4Only, false, nil, "")
			zone := &awsapi.Zone{Name: zoneName}
			r, err := fc.resolveZoneCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.WorkersV4).To(BeEmpty())
			Expect(r.InternalV4).To(BeEmpty())
			Expect(r.PublicV4).To(BeEmpty())
		})
	})

	Context("BYO mode", func() {
		It("reads all six CIDRs from state (dual-stack)", func() {
			byoState := map[string]string{
				IdentifierZoneSubnetWorkersCIDR:     "10.1.0.0/16",
				IdentifierZoneSubnetWorkersIPv6CIDR: "2001:db8:1234:5610::/64",
				IdentifierZoneSubnetPublicCIDR:      "10.1.0.0/24",
				IdentifierZoneSubnetPublicIPv6CIDR:  "2001:db8:1234:5677::/64",
				IdentifierZoneSubnetPrivateCIDR:     "10.1.1.0/24",
				IdentifierZoneSubnetPrivateIPv6CIDR: "2001:db8:1234:5678::/64",
			}
			// vpcIPv6 is set in state but must NOT be used in BYO mode — assert we
			// do not derive from it.
			fc := newFC(dualStack, true, byoState, vpcIPv6)
			zone := &awsapi.Zone{Name: zoneName, WorkersSubnetID: ptr.To("subnet-workers")}
			r, err := fc.resolveZoneCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.WorkersV4).To(Equal("10.1.0.0/16"))
			Expect(r.WorkersV6).To(Equal("2001:db8:1234:5610::/64"))
			Expect(r.InternalV4).To(Equal("10.1.1.0/24"))
			Expect(r.InternalV6).To(Equal("2001:db8:1234:5678::/64"))
			Expect(r.PublicV4).To(Equal("10.1.0.0/24"))
			Expect(r.PublicV6).To(Equal("2001:db8:1234:5677::/64"))
			// Explicitly assert BYO did NOT derive from the VPC block.
			Expect(r.WorkersV6).NotTo(Equal(derivedWorkersV6Idx0))
			Expect(r.InternalV6).NotTo(Equal(derivedInternalV6Idx0))
			Expect(r.PublicV6).NotTo(Equal(derivedPublicV6Idx0))
		})

		It("returns empty LB CIDRs when state has no LB subnet CIDRs (pre-tagged discovery case, workers still populated)", func() {
			// Explicit workers subnet only; LB subnets rely on discovery which
			// hasn't populated state yet at helper-call time in this test.
			byoState := map[string]string{
				IdentifierZoneSubnetWorkersCIDR:     "10.1.0.0/16",
				IdentifierZoneSubnetWorkersIPv6CIDR: "2001:db8:1234:5610::/64",
			}
			fc := newFC(dualStack, true, byoState, vpcIPv6)
			zone := &awsapi.Zone{Name: zoneName, WorkersSubnetID: ptr.To("subnet-workers")}
			r, err := fc.resolveZoneCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.WorkersV4).To(Equal("10.1.0.0/16"), "workers must be populated even when LB CIDRs are not")
			Expect(r.WorkersV6).To(Equal("2001:db8:1234:5610::/64"))
			Expect(r.InternalV4).To(BeEmpty())
			Expect(r.InternalV6).To(BeEmpty())
			Expect(r.PublicV4).To(BeEmpty())
			Expect(r.PublicV6).To(BeEmpty())
		})

		It("returns empty IPv6 CIDRs when only IPv4 CIDRs are in state (IPv4-only BYO)", func() {
			byoState := map[string]string{
				IdentifierZoneSubnetWorkersCIDR: "10.1.0.0/16",
				IdentifierZoneSubnetPublicCIDR:  "10.1.0.0/24",
				IdentifierZoneSubnetPrivateCIDR: "10.1.1.0/24",
			}
			fc := newFC(ipv4Only, true, byoState, "")
			zone := &awsapi.Zone{Name: zoneName, WorkersSubnetID: ptr.To("subnet-workers")}
			r, err := fc.resolveZoneCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.WorkersV4).To(Equal("10.1.0.0/16"))
			Expect(r.WorkersV6).To(BeEmpty())
			Expect(r.InternalV4).To(Equal("10.1.1.0/24"))
			Expect(r.InternalV6).To(BeEmpty())
			Expect(r.PublicV4).To(Equal("10.1.0.0/24"))
			Expect(r.PublicV6).To(BeEmpty())
		})

		It("ignores zone.Workers / Internal / Public from config in BYO (they are nil anyway, but assert we do not read them)", func() {
			// BYO with all CIDRs in state; also (hypothetically) non-nil zone
			// config fields that would win if the BYO branch accidentally fell through.
			byoState := map[string]string{
				IdentifierZoneSubnetWorkersCIDR: "192.168.0.0/16",
				IdentifierZoneSubnetPublicCIDR:  "192.168.1.0/24",
				IdentifierZoneSubnetPrivateCIDR: "192.168.2.0/24",
			}
			fc := newFC(ipv4Only, true, byoState, "")
			zone := &awsapi.Zone{
				Name:             zoneName,
				WorkersSubnetID:  ptr.To("subnet-workers"),
				Workers:          ptr.To("10.9.7.0/24"),
				Internal:         ptr.To("10.9.9.0/24"),
				Public:           ptr.To("10.9.8.0/24"),
				PublicSubnetID:   ptr.To("subnet-public"),
				InternalSubnetID: ptr.To("subnet-internal"),
			}
			r, err := fc.resolveZoneCIDRs(zone, 0)
			Expect(err).NotTo(HaveOccurred())
			Expect(r.WorkersV4).To(Equal("192.168.0.0/16"), "workers CIDR must come from state, not config")
			Expect(r.InternalV4).To(Equal("192.168.2.0/24"), "internal CIDR must come from state, not config")
			Expect(r.PublicV4).To(Equal("192.168.1.0/24"), "public CIDR must come from state, not config")
		})
	})
})
