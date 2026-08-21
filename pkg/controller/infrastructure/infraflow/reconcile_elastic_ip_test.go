// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
)

var _ = Describe("#ensureElasticIP", func() {
	const (
		zoneName     = "eu-central-1a"
		managedEIP   = "eipalloc-managed1111"
		differentEIP = "eipalloc-user22222"
	)

	var f flowContextFixture

	BeforeEach(func() {
		f.setup()
		// Pre-set the zone suffix so zoneSuffixHelpers doesn't need to scan other zones.
		f.c.state.GetChild(ChildIdZones).GetChild(zoneName).Set(IdentifierZoneSuffix, "z0")
	})

	// helper to set the managed EIP state key
	setManagedEIP := func(id string) {
		f.c.state.GetChild(ChildIdZones).GetChild(zoneName).Set(IdentifierManagedZoneNATGWElasticIP, id)
	}

	// helper to read the managed EIP state key
	getManagedEIPState := func() *string {
		return f.c.state.GetChild(ChildIdZones).GetChild(zoneName).Get(IdentifierManagedZoneNATGWElasticIP)
	}

	zone := func(eipAllocationID *string) *aws.Zone {
		return &aws.Zone{Name: zoneName, ElasticIPAllocationID: eipAllocationID}
	}

	Describe("user pins to the gardener-managed EIP (issue #1897)", func() {
		It("should remove the managed state entry so the EIP is not deleted on shoot teardown", func() {
			setManagedEIP(managedEIP)

			// No AWS calls expected: we just clear state without touching AWS.
			Expect(f.c.ensureElasticIP(zone(ptr.To(managedEIP)))(f.ctx)).To(Succeed())

			Expect(getManagedEIPState()).To(BeNil(), "managed state entry must be cleared so deleteElasticIP skips it")
		})
	})

	Describe("user switches to a different BYO EIP", func() {
		It("should delete the old managed EIP if it is not in use", func() {
			setManagedEIP(managedEIP)

			oldEIP := &awsclient.ElasticIP{AllocationId: managedEIP, AssociationID: nil}
			f.client.EXPECT().GetElasticIP(f.ctx, managedEIP).Return(oldEIP, nil).Times(1)
			f.client.EXPECT().DeleteElasticIP(f.ctx, managedEIP).Return(nil).Times(1)

			Expect(f.c.ensureElasticIP(zone(ptr.To(differentEIP)))(f.ctx)).To(Succeed())

			Expect(getManagedEIPState()).To(BeNil())
		})

		It("should not delete the old managed EIP if it is still associated", func() {
			setManagedEIP(managedEIP)

			oldEIP := &awsclient.ElasticIP{AllocationId: managedEIP, AssociationID: ptr.To("eipassoc-abc")}
			f.client.EXPECT().GetElasticIP(f.ctx, managedEIP).Return(oldEIP, nil).Times(1)

			Expect(f.c.ensureElasticIP(zone(ptr.To(differentEIP)))(f.ctx)).To(Succeed())

			// State entry is NOT cleared: the EIP is still in use and will be retried on next reconcile.
			Expect(getManagedEIPState()).To(HaveValue(Equal(managedEIP)))
		})

		It("should clear state if the old managed EIP no longer exists", func() {
			setManagedEIP(managedEIP)

			// The old EIP was already released out-of-band; GetElasticIP returns (nil, nil).
			f.client.EXPECT().GetElasticIP(f.ctx, managedEIP).Return(nil, nil).Times(1)

			Expect(f.c.ensureElasticIP(zone(ptr.To(differentEIP)))(f.ctx)).To(Succeed())

			// Nothing to delete, but the stale state entry must be cleared.
			Expect(getManagedEIPState()).To(BeNil())
		})
	})

	Describe("no managed EIP in state, user provides BYO EIP", func() {
		It("should be a no-op", func() {
			// No state, no AWS calls expected.
			Expect(f.c.ensureElasticIP(zone(ptr.To(differentEIP)))(f.ctx)).To(Succeed())

			Expect(getManagedEIPState()).To(BeNil())
		})
	})

	Describe("no ElasticIPAllocationID set (gardener manages the EIP)", func() {
		// The EIP tag Name is "<namespace>-eip-natgw-<zone-suffix>". In tests, namespace is empty.
		eipTagName := func() awsclient.Tags { return f.c.commonTagsWithSuffix("eip-natgw-z0") }

		It("should create a new EIP if none exists in state or by tags", func() {
			tags := eipTagName()
			created := &awsclient.ElasticIP{AllocationId: managedEIP}

			f.client.EXPECT().FindElasticIPsByTags(f.ctx, tags).Return(nil, nil).Times(1)
			f.client.EXPECT().CreateElasticIP(f.ctx, &awsclient.ElasticIP{Tags: tags, Vpc: true}).Return(created, nil).Times(1)

			Expect(f.c.ensureElasticIP(zone(nil))(f.ctx)).To(Succeed())

			Expect(getManagedEIPState()).To(HaveValue(Equal(managedEIP)))
		})

		It("should reuse an existing EIP found by tags", func() {
			tags := eipTagName()
			existing := &awsclient.ElasticIP{AllocationId: managedEIP, Tags: tags}

			f.client.EXPECT().FindElasticIPsByTags(f.ctx, tags).Return([]*awsclient.ElasticIP{existing}, nil).Times(1)
			f.updater.EXPECT().UpdateEC2Tags(f.ctx, managedEIP, tags, tags).Return(false, nil).Times(1)

			Expect(f.c.ensureElasticIP(zone(nil))(f.ctx)).To(Succeed())

			Expect(getManagedEIPState()).To(HaveValue(Equal(managedEIP)))
		})

		It("should reuse an existing EIP found by state ID", func() {
			setManagedEIP(managedEIP)
			tags := eipTagName()
			existing := &awsclient.ElasticIP{AllocationId: managedEIP, Tags: tags}

			// FindExisting: ID is present → calls GetElasticIP first.
			f.client.EXPECT().GetElasticIP(f.ctx, managedEIP).Return(existing, nil).Times(1)
			f.updater.EXPECT().UpdateEC2Tags(f.ctx, managedEIP, tags, tags).Return(false, nil).Times(1)

			Expect(f.c.ensureElasticIP(zone(nil))(f.ctx)).To(Succeed())

			Expect(getManagedEIPState()).To(HaveValue(Equal(managedEIP)))
		})
	})
})
