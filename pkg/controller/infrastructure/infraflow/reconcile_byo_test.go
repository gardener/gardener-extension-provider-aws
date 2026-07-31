// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package infraflow

import (
	awsefs "github.com/aws/aws-sdk-go-v2/service/efs"
	efstypes "github.com/aws/aws-sdk-go-v2/service/efs/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"k8s.io/utils/ptr"

	"github.com/gardener/gardener-extension-provider-aws/pkg/apis/aws"
	awsclient "github.com/gardener/gardener-extension-provider-aws/pkg/aws/client"
	"github.com/gardener/gardener-extension-provider-aws/pkg/controller/infrastructure/infraflow/shared"
)

var _ = Describe("#cacheBYOSubnetCIDRs", func() {
	newChild := func() shared.Whiteboard {
		return shared.NewWhiteboard().GetChild("zone")
	}

	It("does nothing when subnet is nil", func() {
		child := newChild()
		cacheBYOSubnetCIDRs(child, nil, byoSubnetPurposeWorkers)
		Expect(child.Get(IdentifierZoneSubnetWorkersCIDR)).To(BeNil())
		Expect(child.Get(IdentifierZoneSubnetWorkersIPv6CIDR)).To(BeNil())
	})

	It("writes IPv4 CIDR for workers purpose", func() {
		child := newChild()
		subnet := &awsclient.Subnet{SubnetId: "subnet-abc", CidrBlock: "10.0.0.0/24"}
		cacheBYOSubnetCIDRs(child, subnet, byoSubnetPurposeWorkers)
		Expect(child.Get(IdentifierZoneSubnetWorkersCIDR)).To(HaveValue(Equal("10.0.0.0/24")))
		Expect(child.Get(IdentifierZoneSubnetWorkersIPv6CIDR)).To(BeNil())
	})

	It("writes IPv6 CIDR for workers purpose when present", func() {
		child := newChild()
		subnet := &awsclient.Subnet{SubnetId: "subnet-abc", CidrBlock: "10.0.0.0/24", Ipv6CidrBlocks: []string{"2001:db8::/64"}}
		cacheBYOSubnetCIDRs(child, subnet, byoSubnetPurposeWorkers)
		Expect(child.Get(IdentifierZoneSubnetWorkersCIDR)).To(HaveValue(Equal("10.0.0.0/24")))
		Expect(child.Get(IdentifierZoneSubnetWorkersIPv6CIDR)).To(HaveValue(Equal("2001:db8::/64")))
	})

	It("writes correct keys for public purpose", func() {
		child := newChild()
		subnet := &awsclient.Subnet{SubnetId: "subnet-pub", CidrBlock: "10.0.1.0/24", Ipv6CidrBlocks: []string{"2001:db8:1::/64"}}
		cacheBYOSubnetCIDRs(child, subnet, byoSubnetPurposePublic)
		Expect(child.Get(IdentifierZoneSubnetPublicCIDR)).To(HaveValue(Equal("10.0.1.0/24")))
		Expect(child.Get(IdentifierZoneSubnetPublicIPv6CIDR)).To(HaveValue(Equal("2001:db8:1::/64")))
	})

	It("writes correct keys for internal purpose", func() {
		child := newChild()
		subnet := &awsclient.Subnet{SubnetId: "subnet-int", CidrBlock: "10.0.2.0/24"}
		cacheBYOSubnetCIDRs(child, subnet, byoSubnetPurposeInternal)
		Expect(child.Get(IdentifierZoneSubnetPrivateCIDR)).To(HaveValue(Equal("10.0.2.0/24")))
		Expect(child.Get(IdentifierZoneSubnetPrivateIPv6CIDR)).To(BeNil())
	})

	It("only writes the first IPv6 CIDR when multiple are present", func() {
		child := newChild()
		subnet := &awsclient.Subnet{SubnetId: "subnet-abc", Ipv6CidrBlocks: []string{"2001:db8::/64", "2001:db8:1::/64"}}
		cacheBYOSubnetCIDRs(child, subnet, byoSubnetPurposeWorkers)
		Expect(child.Get(IdentifierZoneSubnetWorkersIPv6CIDR)).To(HaveValue(Equal("2001:db8::/64")))
	})

	It("skips writing IPv4 when CidrBlock is empty", func() {
		child := newChild()
		subnet := &awsclient.Subnet{SubnetId: "subnet-abc", CidrBlock: "", Ipv6CidrBlocks: []string{"2001:db8::/64"}}
		cacheBYOSubnetCIDRs(child, subnet, byoSubnetPurposeWorkers)
		Expect(child.Get(IdentifierZoneSubnetWorkersCIDR)).To(BeNil())
		Expect(child.Get(IdentifierZoneSubnetWorkersIPv6CIDR)).To(HaveValue(Equal("2001:db8::/64")))
	})
})

var _ = Describe("#ensureEfs", func() {
	var f flowContextFixture
	BeforeEach(func() { f.setup() })

	Context("BYO mode", func() {
		BeforeEach(func() {
			workerSubnetID := "subnet-workers-byo"
			f.c.config.Networks.Zones = []aws.Zone{{Name: "eu-central-1a", WorkersSubnetID: &workerSubnetID}}
		})

		It("should do nothing when no EFS is configured", func() {
			f.c.config.ElasticFileSystem = nil
			// No mock expectations — no AWS calls should be made.
			Expect(f.c.ensureEfs(f.ctx)).To(Succeed())
		})

		It("should do nothing when EFS is configured but has no ID", func() {
			f.c.config.ElasticFileSystem = &aws.ElasticFileSystemConfig{}
			Expect(f.c.ensureEfs(f.ctx)).To(Succeed())
		})

		It("should discover and store existing mount targets when EFS ID is configured", func() {
			efsID := "fs-12345678"
			f.c.config.ElasticFileSystem = &aws.ElasticFileSystemConfig{ID: &efsID}

			mountTargets := &awsefs.DescribeMountTargetsOutput{
				MountTargets: []efstypes.MountTargetDescription{
					{MountTargetId: ptr.To("fsmt-aaa"), SubnetId: ptr.To("subnet-workers-byo"), AvailabilityZoneName: ptr.To("eu-central-1a")},
					{MountTargetId: ptr.To("fsmt-bbb"), SubnetId: ptr.To("subnet-other"), AvailabilityZoneName: ptr.To("eu-central-1b")},
				},
			}
			f.client.EXPECT().GetMountTargetsEfs(f.ctx, efsID).Return(mountTargets, nil).Times(1)

			Expect(f.c.ensureEfs(f.ctx)).To(Succeed())

			child := f.c.state.GetChild(ChildEfsMountTargets)
			Expect(child.Get("fs-12345678_subnet-workers-byo")).To(HaveValue(Equal("fsmt-aaa")))
			Expect(child.Get("fs-12345678_subnet-other")).To(HaveValue(Equal("fsmt-bbb")))
		})

		It("should succeed gracefully when GetMountTargetsEfs returns nil output", func() {
			efsID := "fs-12345678"
			f.c.config.ElasticFileSystem = &aws.ElasticFileSystemConfig{ID: &efsID}
			f.client.EXPECT().GetMountTargetsEfs(f.ctx, efsID).Return(nil, nil).Times(1)
			Expect(f.c.ensureEfs(f.ctx)).To(Succeed())
		})
	})
})
