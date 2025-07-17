// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package bastion

import (
	"github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AWSUtilities", func() {
	validator := func(current []ec2types.IpPermission, desired ec2types.IpPermission, expected bool) {
		Expect(securityGroupHasPermissions(current, desired)).To(Equal(expected))
	}

	DescribeTable("securityGroupHasPermissions", validator,
		Entry("empty security group", []ec2types.IpPermission{}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}, false),

		Entry("perfect match", []ec2types.IpPermission{{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}, true),

		// notice the single empty permission in the slice here
		Entry("empty permissions are fine", []ec2types.IpPermission{{}}, ec2types.IpPermission{}, true),

		Entry("subset", []ec2types.IpPermission{{
			FromPort: aws.Int32(80),
			ToPort:   aws.Int32(80),
		}, {
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}, true),

		Entry("different port ranges", []ec2types.IpPermission{{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(23),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(24),
		}, false),

		Entry("protocols match", []ec2types.IpPermission{{
			FromPort:   aws.Int32(22),
			ToPort:     aws.Int32(22),
			IpProtocol: aws.String("tcp"),
		}}, ec2types.IpPermission{
			FromPort:   aws.Int32(22),
			ToPort:     aws.Int32(22),
			IpProtocol: aws.String("tcp"),
		}, true),

		Entry("protocols do not match", []ec2types.IpPermission{{
			FromPort:   aws.Int32(22),
			ToPort:     aws.Int32(22),
			IpProtocol: aws.String("udp"),
		}}, ec2types.IpPermission{
			FromPort:   aws.Int32(22),
			ToPort:     aws.Int32(22),
			IpProtocol: aws.String("tcp"),
		}, false),

		Entry("IPv4 ranges must match verbatim", []ec2types.IpPermission{{
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}},
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}},
		}, true),

		Entry("IPv4 ranges are not normalized", []ec2types.IpPermission{{
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}},
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("1.1.1.1"),
			}},
		}, false),

		Entry("IPv4 range descriptions are not considered for equality", []ec2types.IpPermission{{
			IpRanges: []ec2types.IpRange{{
				CidrIp:      aws.String("1.1.1.1/32"),
				Description: aws.String("foobar"),
			}},
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
			IpRanges: []ec2types.IpRange{{
				CidrIp:      aws.String("1.1.1.1/32"),
				Description: aws.String("not foobar"),
			}},
		}, true),

		Entry("IPv4 range can be a superset", []ec2types.IpPermission{{
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}, {
				CidrIp: aws.String("8.8.8.8/32"),
			}},
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("8.8.8.8/32"),
			}},
		}, true),

		Entry("IPv4 range cannot be a subset", []ec2types.IpPermission{{
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}},
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("8.8.8.8/32"),
			}, {
				CidrIp: aws.String("1.1.1.1/32"),
			}},
		}, false),

		Entry("security group IDs as CIDR's must not confuse the code", []ec2types.IpPermission{{
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("8.8.8.8/32"),
			}, {
				CidrIp: aws.String("sg-dummyid"),
			}},
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
			IpRanges: []ec2types.IpRange{{
				CidrIp: aws.String("8.8.8.8/32"),
			}},
		}, true),

		Entry("consider security groups 1", []ec2types.IpPermission{{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
			UserIdGroupPairs: []ec2types.UserIdGroupPair{
				{
					GroupId: aws.String("sg-dummyid"),
				},
			},
		}, false),

		Entry("consider security groups 2", []ec2types.IpPermission{{
			UserIdGroupPairs: []ec2types.UserIdGroupPair{
				{
					GroupId: aws.String("sg-dummyid"),
				},
			},
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
			UserIdGroupPairs: []ec2types.UserIdGroupPair{
				{
					GroupId: aws.String("sg-dummyid"),
				},
			},
		}, true),

		Entry("consider security groups 3", []ec2types.IpPermission{{
			UserIdGroupPairs: []ec2types.UserIdGroupPair{
				{
					GroupId: aws.String("sg-dummyid"),
				},
			},
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
		}}, ec2types.IpPermission{
			FromPort: aws.Int32(22),
			ToPort:   aws.Int32(22),
			UserIdGroupPairs: []ec2types.UserIdGroupPair{
				{
					GroupId: aws.String("sg-another-dummyid"),
				},
			},
		}, false),
	)
})
