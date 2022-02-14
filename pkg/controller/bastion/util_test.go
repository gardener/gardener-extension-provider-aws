// Copyright (c) 2021 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package bastion

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/ec2"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var _ = Describe("AWSUtilities", func() {
	validator := func(current []*ec2.IpPermission, desired *ec2.IpPermission, expected bool) {
		Expect(securityGroupHasPermissions(current, desired)).To(Equal(expected))
	}

	DescribeTable("securityGroupHasPermissions", validator,
		Entry("empty security group", []*ec2.IpPermission{}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}, false),

		Entry("perfect match", []*ec2.IpPermission{{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}, true),

		// notice the single empty permission in the slice here
		Entry("empty permissions are fine", []*ec2.IpPermission{{}}, &ec2.IpPermission{}, true),

		Entry("subset", []*ec2.IpPermission{{
			FromPort: aws.Int64(80),
			ToPort:   aws.Int64(80),
		}, {
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}, true),

		Entry("different port ranges", []*ec2.IpPermission{{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(23),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(24),
		}, false),

		Entry("protocols match", []*ec2.IpPermission{{
			FromPort:   aws.Int64(22),
			ToPort:     aws.Int64(22),
			IpProtocol: aws.String("tcp"),
		}}, &ec2.IpPermission{
			FromPort:   aws.Int64(22),
			ToPort:     aws.Int64(22),
			IpProtocol: aws.String("tcp"),
		}, true),

		Entry("protocols do not match", []*ec2.IpPermission{{
			FromPort:   aws.Int64(22),
			ToPort:     aws.Int64(22),
			IpProtocol: aws.String("udp"),
		}}, &ec2.IpPermission{
			FromPort:   aws.Int64(22),
			ToPort:     aws.Int64(22),
			IpProtocol: aws.String("tcp"),
		}, false),

		Entry("IPv4 ranges must match verbatim", []*ec2.IpPermission{{
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}},
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}},
		}, true),

		Entry("IPv4 ranges are not normalized", []*ec2.IpPermission{{
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}},
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("1.1.1.1"),
			}},
		}, false),

		Entry("IPv4 range descriptions are not considered for equality", []*ec2.IpPermission{{
			IpRanges: []*ec2.IpRange{{
				CidrIp:      aws.String("1.1.1.1/32"),
				Description: aws.String("foobar"),
			}},
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
			IpRanges: []*ec2.IpRange{{
				CidrIp:      aws.String("1.1.1.1/32"),
				Description: aws.String("not foobar"),
			}},
		}, true),

		Entry("IPv4 range can be a superset", []*ec2.IpPermission{{
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}, {
				CidrIp: aws.String("8.8.8.8/32"),
			}},
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("8.8.8.8/32"),
			}},
		}, true),

		Entry("IPv4 range cannot be a subset", []*ec2.IpPermission{{
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("1.1.1.1/32"),
			}},
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("8.8.8.8/32"),
			}, {
				CidrIp: aws.String("1.1.1.1/32"),
			}},
		}, false),

		Entry("security group IDs as CIDR's must not confuse the code", []*ec2.IpPermission{{
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("8.8.8.8/32"),
			}, {
				CidrIp: aws.String("sg-dummyid"),
			}},
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
			IpRanges: []*ec2.IpRange{{
				CidrIp: aws.String("8.8.8.8/32"),
			}},
		}, true),

		Entry("consider security groups 1", []*ec2.IpPermission{{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
			UserIdGroupPairs: []*ec2.UserIdGroupPair{
				{
					GroupId: aws.String("sg-dummyid"),
				},
			},
		}, false),

		Entry("consider security groups 2", []*ec2.IpPermission{{
			UserIdGroupPairs: []*ec2.UserIdGroupPair{
				{
					GroupId: aws.String("sg-dummyid"),
				},
			},
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
			UserIdGroupPairs: []*ec2.UserIdGroupPair{
				{
					GroupId: aws.String("sg-dummyid"),
				},
			},
		}, true),

		Entry("consider security groups 3", []*ec2.IpPermission{{
			UserIdGroupPairs: []*ec2.UserIdGroupPair{
				{
					GroupId: aws.String("sg-dummyid"),
				},
			},
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
		}}, &ec2.IpPermission{
			FromPort: aws.Int64(22),
			ToPort:   aws.Int64(22),
			UserIdGroupPairs: []*ec2.UserIdGroupPair{
				{
					GroupId: aws.String("sg-another-dummyid"),
				},
			},
		}, false),
	)
})
