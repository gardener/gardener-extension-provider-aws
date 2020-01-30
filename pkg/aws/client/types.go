// Copyright (c) 2018 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package client

import (
	"context"
)

const (
	// AWS-SDK is missing these constant. So, added here till the time it comes from
	// upstream AWS-SDK-GO

	// errCodeBucketNotEmpty for service response error code
	// "BucketNotEmpty".
	//
	// The specified bucket us exist.
	errCodeBucketNotEmpty = "BucketNotEmpty"
)

// Interface is an interface which must be implemented by AWS clients.
type Interface interface {
	GetAccountID(ctx context.Context) (string, error)
	GetInternetGateway(ctx context.Context, vpcID string) (string, error)

	// S3 wrappers
	DeleteObjectsWithPrefix(ctx context.Context, bucket, prefix string) error
	CreateBucketIfNotExists(ctx context.Context, bucket, region string) error
	DeleteBucketIfExists(ctx context.Context, bucket string) error

	// The following functions are only temporary needed due to https://github.com/gardener/gardener/issues/129.
	ListKubernetesELBs(ctx context.Context, vpcID, clusterName string) ([]string, error)
	ListKubernetesELBsV2(ctx context.Context, vpcID, clusterName string) ([]LoadBalancer, error)
	ListKubernetesSecurityGroups(ctx context.Context, vpcID, clusterName string) ([]string, error)
	DeleteELB(ctx context.Context, name string) error
	DeleteELBV2(ctx context.Context, arn *string) error
	DeleteSecurityGroup(ctx context.Context, id string) error
}
