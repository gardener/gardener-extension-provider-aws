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
	VerifyVPCAttributes(ctx context.Context, vpcID string) error

	// S3 wrappers
	DeleteObjectsWithPrefix(ctx context.Context, bucket, prefix string) error
	CreateBucketIfNotExists(ctx context.Context, bucket, region string) error
	DeleteBucketIfExists(ctx context.Context, bucket string) error

	// Route53 wrappers
	GetDNSHostedZones(ctx context.Context) (map[string]string, error)
	CreateOrUpdateDNSRecord(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64) error
	DeleteDNSRecord(ctx context.Context, zoneId, name, recordType string, values []string, ttl int64) error

	// The following functions are only temporary needed due to https://github.com/gardener/gardener/issues/129.
	ListKubernetesELBs(ctx context.Context, vpcID, clusterName string) ([]string, error)
	ListKubernetesELBsV2(ctx context.Context, vpcID, clusterName string) ([]string, error)
	ListKubernetesSecurityGroups(ctx context.Context, vpcID, clusterName string) ([]string, error)
	DeleteELB(ctx context.Context, name string) error
	DeleteELBV2(ctx context.Context, arn string) error
	DeleteSecurityGroup(ctx context.Context, id string) error
}

// Factory creates instances of Interface.
type Factory interface {
	// NewClient creates a new instance of Interface for the given AWS credentials and region.
	NewClient(accessKeyID, secretAccessKey, region string) (Interface, error)
}

// FactoryFunc is a function that implements Factory.
type FactoryFunc func(accessKeyID, secretAccessKey, region string) (Interface, error)

// NewClient creates a new instance of Interface for the given AWS credentials and region.
func (f FactoryFunc) NewClient(accessKeyID, secretAccessKey, region string) (Interface, error) {
	return f(accessKeyID, secretAccessKey, region)
}
