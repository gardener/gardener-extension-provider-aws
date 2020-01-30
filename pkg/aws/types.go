// Copyright (c) 2019 SAP SE or an SAP affiliate company. All rights reserved. This file is licensed under the Apache Software License, v. 2 except as noted otherwise in the LICENSE file
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

package aws

import "path/filepath"

const (
	// Name is the name of the AWS provider.
	Name = "provider-aws"
	// StorageProviderName is the name of the AWS storage provider.
	StorageProviderName = "S3"

	// MachineControllerManagerImageName is the name of the MachineControllerManager image.
	MachineControllerManagerImageName = "machine-controller-manager"
	// TerraformerImageName is the name of the Terraformer image.
	TerraformerImageName = "terraformer"
	// CloudControllerManagerImageName is the name of the cloud-controller-manager image.
	CloudControllerManagerImageName = "cloud-controller-manager"
	// ETCDBackupRestoreImageName is the name of the etcd backup and restore image.
	ETCDBackupRestoreImageName = "etcd-backup-restore"
	// AWSLBReadvertiserImageName is the name of the AWSLBReadvertiser image.
	AWSLBReadvertiserImageName = "aws-lb-readvertiser"

	// AccessKeyID is a constant for the key in a cloud provider secret and backup secret that holds the AWS access key id.
	AccessKeyID = "accessKeyID"
	// SecretAccessKey is a constant for the key in a cloud provider secret and backup secret that holds the AWS secret access key.
	SecretAccessKey = "secretAccessKey"
	// Region is a constant for the key in a backup secret that holds the AWS region.
	Region = "region"
	// BucketName is a constant for the key in a backup secret that holds the bucket name.
	// The bucket name is written to the backup secret by Gardener as a temporary solution.
	// TODO In the future, the bucket name should come from a BackupBucket resource (see https://github.com/gardener/gardener/blob/master/docs/proposals/02-backupinfra.md)
	BucketName = "bucketName"
	// TerraformerPurposeInfra is a constant for the complete Terraform setup with purpose 'infrastructure'.
	TerraformerPurposeInfra = "infra"
	// VPCIDKey is the vpc_id tf state key
	VPCIDKey = "vpc_id"
	// SubnetPublicPrefix is the prefix for the subnets
	SubnetPublicPrefix = "subnet_public_utility_z"
	// SubnetNodesPrefix is the prefix for the subnets
	SubnetNodesPrefix = "subnet_nodes_z"
	// SecurityGroupsNodes is the key for accessing nodes security groups from outputs in terraform
	SecurityGroupsNodes = "security_group_nodes"
	// SSHKeyName key for accessing SSH key name from outputs in terraform
	SSHKeyName = "keyName"
	// IAMInstanceProfileNodes key for accessing Nodes Instance profile from outputs in terraform
	IAMInstanceProfileNodes = "iamInstanceProfileNodes"
	// IAMInstanceProfileBastions key for accessing Bastions Instance profile from outputs in terraform
	IAMInstanceProfileBastions = "iamInstanceProfileBastions"
	// NodesRole role for nodes
	NodesRole = "nodes_role_arn"
	// BastionsRole role for bastions
	BastionsRole = "bastions_role_arn"

	// CloudProviderConfigName is the name of the configmap containing the cloud provider config.
	CloudProviderConfigName = "cloud-provider-config"
	// MachineControllerManagerName is a constant for the name of the machine-controller-manager.
	MachineControllerManagerName = "machine-controller-manager"
	// MachineControllerManagerVpaName is the name of the VerticalPodAutoscaler of the machine-controller-manager deployment.
	MachineControllerManagerVpaName = "machine-controller-manager-vpa"
	// MachineControllerManagerMonitoringConfigName is the name of the ConfigMap containing monitoring stack configurations for machine-controller-manager.
	MachineControllerManagerMonitoringConfigName = "machine-controller-manager-monitoring-config"
	// BackupSecretName is the name of the secret containing the credentials for storing the backups of Shoot clusters.
	BackupSecretName = "etcd-backup"

	// CloudControllerManagerName is the constant for the name of the CloudController deployed by the control plane controller.
	CloudControllerManagerName = "cloud-controller-manager"
	// LBReadvertiserDeploymentName is the constant for the name of the AWS LB Readvertiser deployment
	LBReadvertiserDeploymentName = "aws-lb-readvertiser"
)

var (
	// ChartsPath is the path to the charts
	ChartsPath = filepath.Join("controllers", Name, "charts")
	// InternalChartsPath is the path to the internal charts
	InternalChartsPath = filepath.Join(ChartsPath, "internal")
)

// Credentials stores AWS credentials.
type Credentials struct {
	AccessKeyID     []byte
	SecretAccessKey []byte
}
