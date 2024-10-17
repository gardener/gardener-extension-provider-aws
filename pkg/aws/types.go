// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
)

const (
	// Name is the name of the AWS provider.
	Name = "provider-aws"

	// VolumeAttachLimit is the key for an annotation on a Shoot object whose value
	// represents the maximum number of volumes attachable for all nodes.
	VolumeAttachLimit = "aws.provider.extensions.gardener.cloud/volume-attach-limit"

	// CloudControllerManagerImageName is the name of the cloud-controller-manager image.
	CloudControllerManagerImageName = "cloud-controller-manager"
	// AWSCustomRouteControllerImageName is the name of the aws-custom-route-controller image.
	AWSCustomRouteControllerImageName = "aws-custom-route-controller"
	// AWSIPAMControllerImageName is the name of the aws-ipam-controller image.
	AWSIPAMControllerImageName = "aws-ipam-controller"
	// AWSLoacBalancerControllerImageName is the name of the ALB controller image.
	AWSLoacBalancerControllerImageName = "aws-load-balancer-controller"

	// CSIDriverImageName is the name of the csi-driver image.
	CSIDriverImageName = "csi-driver"
	// CSIProvisionerImageName is the name of the csi-provisioner image.
	CSIProvisionerImageName = "csi-provisioner"
	// CSIAttacherImageName is the name of the csi-attacher image.
	CSIAttacherImageName = "csi-attacher"
	// CSISnapshotterImageName is the name of the csi-snapshotter image.
	CSISnapshotterImageName = "csi-snapshotter"
	// CSIResizerImageName is the name of the csi-resizer image.
	CSIResizerImageName = "csi-resizer"
	// CSISnapshotControllerImageName is the name of the csi-snapshot-controller image.
	CSISnapshotControllerImageName = "csi-snapshot-controller"
	// CSINodeDriverRegistrarImageName is the name of the csi-node-driver-registrar image.
	CSINodeDriverRegistrarImageName = "csi-node-driver-registrar"
	// CSILivenessProbeImageName is the name of the csi-liveness-probe image.
	CSILivenessProbeImageName = "csi-liveness-probe"
	// CSISnapshotValidationWebhookImageName is the name of the csi-snapshot-validation-webhook image.
	CSISnapshotValidationWebhookImageName = "csi-snapshot-validation-webhook"
	// CSIVolumeModifierImageName is the name of the csi-volume-modifier image.
	CSIVolumeModifierImageName = "csi-volume-modifier"

	// MachineControllerManagerProviderAWSImageName is the name of the MachineController AWS image.
	MachineControllerManagerProviderAWSImageName = "machine-controller-manager-provider-aws"
	// TerraformerImageName is the name of the Terraformer image.
	TerraformerImageName = "terraformer"
	// ECRCredentialHelperImageName image is the name of the image containing the ecr-credential-helper binary.
	ECRCredentialProviderImageName = "ecr-credential-provider"

	// AccessKeyID is a constant for the key in a cloud provider secret and backup secret that holds the AWS access key id.
	AccessKeyID = "accessKeyID"
	// SecretAccessKey is a constant for the key in a cloud provider secret and backup secret that holds the AWS secret access key.
	SecretAccessKey = "secretAccessKey"
	// SharedCredentialsFile is a constant for the key in cloud provider secret that holds the AWS credentials file.
	SharedCredentialsFile = "credentialsFile"
	// Region is a constant for the key in a backup secret that holds the AWS region.
	Region = "region"
	// DNSAccessKeyID is a constant for the key in a DNS secret that holds the AWS access key id.
	DNSAccessKeyID = "AWS_ACCESS_KEY_ID"
	// DNSSecretAccessKey is a constant for the key in a DNS secret that holds the AWS secret access key.
	DNSSecretAccessKey = "AWS_SECRET_ACCESS_KEY"
	// DNSRegion is a constant for the key in a DNS secret that holds the AWS region.
	DNSRegion = "AWS_REGION"
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
	// NodesRole role for nodes
	NodesRole = "nodes_role_arn"

	// DefaultDNSRegion is the default region to be used if a region is not specified in the DNS secret
	// or in the DNSRecord resource.
	DefaultDNSRegion = "us-west-2"

	// CloudProviderConfigName is the name of the configmap containing the cloud provider config.
	CloudProviderConfigName = "cloud-provider-config"

	// CloudControllerManagerName is the constant for the name of the CloudController deployed by the control plane controller.
	CloudControllerManagerName = "cloud-controller-manager"
	// AWSCustomRouteControllerName is the constant for the name of the custom routes controller deployed by the control plane controller.
	AWSCustomRouteControllerName = "aws-custom-route-controller"
	// AWSIPAMControllerName is the constant for the name of the IPAM controller deployed by the control plane controller.
	AWSIPAMControllerName = "aws-ipam-controller"
	// AWSLoadBalancerControllerName is the constant for the name of the ALB controller deployed by the control plane controller.
	AWSLoadBalancerControllerName = "aws-load-balancer-controller"
	// CSIControllerName is a constant for the name of the CSI controller deployment in the seed.
	CSIControllerName = "csi-driver-controller"
	// CSINodeName is a constant for the name of the CSI node deployment in the shoot.
	CSINodeName = "csi-driver-node"
	// CSIDriverName is a constant for the name of the csi-driver component.
	CSIDriverName = "csi-driver"
	// CSIProvisionerName is a constant for the name of the csi-provisioner component.
	CSIProvisionerName = "csi-provisioner"
	// CSIAttacherName is a constant for the name of the csi-attacher component.
	CSIAttacherName = "csi-attacher"
	// CSISnapshotterName is a constant for the name of the csi-snapshotter component.
	CSISnapshotterName = "csi-snapshotter"
	// CSIResizerName is a constant for the name of the csi-resizer component.
	CSIResizerName = "csi-resizer"
	// CSISnapshotControllerName is a constant for the name of the csi-snapshot-controller component.
	CSISnapshotControllerName = "csi-snapshot-controller"
	// CSINodeDriverRegistrarName is a constant for the name of the csi-node-driver-registrar component.
	CSINodeDriverRegistrarName = "csi-node-driver-registrar"
	// CSILivenessProbeName is a constant for the name of the csi-liveness-probe component.
	CSILivenessProbeName = "csi-liveness-probe"
	// CSISnapshotValidationName is the constant for the name of the csi-snapshot-validation-webhook component.
	CSISnapshotValidationName = "csi-snapshot-validation"
	// CSIVolumeModifierName is the constant for the name of the csi-volume-modifier.
	CSIVolumeModifierName = "csi-volume-modifier"
)

var (
	// UsernamePrefix is a constant for the username prefix of components deployed by AWS.
	UsernamePrefix = extensionsv1alpha1.SchemeGroupVersion.Group + ":" + Name + ":"
)

// Credentials stores AWS credentials.
type Credentials struct {
	AccessKeyID     []byte
	SecretAccessKey []byte
	Region          []byte
}
