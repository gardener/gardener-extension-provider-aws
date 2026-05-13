// SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package aws

import (
	gardencorev1beta1 "github.com/gardener/gardener/pkg/apis/core/v1beta1"
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkerConfig contains configuration settings for the worker nodes.
type WorkerConfig struct {
	metav1.TypeMeta
	// NodeTemplate contains resource information of the machine which is used by Cluster Autoscaler to generate nodeTemplate during scaling a nodeGroup from zero.
	NodeTemplate *extensionsv1alpha1.NodeTemplate
	// Volume contains configuration for the root disks attached to VMs.
	Volume *Volume
	// DataVolumes contains configuration for the additional disks attached to VMs.
	DataVolumes []DataVolume
	// IAMInstanceProfile contains configuration for the IAM instance profile that should be used for the VMs of this
	// worker pool.
	IAMInstanceProfile *IAMInstanceProfile
	// InstanceMetadataOptions contains configuration for controlling access to the metadata API.
	InstanceMetadataOptions *InstanceMetadataOptions
	// CpuOptions contains detailed configuration for the number of cores and threads for the instance.
	CpuOptions *CpuOptions
	// CapacityReservation contains configuration about the Capacity Reservation to use for the instance.
	CapacityReservation *CapacityReservation
	// NetworkInterfaces contains configuration for the network interfaces attached to VMs.
	NetworkInterfaces []NetworkInterface
	// Placement contains configuration for instance placement (placement groups, tenancy, dedicated hosts).
	Placement *Placement
	// InstanceMarketOptions configures the instance market type.
	// If not specified, on-demand instances are launched.
	InstanceMarketOptions *InstanceMarketOptions
}

// Volume contains configuration for the root disks attached to VMs.
type Volume struct {
	// IOPS is the number of I/O operations per second (IOPS) that the volume supports.
	// For io1 and gp3 volume type, this represents the number of IOPS that are provisioned for the
	// volume. For gp2 volume type, this represents the baseline performance of the volume and
	// the rate at which the volume accumulates I/O credits for bursting. For more
	// information about General Purpose SSD baseline performance, I/O credits,
	// and bursting, see Amazon EBS Volume Types (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html)
	// in the Amazon Elastic Compute Cloud User Guide.
	//
	// Constraint: IOPS should be a positive value.
	// Validation of IOPS (i.e. whether it is allowed and is in the specified range for a particular volume type) is done on aws side.
	//
	// Condition: This parameter is required for requests to create io1 volumes;
	// Do not specify it in requests to create gp2, st1, sc1, or standard volumes.
	IOPS *int32

	// The throughput that the volume supports, in MiB/s.
	//
	// This parameter is valid only for gp3 volumes.
	//
	// Valid Range: The range as of 16th Aug 2022 is from 125 MiB/s to 1000 MiB/s. For more info refer (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html)
	Throughput *int32
}

// DataVolume contains configuration for data volumes attached to VMs.
type DataVolume struct {
	// Name is the name of the data volume this configuration applies to.
	Name string
	// Volume contains configuration for the volume.
	Volume
	// SnapshotID is the ID of the snapshot.
	SnapshotID *string
}

// IAMInstanceProfile contains configuration for the IAM instance profile that should be used for the VMs of this
// worker pool. Either 'Name' or 'ARN' must be specified.
type IAMInstanceProfile struct {
	// Name is the name of the instance profile.
	Name *string
	// ARN is the ARN of the instance profile.
	ARN *string
}

// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkerStatus contains information about created worker resources.
type WorkerStatus struct {
	metav1.TypeMeta

	// MachineImages is a list of machine images that have been used in this worker. Usually, the extension controller
	// gets the mapping from name/version to the provider-specific machine image data in its componentconfig. However, if
	// a version that is still in use gets removed from this componentconfig it cannot reconcile anymore existing `Worker`
	// resources that are still using this version. Hence, it stores the used versions in the provider status to ensure
	// reconciliation is possible.
	MachineImages []MachineImage
}

// MachineImage is a mapping from logical names and versions to provider-specific machine image data.
type MachineImage struct {
	// Name is the logical name of the machine image.
	Name string
	// Version is the logical version of the machine image.
	Version string
	// AMI is the AMI for the machine image.
	AMI string
	// Architecture is the CPU architecture of the machine image.
	Architecture *string
	// Capabilities of the machine image.
	Capabilities gardencorev1beta1.Capabilities
}

// VolumeType is a constant for volume types.
type VolumeType string

const (
	// VolumeTypeIO1 is a constant for the io1 volume type.
	VolumeTypeIO1 VolumeType = "io1"
	// VolumeTypeGP2 is a constant for the gp2 volume type.
	VolumeTypeGP2 VolumeType = "gp2"
	// VolumeTypeGP3 is a constant for the gp3 volume type.
	VolumeTypeGP3 VolumeType = "gp3"
)

// HTTPTokensValue is a constant for HTTPTokens values.
type HTTPTokensValue string

const (
	// HTTPTokensRequired is a constant for requiring the use of tokens to access IMDS. Effectively disables access via
	// the IMDSv1 endpoints.
	HTTPTokensRequired HTTPTokensValue = "required"
	// HTTPTokensOptional that makes the use of tokens for IMDS optional. Effectively allows access via both IMDSv1 and
	// IMDSv2 endpoints.
	HTTPTokensOptional HTTPTokensValue = "optional"
)

// InstanceMetadataOptions contains configuration for controlling access to the metadata API.
type InstanceMetadataOptions struct {
	// HTTPTokens enforces the use of metadata v2 API.
	HTTPTokens *HTTPTokensValue
	// HTTPPutResponseHopLimit is the response hop limit for instance metadata requests.
	// Valid values are between 1 and 64.
	HTTPPutResponseHopLimit *int32
}

// CpuOptions contains detailed configuration for the number of cores and threads for the instance.
type CpuOptions struct {
	// CoreCount specifies the number of CPU cores per instance.
	CoreCount *int32
	// ThreadsPerCore sets the number of threads per core. Must be either '1' (disable multi-threading) or '2'.
	ThreadsPerCore *int32
	// AmdSevSnp indicates whether AMD SEV-SNP is enabled.
	// Currently, this option is only supported on M6a, R6a, and C6a instance types.
	// Valid options are "enabled" and "disabled".
	AmdSevSnp *string
}

// CapacityReservation contains configuration about the Capacity Reservation to use for the instance.
type CapacityReservation struct {
	// CapacityReservationPreference defines the instance's reservation preferences.
	CapacityReservationPreference *string
	// CapacityReservationID is the ID of the Capacity Reservation in which to run the instance. Mutually exclusive with CapacityReservationResourceGroupArn.
	CapacityReservationID *string
	// CapacityReservationResourceGroupARN is the ARN of the Capacity Reservation Group in which to look for a Capacity Reservation. Mutually exclusive with CapacityReservationID.
	CapacityReservationResourceGroupARN *string
}

// NetworkInterface contains configuration for a network interface or range of network interfaces attached to VMs.
type NetworkInterface struct {
	// NetworkCardIndex is the index of the network card.
	// Mutually exclusive with NetworkCardIndexRange.
	NetworkCardIndex *int64
	// NetworkCardIndexRange is the range of network card indices for the network interface configuration.
	// Mutually exclusive with NetworkCardIndex.
	NetworkCardIndexRange *IndexRange
	// DeviceIndex is the device index for the network interface attachment.
	// Mutually exclusive with DeviceIndexRange.
	DeviceIndex *int64
	// DeviceIndexRange is the range of device indices. Iterates in lockstep with NetworkCardIndexRange.
	// Must have the same length as NetworkCardIndexRange. Mutually exclusive with DeviceIndex.
	// Can only be specified when NetworkCardIndexRange is set.
	DeviceIndexRange *IndexRange
	// Type is the type of network interface.
	// Currently valid values for EC2 RunInstances: "interface", "efa", "efa-only".
	// See https://github.com/aws/aws-sdk-go-v2/blob/service/ec2/v1.279.0/service/ec2/types/types.go#L9181
	// If not specified, "interface" is used by default.
	Type *string
	// Description is a description for the network interface.
	Description *string
	// SubnetID is the ID of the subnet to which the network interface should be attached.
	SubnetID *string
	// SecurityGroupIDs is a list of security group IDs to associate with the network interface.
	SecurityGroupIDs []string
	// AssociatePublicIPAddress indicates whether to associate a public IP address.
	AssociatePublicIPAddress *bool
	// DeleteOnTermination indicates whether the network interface should be deleted when the instance is terminated.
	DeleteOnTermination *bool
	// Ipv6AddressCount is the number of IPv6 addresses to assign to the network interface.
	Ipv6AddressCount *int64
	// PrimaryIpv6 indicates whether the first IPv6 address will be the primary IPv6 address.
	PrimaryIpv6 *bool
}

// IndexRange represents an inclusive range of integer indices.
type IndexRange struct {
	// From is the start of the range (inclusive).
	From int64
	// To is the end of the range (inclusive).
	To int64
}

// Placement contains configuration for instance placement.
type Placement struct {
	// GroupID is the ID of the placement group for the instance.
	GroupID *string
	// Tenancy is the tenancy of the instance. Valid values: "default", "dedicated", "host".
	Tenancy *string
	// HostID is the ID of the Dedicated Host for the instance.
	HostID *string
	// PartitionNumber is the number of the partition the instance should launch in.
	PartitionNumber *int64
	// Affinity is the affinity setting for the instance on the Dedicated Host. Valid values: "default", "host".
	Affinity *string
}

// InstanceMarketOptions configures the instance market type.
type InstanceMarketOptions struct {
	// MarketType is the market type for the instance.
	// Supported values: "spot", "capacity-block", "interruptible-capacity-reservation".
	MarketType string
}
