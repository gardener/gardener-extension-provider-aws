// SPDX-FileCopyrightText: 2024 SAP SE or an SAP affiliate company and Gardener contributors
//
// SPDX-License-Identifier: Apache-2.0

package v1alpha1

import (
	extensionsv1alpha1 "github.com/gardener/gardener/pkg/apis/extensions/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkerConfig contains configuration settings for the worker nodes.
type WorkerConfig struct {
	metav1.TypeMeta `json:",inline"`

	// NodeTemplate contains resource information of the machine which is used by Cluster Autoscaler to generate nodeTemplate during scaling a nodeGroup from zero.
	// +optional
	NodeTemplate *extensionsv1alpha1.NodeTemplate `json:"nodeTemplate,omitempty"`
	// Volume contains configuration for the root disks attached to VMs.
	// +optional
	Volume *Volume `json:"volume,omitempty"`
	// DataVolumes contains configuration for the additional disks attached to VMs.
	// +optional
	DataVolumes []DataVolume `json:"dataVolumes,omitempty"`
	// IAMInstanceProfile contains configuration for the IAM instance profile that should be used for the VMs of this
	// worker pool.
	// +optional
	IAMInstanceProfile *IAMInstanceProfile `json:"iamInstanceProfile,omitempty"`
	// InstanceMetadataOptions contains configuration for controlling access to the metadata API.
	InstanceMetadataOptions *InstanceMetadataOptions `json:"instanceMetadataOptions,omitempty"`
}

// Volume contains configuration for the root disks attached to VMs.
type Volume struct {
	// IOPS is the number of I/O operations per second (IOPS) that the volume supports.
	// For io1 volume type, this represents the number of IOPS that are provisioned for the
	// volume. For gp2 volume type, this represents the baseline performance of the volume and
	// the rate at which the volume accumulates I/O credits for bursting. For more
	// information about General Purpose SSD baseline performance, I/O credits,
	// and bursting, see Amazon EBS Volume Types (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html)
	// in the Amazon Elastic Compute Cloud User Guide.
	//
	// Constraint: Range is 100-20000 IOPS for io1 volumes and 100-10000 IOPS for
	// gp2 volumes.
	//
	// Condition: This parameter is required for requests to create io1 volumes;
	// it is not used in requests to create gp2, st1, sc1, or standard volumes.
	// +optional
	IOPS *int64 `json:"iops,omitempty"`

	// The throughput that the volume supports, in MiB/s.
	//
	// This parameter is valid only for gp3 volumes.
	//
	// Valid Range: The range as of 16th Aug 2022 is from 125 MiB/s to 1000 MiB/s. For more info refer (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html)
	Throughput *int64 `json:"throughput,omitempty"`
}

// DataVolume contains configuration for data volumes attached to VMs.
type DataVolume struct {
	// Name is the name of the data volume this configuration applies to.
	Name string `json:"name"`
	// Volume contains configuration for the volume.
	Volume `json:",inline"`
	// SnapshotID is the ID of the snapshot.
	// +optional
	SnapshotID *string `json:"snapshotID,omitempty"`
}

// IAMInstanceProfile contains configuration for the IAM instance profile that should be used for the VMs of this
// worker pool. Either 'Name" or 'ARN' must be specified.
type IAMInstanceProfile struct {
	// Name is the name of the instance profile.
	// +optional
	Name *string `json:"name,omitempty"`
	// ARN is the ARN of the instance profile.
	// +optional
	ARN *string `json:"arn,omitempty"`
}

// +genclient
// +k8s:deepcopy-gen:interfaces=k8s.io/apimachinery/pkg/runtime.Object

// WorkerStatus contains information about created worker resources.
type WorkerStatus struct {
	metav1.TypeMeta `json:",inline"`

	// MachineImages is a list of machine images that have been used in this worker. Usually, the extension controller
	// gets the mapping from name/version to the provider-specific machine image data in its componentconfig. However, if
	// a version that is still in use gets removed from this componentconfig it cannot reconcile anymore existing `Worker`
	// resources that are still using this version. Hence, it stores the used versions in the provider status to ensure
	// reconciliation is possible.
	// +optional
	MachineImages []MachineImage `json:"machineImages,omitempty"`
}

// MachineImage is a mapping from logical names and versions to provider-specific machine image data.
type MachineImage struct {
	// Name is the logical name of the machine image.
	Name string `json:"name"`
	// Version is the logical version of the machine image.
	Version string `json:"version"`
	// AMI is the AMI for the machine image.
	AMI string `json:"ami"`
	// Architecture is the CPU architecture of the machine image.
	// +optional
	Architecture *string `json:"architecture,omitempty"`
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
	HTTPTokens *HTTPTokensValue `json:"httpTokens,omitempty"`
	// HTTPPutResponseHopLimit is the response hop limit for instance metadata requests.
	// Valid values are between 1 and 64.
	HTTPPutResponseHopLimit *int64 `json:"httpPutResponseHopLimit,omitempty"`
}
