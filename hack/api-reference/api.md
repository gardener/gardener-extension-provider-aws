<p>Packages:</p>
<ul>
<li>
<a href="#aws.provider.extensions.gardener.cloud%2fv1alpha1">aws.provider.extensions.gardener.cloud/v1alpha1</a>
</li>
</ul>

<h2 id="aws.provider.extensions.gardener.cloud/v1alpha1">aws.provider.extensions.gardener.cloud/v1alpha1</h2>
<p>

</p>

<h3 id="backupbucketconfig">BackupBucketConfig
</h3>


<p>
BackupBucketConfig represents the configuration for a backup bucket.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>immutability</code></br>
<em>
<a href="#immutableconfig">ImmutableConfig</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Immutability defines the immutability configuration for the backup bucket.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="capacityreservation">CapacityReservation
</h3>


<p>
(<em>Appears on:</em><a href="#workerconfig">WorkerConfig</a>)
</p>

<p>
CapacityReservation contains configuration about the Capacity Reservation to use for the instance.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>capacityReservationPreference</code></br>
<em>
string
</em>
</td>
<td>
<p>CapacityReservationPreference defines the instance's reservation preferences.</p>
</td>
</tr>
<tr>
<td>
<code>capacityReservationId</code></br>
<em>
string
</em>
</td>
<td>
<p>CapacityReservationID is the ID of the Capacity Reservation in which to run the instance. Mutually exclusive with CapacityReservationResourceGroupArn.</p>
</td>
</tr>
<tr>
<td>
<code>capacityReservationResourceGroupArn</code></br>
<em>
string
</em>
</td>
<td>
<p>CapacityReservationResourceGroupARN is the ARN of the Capacity Reservation Group in which to look for a Capacity Reservation. Mutually exclusive with CapacityReservationID.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="cloudcontrollermanagerconfig">CloudControllerManagerConfig
</h3>


<p>
(<em>Appears on:</em><a href="#controlplaneconfig">ControlPlaneConfig</a>)
</p>

<p>
CloudControllerManagerConfig contains configuration settings for the cloud-controller-manager.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>featureGates</code></br>
<em>
object (keys:string, values:boolean)
</em>
</td>
<td>
<em>(Optional)</em>
<p>FeatureGates contains information about enabled feature gates.</p>
</td>
</tr>
<tr>
<td>
<code>useCustomRouteController</code></br>
<em>
boolean
</em>
</td>
<td>
<em>(Optional)</em>
<p>UseCustomRouteController controls if custom route controller should be used.<br />Defaults to false.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="cloudprofileconfig">CloudProfileConfig
</h3>


<p>
CloudProfileConfig contains provider-specific configuration that is embedded into Gardener's `CloudProfile`
resource.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>machineImages</code></br>
<em>
<a href="#machineimages">MachineImages</a> array
</em>
</td>
<td>
<p>MachineImages is the list of machine images that are understood by the controller. It maps<br />logical names and versions to provider-specific identifiers.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="controlplaneconfig">ControlPlaneConfig
</h3>


<p>
ControlPlaneConfig contains configuration settings for the control plane.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>cloudControllerManager</code></br>
<em>
<a href="#cloudcontrollermanagerconfig">CloudControllerManagerConfig</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CloudControllerManager contains configuration settings for the cloud-controller-manager.</p>
</td>
</tr>
<tr>
<td>
<code>loadBalancerController</code></br>
<em>
<a href="#loadbalancercontrollerconfig">LoadBalancerControllerConfig</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>LoadBalancerController contains configuration settings for the optional aws-load-balancer-controller (ALB).</p>
</td>
</tr>
<tr>
<td>
<code>storage</code></br>
<em>
<a href="#storage">Storage</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Storage contains configuration for storage in the cluster.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="cpuoptions">CpuOptions
</h3>


<p>
(<em>Appears on:</em><a href="#workerconfig">WorkerConfig</a>)
</p>

<p>
CpuOptions contains detailed configuration for the number of cores and threads for the instance.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>coreCount</code></br>
<em>
integer
</em>
</td>
<td>
<p>CoreCount specifies the number of CPU cores per instance.</p>
</td>
</tr>
<tr>
<td>
<code>threadsPerCore</code></br>
<em>
integer
</em>
</td>
<td>
<p>ThreadsPerCore sets the number of threads per core. Must be either '1' (disable multi-threading) or '2'.</p>
</td>
</tr>
<tr>
<td>
<code>amdSevSnp</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>AmdSevSnp indicates whether AMD SEV-SNP is enabled.<br />Currently, this option is only supported on M6a, R6a, and C6a instance types.<br />Valid options are "enabled" and "disabled".</p>
</td>
</tr>

</tbody>
</table>


<h3 id="customroute">CustomRoute
</h3>


<p>
(<em>Appears on:</em><a href="#networks">Networks</a>, <a href="#seedproviderconfig">SeedProviderConfig</a>)
</p>

<p>
CustomRoute defines a route to be added to all zone (private) route tables.
Exactly one destination and one target must be specified.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>destinationCidrBlock</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>DestinationCidrBlock is the destination CIDR for this route.</p>
</td>
</tr>
<tr>
<td>
<code>destinationPrefixListId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>DestinationPrefixListId is the ID of a managed prefix list.<br />Alternative to DestinationCidrBlock for dynamic CIDR sets.</p>
</td>
</tr>
<tr>
<td>
<code>transitGatewayId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>TransitGatewayId routes traffic to a Transit Gateway.</p>
</td>
</tr>
<tr>
<td>
<code>vpcPeeringConnectionId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>VpcPeeringConnectionId routes traffic to a VPC peering connection.</p>
</td>
</tr>
<tr>
<td>
<code>networkInterfaceId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>NetworkInterfaceId routes traffic to a network interface.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="datavolume">DataVolume
</h3>


<p>
(<em>Appears on:</em><a href="#workerconfig">WorkerConfig</a>)
</p>

<p>
DataVolume contains configuration for data volumes attached to VMs.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name is the name of the data volume this configuration applies to.</p>
</td>
</tr>
<tr>
<td>
<code>iops</code></br>
<em>
integer
</em>
</td>
<td>
<em>(Optional)</em>
<p>IOPS is the number of I/O operations per second (IOPS) that the volume supports.<br />For io1 volume type, this represents the number of IOPS that are provisioned for the<br />volume. For gp2 volume type, this represents the baseline performance of the volume and<br />the rate at which the volume accumulates I/O credits for bursting. For more<br />information about General Purpose SSD baseline performance, I/O credits,<br />and bursting, see Amazon EBS Volume Types (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html)<br />in the Amazon Elastic Compute Cloud User Guide.<br />Constraint: Range is 100-20000 IOPS for io1 volumes and 100-10000 IOPS for<br />gp2 volumes.<br />Condition: This parameter is required for requests to create io1 volumes;<br />it is not used in requests to create gp2, st1, sc1, or standard volumes.</p>
</td>
</tr>
<tr>
<td>
<code>throughput</code></br>
<em>
integer
</em>
</td>
<td>
<p>The throughput that the volume supports, in MiB/s.<br />This parameter is valid only for gp3 volumes.<br />Valid Range: The range as of 16th Aug 2022 is from 125 MiB/s to 1000 MiB/s. For more info refer (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html)</p>
</td>
</tr>
<tr>
<td>
<code>snapshotID</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>SnapshotID is the ID of the snapshot.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="dualstack">DualStack
</h3>


<p>
(<em>Appears on:</em><a href="#infrastructureconfig">InfrastructureConfig</a>)
</p>

<p>
DualStack specifies whether dual-stack or IPv4-only should be supported.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>enabled</code></br>
<em>
boolean
</em>
</td>
<td>
<p>Enabled specifies if dual-stack is enabled or not.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="ec2">EC2
</h3>


<p>
(<em>Appears on:</em><a href="#infrastructurestatus">InfrastructureStatus</a>)
</p>

<p>
EC2 contains information about the  AWS EC2 resources.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>keyName</code></br>
<em>
string
</em>
</td>
<td>
<p>KeyName is the name of the SSH key.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="elasticfilesystemconfig">ElasticFileSystemConfig
</h3>


<p>
(<em>Appears on:</em><a href="#infrastructureconfig">InfrastructureConfig</a>)
</p>

<p>
ElasticFileSystemConfig holds config information about the EFS storage
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>enabled</code></br>
<em>
boolean
</em>
</td>
<td>
<p>Enabled is the switch to install the CSI EFS driver<br />if enabled:<br />- the IAM role policy for the worker nodes shall contain permissions to access the EFS.<br />- an EFS will be created if the ID is not specified.<br />- firewall rules will be created to allow access to the EFS from the worker nodes.</p>
</td>
</tr>
<tr>
<td>
<code>id</code></br>
<em>
string
</em>
</td>
<td>
<p>ID of the EFS to use. For example: fs-0272b97527ed4de53.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="elasticfilesystemstatus">ElasticFileSystemStatus
</h3>


<p>
(<em>Appears on:</em><a href="#infrastructurestatus">InfrastructureStatus</a>)
</p>

<p>
ElasticFileSystemStatus contains status info about the Elastic File System (EFS).
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>ID</code></br>
<em>
string
</em>
</td>
<td>
<p>ID contains the Elastic Files System ID.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="globalvpc">GlobalVPC
</h3>


<p>
(<em>Appears on:</em><a href="#transitgateway">TransitGateway</a>)
</p>

<p>
GlobalVPC defines a shared/utility VPC that should be accessible to all
shoots on this seed via the TGW.

Two modes:
  - Referenced (attachmentId set): attachment already exists, extension only manages
    association/propagation/routes.
  - Managed (vpcId + subnetIds set): extension creates and manages the TGW VPC attachment.

Exactly one of attachmentId or vpcId must be set.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name is a human-readable identifier for this VPC (e.g., "harbor-registry").</p>
</td>
</tr>
<tr>
<td>
<code>attachmentId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>AttachmentID is the pre-existing TGW VPC attachment ID (referenced mode).<br />Provider-aws does NOT create or delete it.<br />Mutually exclusive with vpcId.</p>
</td>
</tr>
<tr>
<td>
<code>vpcId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>VpcID is the ID of the utility VPC to attach to the TGW (managed mode).<br />When set, provider-aws creates the TGW VPC attachment and manages its<br />lifecycle (create on add, delete on removal).<br />Mutually exclusive with attachmentId. Requires subnetIds.</p>
</td>
</tr>
<tr>
<td>
<code>subnetIds</code></br>
<em>
string array
</em>
</td>
<td>
<em>(Optional)</em>
<p>SubnetIDs are private subnet IDs in the utility VPC, one per AZ.<br />TGW creates an ENI in each subnet. Required when vpcId is set.</p>
</td>
</tr>
<tr>
<td>
<code>credentialsRef</code></br>
<em>
<a href="#globalvpccredentialsref">GlobalVPCCredentialsRef</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CredentialsRef references a Secret containing AWS credentials for the<br />account that owns the utility VPC. Only needed for cross-account<br />globalVPCs where the utility VPC is in a different account than the TGW.<br />If nil, the extension uses the shoot's default credentials (same account).<br />The secret must contain 'accessKeyID' and 'secretAccessKey' keys.</p>
</td>
</tr>
<tr>
<td>
<code>cidrs</code></br>
<em>
string array
</em>
</td>
<td>
<em>(Optional)</em>
<p>CIDRs are the CIDR blocks reachable through this VPC.<br />If omitted, provider-aws discovers them via DescribeVpcs.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="globalvpccredentialsref">GlobalVPCCredentialsRef
</h3>


<p>
(<em>Appears on:</em><a href="#globalvpc">GlobalVPC</a>, <a href="#transitgateway">TransitGateway</a>)
</p>

<p>
GlobalVPCCredentialsRef references AWS credentials for cross-account operations.
Three modes are supported:

 1. Secret only (name+namespace): static keys from a k8s Secret. Used directly.
 2. AssumeRole only (assumeRoleARN without name/namespace): the shoot's own
    credentials call sts:AssumeRole to get temporary creds in the target account.
 3. Secret + AssumeRole (name+namespace AND assumeRoleARN): keys from the Secret
    are used as base credentials to call sts:AssumeRole. Supports intermediary
    account keys assuming a role in the target account.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Name is the secret name containing AWS credentials used as base credentials.<br />In mode 1, these are used directly. In mode 3, these call sts:AssumeRole.</p>
</td>
</tr>
<tr>
<td>
<code>namespace</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Namespace is the secret namespace.</p>
</td>
</tr>
<tr>
<td>
<code>assumeRoleARN</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>AssumeRoleARN is the ARN of an IAM role to assume for cross-account access.<br />In mode 2 (no name/namespace), the shoot's own credentials call sts:AssumeRole.<br />In mode 3 (with name/namespace), the Secret's credentials call sts:AssumeRole.</p>
</td>
</tr>
<tr>
<td>
<code>externalID</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ExternalID is an optional external ID for the AssumeRole call.<br />Recommended for cross-account access to prevent confused deputy attacks.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="httptokensvalue">HTTPTokensValue
</h3>
<p><em>Underlying type: string</em></p>


<p>
(<em>Appears on:</em><a href="#instancemetadataoptions">InstanceMetadataOptions</a>)
</p>

<p>
HTTPTokensValue is a constant for HTTPTokens values.
</p>


<h3 id="iam">IAM
</h3>


<p>
(<em>Appears on:</em><a href="#infrastructurestatus">InfrastructureStatus</a>)
</p>

<p>
IAM contains information about the AWS IAM resources.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>instanceProfiles</code></br>
<em>
<a href="#instanceprofile">InstanceProfile</a> array
</em>
</td>
<td>
<p>InstanceProfiles is a list of AWS IAM instance profiles.</p>
</td>
</tr>
<tr>
<td>
<code>roles</code></br>
<em>
<a href="#role">Role</a> array
</em>
</td>
<td>
<p>Roles is a list of AWS IAM roles.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="iaminstanceprofile">IAMInstanceProfile
</h3>


<p>
(<em>Appears on:</em><a href="#workerconfig">WorkerConfig</a>)
</p>

<p>
IAMInstanceProfile contains configuration for the IAM instance profile that should be used for the VMs of this
worker pool. Either 'Name" or 'ARN' must be specified.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Name is the name of the instance profile.</p>
</td>
</tr>
<tr>
<td>
<code>arn</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ARN is the ARN of the instance profile.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="ipampool">IPAMPool
</h3>


<p>
(<em>Appears on:</em><a href="#vpc">VPC</a>)
</p>

<p>
IPAMPool represents an AWS IPAM pool referenced for IPv6 address allocation of the VPC.
Currently only the ID is required; future fields may extend configuration.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>id</code></br>
<em>
string
</em>
</td>
<td>
<p>ID is the IPAM pool id.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="ignoretags">IgnoreTags
</h3>


<p>
(<em>Appears on:</em><a href="#infrastructureconfig">InfrastructureConfig</a>)
</p>

<p>
IgnoreTags holds information about ignored resource tags.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>keys</code></br>
<em>
string array
</em>
</td>
<td>
<em>(Optional)</em>
<p>Keys is a list of individual tag keys, that should be ignored during infrastructure reconciliation.</p>
</td>
</tr>
<tr>
<td>
<code>keyPrefixes</code></br>
<em>
string array
</em>
</td>
<td>
<em>(Optional)</em>
<p>KeyPrefixes is a list of tag key prefixes, that should be ignored during infrastructure reconciliation.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="immutableconfig">ImmutableConfig
</h3>


<p>
(<em>Appears on:</em><a href="#backupbucketconfig">BackupBucketConfig</a>)
</p>

<p>
ImmutableConfig represents the immutability configuration for a backup bucket.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>retentionType</code></br>
<em>
<a href="#retentiontype">RetentionType</a>
</em>
</td>
<td>
<p>RetentionType specifies the type of retention for the backup bucket.<br />Currently allowed value is:<br />- "bucket": retention policy applies on the entire bucket.</p>
</td>
</tr>
<tr>
<td>
<code>retentionPeriod</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.33/#duration-v1-meta">Duration</a>
</em>
</td>
<td>
<p>RetentionPeriod specifies the immutability retention period for the backup bucket.<br />S3 only supports immutability durations in days or years, therefore this field must be set as multiple of 24h.</p>
</td>
</tr>
<tr>
<td>
<code>mode</code></br>
<em>
<a href="#modetype">ModeType</a>
</em>
</td>
<td>
<p>S3 provides two retention modes that apply different levels of protection to objects:<br />Allowed values are: "governance" or "compliance" mode.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="infrastructureconfig">InfrastructureConfig
</h3>


<p>
InfrastructureConfig infrastructure configuration resource
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>enableECRAccess</code></br>
<em>
boolean
</em>
</td>
<td>
<em>(Optional)</em>
<p>EnableECRAccess specifies whether the IAM role policy for the worker nodes shall contain<br />permissions to access the ECR.<br />default: true</p>
</td>
</tr>
<tr>
<td>
<code>dualStack</code></br>
<em>
<a href="#dualstack">DualStack</a>
</em>
</td>
<td>
<p>DualStack specifies whether dual-stack or IPv4-only should be supported.</p>
</td>
</tr>
<tr>
<td>
<code>networks</code></br>
<em>
<a href="#networks">Networks</a>
</em>
</td>
<td>
<p>Networks is the AWS specific network configuration (VPC, subnets, etc.)</p>
</td>
</tr>
<tr>
<td>
<code>ignoreTags</code></br>
<em>
<a href="#ignoretags">IgnoreTags</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IgnoreTags allows to configure which resource tags on resources managed by Gardener should be ignored during<br />infrastructure reconciliation. By default, all tags that are added outside of Gardener's / terraform's<br />reconciliation will be removed during the next reconciliation. This field allows users and automation to add<br />custom tags on resources created and managed by Gardener without loosing them on the next reconciliation.<br />See https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/resource-tagging#ignoring-changes-in-all-resources<br />for details of the underlying terraform implementation.</p>
</td>
</tr>
<tr>
<td>
<code>enableDedicatedTenancyForVPC</code></br>
<em>
boolean
</em>
</td>
<td>
<em>(Optional)</em>
<p>EnableDedicatedTenancyForVPC allows to configure the VPC to use dedicated tenancy.<br />If this field is set to true, all VMs created in this VPC will have dedicated tenancy enabled.<br />This setting is immutable and cannot be changed once the VPC has been created.<br />default: false</p>
</td>
</tr>
<tr>
<td>
<code>elasticFileSystem</code></br>
<em>
<a href="#elasticfilesystemconfig">ElasticFileSystemConfig</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>ElasticFileSystem contains information about the EFS that should be used.<br />This field is immutable and cannot be changed once created.</p>
</td>
</tr>
<tr>
<td>
<code>enableMTUCustomizer</code></br>
<em>
boolean
</em>
</td>
<td>
<em>(Optional)</em>
<p>EnableMTUCustomizer controls whether the mtu-customizer systemd unit and script are deployed<br />to the shoot worker nodes. When enabled, the MTU of all non-virtual network interfaces is set to 1460.<br />default: true</p>
</td>
</tr>

</tbody>
</table>


<h3 id="infrastructurestate">InfrastructureState
</h3>


<p>
InfrastructureState is the state which is persisted as part of the infrastructure status.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>data</code></br>
<em>
object (keys:string, values:string)
</em>
</td>
<td>
<p></p>
</td>
</tr>

</tbody>
</table>


<h3 id="infrastructurestatus">InfrastructureStatus
</h3>


<p>
InfrastructureStatus contains information about created infrastructure resources.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>ec2</code></br>
<em>
<a href="#ec2">EC2</a>
</em>
</td>
<td>
<p>EC2 contains information about the created AWS EC2 resources.</p>
</td>
</tr>
<tr>
<td>
<code>iam</code></br>
<em>
<a href="#iam">IAM</a>
</em>
</td>
<td>
<p>IAM contains information about the created AWS IAM resources.</p>
</td>
</tr>
<tr>
<td>
<code>vpc</code></br>
<em>
<a href="#vpcstatus">VPCStatus</a>
</em>
</td>
<td>
<p>VPC contains information about the created AWS VPC and some related resources.</p>
</td>
</tr>
<tr>
<td>
<code>elasticFileSystem</code></br>
<em>
<a href="#elasticfilesystemstatus">ElasticFileSystemStatus</a>
</em>
</td>
<td>
<p>ElasticFileSystem contains information about the created ElasticFileSystem.</p>
</td>
</tr>
<tr>
<td>
<code>transitGateway</code></br>
<em>
<a href="#transitgatewaystatus">TransitGatewayStatus</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>TransitGateway contains information about the TGW resources used by this shoot.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="instancemetadataoptions">InstanceMetadataOptions
</h3>


<p>
(<em>Appears on:</em><a href="#workerconfig">WorkerConfig</a>)
</p>

<p>
InstanceMetadataOptions contains configuration for controlling access to the metadata API.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>httpTokens</code></br>
<em>
<a href="#httptokensvalue">HTTPTokensValue</a>
</em>
</td>
<td>
<p>HTTPTokens enforces the use of metadata v2 API.</p>
</td>
</tr>
<tr>
<td>
<code>httpPutResponseHopLimit</code></br>
<em>
integer
</em>
</td>
<td>
<p>HTTPPutResponseHopLimit is the response hop limit for instance metadata requests.<br />Valid values are between 1 and 64.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="instanceprofile">InstanceProfile
</h3>


<p>
(<em>Appears on:</em><a href="#iam">IAM</a>)
</p>

<p>
InstanceProfile is an AWS IAM instance profile.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>purpose</code></br>
<em>
string
</em>
</td>
<td>
<p>Purpose is a logical description of the instance profile.</p>
</td>
</tr>
<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name is the name for this instance profile.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="loadbalancercontrollerconfig">LoadBalancerControllerConfig
</h3>


<p>
(<em>Appears on:</em><a href="#controlplaneconfig">ControlPlaneConfig</a>)
</p>

<p>
LoadBalancerControllerConfig contains configuration settings for the optional aws-load-balancer-controller (ALB).
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>enabled</code></br>
<em>
boolean
</em>
</td>
<td>
<p>Enabled controls if the ALB should be deployed.</p>
</td>
</tr>
<tr>
<td>
<code>ingressClassName</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>IngressClassName is the name of the ingress class the ALB controller will target. Default value is 'alb'.<br />If empty string is specified, it will match all ingresses without ingress class annotation and ingresses of type alb</p>
</td>
</tr>

</tbody>
</table>


<h3 id="machineimage">MachineImage
</h3>


<p>
(<em>Appears on:</em><a href="#workerstatus">WorkerStatus</a>)
</p>

<p>
MachineImage is a mapping from logical names and versions to provider-specific machine image data.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name is the logical name of the machine image.</p>
</td>
</tr>
<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
<p>Version is the logical version of the machine image.</p>
</td>
</tr>
<tr>
<td>
<code>ami</code></br>
<em>
string
</em>
</td>
<td>
<p>AMI is the AMI for the machine image.</p>
</td>
</tr>
<tr>
<td>
<code>architecture</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Architecture is the CPU architecture of the machine image.</p>
</td>
</tr>
<tr>
<td>
<code>capabilities</code></br>
<em>
<a href="#capabilities">Capabilities</a>
</em>
</td>
<td>
<p>Capabilities of the machine image.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="machineimageflavor">MachineImageFlavor
</h3>


<p>
(<em>Appears on:</em><a href="#machineimageversion">MachineImageVersion</a>)
</p>

<p>
MachineImageFlavor groups all RegionAMIMappings for a specific set of capabilities.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>regions</code></br>
<em>
<a href="#regionamimapping">RegionAMIMapping</a> array
</em>
</td>
<td>
<p>Regions is a mapping to the correct AMI for the machine image in the supported regions.</p>
</td>
</tr>
<tr>
<td>
<code>capabilities</code></br>
<em>
<a href="#capabilities">Capabilities</a>
</em>
</td>
<td>
<p>Capabilities that are supported by the AMIs in this set.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="machineimageversion">MachineImageVersion
</h3>


<p>
(<em>Appears on:</em><a href="#machineimages">MachineImages</a>)
</p>

<p>
MachineImageVersion contains a version and a provider-specific identifier.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>version</code></br>
<em>
string
</em>
</td>
<td>
<p>Version is the version of the image.</p>
</td>
</tr>
<tr>
<td>
<code>regions</code></br>
<em>
<a href="#regionamimapping">RegionAMIMapping</a> array
</em>
</td>
<td>
<p>Regions is a mapping to the correct AMI for the machine image in the supported regions.</p>
</td>
</tr>
<tr>
<td>
<code>capabilityFlavors</code></br>
<em>
<a href="#machineimageflavor">MachineImageFlavor</a> array
</em>
</td>
<td>
<p>CapabilityFlavors is grouping of region AMIs by capabilities.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="machineimages">MachineImages
</h3>


<p>
(<em>Appears on:</em><a href="#cloudprofileconfig">CloudProfileConfig</a>)
</p>

<p>
MachineImages is a mapping from logical names and versions to provider-specific identifiers.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name is the logical name of the machine image.</p>
</td>
</tr>
<tr>
<td>
<code>versions</code></br>
<em>
<a href="#machineimageversion">MachineImageVersion</a> array
</em>
</td>
<td>
<p>Versions contains versions and a provider-specific identifier.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="modetype">ModeType
</h3>
<p><em>Underlying type: string</em></p>


<p>
(<em>Appears on:</em><a href="#immutableconfig">ImmutableConfig</a>)
</p>

<p>
ModeType defines the type of object lock mode for immutability settings.
</p>


<h3 id="networks">Networks
</h3>


<p>
(<em>Appears on:</em><a href="#infrastructureconfig">InfrastructureConfig</a>)
</p>

<p>
Networks holds information about the Kubernetes and infrastructure networks.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>vpc</code></br>
<em>
<a href="#vpc">VPC</a>
</em>
</td>
<td>
<p>VPC indicates whether to use an existing VPC or create a new one.</p>
</td>
</tr>
<tr>
<td>
<code>zones</code></br>
<em>
<a href="#zone">Zone</a> array
</em>
</td>
<td>
<p>Zones belonging to the same region</p>
</td>
</tr>
<tr>
<td>
<code>transitGateway</code></br>
<em>
<a href="#transitgateway">TransitGateway</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>TransitGateway configures this shoot's own TGW connection, independent<br />of the seed's platform TGW. This is additive — the shoot gets both<br />the seed TGW attachment (if seed has one) and this shoot-level attachment.</p>
</td>
</tr>
<tr>
<td>
<code>customRoutes</code></br>
<em>
<a href="#customroute">CustomRoute</a> array
</em>
</td>
<td>
<em>(Optional)</em>
<p>CustomRoutes are additional routes added to this shoot's zone route tables.<br />Merged with the seed's globalCustomRoutes (global applied first).<br />Must not conflict with global routes — conflicts are rejected at validation.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="regionamimapping">RegionAMIMapping
</h3>


<p>
(<em>Appears on:</em><a href="#machineimageflavor">MachineImageFlavor</a>, <a href="#machineimageversion">MachineImageVersion</a>)
</p>

<p>
RegionAMIMapping is a mapping to the correct AMI for the machine image in the given region.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name is the name of the region.</p>
</td>
</tr>
<tr>
<td>
<code>ami</code></br>
<em>
string
</em>
</td>
<td>
<p>AMI is the AMI for the machine image.</p>
</td>
</tr>
<tr>
<td>
<code>architecture</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>Architecture is the CPU architecture of the machine image.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="retentiontype">RetentionType
</h3>
<p><em>Underlying type: string</em></p>


<p>
(<em>Appears on:</em><a href="#immutableconfig">ImmutableConfig</a>)
</p>

<p>
RetentionType defines the level at which immutability properties are applied on objects.
</p>


<h3 id="role">Role
</h3>


<p>
(<em>Appears on:</em><a href="#iam">IAM</a>)
</p>

<p>
Role is an AWS IAM role.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>purpose</code></br>
<em>
string
</em>
</td>
<td>
<p>Purpose is a logical description of the role.</p>
</td>
</tr>
<tr>
<td>
<code>arn</code></br>
<em>
string
</em>
</td>
<td>
<p>ARN is the AWS Resource Name for this role.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="securitygroup">SecurityGroup
</h3>


<p>
(<em>Appears on:</em><a href="#vpcstatus">VPCStatus</a>)
</p>

<p>
SecurityGroup is an AWS security group related to a VPC.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>purpose</code></br>
<em>
string
</em>
</td>
<td>
<p>Purpose is a logical description of the security group.</p>
</td>
</tr>
<tr>
<td>
<code>id</code></br>
<em>
string
</em>
</td>
<td>
<p>ID is the subnet id.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="seedproviderconfig">SeedProviderConfig
</h3>


<p>
SeedProviderConfig is the provider-specific configuration for AWS seeds.
Specified in Seed.spec.provider.providerConfig.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>transitGateway</code></br>
<em>
<a href="#transitgateway">TransitGateway</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>TransitGateway configures the platform TGW for all shoots on this seed.<br />When nil or Enabled=false, no TGW operations are performed.</p>
</td>
</tr>
<tr>
<td>
<code>globalCustomRoutes</code></br>
<em>
<a href="#customroute">CustomRoute</a> array
</em>
</td>
<td>
<em>(Optional)</em>
<p>GlobalCustomRoutes are routes enforced on ALL shoot zone route tables<br />on this seed. These are generic routes (TGW, VPC peering, network interface<br />targets) and do NOT require a TGW — they work independently.<br />Per-shoot customRoutes cannot conflict with global routes —<br />conflicting shoot routes are rejected at validation.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="storage">Storage
</h3>


<p>
(<em>Appears on:</em><a href="#controlplaneconfig">ControlPlaneConfig</a>)
</p>

<p>
Storage contains configuration for storage in the cluster.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>managedDefaultClass</code></br>
<em>
boolean
</em>
</td>
<td>
<em>(Optional)</em>
<p>ManagedDefaultClass controls if the 'default' StorageClass and 'default' VolumeSnapshotClass<br />would be marked as default. Set to false to manually set the default to another class not<br />managed by Gardener.<br />Defaults to true.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="subnet">Subnet
</h3>


<p>
(<em>Appears on:</em><a href="#vpcstatus">VPCStatus</a>)
</p>

<p>
Subnet is an AWS subnet related to a VPC.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>purpose</code></br>
<em>
string
</em>
</td>
<td>
<p>Purpose is a logical description of the subnet.</p>
</td>
</tr>
<tr>
<td>
<code>id</code></br>
<em>
string
</em>
</td>
<td>
<p>ID is the subnet id.</p>
</td>
</tr>
<tr>
<td>
<code>zone</code></br>
<em>
string
</em>
</td>
<td>
<p>Zone is the availability zone into which the subnet has been created.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="transitgateway">TransitGateway
</h3>


<p>
(<em>Appears on:</em><a href="#networks">Networks</a>, <a href="#seedproviderconfig">SeedProviderConfig</a>)
</p>

<p>
TransitGateway configures optional connectivity via an AWS Transit Gateway.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>enabled</code></br>
<em>
boolean
</em>
</td>
<td>
<p>Enabled explicitly enables TGW integration. Must be true for any<br />TGW operations to occur.</p>
</td>
</tr>
<tr>
<td>
<code>id</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ID of an existing Transit Gateway (referenced). If set, provider-aws uses it as-is<br />and never deletes it. If nil, provider-aws auto-creates and manages a TGW.</p>
</td>
</tr>
<tr>
<td>
<code>createConfig</code></br>
<em>
<a href="#transitgatewaycreateconfig">TransitGatewayCreateConfig</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>CreateConfig optionally tunes parameters for auto-created TGWs (ASN, default<br />association/propagation). Ignored when ID is set (referenced).</p>
</td>
</tr>
<tr>
<td>
<code>hubRouteTableId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>HubRouteTableID is a referenced TGW route table used by the hub (seed VPC).<br />All shoot/seed VPC attachments propagate to this table so the hub can reach them.<br />If nil, provider-aws auto-creates and manages a hub route table.</p>
</td>
</tr>
<tr>
<td>
<code>spokeRouteTableId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>SpokeRouteTableID is a referenced TGW route table used by spoke VPCs<br />(seed VPCs, shoot VPCs, globalVPCs). Shoot VPC attachments associate<br />with this table, enforcing isolation — shoots can only route to CIDRs<br />propagated to this table.<br />If nil, provider-aws auto-creates and manages a spoke route table.</p>
</td>
</tr>
<tr>
<td>
<code>deleteManagedOnDisable</code></br>
<em>
boolean
</em>
</td>
<td>
<em>(Optional)</em>
<p>DeleteManagedOnDisable controls what happens to auto-created (managed) TGW resources<br />when TGW is disabled (Enabled set to false).<br />When true: auto-created TGW and route tables are deleted (aggressive cleanup).<br />When false (default): only the VPC attachment is removed; TGW and route tables are preserved (safe).<br />Has NO EFFECT on referenced resources (ID, HubRouteTableID, or SpokeRouteTableID set) —<br />referenced resources are never deleted regardless of this setting.<br />Only readable when the config block exists (enabled: false). If the entire<br />transitGateway block is removed from config, behavior defaults to preserve (safe, same as false).</p>
</td>
</tr>
<tr>
<td>
<code>isolationMode</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>IsolationMode controls how shoot VPCs are isolated from each other.<br />"hub-spoke" (default): two route tables, shoots isolated from each other.<br />"shared": single route table, all VPCs see each other.<br />Immutable once set. To change: disable TGW first.</p>
</td>
</tr>
<tr>
<td>
<code>routeTableId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>RouteTableID is the single TGW route table for "shared" isolation mode.<br />Rejected in "hub-spoke" mode.</p>
</td>
</tr>
<tr>
<td>
<code>globalVPCs</code></br>
<em>
<a href="#globalvpc">GlobalVPC</a> array
</em>
</td>
<td>
<em>(Optional)</em>
<p>GlobalVPCs are utility/shared VPCs that all shoots on this seed should<br />be able to reach via the TGW. Each entry references a pre-existing TGW<br />VPC attachment. Provider-aws manages TGW route table association/propagation<br />and adds routes to shoot VPC route tables for the specified CIDRs.<br />Lives under TransitGateway because globalVPCs require a TGW to function.</p>
</td>
</tr>
<tr>
<td>
<code>seedVPCCredentialsRef</code></br>
<em>
<a href="#globalvpccredentialsref">GlobalVPCCredentialsRef</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>SeedVPCCredentialsRef references a Secret containing AWS credentials for<br />cross-account seed VPC operations. Only needed when the seed VPC (runtime VPC<br />for this seed) is in a different AWS account than the TGW.<br />When nil, the extension uses the shoot's default credentials (same account).<br />The secret must contain 'accessKeyID' and 'secretAccessKey' keys.</p>
</td>
</tr>
<tr>
<td>
<code>transitGatewayCredentialsRef</code></br>
<em>
<a href="#globalvpccredentialsref">GlobalVPCCredentialsRef</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>TransitGatewayCredentialsRef references a Secret containing AWS credentials for<br />the account that owns the Transit Gateway. Required when the TGW is in a different<br />AWS account than the shoot. When nil, uses the shoot's default credentials.<br />The secret must contain 'accessKeyID' and 'secretAccessKey' keys.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="transitgatewaycreateconfig">TransitGatewayCreateConfig
</h3>


<p>
(<em>Appears on:</em><a href="#transitgateway">TransitGateway</a>)
</p>

<p>
TransitGatewayCreateConfig specifies parameters for TGW auto-creation.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>amazonSideAsn</code></br>
<em>
integer
</em>
</td>
<td>
<em>(Optional)</em>
<p>AmazonSideAsn is the private ASN for the AWS side of the TGW.<br />Only relevant for BGP (VPN, Direct Connect, TGW peering).<br />Default: 64512.<br />Mutable: can be changed later if no BGP attachments are active.<br />Valid ranges: 64512-65534 (16-bit) or 4200000000-4294967294 (32-bit).</p>
</td>
</tr>
<tr>
<td>
<code>enableDefaultAssociation</code></br>
<em>
boolean
</em>
</td>
<td>
<p>EnableDefaultAssociation controls whether new attachments auto-associate<br />with the default TGW route table. Recommend false for explicit control.</p>
</td>
</tr>
<tr>
<td>
<code>enableDefaultPropagation</code></br>
<em>
boolean
</em>
</td>
<td>
<p>EnableDefaultPropagation controls whether new attachments auto-propagate<br />to the default TGW route table. Recommend false for explicit control.</p>
</td>
</tr>
<tr>
<td>
<code>autoAcceptSharedAttachments</code></br>
<em>
boolean
</em>
</td>
<td>
<p>AutoAcceptSharedAttachments enables auto-accept for cross-account<br />attachments (via RAM).</p>
</td>
</tr>

</tbody>
</table>


<h3 id="transitgatewaystatus">TransitGatewayStatus
</h3>


<p>
(<em>Appears on:</em><a href="#infrastructurestatus">InfrastructureStatus</a>)
</p>

<p>
TransitGatewayStatus contains information about TGW resources for a shoot.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>id</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ID is the Transit Gateway ID (referenced or auto-created).</p>
</td>
</tr>
<tr>
<td>
<code>hubRouteTableId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>HubRouteTableID is the hub TGW route table ID.</p>
</td>
</tr>
<tr>
<td>
<code>spokeRouteTableId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>SpokeRouteTableID is the spoke TGW route table ID.</p>
</td>
</tr>
<tr>
<td>
<code>attachmentId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>AttachmentID is the seed-level TGW VPC attachment ID.</p>
</td>
</tr>
<tr>
<td>
<code>shootAttachmentId</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ShootAttachmentID is the shoot-level TGW VPC attachment ID (if configured).</p>
</td>
</tr>

</tbody>
</table>


<h3 id="vpc">VPC
</h3>


<p>
(<em>Appears on:</em><a href="#networks">Networks</a>)
</p>

<p>
VPC contains information about the AWS VPC and some related resources.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>id</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ID is the VPC id.</p>
</td>
</tr>
<tr>
<td>
<code>cidr</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>CIDR is the VPC CIDR.</p>
</td>
</tr>
<tr>
<td>
<code>gatewayEndpoints</code></br>
<em>
string array
</em>
</td>
<td>
<em>(Optional)</em>
<p>GatewayEndpoints service names to configure as gateway endpoints in the VPC.</p>
</td>
</tr>
<tr>
<td>
<code>ipv6IpamPool</code></br>
<em>
<a href="#ipampool">IPAMPool</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Ipv6IpamPool references an AWS IPv6 IPAM pool used to allocate the VPC's IPv6 CIDR block.<br />If specified, the extension will request the VPC's IPv6 CIDR from this pool instead of<br />letting AWS auto-assign one. The pool must already exist in the target account/region.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="vpcstatus">VPCStatus
</h3>


<p>
(<em>Appears on:</em><a href="#infrastructurestatus">InfrastructureStatus</a>)
</p>

<p>
VPCStatus contains information about a generated VPC or resources inside an existing VPC.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>id</code></br>
<em>
string
</em>
</td>
<td>
<p>ID is the VPC id.</p>
</td>
</tr>
<tr>
<td>
<code>subnets</code></br>
<em>
<a href="#subnet">Subnet</a> array
</em>
</td>
<td>
<p>Subnets is a list of subnets that have been created.</p>
</td>
</tr>
<tr>
<td>
<code>securityGroups</code></br>
<em>
<a href="#securitygroup">SecurityGroup</a> array
</em>
</td>
<td>
<p>SecurityGroups is a list of security groups that have been created.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="volume">Volume
</h3>


<p>
(<em>Appears on:</em><a href="#datavolume">DataVolume</a>, <a href="#workerconfig">WorkerConfig</a>)
</p>

<p>
Volume contains configuration for the root disks attached to VMs.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>iops</code></br>
<em>
integer
</em>
</td>
<td>
<em>(Optional)</em>
<p>IOPS is the number of I/O operations per second (IOPS) that the volume supports.<br />For io1 volume type, this represents the number of IOPS that are provisioned for the<br />volume. For gp2 volume type, this represents the baseline performance of the volume and<br />the rate at which the volume accumulates I/O credits for bursting. For more<br />information about General Purpose SSD baseline performance, I/O credits,<br />and bursting, see Amazon EBS Volume Types (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html)<br />in the Amazon Elastic Compute Cloud User Guide.<br />Constraint: Range is 100-20000 IOPS for io1 volumes and 100-10000 IOPS for<br />gp2 volumes.<br />Condition: This parameter is required for requests to create io1 volumes;<br />it is not used in requests to create gp2, st1, sc1, or standard volumes.</p>
</td>
</tr>
<tr>
<td>
<code>throughput</code></br>
<em>
integer
</em>
</td>
<td>
<p>The throughput that the volume supports, in MiB/s.<br />This parameter is valid only for gp3 volumes.<br />Valid Range: The range as of 16th Aug 2022 is from 125 MiB/s to 1000 MiB/s. For more info refer (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html)</p>
</td>
</tr>

</tbody>
</table>


<h3 id="volumetype">VolumeType
</h3>
<p><em>Underlying type: string</em></p>


<p>
VolumeType is a constant for volume types.
</p>


<h3 id="workerconfig">WorkerConfig
</h3>


<p>
WorkerConfig contains configuration settings for the worker nodes.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>nodeTemplate</code></br>
<em>
<a href="#nodetemplate">NodeTemplate</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>NodeTemplate contains resource information of the machine which is used by Cluster Autoscaler to generate nodeTemplate during scaling a nodeGroup from zero.</p>
</td>
</tr>
<tr>
<td>
<code>volume</code></br>
<em>
<a href="#volume">Volume</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Volume contains configuration for the root disks attached to VMs.</p>
</td>
</tr>
<tr>
<td>
<code>dataVolumes</code></br>
<em>
<a href="#datavolume">DataVolume</a> array
</em>
</td>
<td>
<em>(Optional)</em>
<p>DataVolumes contains configuration for the additional disks attached to VMs.</p>
</td>
</tr>
<tr>
<td>
<code>iamInstanceProfile</code></br>
<em>
<a href="#iaminstanceprofile">IAMInstanceProfile</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IAMInstanceProfile contains configuration for the IAM instance profile that should be used for the VMs of this<br />worker pool.</p>
</td>
</tr>
<tr>
<td>
<code>instanceMetadataOptions</code></br>
<em>
<a href="#instancemetadataoptions">InstanceMetadataOptions</a>
</em>
</td>
<td>
<p>InstanceMetadataOptions contains configuration for controlling access to the metadata API.</p>
</td>
</tr>
<tr>
<td>
<code>cpuOptions</code></br>
<em>
<a href="#cpuoptions">CpuOptions</a>
</em>
</td>
<td>
<p>CpuOptions contains detailed configuration for the number of cores and threads for the instance.</p>
</td>
</tr>
<tr>
<td>
<code>capacityReservation</code></br>
<em>
<a href="#capacityreservation">CapacityReservation</a>
</em>
</td>
<td>
<p>CapacityReservation contains configuration about the Capacity Reservation to use for the instance.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="workerstatus">WorkerStatus
</h3>


<p>
WorkerStatus contains information about created worker resources.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>machineImages</code></br>
<em>
<a href="#machineimage">MachineImage</a> array
</em>
</td>
<td>
<em>(Optional)</em>
<p>MachineImages is a list of machine images that have been used in this worker. Usually, the extension controller<br />gets the mapping from name/version to the provider-specific machine image data in its componentconfig. However, if<br />a version that is still in use gets removed from this componentconfig it cannot reconcile anymore existing `Worker`<br />resources that are still using this version. Hence, it stores the used versions in the provider status to ensure<br />reconciliation is possible.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="workloadidentityconfig">WorkloadIdentityConfig
</h3>


<p>
WorkloadIdentityConfig contains configuration settings for workload identity.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>roleARN</code></br>
<em>
string
</em>
</td>
<td>
<p>RoleARN is the identifier of the role that the workload identity will assume.</p>
</td>
</tr>

</tbody>
</table>


<h3 id="zone">Zone
</h3>


<p>
(<em>Appears on:</em><a href="#networks">Networks</a>)
</p>

<p>
Zone describes the properties of a zone.
</p>

<table>
<thead>
<tr>
<th>Field</th>
<th>Description</th>
</tr>
</thead>
<tbody>

<tr>
<td>
<code>name</code></br>
<em>
string
</em>
</td>
<td>
<p>Name is the name for this zone.</p>
</td>
</tr>
<tr>
<td>
<code>internal</code></br>
<em>
string
</em>
</td>
<td>
<p>Internal is the private subnet range to create (used for internal load balancers).</p>
</td>
</tr>
<tr>
<td>
<code>public</code></br>
<em>
string
</em>
</td>
<td>
<p>Public is the public subnet range to create (used for bastion and load balancers).</p>
</td>
</tr>
<tr>
<td>
<code>workers</code></br>
<em>
string
</em>
</td>
<td>
<p>Workers is the workers subnet range to create (used for the VMs).</p>
</td>
</tr>
<tr>
<td>
<code>elasticIPAllocationID</code></br>
<em>
string
</em>
</td>
<td>
<em>(Optional)</em>
<p>ElasticIPAllocationID contains the allocation ID of an Elastic IP that will be attached to the NAT gateway in<br />this zone (e.g., `eipalloc-123456`). If it's not provided then a new Elastic IP will be automatically created<br />and attached.<br />Important: If this field is changed then the already attached Elastic IP will be disassociated from the NAT gateway<br />(and potentially removed if it was created by this extension). Also, the NAT gateway will be deleted. This will<br />disrupt egress traffic for a while.</p>
</td>
</tr>

</tbody>
</table>


