<p>Packages:</p>
<ul>
<li>
<a href="#aws.provider.extensions.gardener.cloud%2fv1alpha1">aws.provider.extensions.gardener.cloud/v1alpha1</a>
</li>
</ul>
<h2 id="aws.provider.extensions.gardener.cloud/v1alpha1">aws.provider.extensions.gardener.cloud/v1alpha1</h2>
<p>
<p>Package v1alpha1 contains the AWS provider API resources.</p>
</p>
Resource Types:
<ul><li>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.BackupBucketConfig">BackupBucketConfig</a>
</li><li>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.CloudProfileConfig">CloudProfileConfig</a>
</li><li>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ControlPlaneConfig">ControlPlaneConfig</a>
</li><li>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureConfig">InfrastructureConfig</a>
</li><li>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.WorkerConfig">WorkerConfig</a>
</li><li>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.WorkerStatus">WorkerStatus</a>
</li><li>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.WorkloadIdentityConfig">WorkloadIdentityConfig</a>
</li></ul>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.BackupBucketConfig">BackupBucketConfig
</h3>
<p>
<p>BackupBucketConfig represents the configuration for a backup bucket.</p>
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
<code>apiVersion</code></br>
string</td>
<td>
<code>
aws.provider.extensions.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>BackupBucketConfig</code></td>
</tr>
<tr>
<td>
<code>immutability</code></br>
<em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ImmutableConfig">
ImmutableConfig
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Immutability defines the immutability configuration for the backup bucket.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.CloudProfileConfig">CloudProfileConfig
</h3>
<p>
<p>CloudProfileConfig contains provider-specific configuration that is embedded into Gardener&rsquo;s <code>CloudProfile</code>
resource.</p>
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
<code>apiVersion</code></br>
string</td>
<td>
<code>
aws.provider.extensions.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>CloudProfileConfig</code></td>
</tr>
<tr>
<td>
<code>machineImages</code></br>
<em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.MachineImages">
[]MachineImages
</a>
</em>
</td>
<td>
<p>MachineImages is the list of machine images that are understood by the controller. It maps
logical names and versions to provider-specific identifiers.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.ControlPlaneConfig">ControlPlaneConfig
</h3>
<p>
<p>ControlPlaneConfig contains configuration settings for the control plane.</p>
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
<code>apiVersion</code></br>
string</td>
<td>
<code>
aws.provider.extensions.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>ControlPlaneConfig</code></td>
</tr>
<tr>
<td>
<code>cloudControllerManager</code></br>
<em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.CloudControllerManagerConfig">
CloudControllerManagerConfig
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.LoadBalancerControllerConfig">
LoadBalancerControllerConfig
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.Storage">
Storage
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>Storage contains configuration for storage in the cluster.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureConfig">InfrastructureConfig
</h3>
<p>
<p>InfrastructureConfig infrastructure configuration resource</p>
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
<code>apiVersion</code></br>
string</td>
<td>
<code>
aws.provider.extensions.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>InfrastructureConfig</code></td>
</tr>
<tr>
<td>
<code>enableECRAccess</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>EnableECRAccess specifies whether the IAM role policy for the worker nodes shall contain
permissions to access the ECR.
default: true</p>
</td>
</tr>
<tr>
<td>
<code>dualStack</code></br>
<em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.DualStack">
DualStack
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.Networks">
Networks
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.IgnoreTags">
IgnoreTags
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IgnoreTags allows to configure which resource tags on resources managed by Gardener should be ignored during
infrastructure reconciliation. By default, all tags that are added outside of Gardener&rsquo;s / terraform&rsquo;s
reconciliation will be removed during the next reconciliation. This field allows users and automation to add
custom tags on resources created and managed by Gardener without loosing them on the next reconciliation.
See <a href="https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/resource-tagging#ignoring-changes-in-all-resources">https://registry.terraform.io/providers/hashicorp/aws/latest/docs/guides/resource-tagging#ignoring-changes-in-all-resources</a>
for details of the underlying terraform implementation.</p>
</td>
</tr>
<tr>
<td>
<code>enableDedicatedTenancyForVPC</code></br>
<em>
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>EnableDedicatedTenancyForVPC allows to configure the VPC to use dedicated tenancy.
If this field is set to true, all VMs created in this VPC will have dedicated tenancy enabled.
This setting is immutable and cannot be changed once the VPC has been created.
default: false</p>
</td>
</tr>
<tr>
<td>
<code>elasticFileSystem</code></br>
<em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ElasticFileSystemConfig">
ElasticFileSystemConfig
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>ElasticFileSystem contains information about the EFS that should be used.
This field is immutable and cannot be changed once created.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.WorkerConfig">WorkerConfig
</h3>
<p>
<p>WorkerConfig contains configuration settings for the worker nodes.</p>
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
<code>apiVersion</code></br>
string</td>
<td>
<code>
aws.provider.extensions.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>WorkerConfig</code></td>
</tr>
<tr>
<td>
<code>nodeTemplate</code></br>
<em>
github.com/gardener/gardener/pkg/apis/extensions/v1alpha1.NodeTemplate
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.Volume">
Volume
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.DataVolume">
[]DataVolume
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.IAMInstanceProfile">
IAMInstanceProfile
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>IAMInstanceProfile contains configuration for the IAM instance profile that should be used for the VMs of this
worker pool.</p>
</td>
</tr>
<tr>
<td>
<code>instanceMetadataOptions</code></br>
<em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InstanceMetadataOptions">
InstanceMetadataOptions
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.CpuOptions">
CpuOptions
</a>
</em>
</td>
<td>
<p>CpuOptions contains detailed configuration for the number of cores and threads for the instance.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.WorkerStatus">WorkerStatus
</h3>
<p>
<p>WorkerStatus contains information about created worker resources.</p>
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
<code>apiVersion</code></br>
string</td>
<td>
<code>
aws.provider.extensions.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>WorkerStatus</code></td>
</tr>
<tr>
<td>
<code>machineImages</code></br>
<em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.MachineImage">
[]MachineImage
</a>
</em>
</td>
<td>
<em>(Optional)</em>
<p>MachineImages is a list of machine images that have been used in this worker. Usually, the extension controller
gets the mapping from name/version to the provider-specific machine image data in its componentconfig. However, if
a version that is still in use gets removed from this componentconfig it cannot reconcile anymore existing <code>Worker</code>
resources that are still using this version. Hence, it stores the used versions in the provider status to ensure
reconciliation is possible.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.WorkloadIdentityConfig">WorkloadIdentityConfig
</h3>
<p>
<p>WorkloadIdentityConfig contains configuration settings for workload identity.</p>
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
<code>apiVersion</code></br>
string</td>
<td>
<code>
aws.provider.extensions.gardener.cloud/v1alpha1
</code>
</td>
</tr>
<tr>
<td>
<code>kind</code></br>
string
</td>
<td><code>WorkloadIdentityConfig</code></td>
</tr>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.CloudControllerManagerConfig">CloudControllerManagerConfig
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ControlPlaneConfig">ControlPlaneConfig</a>)
</p>
<p>
<p>CloudControllerManagerConfig contains configuration settings for the cloud-controller-manager.</p>
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
map[string]bool
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
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>UseCustomRouteController controls if custom route controller should be used.
Defaults to false.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.CpuOptions">CpuOptions
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.WorkerConfig">WorkerConfig</a>)
</p>
<p>
<p>CpuOptions contains detailed configuration for the number of cores and threads for the instance.</p>
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
int64
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
int64
</em>
</td>
<td>
<p>ThreadsPerCore sets the number of threads per core. Must be either &lsquo;1&rsquo; (disable multi-threading) or &lsquo;2&rsquo;.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.DataVolume">DataVolume
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.WorkerConfig">WorkerConfig</a>)
</p>
<p>
<p>DataVolume contains configuration for data volumes attached to VMs.</p>
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
<code>Volume</code></br>
<em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.Volume">
Volume
</a>
</em>
</td>
<td>
<p>
(Members of <code>Volume</code> are embedded into this type.)
</p>
<p>Volume contains configuration for the volume.</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.DualStack">DualStack
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureConfig">InfrastructureConfig</a>)
</p>
<p>
<p>DualStack specifies whether dual-stack or IPv4-only should be supported.</p>
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
bool
</em>
</td>
<td>
<p>Enabled specifies if dual-stack is enabled or not.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.EC2">EC2
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureStatus">InfrastructureStatus</a>)
</p>
<p>
<p>EC2 contains information about the  AWS EC2 resources.</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.ElasticFileSystemConfig">ElasticFileSystemConfig
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureConfig">InfrastructureConfig</a>)
</p>
<p>
<p>ElasticFileSystemConfig holds config information about the EFS storage</p>
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
bool
</em>
</td>
<td>
<p>Enabled is the switch to install the CSI EFS driver
if enabled:
- the IAM role policy for the worker nodes shall contain permissions to access the EFS.
- an EFS will be created if the ID is not specified.
- firewall rules will be created to allow access to the EFS from the worker nodes.</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.ElasticFileSystemStatus">ElasticFileSystemStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureStatus">InfrastructureStatus</a>)
</p>
<p>
<p>ElasticFileSystemStatus contains status info about the Elastic File System (EFS).</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.HTTPTokensValue">HTTPTokensValue
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InstanceMetadataOptions">InstanceMetadataOptions</a>)
</p>
<p>
<p>HTTPTokensValue is a constant for HTTPTokens values.</p>
</p>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.IAM">IAM
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureStatus">InfrastructureStatus</a>)
</p>
<p>
<p>IAM contains information about the AWS IAM resources.</p>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InstanceProfile">
[]InstanceProfile
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.Role">
[]Role
</a>
</em>
</td>
<td>
<p>Roles is a list of AWS IAM roles.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.IAMInstanceProfile">IAMInstanceProfile
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.WorkerConfig">WorkerConfig</a>)
</p>
<p>
<p>IAMInstanceProfile contains configuration for the IAM instance profile that should be used for the VMs of this
worker pool. Either &lsquo;Name&rdquo; or &lsquo;ARN&rsquo; must be specified.</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.IgnoreTags">IgnoreTags
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureConfig">InfrastructureConfig</a>)
</p>
<p>
<p>IgnoreTags holds information about ignored resource tags.</p>
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
[]string
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
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>KeyPrefixes is a list of tag key prefixes, that should be ignored during infrastructure reconciliation.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.ImmutableConfig">ImmutableConfig
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.BackupBucketConfig">BackupBucketConfig</a>)
</p>
<p>
<p>ImmutableConfig represents the immutability configuration for a backup bucket.</p>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.RetentionType">
RetentionType
</a>
</em>
</td>
<td>
<p>RetentionType specifies the type of retention for the backup bucket.
Currently allowed value is:
- &ldquo;bucket&rdquo;: retention policy applies on the entire bucket.</p>
</td>
</tr>
<tr>
<td>
<code>retentionPeriod</code></br>
<em>
<a href="https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.31/#duration-v1-meta">
Kubernetes meta/v1.Duration
</a>
</em>
</td>
<td>
<p>RetentionPeriod specifies the immutability retention period for the backup bucket.
S3 only supports immutability durations in days or years, therefore this field must be set as multiple of 24h.</p>
</td>
</tr>
<tr>
<td>
<code>mode</code></br>
<em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ModeType">
ModeType
</a>
</em>
</td>
<td>
<p>S3 provides two retention modes that apply different levels of protection to objects:
Allowed values are: &ldquo;governance&rdquo; or &ldquo;compliance&rdquo; mode.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureState">InfrastructureState
</h3>
<p>
<p>InfrastructureState is the state which is persisted as part of the infrastructure status.</p>
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
map[string]string
</em>
</td>
<td>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureStatus">InfrastructureStatus
</h3>
<p>
<p>InfrastructureStatus contains information about created infrastructure resources.</p>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.EC2">
EC2
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.IAM">
IAM
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.VPCStatus">
VPCStatus
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ElasticFileSystemStatus">
ElasticFileSystemStatus
</a>
</em>
</td>
<td>
<p>ElasticFileSystem contains information about the created ElasticFileSystem.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.InstanceMetadataOptions">InstanceMetadataOptions
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.WorkerConfig">WorkerConfig</a>)
</p>
<p>
<p>InstanceMetadataOptions contains configuration for controlling access to the metadata API.</p>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.HTTPTokensValue">
HTTPTokensValue
</a>
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
int64
</em>
</td>
<td>
<p>HTTPPutResponseHopLimit is the response hop limit for instance metadata requests.
Valid values are between 1 and 64.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.InstanceProfile">InstanceProfile
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.IAM">IAM</a>)
</p>
<p>
<p>InstanceProfile is an AWS IAM instance profile.</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.LoadBalancerControllerConfig">LoadBalancerControllerConfig
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ControlPlaneConfig">ControlPlaneConfig</a>)
</p>
<p>
<p>LoadBalancerControllerConfig contains configuration settings for the optional aws-load-balancer-controller (ALB).</p>
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
bool
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
<p>IngressClassName is the name of the ingress class the ALB controller will target. Default value is &lsquo;alb&rsquo;.
If empty string is specified, it will match all ingresses without ingress class annotation and ingresses of type alb</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.MachineImage">MachineImage
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.WorkerStatus">WorkerStatus</a>)
</p>
<p>
<p>MachineImage is a mapping from logical names and versions to provider-specific machine image data.</p>
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
github.com/gardener/gardener/pkg/apis/core/v1beta1.Capabilities
</em>
</td>
<td>
<p>Capabilities of the machine image.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.MachineImageFlavor">MachineImageFlavor
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.MachineImageVersion">MachineImageVersion</a>)
</p>
<p>
<p>MachineImageFlavor groups all RegionAMIMappings for a specific et of capabilities.</p>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.RegionAMIMapping">
[]RegionAMIMapping
</a>
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
github.com/gardener/gardener/pkg/apis/core/v1beta1.Capabilities
</em>
</td>
<td>
<p>Capabilities that are supported by the AMIs in this set.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.MachineImageVersion">MachineImageVersion
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.MachineImages">MachineImages</a>)
</p>
<p>
<p>MachineImageVersion contains a version and a provider-specific identifier.</p>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.RegionAMIMapping">
[]RegionAMIMapping
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.MachineImageFlavor">
[]MachineImageFlavor
</a>
</em>
</td>
<td>
<p>CapabilityFlavors is grouping of region AMIs by capabilities.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.MachineImages">MachineImages
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.CloudProfileConfig">CloudProfileConfig</a>)
</p>
<p>
<p>MachineImages is a mapping from logical names and versions to provider-specific identifiers.</p>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.MachineImageVersion">
[]MachineImageVersion
</a>
</em>
</td>
<td>
<p>Versions contains versions and a provider-specific identifier.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.ModeType">ModeType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ImmutableConfig">ImmutableConfig</a>)
</p>
<p>
<p>ModeType defines the type of object lock mode for immutability settings.</p>
</p>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.Networks">Networks
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureConfig">InfrastructureConfig</a>)
</p>
<p>
<p>Networks holds information about the Kubernetes and infrastructure networks.</p>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.VPC">
VPC
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.Zone">
[]Zone
</a>
</em>
</td>
<td>
<p>Zones belonging to the same region</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.RegionAMIMapping">RegionAMIMapping
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.MachineImageFlavor">MachineImageFlavor</a>, 
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.MachineImageVersion">MachineImageVersion</a>)
</p>
<p>
<p>RegionAMIMapping is a mapping to the correct AMI for the machine image in the given region.</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.RetentionType">RetentionType
(<code>string</code> alias)</p></h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ImmutableConfig">ImmutableConfig</a>)
</p>
<p>
<p>RetentionType defines the level at which immutability properties are applied on objects.</p>
</p>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.Role">Role
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.IAM">IAM</a>)
</p>
<p>
<p>Role is an AWS IAM role.</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.SecurityGroup">SecurityGroup
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.VPCStatus">VPCStatus</a>)
</p>
<p>
<p>SecurityGroup is an AWS security group related to a VPC.</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.Storage">Storage
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.ControlPlaneConfig">ControlPlaneConfig</a>)
</p>
<p>
<p>Storage contains configuration for storage in the cluster.</p>
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
bool
</em>
</td>
<td>
<em>(Optional)</em>
<p>ManagedDefaultClass controls if the &lsquo;default&rsquo; StorageClass and &lsquo;default&rsquo; VolumeSnapshotClass
would be marked as default. Set to false to manually set the default to another class not
managed by Gardener.
Defaults to true.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.Subnet">Subnet
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.VPCStatus">VPCStatus</a>)
</p>
<p>
<p>Subnet is an AWS subnet related to a VPC.</p>
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
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.VPC">VPC
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.Networks">Networks</a>)
</p>
<p>
<p>VPC contains information about the AWS VPC and some related resources.</p>
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
[]string
</em>
</td>
<td>
<em>(Optional)</em>
<p>GatewayEndpoints service names to configure as gateway endpoints in the VPC.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.VPCStatus">VPCStatus
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.InfrastructureStatus">InfrastructureStatus</a>)
</p>
<p>
<p>VPCStatus contains information about a generated VPC or resources inside an existing VPC.</p>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.Subnet">
[]Subnet
</a>
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
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.SecurityGroup">
[]SecurityGroup
</a>
</em>
</td>
<td>
<p>SecurityGroups is a list of security groups that have been created.</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.Volume">Volume
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.WorkerConfig">WorkerConfig</a>, 
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.DataVolume">DataVolume</a>)
</p>
<p>
<p>Volume contains configuration for the root disks attached to VMs.</p>
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
int64
</em>
</td>
<td>
<em>(Optional)</em>
<p>IOPS is the number of I/O operations per second (IOPS) that the volume supports.
For io1 volume type, this represents the number of IOPS that are provisioned for the
volume. For gp2 volume type, this represents the baseline performance of the volume and
the rate at which the volume accumulates I/O credits for bursting. For more
information about General Purpose SSD baseline performance, I/O credits,
and bursting, see Amazon EBS Volume Types (<a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html">http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html</a>)
in the Amazon Elastic Compute Cloud User Guide.</p>
<p>Constraint: Range is 100-20000 IOPS for io1 volumes and 100-10000 IOPS for
gp2 volumes.</p>
<p>Condition: This parameter is required for requests to create io1 volumes;
it is not used in requests to create gp2, st1, sc1, or standard volumes.</p>
</td>
</tr>
<tr>
<td>
<code>throughput</code></br>
<em>
int64
</em>
</td>
<td>
<p>The throughput that the volume supports, in MiB/s.</p>
<p>This parameter is valid only for gp3 volumes.</p>
<p>Valid Range: The range as of 16th Aug 2022 is from 125 MiB/s to 1000 MiB/s. For more info refer (<a href="http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html">http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html</a>)</p>
</td>
</tr>
</tbody>
</table>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.VolumeType">VolumeType
(<code>string</code> alias)</p></h3>
<p>
<p>VolumeType is a constant for volume types.</p>
</p>
<h3 id="aws.provider.extensions.gardener.cloud/v1alpha1.Zone">Zone
</h3>
<p>
(<em>Appears on:</em>
<a href="#aws.provider.extensions.gardener.cloud/v1alpha1.Networks">Networks</a>)
</p>
<p>
<p>Zone describes the properties of a zone.</p>
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
<p>ElasticIPAllocationID contains the allocation ID of an Elastic IP that will be attached to the NAT gateway in
this zone (e.g., <code>eipalloc-123456</code>). If it&rsquo;s not provided then a new Elastic IP will be automatically created
and attached.
Important: If this field is changed then the already attached Elastic IP will be disassociated from the NAT gateway
(and potentially removed if it was created by this extension). Also, the NAT gateway will be deleted. This will
disrupt egress traffic for a while.</p>
</td>
</tr>
</tbody>
</table>
<hr/>
<p><em>
Generated with <a href="https://github.com/ahmetb/gen-crd-api-reference-docs">gen-crd-api-reference-docs</a>
</em></p>
