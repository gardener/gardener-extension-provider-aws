# Using the AWS provider extension with Gardener as end-user

The [`core.gardener.cloud/v1beta1.Shoot` resource](https://github.com/gardener/gardener/blob/master/example/90-shoot.yaml) declares a few fields that are meant to contain provider-specific configuration.

In this document we are describing how this configuration looks like for AWS and provide an example `Shoot` manifest with minimal configuration that you can use to create an AWS cluster (modulo the landscape-specific information like cloud profile names, secret binding names, etc.).

## Provider Secret Data

Every shoot cluster references a `SecretBinding` which itself references a `Secret`, and this `Secret` contains the provider credentials of your AWS account.
This `Secret` must look as follows:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: core-aws
  namespace: garden-dev
type: Opaque
data:
  accessKeyID: base64(access-key-id)
  secretAccessKey: base64(secret-access-key)
```

The [AWS documentation](https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys) explains the necessary steps to enable programmatic access, i.e. create **access key ID** and **access key**, for the user of your choice.

⚠️ For security reasons, we recommend creating a **dedicated user with programmatic access only**. Please avoid re-using a IAM user which has access to the AWS console (human user).

⚠️ Depending on your AWS API usage it can be problematic to reuse the same AWS Account for different Shoot clusters in the same region due to rate limits. Please consider spreading your Shoots over multiple AWS Accounts if you are hitting those limits.

### Permissions

Please make sure that the provided credentials have the correct privileges. You can use the following AWS IAM policy document and attach it to the IAM user backed by the credentials you provided (please check the [official AWS documentation](http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage.html) as well):

<details>
  <summary>Click to expand the AWS IAM policy document!</summary>

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "autoscaling:*",
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": "ec2:*",
        "Resource": "*"
      },
      {
        "Effect": "Allow",
        "Action": "elasticloadbalancing:*",
        "Resource": "*"
      },
      {
        "Action": [
          "iam:GetInstanceProfile",
          "iam:GetPolicy",
          "iam:GetPolicyVersion",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListPolicyVersions",
          "iam:ListRolePolicies",
          "iam:ListAttachedRolePolicies",
          "iam:ListInstanceProfilesForRole",
          "iam:CreateInstanceProfile",
          "iam:CreatePolicy",
          "iam:CreatePolicyVersion",
          "iam:CreateRole",
          "iam:CreateServiceLinkedRole",
          "iam:AddRoleToInstanceProfile",
          "iam:AttachRolePolicy",
          "iam:DetachRolePolicy",
          "iam:RemoveRoleFromInstanceProfile",
          "iam:DeletePolicy",
          "iam:DeletePolicyVersion",
          "iam:DeleteRole",
          "iam:DeleteRolePolicy",
          "iam:DeleteInstanceProfile",
          "iam:PutRolePolicy",
          "iam:PassRole",
          "iam:UpdateAssumeRolePolicy"
        ],
        "Effect": "Allow",
        "Resource": "*"
      }
    ]
  }
  ```
</details>

## `InfrastructureConfig`

The infrastructure configuration mainly describes how the network layout looks like in order to create the shoot worker nodes in a later step, thus, prepares everything relevant to create VMs, load balancers, volumes, etc.

An example `InfrastructureConfig` for the AWS extension looks as follows:

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: InfrastructureConfig
enableECRAccess: true
networks:
  vpc: # specify either 'id' or 'cidr'
  # id: vpc-123456
    cidr: 10.250.0.0/16
  # gatewayEndpoints:
  # - s3
  zones:
  - name: eu-west-1a
    internal: 10.250.112.0/22
    public: 10.250.96.0/22
    workers: 10.250.0.0/19
  # elasticIPAllocationID: eipalloc-123456
ignoreTags:
  keys: # individual ignored tag keys
  - SomeCustomKey
  - AnotherCustomKey
  keyPrefixes: # ignored tag key prefixes
  - user.specific/prefix/
```

The `enableECRAccess` flag specifies whether the AWS IAM role policy attached to all worker nodes of the cluster shall contain permissions to access the Elastic Container Registry of the respective AWS account.
If the flag is not provided it is defaulted to `true`.
Please note that if the `iamInstanceProfile` is set for a worker pool in the `WorkerConfig` (see below) then `enableECRAccess` does not have any effect.
It only applies for those worker pools whose `iamInstanceProfile` is not set.

<details>
  <summary>Click to expand the default AWS IAM policy document used for the instance profiles!</summary>

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "ec2:DescribeInstances"
        ],
        "Resource": [
          "*"
        ]
      },
      // Only if `.enableECRAccess` is `true`.
      {
        "Effect": "Allow",
        "Action": [
          "ecr:GetAuthorizationToken",
          "ecr:BatchCheckLayerAvailability",
          "ecr:GetDownloadUrlForLayer",
          "ecr:GetRepositoryPolicy",
          "ecr:DescribeRepositories",
          "ecr:ListImages",
          "ecr:BatchGetImage"
        ],
        "Resource": [
          "*"
        ]
      }
    ]
  }
  ```
</details>

The `networks.vpc` section describes whether you want to create the shoot cluster in an already existing VPC or whether to create a new one:

* If `networks.vpc.id` is given then you have to specify the VPC ID of the existing VPC that was created by other means (manually, other tooling, ...).
Please make sure that the VPC has attached an internet gateway - the AWS controller won't create one automatically for existing VPCs. To make sure the nodes are able to join and operate in your cluster properly, please make sure that your VPC has enabled [DNS Support](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-dns.html), explicitly the attributes `enableDnsHostnames` and `enableDnsSupport` must be set to `true`.
* If `networks.vpc.cidr` is given then you have to specify the VPC CIDR of a new VPC that will be created during shoot creation.
You can freely choose a private CIDR range.
* Either `networks.vpc.id` or `networks.vpc.cidr` must be present, but not both at the same time.
* `networks.vpc.gatewayEndpoints` is optional. If specified then each item is used as service name in a corresponding Gateway VPC Endpoint.

The `networks.zones` section contains configuration for resources you want to create or use in availability zones.
For every zone, the AWS extension creates three subnets:

* The `internal` subnet is used for [internal AWS load balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-internal-load-balancers.html).
* The `public` subnet is used for [public AWS load balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-internet-facing-load-balancers.html).
* The `workers` subnet is used for all shoot worker nodes, i.e., VMs which later run your applications.

For every subnet, you have to specify a CIDR range contained in the VPC CIDR specified above, or the VPC CIDR of your already existing VPC.
You can freely choose these CIDRs and it is your responsibility to properly design the network layout to suit your needs.

Also, the AWS extension creates a dedicated NAT gateway for each zone.
By default, it also creates a corresponding Elastic IP that it attaches to this NAT gateway and which is used for egress traffic.
The `elasticIPAllocationID` field allows you to specify the ID of an existing Elastic IP allocation in case you want to bring your own.
If provided, no new Elastic IP will be created and, instead, the Elastic IP specified by you will be used.

⚠️ If you change this field for an already existing infrastructure then it will disrupt egress traffic while AWS applies this change.
The reason is that the NAT gateway must be recreated with the new Elastic IP association.
Also, please note that the existing Elastic IP will be permanently deleted if it was earlier created by the AWS extension.

You can configure [Gateway VPC Endpoints](https://docs.aws.amazon.com/vpc/latest/userguide/vpce-gateway.html) by adding items in the optional list `networks.vpc.gatewayEndpoints`. Each item in the list is used as a service name and a corresponding endpoint is created for it. All created endpoints point to the service within the cluster's region. For example, consider this (partial) shoot config:

```yaml
spec:
  region: eu-central-1
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          gatewayEndpoints:
          - s3
```

The service name of the S3 Gateway VPC Endpoint in this example is `com.amazonaws.eu-central-1.s3`.

If you want to use multiple availability zones then add a second, third, ... entry to the `networks.zones[]` list and properly specify the AZ name in `networks.zones[].name`.

Apart from the VPC and the subnets the AWS extension will also create DHCP options and an internet gateway (only if a new VPC is created), routing tables, security groups, elastic IPs, NAT gateways, EC2 key pairs, IAM roles, and IAM instance profiles.

The `ignoreTags` section allows to configure which resource tags on AWS resources managed by Gardener should be ignored during
infrastructure reconciliation. By default, all tags that are added outside of Gardener's
reconciliation will be removed during the next reconciliation. This field allows users and automation to add
custom tags on AWS resources created and managed by Gardener without loosing them on the next reconciliation.
Tags can ignored either by specifying exact key values (`ignoreTags.keys`) or key prefixes (`ignoreTags.keyPrefixes`).
In both cases it is forbidden to ignore the `Name` tag or any tag starting with `kubernetes.io` or `gardener.cloud`.  
Please note though, that the tags are only ignored on resources created on behalf of the `Infrastructure` CR (i.e. VPC,
subnets, security groups, keypair, etc.), while tags on machines, volumes, etc. are not in the scope of this controller.

## `ControlPlaneConfig`

The control plane configuration mainly contains values for the AWS-specific control plane components.
Today, the only component deployed by the AWS extension is the `cloud-controller-manager`.

An example `ControlPlaneConfig` for the AWS extension looks as follows:

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: ControlPlaneConfig
cloudControllerManager:
  featureGates:
    CustomResourceValidation: true
  useCustomRouteController: true
storage:
  managedDefaultClass: false
```

The `cloudControllerManager.featureGates` contains a map of explicitly enabled or disabled feature gates.
For production usage it's not recommend to use this field at all as you can enable alpha features or disable beta/stable features, potentially impacting the cluster stability.
If you don't want to configure anything for the `cloudControllerManager` simply omit the key in the YAML specification.

The `cloudControllerManager.useCustomRouteController` controls if the [custom routes controller](https://github.com/gardener/aws-custom-route-controller) should be enabled.
If enabled, it will add routes to the pod CIDRs for all nodes in the route tables for all zones.

The `storage.managedDefaultClass` controls if the `default` storage / volume snapshot classes are marked as default by Gardener. Set it to `false` to [mark another storage / volume snapshot class as default](https://kubernetes.io/docs/tasks/administer-cluster/change-default-storage-class/) without Gardener overwriting this change. If unset, this field defaults to `true`.

## `WorkerConfig`

The AWS extension supports encryption for volumes plus support for additional data volumes per machine.
For each data volume, you have to specify a name.
By default (if not stated otherwise), all the disks (root & data volumes) are encrypted.
Please make sure that your [instance-type supports encryption](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html).
If your instance-type doesn't support encryption, you will have to disable encryption (which is enabled by default) by setting `volume.encrpyted` to `false` (refer below shown YAML snippet).

The following YAML is a snippet of a `Shoot` resource:

```yaml
spec:
  provider:
    workers:
    - name: cpu-worker
      ...
      volume:
        type: gp2
        size: 20Gi
        encrypted: false
      dataVolumes:
      - name: kubelet-dir
        type: gp2
        size: 25Gi
        encrypted: true
```

> Note: The AWS extension does not support EBS volume (root & data volumes) encryption with [customer managed CMK](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk). Support for [customer managed CMK](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#customer-cmk) is out of scope for now. Only [AWS managed CMK](https://docs.aws.amazon.com/kms/latest/developerguide/concepts.html#aws-managed-cmk) is supported.

Additionally, it is possible to provide further AWS-specific values for configuring the worker pools.
It can be provided in `.spec.provider.workers[].providerConfig` and is evaluated by the AWS worker controller when it reconciles the shoot machines.

An example `WorkerConfig` for the AWS extension looks as follows:

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkerConfig
volume:
  iops: 10000
  throughput: 200 
dataVolumes:
- name: kubelet-dir
  iops: 12345
  throughput: 150
  snapshotID: snap-1234
iamInstanceProfile: # (specify either ARN or name)
  name: my-profile
# arn: my-instance-profile-arn
nodeTemplate: # (to be specified only if the node capacity would be different from cloudprofile info during runtime)
  capacity:
    cpu: 2
    gpu: 0
    memory: 50Gi
```

The `.volume.iops` is the number of I/O operations per second (IOPS) that the volume supports.
For `io1` and `gp3` volume type, this represents the number of IOPS that are provisioned for the volume.
For `gp2` volume type, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting. For more information about General Purpose SSD baseline performance, I/O credits, IOPS range and bursting, see Amazon EBS Volume Types (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html) in the Amazon Elastic Compute Cloud User Guide.\
Constraint: IOPS should be a positive value. Validation of IOPS (i.e. whether it is allowed and is in the specified range for a particular volume type) is done on aws side.

The `volume.throughput` is the throughput that the volume supports, in `MiB/s`. As of `16th Aug 2022`, this parameter is valid only for `gp3` volume types and will return an error from the provider side if specified for other volume types. Its current range of throughput is from `125MiB/s` to `1000 MiB/s`. To know more about throughput and its range, see the official AWS documentation [here](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html).

The `.dataVolumes` can optionally contain configurations for the data volumes stated in the `Shoot` specification in the `.spec.provider.workers[].dataVolumes` list.
The `.name` must match to the name of the data volume in the shoot.
It is also possible to provide a snapshot ID. It allows to [restore the data volume from an existing snapshot](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ebs-restoring-volume.html).

The `iamInstanceProfile` section allows to specify the IAM instance profile name xor ARN that should be used for this worker pool.
If not specified, a dedicated IAM instance profile created by the infrastructure controller is used (see above).

## Example `Shoot` manifest (one availability zone)

Please find below an example `Shoot` manifest for one availability zone:

```yaml
apiVersion: core.gardener.cloud/v1beta1
kind: Shoot
metadata:
  name: johndoe-aws
  namespace: garden-dev
spec:
  cloudProfileName: aws
  region: eu-central-1
  secretBindingName: core-aws
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          cidr: 10.250.0.0/16
        zones:
        - name: eu-central-1a
          internal: 10.250.112.0/22
          public: 10.250.96.0/22
          workers: 10.250.0.0/19
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-xoluy
      machine:
        type: m5.large
      minimum: 2
      maximum: 2
      volume:
        size: 50Gi
        type: gp2
    # The following provider config is valid if the volume type is `io1`.
    # providerConfig:
    #   apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
    #   kind: WorkerConfig
    #   volume:
    #     iops: 10000
      zones:
      - eu-central-1a
  networking:
    nodes: 10.250.0.0/16
    type: calico
  kubernetes:
    version: 1.24.3
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
  addons:
    kubernetesDashboard:
      enabled: true
    nginxIngress:
      enabled: true
```

## Example `Shoot` manifest (three availability zones)

Please find below an example `Shoot` manifest for three availability zones:

```yaml
apiVersion: core.gardener.cloud/v1beta1
kind: Shoot
metadata:
  name: johndoe-aws
  namespace: garden-dev
spec:
  cloudProfileName: aws
  region: eu-central-1
  secretBindingName: core-aws
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          cidr: 10.250.0.0/16
        zones:
        - name: eu-central-1a
          workers: 10.250.0.0/26
          public: 10.250.96.0/26
          internal: 10.250.112.0/26
        - name: eu-central-1b
          workers: 10.250.0.64/26
          public: 10.250.96.64/26
          internal: 10.250.112.64/26
        - name: eu-central-1c
          workers: 10.250.0.128/26
          public: 10.250.96.128/26
          internal: 10.250.112.128/26
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-xoluy
      machine:
        type: m5.large
      minimum: 3
      maximum: 9
      volume:
        size: 50Gi
        type: gp2
      zones:
      - eu-central-1a
      - eu-central-1b
      - eu-central-1c
  networking:
    nodes: 10.250.0.0/16
    type: calico
  kubernetes:
    version: 1.24.3
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
  addons:
    kubernetesDashboard:
      enabled: true
    nginxIngress:
      enabled: true
```

## CSI volume provisioners

Every AWS shoot cluster will be deployed with the AWS EBS CSI driver.
It is compatible with the legacy in-tree volume provisioner that was deprecated by the Kubernetes community and will be removed in future versions of Kubernetes.
End-users might want to update their custom `StorageClass`es to the new `ebs.csi.aws.com` provisioner.

### Node-specific Volume Limits

The Kubernetes scheduler allows configurable limit for the number of volumes that can be attached to a node. See https://k8s.io/docs/concepts/storage/storage-limits/#custom-limits.

CSI drivers usually have a different procedure for configuring this custom limit. By default, the EBS CSI driver parses the machine type name and then decides the volume limit. However, this is only a rough approximation and not good enough in most cases. Specifying the volume attach limit via command line flag (`--volume-attach-limit`) is currently the alternative until a more sophisticated solution presents itself (dynamically discovering the maximum number of attachable volume per EC2 machine type, see also https://github.com/kubernetes-sigs/aws-ebs-csi-driver/issues/347). The AWS extension allows the `--volume-attach-limit` flag of the EBS CSI driver to be configurable via `aws.provider.extensions.gardener.cloud/volume-attach-limit` annotation on the `Shoot` resource. If the annotation is added to an existing `Shoot`, then reconciliation needs to be triggered manually (see [Immediate reconciliation](https://github.com/gardener/gardener/blob/master/docs/usage/shoot_operations.md#immediate-reconciliation)), as in general adding annotation to resource is not a change that leads to `.metadata.generation` increase in general.

## Kubernetes Versions per Worker Pool

This extension supports `gardener/gardener`'s `WorkerPoolKubernetesVersion` feature gate, i.e., having [worker pools with overridden Kubernetes versions](https://github.com/gardener/gardener/blob/8a9c88866ec5fce59b5acf57d4227eeeb73669d7/example/90-shoot.yaml#L69-L70) since `gardener-extension-provider-aws@v1.34`.

## Shoot CA Certificate and `ServiceAccount` Signing Key Rotation

This extension supports `gardener/gardener`'s `ShootCARotation` and `ShootSARotation` feature gates since `gardener-extension-provider-aws@v1.36`.
