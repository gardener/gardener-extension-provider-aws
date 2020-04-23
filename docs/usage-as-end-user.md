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

Please look up https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys as well.

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
```

The `enableECRAccess` flag specifies whether the AWS IAM role policy attached to all worker nodes of the cluster shall contain permissions to access the Elastic Container Registry of the respective AWS account.
If the flag is not provided it is defaulted to `true`.

The `networks.vpc` section describes whether you want to create the shoot cluster in an already existing VPC or whether to create a new one:

* If `networks.vpc.id` is given then you have to specify the VPC ID of the existing VPC that was created by other means (manually, other tooling, ...).
Please make sure that the VPC has attached an internet gateway - the AWS controller won't create one automatically for existing VPCs.
* If `networks.vpc.cidr` is given then you have to specify the VPC CIDR of a new VPC that will be created during shoot creation.
You can freely choose a private CIDR range.
* Either `networks.vpc.id` or `networks.vpc.cidr` must be present, but not both at the same time.
* `networks.vpc.gatewayEndpoints` is optional. If specified then each item is used as service name in a corresponding Gateway VPC Endpoint.

The `networks.zones` section describes which subnets you want to create in availability zones.
For every zone, the AWS extension creates three subnets:

* The `internal` subnet is used for [internal AWS load balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-internal-load-balancers.html).
* The `public` subnet is used for [public AWS load balancers](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/elb-internet-facing-load-balancers.html).
* The `workers` subnet is used for all shoot worker nodes, i.e., VMs which later run your applications.

For every subnet, you have to specify a CIDR range contained in the VPC CIDR specified above, or the VPC CIDR of your already existing VPC.
You can freely choose these CIDR and it is your responsibility to properly design the network layout to suit your needs.

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
```

The `cloudControllerManager.featureGates` contains a map of explicitly enabled or disabled feature gates.
For production usage it's not recommend to use this field at all as you can enable alpha features or disable beta/stable features, potentially impacting the cluster stability.
If you don't want to configure anything for the `cloudControllerManager` simply omit the key in the YAML specification.

## `WorkerConfig`

The worker configuration contains AWS-specific value for configuring the worker pools.
It can be provided in `.spec.provider.workers[].providerConfig` and is evaluated by the AWS worker controller when it reconciles the shoot machines.

An example `WorkerConfig` for the AWS extension looks as follows:

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: WorkerConfig
volume:
  iops: 10000
```

The `.volume.iops` is the number of I/O operations per second (IOPS) that the volume supports.
For `io1` volume type, this represents the number of IOPS that are provisioned for the volume.
For `gp2` volume type, this represents the baseline performance of the volume and the rate at which the volume accumulates I/O credits for bursting. For more information about General Purpose SSD baseline performance, I/O credits, and bursting, see Amazon EBS Volume Types (http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSVolumeTypes.html) in the Amazon Elastic Compute Cloud User Guide.\
Constraint: Range is 100-20000 IOPS for `io1` volumes and 100-10000 IOPS for `gp2` volumes.

## Example `Shoot` manifest (one availability zone)

Please find below an example `Shoot` manifest for one availability zone:

```yaml
apiVersion: core.gardener.cloud/v1alpha1
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
    # The following provider config is only valid if the volume type is `io1`.
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
    version: 1.16.1
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
  addons:
    kubernetes-dashboard:
      enabled: true
    nginx-ingress:
      enabled: true
```

## Example `Shoot` manifest (three availability zones)

Please find below an example `Shoot` manifest for three availability zones:

```yaml
apiVersion: core.gardener.cloud/v1alpha1
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
    version: 1.16.1
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
  addons:
    kubernetes-dashboard:
      enabled: true
    nginx-ingress:
      enabled: true
```

## CSI volume provisioners

Every AWS shoot cluster that has at least Kubernetes v1.18 will be deployed with the AWS EBS CSI driver.
It is compatible with the legacy in-tree volume provisioner that was deprecated by the Kubernetes community and will be removed in future versions of Kubernetes.
End-users might want to update their custom `StorageClass`es to the new `ebs.csi.aws.com` provisioner.
Shoot clusters with Kubernetes v1.17 or less will use the in-tree `kubernetes.io/aws-ebs` volume provisioner in the kube-controller-manager and the kubelet.
