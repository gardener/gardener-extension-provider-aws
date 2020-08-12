# Using the AWS provider extension with Gardener as operator

The [`core.gardener.cloud/v1beta1.CloudProfile` resource](https://github.com/gardener/gardener/blob/master/example/30-cloudprofile.yaml) declares a `providerConfig` field that is meant to contain provider-specific configuration.
Similarly, the [`core.gardener.cloud/v1beta1.Seed` resource](https://github.com/gardener/gardener/blob/master/example/50-seed.yaml) is structured.
Additionally, it allows to configure settings for the backups of the main etcds' data of shoot clusters control planes running in this seed cluster.

This document explains what is necessary to configure for this provider extension.

## `CloudProfile` resource

In this section we are describing how the configuration for `CloudProfile`s looks like for AWS and provide an example `CloudProfile` manifest with minimal configuration that you can use to allow creating AWS shoot clusters.

### `CloudProfileConfig`

The cloud profile configuration contains information about the real machine image IDs in the AWS environment (AMIs).
You have to map every version that you specify in `.spec.machineImages[].versions` here such that the AWS extension knows the AMI for every version you want to offer.

An example `CloudProfileConfig` for the AWS extension looks as follows:

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: CloudProfileConfig
machineImages:
- name: coreos
  versions:
  - version: 2135.6.0
    regions:
    - name: eu-central-1
      ami: ami-034fd8c3f4026eb39
```

### Example `CloudProfile` manifest

Please find below an example `CloudProfile` manifest:

```yaml
apiVersion: core.gardener.cloud/v1beta1
kind: CloudProfile
metadata:
  name: aws
spec:
  type: aws
  kubernetes:
    versions:
    - version: 1.16.1
    - version: 1.16.0
      expirationDate: "2020-04-05T01:02:03Z"
  machineImages:
  - name: coreos
    versions:
    - version: 2135.6.0
  machineTypes:
  - name: m5.large
    cpu: "2"
    gpu: "0"
    memory: 8Gi
    usable: true
  volumeTypes:
  - name: gp2
    class: standard
    usable: true
  - name: io1
    class: premium
    usable: true
  regions:
  - name: eu-central-1
    zones:
    - name: eu-central-1a
    - name: eu-central-1b
    - name: eu-central-1c
  providerConfig:
    apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
    kind: CloudProfileConfig
    machineImages:
    - name: coreos
      versions:
      - version: 2135.6.0
        regions:
        - name: eu-central-1
          ami: ami-034fd8c3f4026eb39
```

## `Seed` resource

This provider extension does not support any provider configuration for the `Seed`'s `.spec.provider.providerConfig` field.
However, it supports to manage backup infrastructure, i.e., you can specify configuration for the `.spec.backup` field.

### Backup configuration

Please find below an example `Seed` manifest (partly) that configures backups.
As you can see, the location/region where the backups will be stored can be different to the region where the seed cluster is running.

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: backup-credentials
  namespace: garden
type: Opaque
data:
  accessKeyID: base64(access-key-id)
  secretAccessKey: base64(secret-access-key)
---
apiVersion: core.gardener.cloud/v1beta1
kind: Seed
metadata:
  name: my-seed
spec:
  provider:
    type: aws
    region: eu-west-1
  backup:
    provider: aws
    region: eu-central-1
    secretRef:
      name: backup-credentials
      namespace: garden
  ...
```

Please look up https://docs.aws.amazon.com/general/latest/gr/aws-sec-cred-types.html#access-keys-and-secret-access-keys as well.

#### Permissions for AWS IAM user

Please make sure that the provided credentials have the correct privileges. You can use the following AWS IAM policy document and attach it to the IAM user backed by the credentials you provided (please check the [official AWS documentation](http://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_manage.html) as well):

<details>
  <summary>Click to expand the AWS IAM policy document!</summary>

  ```json
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": "s3:*",
        "Resource": "*"
      }
    ]
  }
  ```
</details>
