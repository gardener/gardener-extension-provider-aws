# Support for IPv6

## Overview

Gardener supports different levels of IPv6 support in shoot clusters.
This document describes the differences between them and what to consider when using them.

In [IPv6 Ingress for IPv4 Shoot Clusters](#ipv6-ingress-for-ipv4-shoot-clusters), the focus is on how an existing IPv4-only shoot cluster can provide dual-stack services to clients.
Section [IPv6-only Shoot Clusters](#ipv6-only-shoot-clusters) describes how to create a shoot cluster that only supports IPv6.
Finally, [Dual-Stack Shoot Clusters](#dual-stack-shoot-clusters) explains how to create a shoot cluster that supports both IPv4 and IPv6.

## IPv6 Ingress for IPv4 Shoot Clusters

Per default, Gardener shoot clusters use only IPv4.
Therefore, they also expose their services only via load balancers with IPv4 addresses.
To allow external clients to also use IPv6 to access services in an IPv4 shoot cluster, the cluster needs to be configured to support dual-stack ingress.

It is possible to configure a shoot cluster to support dual-stack ingress, see [Using IPv4/IPv6 (dual-stack) Ingress in an IPv4 single-stack cluster](dual-stack-ingress.md) for more information.

The main benefit of this approach is that the existing cluster stays almost as is without mayor changes, keeping the operational simplicity.
It works very well for services that only require incoming communication, e.g. pure web services.

The main drawback is that certain scenarios, especially related to IPv6 callbacks, are not possible.
This means that services, which actively call to their clients via web hooks, will not be able to do so over IPv6.
Hence, those services will not be able to allow full-usage via IPv6.

## IPv6-only Shoot Clusters

### Motivation

IPv6-only shoot clusters are the best option to verify that services are fully IPv6-compatible.
While [Dual-Stack Shoot Clusters](#dual-stack-shoot-clusters) may fall back on using IPv4 transparently, IPv6-only shoot clusters enforce the usage of IPv6 inside the cluster.
Therefore, it is recommended to check with IPv6-only shoot clusters if a workload is fully IPv6-compatible.

In addition to being a good testbed for IPv6 compatibility, IPv6-only shoot clusters may also be a desirable eventual target in the IPv6 migration as they allow to support both IPv4 and IPv6 clients while having a single-stack with the cluster.

### Creating an IPv6-only Shoot Cluster

To create an IPv6-only shoot cluster, the following needs to be specified in the `Shoot` resource (see also [here](usage.md#example-shoot-manifest-ipv6)):

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  ...
spec:
  ...
  networking:
    type: ...
    ipFamilies:
      - IPv6
  ...
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          cidr: 192.168.0.0/16
        zones:
          - name: ...
            public: 192.168.32.0/20
            internal: 192.168.48.0/20
```

Please note that `nodes`, `pods` and `services` should not be specified in `.spec.networking` resource.

In contrast to that, it is still required to specify IPv4 ranges for the VPC and the public/internal subnets.
This is mainly due to the fact that public/internal load balancers still require IPv4 addresses as there are no pure IPv6-only load balancers as of now.
The ranges can be sized according to the expected amount of load balancers per zone/type.

### Load Balancer Configuration

The AWS Load Balancer Controller is automatically deployed when using an IPv6-only shoot cluster.
When creating a load balancer, the corresponding annotations need to be configured, see [AWS Load Balancer Documentation - Network Load Balancer](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.4/guide/service/nlb/) for details.

The AWS Load Balancer Controller allows dual-stack ingress so that an IPv6-only shoot cluster can serve IPv4 and IPv6 clients.
You can find an example [here](dual-stack-ingress.md#creating-an-ipv4ipv6-dual-stack-ingress).

### Connectivity to IPv4-only Services

The IPv6-only shoot cluster can connect to IPv4-only services via DNS64/NAT64.
The cluster is configured to use the DNS64/NAT64 service of the underlying cloud provider.
This allows the cluster to resolve IPv4-only DNS names and to connect to IPv4-only services.

Please note that traffic going through NAT64 incurs the same cost as ordinary NAT traffic in an IPv4-only cluster.
Therefore, it might be beneficial to prefer IPv6 for services, which provide IPv4 and IPv6.

## Dual-Stack Shoot Clusters

### Motivation

Dual-stack shoot clusters support IPv4 and IPv6 out-of-the-box.
They might also be the obvious intermediate step on the way towards IPv6 for any existing (IPv4-only) clusters.

### Creating a Dual-Stack Shoot Cluster

To create a dual-stack shoot cluster, the following needs to be specified in the `Shoot` resource:

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  ...
spec:
  ...
  networking:
    type: ...
    pods: 192.168.128.0/17
    nodes: 192.168.0.0/18
    services: 192.168.64.0/18
    ipFamilies:
      - IPv4
      - IPv6
  ...
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          cidr: 192.168.0.0/18
        zones:
          - name: ...
            workers: 192.168.0.0/19
            public: 192.168.32.0/20
            internal: 192.168.48.0/20
```

Please note that the only change compared to an IPv4-only shoot cluster is the addition of `IPv6` to the `.spec.networking.ipFamilies` field.
The order of the IP families defines the preference of the IP family.
In this case, IPv4 is preferred over IPv6, e.g. services specifying no IP family will get only an IPv4 address.

### Migration of IPv4-only Shoot Clusters to Dual-Stack

Eventually, migration should be as easy as changing the `.spec.networking.ipFamilies` field in the `Shoot` resource from `IPv4` to `IPv4, IPv6`.
However, as of now, this is not supported.

It is worth recognizing that the migration from an IPv4-only shoot cluster to a dual-stack shoot cluster involves rolling of the nodes/workload as well.
Nodes will not get a new IPv6 address assigned automatically.
The same is true for pods as well.
Once the migration is supported, the detailed caveats will be documented here.

### Load Balancer Configuration

The AWS Load Balancer Controller is automatically deployed when using a dual-stack shoot cluster.
When creating a load balancer, the corresponding annotations need to be configured, see [AWS Load Balancer Documentation - Network Load Balancer](https://kubernetes-sigs.github.io/aws-load-balancer-controller/v2.4/guide/service/nlb/) for details.

The AWS Load Balancer Controller allows dual-stack ingress so that a dual-stack shoot cluster can serve IPv4 and IPv6 clients.
You can find an example [here](dual-stack-ingress.md#creating-an-ipv4ipv6-dual-stack-ingress).

Please note that load balancer services without any special annotations will default to IPv4-only regardless how `.spec.ipFamilies` is set.
