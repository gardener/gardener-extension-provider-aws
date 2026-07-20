# AWS Infrastructure Setup for Bring-Your-Own VPC

There are multiple ways to create the required AWS infrastructure for a bring-your-own VPC setup.
The examples below show one possible approach and are meant as a basic reference.
Your actual setup may differ depending on your networking requirements and organizational policies.

## Minimal Example (VPC only)

If you only want to bring your own VPC and let Gardener create all other infrastructure (subnets, route tables, NAT gateway, security groups, etc.), the minimum required setup is:

1. Create a VPC with an IPv4 CIDR block (and an IPv6 CIDR block for IPv6-only or dual-stack clusters).
2. Go to **VPC → Edit DNS settings**: enable **DNS resolution** and **DNS hostnames**.
3. Create an Internet Gateway and attach it to your VPC.

> [!NOTE]
> Gardener will not create an Internet Gateway for an existing VPC, so it must be created manually even in the minimal case.

Then reference the VPC by ID in your shoot's `infrastructureConfig`:

```yaml
networks:
  vpc:
    id: vpc-xxxxxxxx
  zones:
    - name: ...
      workers: ...
      public: ...
      internal: ...
```

## Full Custom Infrastructure Examples

The following examples cover the case where you want to bring your own subnets, route tables, security groups, and other networking resources in addition to the VPC. Use these as a starting point if your setup requires full control over the AWS networking infrastructure.

### IPv4 Cluster

1. Create a new VPC with an IPv4 CIDR block.
2. Go to **VPC → Edit DNS settings**: enable **DNS resolution** and **DNS hostnames**.
3. Create a worker subnet in this VPC and choose the correct availability zone. Optionally create public and internal subnets.
4. Optionally create a security group with:
   - **Inbound**: All traffic from itself (select "Custom" and paste the security group ID — you may need to save first and edit again to self-reference).
   - **Outbound**: All traffic to `0.0.0.0/0`.
5. Create an Internet Gateway and attach it to your VPC.
6. Create a NAT Gateway in a public subnet.
7. Create an internal route table for the workers (and optional internal subnet) with:
   - Route: `0.0.0.0/0` → your NAT Gateway.
   - Add subnet associations for your worker subnet (and optionally internal subnets).
8. Optionally create a public route table (for public load balancer subnets) with:
   - Route: `0.0.0.0/0` → your Internet Gateway.
   - Add subnet associations for your public subnets.

Reference your existing resources in the shoot's `infrastructureConfig`:

```yaml
networks:
  vpc:
    id: vpc-xxxxxxxx
  nodesSecurityGroupID: sg-xxxxxxxxxxxxxxxx   # optional
  zones:
    - name: eu-central-1a
      workersSubnetID: subnet-xxxxxxxxxxxxxxxx
      publicSubnetID: subnet-yyyyyyyyyyyyyyyy  # optional
      internalSubnetID: subnet-zzzzzzzzzzzzzz  # optional
```

### IPv6-only Cluster

1. Create a VPC with an IPv6 CIDR block and enable **DNS resolution** and **DNS hostnames**.
2. Create an Egress-Only Internet Gateway for the VPC.
3. Create worker subnets with IPv6 CIDR blocks and **DNS64** enabled.
   Optionally create subnets with IPv6 CIDR blocks for internal and public load balancers. These subnets still need some IPv4 addresses since AWS Load Balancers require IPv4.
4. Create a private route table for workers (and optionally for internal load balancers) with:
   - Route: `::/0` → the Egress-Only Internet Gateway.
   - Route: `64:ff9b::/96` → the NAT Gateway (for NAT64).
5. Optionally create an Internet Gateway and attach it to the VPC (required if you want public load balancers).
6. Optionally create a public route table for public load balancers with:
   - Route: `::/0` → the Internet Gateway.
   - Route: `0.0.0.0/0` → the Internet Gateway.
7. Optionally create a security group with:
   - **Inbound**: All traffic from itself (select "Custom" and paste the security group ID — you may need to save first and edit again to self-reference).
   - **Outbound**: All traffic to `::/0`.
8. Create a NAT Gateway and attach it to your VPC.

Reference your existing resources in the shoot's `infrastructureConfig` and set `ipFamilies` to `IPv6`:

```yaml
networking:
  ipFamilies:
    - IPv6
provider:
  type: aws
  infrastructureConfig:
    apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
    kind: InfrastructureConfig
    networks:
      vpc:
        id: vpc-xxxxxxxx
      nodesSecurityGroupID: sg-xxxxxxxxxxxxxxxx   # optional
      zones:
        - name: eu-central-1a
          workersSubnetID: subnet-xxxxxxxxxxxxxxxx
          publicSubnetID: subnet-yyyyyyyyyyyyyyyy  # optional
          internalSubnetID: subnet-zzzzzzzzzzzzzz  # optional
```

### Dual-Stack Cluster

Same as [IPv6-only](#ipv6-only-cluster) with the following differences:

1. Worker subnets should not be IPv6-native — nodes receive both IPv4 and IPv6 addresses.
2. No DNS64 is needed for the worker subnet since nodes have IPv4 and can reach IPv4 endpoints directly.
3. The worker route table needs an additional route: `0.0.0.0/0` → NAT Gateway (for IPv4 egress).
4. If a security group is created, it needs an additional outbound rule: All traffic to `0.0.0.0/0`.

The shoot config is the same as the IPv6-only example above, but with `ipFamilies` set to both `IPv4` and `IPv6`:

```yaml
networking:
  ipFamilies:
    - IPv4
    - IPv6
provider:
  type: aws
  infrastructureConfig:
    apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
    kind: InfrastructureConfig
    networks:
      vpc:
        id: vpc-xxxxxxxx
      nodesSecurityGroupID: sg-xxxxxxxxxxxxxxxx   # optional
      zones:
        - name: eu-central-1a
          workersSubnetID: subnet-xxxxxxxxxxxxxxxx
          publicSubnetID: subnet-yyyyyyyyyyyyyyyy  # optional
          internalSubnetID: subnet-zzzzzzzzzzzzzz  # optional
```
