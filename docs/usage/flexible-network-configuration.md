# Flexible Network Configuration Proposal

## Summary

This proposal introduces enhanced flexibility in AWS infrastructure configuration, allowing users to:

1. **Use existing AWS subnets for worker nodes** - Integrate with pre-provisioned network infrastructure
2. **Make internal/public subnets optional** - Support private clusters without NAT gateways
3. **Manage their own routing** - Use Transit Gateway, VPC peering, centralized NAT, or VPC endpoints

## Motivation

Currently, Gardener requires users to specify CIDR ranges for three subnet types per availability zone (workers, internal, public), and automatically creates NAT gateways. This prevents:

- **Reusing existing subnets** from centrally-managed network infrastructure
- **Private cluster architectures** using VPC endpoints or centralized egress
- **Custom network topologies** like Transit Gateway or shared NAT architectures
- **Cost optimization** through shared NAT gateways or eliminating NAT entirely

Organizations with existing network infrastructure, strict CIDR policies, or specific connectivity requirements cannot use Gardener effectively today.

## Proposed API Changes

### Zone Structure Enhancement

Add one new optional field to the `Zone` type:

```go
type Zone struct {
    // Name is the name for this zone.
    Name string
    
    // Internal is the private subnet range to create (used for internal load balancers).
    // Optional when using WorkersSubnetID.
    // +optional
    Internal string
    
    // Public is the public subnet range to create (used for bastion and load balancers).
    // Optional for private clusters.
    // +optional
    Public string
    
    // Workers is the workers subnet range to create (used for the VMs).
    // Ignored if WorkersSubnetID is provided.
    // +optional
    Workers string
    
    // WorkersSubnetID is the ID of an existing subnet for worker nodes.
    // When provided, users are responsible for:
    // - Route tables and internet/AWS API connectivity
    // - NAT Gateway, Transit Gateway, VPC endpoints, or other solutions
    // - Load balancer subnets with proper tags if needed
    // +optional
    WorkersSubnetID *string
    
    // ElasticIPAllocationID for NAT gateway (only when Workers CIDR is provided)
    // +optional
    ElasticIPAllocationID *string
}
```

## Configuration Patterns

### Pattern 1: Traditional Gardener (Unchanged)

Gardener creates and manages all infrastructure.

```
┌─────────────────────────────────────────────────────────────┐
│                           VPC                               │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Public     │  │   Internal   │  │     Workers      │  │
│  │   Subnet     │  │   Subnet     │  │     Subnet       │  │
│  │              │  │              │  │                  │  │
│  │  ┌────────┐  │  │  Internal    │  │   ┌──────────┐  │  │
│  │  │  NAT   │◄─┼──┼──────────────┼──┼───│  Nodes   │  │  │
│  │  │Gateway │  │  │   LoadBalancer  │   │          │  │  │
│  │  └───┬────┘  │  │              │  │   └──────────┘  │  │
│  │      │       │  │              │  │                  │  │
│  └──────┼───────┘  └──────────────┘  └──────────────────┘  │
│         │                                                   │
│         ▼                                                   │
│  [Internet Gateway]                                         │
└─────────────────────────────────────────────────────────────┘
```

**Configuration:**
```yaml
networks:
  vpc:
    cidr: 10.250.0.0/16
  zones:
    - name: eu-west-1a
      workers: 10.250.0.0/19
      internal: 10.250.32.0/20
      public: 10.250.48.0/20
```

### Pattern 2: Bring Your Own Subnets

User provides existing worker subnet, manages all routing.

```
┌─────────────────────────────────────────────────────────────┐
│                    VPC (Pre-existing)                       │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Public     │  │   Internal   │  │     Workers      │  │
│  │   Subnet     │  │   Subnet     │  │     Subnet       │  │
│  │ (existing)   │  │ (existing)   │  │   (existing)     │  │
│  │              │  │              │  │                  │  │
│  │  ┌────────┐  │  │    Tags:     │  │   ┌──────────┐  │  │
│  │  │  NAT   │◄─┼──┼──────────────┼──┼───│  Nodes   │  │  │
│  │  │Gateway │  │  │kubernetes.io/│  │   │          │  │  │
│  │  │(user   │  │  │role/internal │  │   │   User   │  │  │
│  │  │managed)│  │  │-elb=1        │  │   │ managed  │  │  │
│  │  └────────┘  │  │              │  │   │ routes   │  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
│                                                             │
│  User manages route tables, NAT, and connectivity          │
└─────────────────────────────────────────────────────────────┘
```

**Configuration:**
```yaml
networks:
  vpc:
    id: vpc-abc123
  zones:
    - name: eu-west-1a
      workersSubnetID: subnet-workers-existing
```

**User responsibilities (CRITICAL):**
- ✅ Route table on worker subnet configured for NAT/Transit Gateway/VPC endpoints
- ✅ Internal LB subnet exists with **REQUIRED** tags:
  - `kubernetes.io/role/internal-elb=1`
  - `kubernetes.io/cluster/<cluster-name>=shared` (or `owned`)
- ✅ Public LB subnet exists with **REQUIRED** tags (if public LBs needed):
  - `kubernetes.io/role/elb=1`
  - `kubernetes.io/cluster/<cluster-name>=shared` (or `owned`)
- ✅ Minimum **2 availability zones** with tagged LB subnets for ALBs
- ✅ Each LB subnet has **minimum 8 available IP addresses**
- ✅ LB subnets have correct reachability (public subnets route to IGW for public LBs)


### Pattern 3: Centralized NAT Architecture

Multiple clusters share centralized NAT/egress infrastructure.

```
┌─────────────────────────────────────────────────────────────┐
│                      Shared VPC                             │
│                                                             │
│  ┌──────────────────────────────────────────────────────┐   │
│  │           Centralized Egress Subnet                  │   │
│  │                                                      │   │
│  │     ┌────────────────┐          ┌────────────┐      │   │
│  │     │  NAT Gateway   │          │  Transit   │      │   │
│  │     │   (shared)     │          │  Gateway   │      │   │
│  │     └────────────────┘          └────────────┘      │   │
│  └─────────────▲──────────────────────────▲────────────┘   │
│                │                           │                │
│  ┌─────────────┴──────────┐   ┌───────────┴─────────────┐  │
│  │  Cluster 1             │   │  Cluster 2              │  │
│  │  ┌─────────────────┐   │   │  ┌─────────────────┐   │  │
│  │  │ Workers Subnet  │   │   │  │ Workers Subnet  │   │  │
│  │  │  (existing)     │   │   │  │  (existing)     │   │  │
│  │  │                 │   │   │  │                 │   │  │
│  │  │  User-managed   │   │   │  │  User-managed   │   │  │
│  │  │  route tables   │   │   │  │  route tables   │   │  │
│  │  └─────────────────┘   │   │  └─────────────────┘   │  │
│  └────────────────────────┘   └─────────────────────────┘  │
│                                                             │
│  Both clusters route through shared egress                 │
└─────────────────────────────────────────────────────────────┘
```

**Configuration (both clusters):**
```yaml
networks:
  vpc:
    id: vpc-shared
  zones:
    - name: eu-west-1a
      workersSubnetID: subnet-cluster1-workers  # or cluster2
```

Users configure route tables to point to shared NAT or Transit Gateway.

### Pattern 5: Hybrid - Gardener Workers, Existing LB Subnets

Gardener creates worker subnets, users provide LB subnets via tags.

```
┌─────────────────────────────────────────────────────────────┐
│                           VPC                               │
│                                                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Public     │  │   Internal   │  │     Workers      │  │
│  │   Subnet     │  │   Subnet     │  │     Subnet       │  │
│  │ (existing)   │  │ (existing)   │  │  (Gardener       │  │
│  │              │  │              │  │   creates)       │  │
│  │    Tags:     │  │    Tags:     │  │                  │  │
│  │ kubernetes.io│  │ kubernetes.io│  │   ┌──────────┐  │  │
│  │ /role/elb=1  │  │ /role/       │  │   │  Nodes   │  │  │
│  │              │  │ internal     │  │   │          │  │  │
│  │  ┌────────┐  │  │ -elb=1       │  │   └──────────┘  │  │
│  │  │  NAT   │◄─┼──┼──────────────┼──┼─── (Gardener    │  │
│  │  │Gateway │  │  │              │  │    creates NAT)  │  │
│  │  └────────┘  │  │              │  │                  │  │
│  └──────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Configuration:**
```yaml
networks:
  vpc:
    id: vpc-abc123
  zones:
    - name: eu-west-1a
      workers: 10.250.0.0/19
      # Internal/public subnets discovered by tags
```

Load balancers find subnets via standard Kubernetes tags.

## Validation Rules

### Required Configuration

At least one of the following must be provided per zone:
- `workers` (CIDR) - Gardener creates worker subnet
- `workersSubnetID` - User provides existing worker subnet

### WorkersSubnetID Validation

When `workersSubnetID` is provided, the extension validates:
- Subnet exists in AWS
- Subnet is in the specified availability zone
- Subnet is in the configured VPC

The extension does NOT validate:
- Route table configuration
- Internet/AWS API connectivity
- NAT gateway presence

These are user responsibilities when bringing existing subnets.

### Subnet Priority

If both `workersSubnetID` and `workers` are provided:
- `workersSubnetID` takes precedence
- `workers` CIDR is ignored

### Optional Subnets

- `internal` and `public` CIDRs are always optional
- Omitting them is valid for private clusters or BYO subnet scenarios

## Load Balancer Subnet Discovery

The Cloud-controller-mamanger and AWS Load Balancer Controller (used by Gardener for load balancer provisioning) discover subnets automatically using a well-defined process. Understanding this is critical when using existing subnets.

A detailed explanation of the discovery process, tag requirements, and selection criteria is provided below can be found in  the [upstream documentation](https://kubernetes-sigs.github.io/aws-load-balancer-controller/latest/deploy/subnet_discovery/#subnet-reachability)

### Subnet Role Tags

Subnets are discovered via standard Kubernetes tags. These tags are **REQUIRED** for load balancer provisioning:

**Internal Load Balancers:**
```
kubernetes.io/role/internal-elb=1 (or empty string "")
kubernetes.io/cluster/<cluster-name>=shared|owned
```

**Public Load Balancers:**
```
kubernetes.io/role/elb=1 (or empty string "")
kubernetes.io/cluster/<cluster-name>=shared|owned
```

**Note**: The role tag value can be either `1` or an empty string `""`. Both are valid.

### Subnet Reachability

The controller automatically classifies subnets as public or private based on route table configuration:

- **Public subnet**: Route table contains a route to an Internet Gateway
- **Private subnet**: No direct route to Internet Gateway

This automatic classification is important when using existing subnets via `workersSubnetID`, as the controller will validate subnet reachability matches the load balancer type.

**Note**: Reachability-based discovery can be disabled via the `SubnetDiscoveryByReachability` feature flag.

### Subnet Filtering

The controller filters out unsuitable subnets:

1. **Cluster Tag Check**: 
   - Subnets with ineligible cluster tags are filtered out
   - If cluster tag exists but doesn't match current cluster, subnet is excluded
   - For LBC < 2.1.1: Subnets without cluster tag matching cluster name are filtered out
   - Can be disabled via `SubnetsClusterTagCheck` feature flag

2. **IP Address Availability**: 
   - Subnets with fewer than 8 available IP addresses are filtered out

### Selection Priority

When multiple subnets exist in the same availability zone, the following priority order applies:

1. Subnets with cluster tag for the current cluster (`kubernetes.io/cluster/<cluster-name>`) are prioritized
2. Subnets with lower lexicographical order of subnet ID are prioritized

### Minimum Subnet Requirements

- **Application Load Balancers (ALB)**: Require at least **2 subnets across different availability zones** by default
  - Can be reduced to 1 subnet with `ALBSingleSubnet` feature gate (for allowlisted customers only)
- **Network Load Balancers (NLB)**: Can use a single subnet

### Behavior by Configuration

| Configuration | Internal LB Subnets                        | Public LB Subnets                                      |
|---------------|--------------------------------------------|--------------------------------------------------------|
| Gardener creates all | Created with proper tags automatically     | Created with proper tags automatically                 |
| `workersSubnetID` only | **User MUST provide with required tags**   | **User MUST provide with required tags**               |
| `internal` CIDR provided | Gardener creates with tags                 | User must provide with tags (if needed)                |
| No `internal` or `public` | **User SHOULD provide with required tags** | **User SHOULD provide with required tags** (if needed) |

### Critical Requirements for BYO Subnets

When using `workersSubnetID`, you **MUST** ensure:

- ✅ Separate subnets exist for load balancers (worker subnets cannot be used for LBs)
- ✅ Internal LB subnet has tag: `kubernetes.io/role/internal-elb=1` (or `""`)
- ✅ Public LB subnet has tag: `kubernetes.io/role/elb=1` (or `""`) - if public LBs needed
- ✅ All LB subnets have cluster tag: `kubernetes.io/cluster/<cluster-name>=shared` or `owned`
- ✅ Each subnet has **at least 8 available IP addresses**
- ✅ For ALBs: **At least 2 subnets across different availability zones**
- ✅ Subnet reachability matches load balancer type (public subnets for public LBs, private for internal)

**Failure to meet these requirements will result in load balancer provisioning failures.**

## Examples

### Example 1: Complete BYO Infrastructure

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: InfrastructureConfig
metadata:
  name: my-cluster
networks:
  vpc:
    id: vpc-0a1b2c3d
  zones:
    - name: eu-west-1a
      workersSubnetID: subnet-workers-1a
    - name: eu-west-1b
      workersSubnetID: subnet-workers-1b
    - name: eu-west-1c
      workersSubnetID: subnet-workers-1c
```

**User must provide (in addition to worker subnets):**

1. **Worker subnet routing:**
   - Route tables configured for internet/AWS API access
   - NAT Gateway, Transit Gateway, VPC endpoints, or other connectivity

2. **Internal Load Balancer subnets** (minimum 2 AZs for ALBs):
   - Subnet in eu-west-1a with tags:
     - `kubernetes.io/role/internal-elb=1`
     - `kubernetes.io/cluster/my-cluster=shared`
   - Subnet in eu-west-1b with tags:
     - `kubernetes.io/role/internal-elb=1`
     - `kubernetes.io/cluster/my-cluster=shared`
   - Each with minimum 8 available IPs
   - Private subnets (no IGW route)

3. **Public Load Balancer subnets** (if public LBs needed, minimum 2 AZs):
   - Subnet in eu-west-1a with tags:
     - `kubernetes.io/role/elb=1`
     - `kubernetes.io/cluster/my-cluster=shared`
   - Subnet in eu-west-1b with tags:
     - `kubernetes.io/role/elb=1`
     - `kubernetes.io/cluster/my-cluster=shared`
   - Each with minimum 8 available IPs
   - Public subnets (route to IGW)

### Example 2: Private Cluster with VPC Endpoints

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: InfrastructureConfig
metadata:
  name: private-cluster
networks:
  vpc:
    id: vpc-0a1b2c3d
    gatewayEndpoints:
      - s3
      - dynamodb
  zones:
    - name: eu-west-1a
      workers: 10.250.0.0/19
      internal: 10.250.32.0/20
      # No public subnet - private cluster
```

**Result:**
- Gardener creates worker and internal subnets
- No NAT gateway created
- Nodes access AWS services via VPC endpoints
- Only internal load balancers supported

### Example 3: Existing Workers, Gardener Creates LB Subnets

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: InfrastructureConfig
metadata:
  name: hybrid-cluster
networks:
  vpc:
    id: vpc-0a1b2c3d
  zones:
    - name: eu-west-1a
      workersSubnetID: subnet-existing-workers
      internal: 10.250.32.0/20
      public: 10.250.48.0/20
```

**Result:**
- Uses existing worker subnet (user manages routing)
- Gardener creates internal and public subnets for load balancers
- Gardener creates NAT gateway in public subnet (but worker subnet won't use it automatically)

### Example 4: Traditional with Custom Elastic IP

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: InfrastructureConfig
metadata:
  name: traditional-cluster
networks:
  vpc:
    cidr: 10.250.0.0/16
  zones:
    - name: eu-west-1a
      workers: 10.250.0.0/19
      internal: 10.250.32.0/20
      public: 10.250.48.0/20
      elasticIPAllocationID: eipalloc-0123456789abcdef0
```

**Result:**
- Gardener creates all subnets
- NAT gateway uses specified Elastic IP instead of creating new one
- Standard Gardener behavior otherwise

### Example 5: Multi-Zone with Mixed Approach

```yaml
apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
kind: InfrastructureConfig
metadata:
  name: mixed-cluster
networks:
  vpc:
    id: vpc-0a1b2c3d
  zones:
    - name: eu-west-1a
      workers: 10.250.0.0/19
      internal: 10.250.32.0/20
      public: 10.250.48.0/20
    - name: eu-west-1b
      workersSubnetID: subnet-existing-1b
    - name: eu-west-1c
      workers: 10.250.64.0/19
      # No internal/public - discovered by tags or not needed
```

**Result:**
- Zone A: Traditional Gardener-managed
- Zone B: BYO worker subnet (user manages routing)
- Zone C: Gardener creates worker subnet, no NAT gateway

## Implementation Approach

### When workersSubnetID is Provided

1. **Skip worker subnet creation** - Use provided subnet ID
2. **Skip route table creation for workers** - User manages routes
3. **Skip NAT gateway creation** - User provides connectivity. Potential preflight check to warn if no NAT gateway or Transit Gateway route detected, but not blocking.
4. **Discover load balancer subnets** - Not very important for provider-aws but controllers relying on subnet discovery will find subnets via tags or reachability. That includes CCM, IPAM and Custrom Route controllers.
5. **Validate subnet existence** - Check subnet exists in correct VPC/AZ
6. IPv6 support: If workersSubnetID is provided, we will check if the subnet has an IPv6 CIDR block and if so, we will use it for provisioning IPv6 worker nodes. This allows users to bring their own IPv6 subnets as well. Discovery of the IPv6 CIDR block will be done via AWS API for the subnet/VPC provided.

### When workers CIDR is Provided (Current Behavior)

1. **Create worker subnet** - As today
2. **Create route table** - Point to NAT gateway (if public subnet exists)
3. **Create NAT gateway** - If public subnet provided
4. **Create internal/public subnets** - If CIDRs provided

### Optional Internal/Public Subnets

When `internal` or `public` CIDRs are omitted:
- Skip subnet creation
- Load balancers discover subnets via tags
- No NAT gateway created if no public subnet


## Open Discussion

### Q: What about IPv6 support?

### Q: How to verify connectivity with control-plane?
**A:** We will validate subnet existence and basic configuration (VPC, AZ) but not connectivity. AWS API errors will surface connectivity issues when provisioning nodes or load balancers. We could consider a non-blocking preflight check to warn if no NAT gateway or Transit Gateway route detected, but this is not critical.

### Q: How to communicate to users the correct naming and tagging requirements for load balancer subnets?

**A:** Clear documentation is critical. We will provide detailed examples and a checklist of required tags and subnet characteristics. We could also consider adding validation for LB subnet tags if `workersSubnetID` is used, but this may be complex and we want to avoid blocking users who are responsible for their own routing.

### Q: Should we validate route table configuration?

**A:** If users provide existing subnets, they own the routing. We validate existence only. AWS API errors will surface connectivity issues. We could surface common issues as warnings in the infrastructure like for example when we do not make any discovery for public subnets.

### Q: What if user doesn't provide load balancer subnets?

**A:** Load balancer provisioning will fail with clear error from AWS cloud-controller-manager about missing subnets with proper tags. This is expected behavior.

### Q: Can users mix BYO and Gardener-managed subnets across zones?

**A:** Potentially yes, but we recommend against it for simplicity. Mixed configurations can lead to confusion about routing and load balancer provisioning. If supported, we will clearly document the behavior and limitations. Probably we will validate for a consistent approach across zones (either all BYO or all Gardener-managed) to avoid complexity.

### Q: Is migration possible for existing clusters?

**A:** Not planned for the initial implementation.

## Success Criteria

- ✅ Users can deploy clusters with existing worker subnets
- ✅ Users can deploy clusters without NAT gateways. Cluster connectivity to internet is still mandatory, but users can provide it via VPC endpoints, Transit Gateway, or centralized NAT
- ✅ Users can use centralized NAT/Transit Gateway architectures
- ✅ Zero breaking changes to existing clusters
- ✅ Clear documentation on tag requirements

## Conclusion

This proposal introduces minimal API changes (one new field) that unlock significant flexibility for enterprise users with existing network infrastructure. By making public/internal subnets optional and supporting BYO worker subnets, Gardener can integrate with various network architectures while maintaining full backward compatibility.

The design principle is simple: **If users provide existing subnets, they own the routing and connectivity. Gardener provisions workloads but doesn't modify key network infrastructure.**
