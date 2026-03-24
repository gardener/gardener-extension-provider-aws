---
title: Flexible Network Configuration (BYOI)
creation-date: 2026-03-23
status: implementable
authors:
- "@kon-angelo"
reviewers:
- "@gardener-extension-provider-aws-maintainers"
- "@gardener-core-networking-maintainers"
---

# Flexible Network Configuration - Bring Your Own Infrastructure (BYOI)

## Table of Contents

- [Summary](#summary)
- [Motivation](#motivation)
  - [Goals](#goals)
  - [Non-Goals](#non-goals)
- [Proposal](#proposal)
  - [Resource Ownership Overview](#resource-ownership-overview)
  - [API Changes](#api-changes)
  - [Validation Rules](#validation-rules)
  - [Configuration Patterns](#configuration-patterns)
  - [Security Group Design](#security-group-design)
  - [Routing Requirements for BYO](#routing-requirements-for-byo)
  - [Load Balancer Subnet Discovery](#load-balancer-subnet-discovery)
  - [Implementation Approach](#implementation-approach)
- [Alternatives](#alternatives)
- [FAQ](#faq)

## Summary

This proposal enables users to deploy Gardener-managed Kubernetes clusters into pre-provisioned AWS infrastructure. Users can bring their own:

1. **VPC** (already supported via `vpc.id`)
2. **Worker subnets** - existing subnets for EC2 node placement
3. **Security group** - existing nodes security group with corporate-compliant rules
4. **Routing** - Transit Gateway, centralized NAT, VPC endpoints, or any custom topology
5. **Load balancer subnets** - discovered automatically via standard AWS tags (no explicit IDs needed)

The design principle is: **BYO resources are referenced, never created, modified, or deleted by Gardener.**

## Motivation

Enterprise organizations need to:

- **Reuse centrally-managed network infrastructure** (shared VPCs, hub-and-spoke topologies)
- **Comply with security policies** requiring pre-approved security groups and firewall rules
- **Deploy private clusters** using VPC endpoints or Transit Gateway (no Internet Gateway)
- **Optimize costs** through shared NAT gateways or centralized egress
- **Integrate with EKS-like architectures** where subnets, security groups, and routing are pre-provisioned by a platform team

Today, Gardener always creates subnets, security groups, NAT gateways, and route tables. This prevents integration with existing network infrastructure.

### Goals

- Allow users to reference pre-existing worker subnets instead of specifying CIDRs
- Allow users to provide their own nodes security group, replacing the Gardener-managed one entirely
- Support deployments without Internet Gateway or NAT gateways (Transit Gateway, VPC endpoints)
- Leverage standard AWS tag-based discovery for load balancer subnets (same as EKS)
- Zero breaking changes to existing clusters

### Non-Goals

- Allowing mixed BYO/Gardener-managed worker subnets across zones (all zones must be consistent)
- Allowing BYO worker subnets combined with Gardener-managed subnets in the same configuration (BYO mode means all subnets are user-managed)
- Managing or modifying any user-provided (BYO) resources
- Supporting IPv6-only BYO subnets in the initial release

## Proposal

### Resource Ownership Overview

```mermaid
flowchart TB
    subgraph UserManaged ["User-Managed (BYO Resources -- never modified/deleted)"]
        direction TB
        VPC["VPC\nvpc.id"]
        WS["Worker Subnets\nworkersSubnetID per zone"]
        SG["Nodes Security Group\nnodesSecurityGroupID"]
        LBS["LB Subnets\nDiscovered via AWS tags"]
        RT["Routing\nTGW / NAT / VPC Endpoints"]
    end

    subgraph GardenerManaged ["Gardener-Managed Resources"]
        direction TB
        IAM["IAM Role +\nInstance Profile"]
        SSH["SSH Key Pair"]
    end

    subgraph Runtime ["Runtime Components"]
        direction TB
        MCM["Machine Controller\nManager"]
        CCM["Cloud Controller\nManager"]
        LBC["LB Controller"]
    end

    VPC --- WS & LBS
    WS --- RT
    SG --> MCM
    WS --> MCM
    IAM --> MCM
    MCM -->|"RunInstances"| EC2["EC2 Worker Nodes"]
    LBS --> CCM & LBC
    CCM -->|"Creates"| NLB["NLB / CLB"]
    LBC -->|"Creates"| ALB["ALB"]
```

### API Changes

#### Zone Structure

One new optional field allows referencing an existing worker subnet:

```go
type Zone struct {
    Name string

    // Gardener-managed subnet CIDRs (mutually exclusive with WorkersSubnetID)
    Workers  *string  // +optional, mutually exclusive with WorkersSubnetID
    Internal *string  // +optional, forbidden when WorkersSubnetID is set
    Public   *string  // +optional, forbidden when WorkersSubnetID is set

    // BYO worker subnet
    WorkersSubnetID *string  // +optional, mutually exclusive with Workers

    // Only valid when Workers and Public CIDRs are set (Gardener-managed)
    ElasticIPAllocationID *string  // +optional
}
```

#### Networks Structure

One new optional field allows referencing an existing security group:

```go
type Networks struct {
    VPC   VPC
    Zones []Zone

    // NodesSecurityGroupID optionally specifies an existing security group for worker nodes.
    // When provided, Gardener will not create a nodes security group.
    // The security group must exist in the same VPC.
    // Requires VPC.ID to be set.
    // +optional
    NodesSecurityGroupID *string
}
```

> **Design note:** `NodesSecurityGroupID` is on `Networks` (not per-zone) because a single security group applies to all worker nodes across all availability zones. AWS security groups are VPC-scoped, not AZ-scoped. `WorkersSubnetID` is per-zone because subnets are AZ-specific.

### Validation Rules

| Field | Rule |
|-------|------|
| `workers` / `workersSubnetID` | **Exactly one** must be provided per zone (XOR) |
| **Zone consistency** | **All zones must use the same approach**: either all `workersSubnetID` or all `workers` CIDR. Mixing is forbidden. |
| `internal` / `public` | **Forbidden** when `workersSubnetID` is set. In BYO mode, all subnets are user-managed; LB subnets are tag-discovered. |
| `elasticIPAllocationID` | Only valid when both `workers` AND `public` CIDRs are set |
| `workersSubnetID` | Requires `VPC.ID` to be set. Must exist in correct VPC/AZ. Immutable. |
| `nodesSecurityGroupID` | Requires `VPC.ID` to be set. Must exist in correct VPC. Immutable. |
| `vpc.gatewayEndpoints` | **Forbidden** when `workersSubnetID` is set. Gateway endpoints require route table associations that Gardener cannot manage in BYO mode. |

Switching from CIDR-based to SubnetID-based workers (or vice versa) is **forbidden** on update. Adding a new zone to an existing cluster requires the new zone to use the same approach as existing zones (all BYO or all managed).

#### Why BYO Worker Subnets Require All Subnets to Be User-Managed

When `workersSubnetID` is used, specifying `internal` or `public` CIDRs is forbidden because:

- Gardener-managed internal/public subnets require an Internet Gateway and NAT gateway
- BYO worker subnets typically operate without an Internet Gateway (Transit Gateway, VPC endpoints)
- The conflicting infrastructure requirements would create an inconsistent network topology
- The BYO mode represents a clean contract: the user owns the network, Gardener owns the compute

### Configuration Patterns

#### Pattern 1: Traditional Gardener (Unchanged)

Gardener creates and manages all network infrastructure.

```mermaid
graph TB
    subgraph VPC["VPC 10.250.0.0/16<br/>(Gardener-created)"]
        subgraph AZ1["eu-west-1a"]
            WS["Workers Subnet<br/>10.250.0.0/19"]
            IS["Internal Subnet<br/>10.250.32.0/20"]
            PS["Public Subnet<br/>10.250.48.0/20"]
        end
        SG["Nodes Security Group<br/>(Gardener-managed)"]
        NAT["NAT Gateway"]
        IGW["Internet Gateway"]
        RT_W["Route Table: Workers<br/>0.0.0.0/0 -> NAT GW"]
        RT_P["Route Table: Public<br/>0.0.0.0/0 -> IGW"]
    end

    PS --- NAT
    NAT -.->|"outbound traffic"| WS
    IGW <-->|"inbound/outbound"| PS
    SG -.->|"attached to"| WS
    WS --- EC2["EC2 Worker Nodes"]
    IS --- ILB["Internal LBs"]
    PS --- PLB["Public LBs"]
    IGW <--> Internet(("Internet"))

    style WS fill:#4a90d9,color:white
    style IS fill:#4a90d9,color:white
    style PS fill:#4a90d9,color:white
    style SG fill:#4a90d9,color:white
    style NAT fill:#4a90d9,color:white
    style IGW fill:#4a90d9,color:white
```

> All resources in blue are Gardener-managed.

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

---

#### Pattern 2: Complete BYO Infrastructure

User provides VPC, worker subnets, and security group. Gardener does not create any network resources. LB subnets are discovered via tags.

```mermaid
graph TB
    subgraph VPC["VPC vpc-abc123<br/>(User-provided)"]
        subgraph AZ1["eu-west-1a"]
            WS1["Workers Subnet<br/>subnet-workers-1a"]
            ILB1["Internal LB Subnet<br/>tagged: internal-elb=1"]
            PLB1["Public LB Subnet<br/>tagged: elb=1"]
        end
        subgraph AZ2["eu-west-1b"]
            WS2["Workers Subnet<br/>subnet-workers-1b"]
            ILB2["Internal LB Subnet<br/>tagged: internal-elb=1"]
            PLB2["Public LB Subnet<br/>tagged: elb=1"]
        end
        SG["Nodes Security Group<br/>sg-0123456789abcdef0<br/>(User-provided)"]
        NAT_TGW["NAT GW / Transit GW<br/>(User-managed routing)"]
        IGW_U["Internet Gateway<br/>(User-managed)"]
    end

    NAT_TGW -.->|"outbound traffic"| WS1 & WS2
    IGW_U <-->|"inbound/outbound"| PLB1 & PLB2
    SG -.->|"attached to"| WS1 & WS2
    WS1 & WS2 --- EC2["EC2 Worker Nodes"]
    ILB1 & ILB2 --- ILB["Internal NLB/ALB<br/>(tag-discovered)"]
    PLB1 & PLB2 --- PLB["Public NLB/ALB<br/>(tag-discovered)"]

    subgraph GardenerCreates ["Gardener Creates"]
        IAM["IAM Role + Profile"]
        SSH["SSH Key Pair"]
    end

    style WS1 fill:#e8833a,color:white
    style WS2 fill:#e8833a,color:white
    style ILB1 fill:#5ba55b,color:white
    style ILB2 fill:#5ba55b,color:white
    style PLB1 fill:#5ba55b,color:white
    style PLB2 fill:#5ba55b,color:white
    style SG fill:#e8833a,color:white
    style NAT_TGW fill:#e8833a,color:white
    style IGW_U fill:#e8833a,color:white
    style IAM fill:#4a90d9,color:white
    style SSH fill:#4a90d9,color:white
```

> Orange = User-provided (BYO) | Blue = Gardener-managed | Green = Tag-discovered by CCM/LBC

```yaml
networks:
  vpc:
    id: vpc-abc123
  nodesSecurityGroupID: sg-0123456789abcdef0
  zones:
    - name: eu-west-1a
      workersSubnetID: subnet-workers-1a
    - name: eu-west-1b
      workersSubnetID: subnet-workers-1b
```

**What Gardener creates:** IAM role, instance profile, SSH key pair only.

**User responsibilities:**
- Worker subnet routing (NAT/Transit Gateway/VPC endpoints for connectivity)
- Security group with appropriate rules (see [Security Group Requirements](#security-group-requirements))
- Internal LB subnets tagged with `kubernetes.io/role/internal-elb=1` and `kubernetes.io/cluster/<name>=shared`
- Public LB subnets tagged with `kubernetes.io/role/elb=1` and `kubernetes.io/cluster/<name>=shared`
- Minimum 8 available IPs per LB subnet; at least 2 AZs for ALBs

---

#### Pattern 3: Private Cluster (No IGW, Transit Gateway)

Fully private cluster with no Internet Gateway. All connectivity via Transit Gateway and VPC endpoints.

```mermaid
graph TB
    subgraph VPC["VPC vpc-private<br/>(User-provided)"]
        subgraph AZ1["eu-west-1a"]
            WS1["Workers Subnet<br/>subnet-private-workers-1a"]
        end
        subgraph AZ2["eu-west-1b"]
            WS2["Workers Subnet<br/>subnet-private-workers-1b"]
        end
        SG["Nodes Security Group<br/>sg-private-nodes<br/>(User-provided)"]
        VPCE_S3["VPC Endpoint<br/>S3 (Gateway)"]
        VPCE_DDB["VPC Endpoint<br/>DynamoDB (Gateway)"]
        NO_IGW["No Internet Gateway"]
        NO_NAT["No NAT Gateway"]
    end

    TGW["Transit Gateway<br/>(User-managed)"] <-->|"all external traffic"| VPC
    TGW <--> OnPrem["On-Premises /<br/>Shared Services VPC"]
    SG -.->|"attached to"| WS1 & WS2
    WS1 & WS2 --- EC2["EC2 Worker Nodes"]
    VPCE_S3 -.->|"S3 access"| WS1 & WS2
    VPCE_DDB -.->|"DynamoDB access"| WS1 & WS2

    style WS1 fill:#e8833a,color:white
    style WS2 fill:#e8833a,color:white
    style SG fill:#e8833a,color:white
    style TGW fill:#e8833a,color:white
    style VPCE_S3 fill:#e8833a,color:white
    style VPCE_DDB fill:#e8833a,color:white
    style NO_IGW fill:#888,color:white
    style NO_NAT fill:#888,color:white
```

> Gray = Not present / disabled

```yaml
networks:
  vpc:
    id: vpc-private
    gatewayEndpoints:
      - s3
      - dynamodb
  nodesSecurityGroupID: sg-private-nodes
  zones:
    - name: eu-west-1a
      workersSubnetID: subnet-private-workers-1a
    - name: eu-west-1b
      workersSubnetID: subnet-private-workers-1b
```

No Internet Gateway required. Connectivity via Transit Gateway + VPC endpoints.

---

#### Pattern 4: Gardener Workers, No Public Subnet (VPC Endpoints Only)

Gardener creates worker and internal subnets, but no public subnet -- connectivity via VPC endpoints only. Since Gardener manages the subnets, it also manages the security group.

```mermaid
graph TB
    subgraph VPC["VPC vpc-private<br/>(User-provided)"]
        subgraph AZ1["eu-west-1a"]
            WS["Workers Subnet<br/>10.250.0.0/19<br/>(Gardener-created)"]
            IS["Internal Subnet<br/>10.250.32.0/20<br/>(Gardener-created)"]
        end
        SG["Nodes Security Group<br/>(Gardener-managed)"]
        VPCE_S3["VPC Endpoint: S3<br/>(Gateway)"]
        VPCE_DDB["VPC Endpoint: DynamoDB<br/>(Gateway)"]
        NO_PS["No Public Subnet"]
        NO_NAT["No NAT Gateway"]
        NO_IGW["No Internet Gateway"]
    end

    SG -.->|"attached to"| WS
    WS --- EC2["EC2 Worker Nodes"]
    IS --- ILB["Internal LBs"]
    VPCE_S3 -.->|"S3 access"| WS
    VPCE_DDB -.->|"DynamoDB access"| WS

    style WS fill:#4a90d9,color:white
    style IS fill:#4a90d9,color:white
    style SG fill:#4a90d9,color:white
    style VPCE_S3 fill:#e8833a,color:white
    style VPCE_DDB fill:#e8833a,color:white
    style NO_PS fill:#888,color:white
    style NO_NAT fill:#888,color:white
    style NO_IGW fill:#888,color:white
```

```yaml
networks:
  vpc:
    id: vpc-private
    gatewayEndpoints:
      - s3
      - dynamodb
  zones:
    - name: eu-west-1a
      workers: 10.250.0.0/19
      internal: 10.250.32.0/20
      # No public subnet -- no NAT gateway
```

---

### Security Group Design

#### Preferred: Full Replacement Model (User-provided SG replaces Gardener's)

When bringing your own infrastructure, the user provides a single security group ID via `nodesSecurityGroupID` that **replaces** Gardener's nodes SG entirely. Gardener does not create or manage any security group rules.

**Why this is the preferred approach:**

1. **Chicken-and-egg problem**: The security group ID must be known at MachineClass creation time, before any EC2 instances exist. You can't discover a SG from instances that don't exist yet.

2. **MCM is the sole consumer**: The security group flows from `InfrastructureStatus` -> Worker controller -> `MachineClass.providerSpec.networkInterfaces[].securityGroupIDs` -> MCM -> `RunInstances` API. It is attached to the EC2 instance's primary network interface at launch.

3. **The CCM does NOT need the SG**: Gardener configures `DisableSecurityGroupIngress=true` in the CCM's cloud-provider-config, which tells it to skip all security group rule management for load balancers.

4. **No standard tag convention exists**: Unlike subnets (which have well-defined `kubernetes.io/role/*` tags), there is no standard tag for "this is the nodes security group." EKS also requires explicit SG specification for node groups.

5. **Complete control for enterprises**: Corporate policy often mandates that all security groups are pre-approved by a security team. The replacement model allows users to restrict egress, tighten NodePort rules, or apply any custom rules without being constrained by Gardener's defaults.

##### Security Group Data Flow

```mermaid
flowchart LR
    A["InfrastructureConfig\nnodesSecurityGroupID:\nsg-xxx"] --> B["Infrastructure\nReconciler"]
    B --> C["InfrastructureStatus\nsecurityGroups:\n  purpose: nodes\n  id: sg-xxx"]
    C --> D["Worker\nController"]
    D --> E["MachineClass\nnetworkInterfaces:\n  securityGroupIDs:\n    - sg-xxx"]
    E --> F["Machine Controller\nManager"]
    F -->|"RunInstances API"| G["EC2 Instance\nwith SG attached"]
```

##### Security Group Requirements

When providing `nodesSecurityGroupID`, the security group **must** include at minimum:

| Direction | Protocol | Ports | Source/Dest | Purpose |
|-----------|----------|-------|-------------|---------|
| Ingress | All | All | Self (same SG) | Pod-to-pod, node-to-node |
| Ingress | TCP | 30000-32767 | 0.0.0.0/0 or LB CIDRs | NodePort services |
| Ingress | UDP | 30000-32767 | 0.0.0.0/0 or LB CIDRs | NodePort services |
| Egress | All | All | 0.0.0.0/0 | Outbound connectivity |

Additional rules for EFS (TCP 2049) if using CSI EFS driver.

> **Egress note:** The `0.0.0.0/0` egress rule is the simplest configuration. For private clusters with strict egress policies, the minimum required destinations are: the Kubernetes API server endpoint, container registries (for image pulls), and AWS APIs (EC2, ELB, STS, S3). These can be reached via VPC endpoints or specific CIDR allowlists instead of a blanket egress rule.

**Risks the user must be aware of:**
- Missing self-referencing ingress rule -> broken pod-to-pod communication
- Missing NodePort range -> broken Services
- Missing egress rule -> nodes can't reach the API server or pull container images
- Gardener cannot recover from these misconfigurations automatically

> **Future work:** A health check that verifies the BYO security group contains the minimum required rules could be added as a condition on the Infrastructure resource, providing early feedback to operators without blocking reconciliation.

#### Alternative: Additive Model (Gardener base SG + user additional SGs)

In this model, Gardener **always** creates and manages a nodes security group with a minimal, known-good rule set. Users can **optionally** provide one or more additional security groups that are attached alongside Gardener's SG on the EC2 instance's primary network interface. AWS evaluates rules across all attached SGs as a union (most permissive wins).

**Gardener's base SG rules (always present in additive model):**

| Direction | Protocol | Ports | IPv4 Source/Dest | IPv6 Source/Dest | Purpose |
|-----------|----------|-------|-----------------|-----------------|---------|
| Ingress | All | All | Self (same SG) | Self (same SG) | Pod-to-pod, node-to-node |
| Ingress | TCP | 30000-32767 | 0.0.0.0/0 | ::/0 | NodePort services |
| Ingress | UDP | 30000-32767 | 0.0.0.0/0 | ::/0 | NodePort services |
| Egress | All | All | 0.0.0.0/0 | ::/0 | All outbound |

The user's additional SG(s) would contain corporate/compliance rules: cross-VPC peering, custom ingress from corporate networks, compliance-mandated ports.

**Advantages of additive model:**
- **No broken clusters**: User cannot accidentally break pod-to-pod communication -- Gardener's base SG always has the self-referencing rule
- **Separation of concerns**: Gardener owns what it needs; users own what they need
- **Standard AWS pattern**: EKS managed node groups work the same way (cluster SG + additional SGs)

**Why additive is not the preferred approach:**
- Users **cannot** make rules more restrictive than Gardener's base set (AWS SG rules are unioned, most permissive wins)
- The base SG allows all egress and NodePort from `0.0.0.0/0` -- an additional SG can only add more permissions, not remove existing ones
- Corporate policies that mandate pre-approved-only security groups would still have Gardener creating an SG

> The additive model may be reconsidered as a complementary option in the future. The API field would be `AdditionalNodesSecurityGroupIDs []string`.

### Routing Requirements for BYO

In BYO mode, Gardener does **not** create any route tables, NAT gateways, or Internet Gateways. The user is fully responsible for all routing. Each BYO worker subnet must be associated with a route table that provides the connectivity required by a functioning Kubernetes cluster.

Routing is **not validated** by Gardener — every subnet in AWS is implicitly associated with the VPC's main route table if no explicit association exists, so there is always a route table. However, users must ensure the route table has the correct routes for their connectivity model. If routing is misconfigured, nodes will fail to join the cluster.

#### Connectivity Requirements

Worker nodes must be able to reach:

| Destination | Purpose | Typical Route |
|---|---|---|
| Kubernetes API server (shoot control plane) | kubelet registration, API calls | Via NAT GW, TGW, or VPC peering to seed |
| Container registries | Image pulls | Via NAT GW, TGW, or VPC endpoints |
| AWS EC2/ELB/STS APIs | Cloud provider operations | Via NAT GW, TGW, or VPC endpoints |
| Other worker nodes (same VPC) | Pod-to-pod, node-to-node | VPC local route (automatic) |
| S3 / DynamoDB (if using ETCD backup, loki) | Backup and logging | Via gateway VPC endpoints (recommended) |

#### Connectivity Models

| Model | Default Route | When to Use |
|---|---|---|
| **Centralized NAT Gateway** | `0.0.0.0/0` -> NAT GW (shared or per-AZ) | Standard outbound internet access via user-managed NAT |
| **Transit Gateway** | `0.0.0.0/0` -> TGW, or specific CIDRs -> TGW | Hub-and-spoke, on-premises connectivity, shared services |
| **VPC Endpoints only** | No default route; AWS service traffic stays in VPC | Fully private clusters, no internet access |
| **Direct Internet** | `0.0.0.0/0` -> IGW (subnet must be public) | Public-facing worker nodes (uncommon) |

#### The `aws-custom-route-controller` and Pod CIDR Routing

When network overlay is disabled (no VXLAN/Geneve encapsulation), Gardener deploys the [`aws-custom-route-controller`](https://github.com/gardener/aws-custom-route-controller) to manage **pod CIDR routes** in AWS VPC route tables. This controller:

1. Watches Kubernetes Node objects for `.spec.podCIDR` assignments
2. Creates AWS VPC routes in all discovered route tables: destination = node's podCIDR, target = node's ENI
3. Discovers route tables via the tag `kubernetes.io/cluster/<cluster-name>`

**In BYO mode**, the custom route controller will still be enabled when overlay is disabled. Since Gardener does not create route tables in BYO mode, the controller discovers them via tags. Users must ensure:

- The route table(s) associated with worker subnets are tagged with `kubernetes.io/cluster/<cluster-name>=shared`
- The AWS VPC route table limit (50 routes by default, expandable to 1000) is sufficient for the number of nodes

If overlay networking **is** enabled (default), the custom route controller is disabled and no route table tagging is needed for pod CIDR routing.

> **Note**: The CCM's built-in route controller is always disabled in Gardener (`--configure-cloud-routes=false`). Pod CIDR routing is exclusively handled by the `aws-custom-route-controller` when needed.

#### Route Table Requirements Summary

| Requirement | When |
|---|---|
| Worker subnets must have a route table with outbound connectivity | Always (user responsibility, not validated) |
| Route table tagged with `kubernetes.io/cluster/<name>=shared` | Only when overlay is disabled (custom route controller needs it) |
| Route table has capacity for pod CIDR routes (50 default, expandable to 1000) | Only when overlay is disabled |

### Load Balancer Subnet Discovery

#### Design Rationale: Why No Explicit LB Subnet IDs

A key design decision is that **internal and public load balancer subnets are NOT referenced by ID**. Instead, they are discovered at runtime via standard AWS tags by the Cloud Controller Manager (CCM) and AWS Load Balancer Controller (LBC). This is because:

1. **The CCM and LBC already discover subnets via tags** - this is the standard AWS Kubernetes pattern (same as EKS). The tags `kubernetes.io/role/internal-elb=1` and `kubernetes.io/role/elb=1` are the authoritative mechanism.

2. **Gardener itself never uses internal/public subnet IDs at runtime** - `PurposePublic` is consumed only for the CCM config's `SubnetID` field (a fallback identity, not for LB placement) - and we can use the workers subnet for that instead.

3. **Users must tag subnets anyway** - even if we accepted subnet IDs, the CCM/LBC would still require the tags. Accepting IDs would create a false sense that tagging isn't needed.

4. **Users can override per-Service** via the `service.beta.kubernetes.io/aws-load-balancer-subnets` annotation if they need explicit control.

#### Discovery Flow

The CCM and LBC discover subnets automatically using the following process (verified from cloud-provider-aws source):

1. **Annotation override**: If `service.beta.kubernetes.io/aws-load-balancer-subnets` is set on the Service, those subnets are used directly (by ID or Name tag)
2. **Tag-based discovery**: Find all subnets in the VPC with cluster tag `kubernetes.io/cluster/<name>`
3. **Per-AZ deduplication** with priority:
   - Role tag: `kubernetes.io/role/elb=1` (public) or `kubernetes.io/role/internal-elb=1` (internal)
   - Cluster tag presence
   - Lexicographic subnet ID order
4. **Reachability check**: Public LB subnets must have an IGW route; private subnets must not

```mermaid
flowchart TD
    SVC["Service created\ntype: LoadBalancer"] --> ANN{"Annotation\naws-load-balancer-subnets\npresent?"}
    ANN -->|Yes| USE["Use specified subnets\ndirectly by ID or Name"]
    ANN -->|No| FIND["Find all subnets in VPC\nwith tag kubernetes.io/cluster/name"]
    FIND --> DEDUP["Per-AZ deduplication\nwith priority order"]
    DEDUP --> ROLE{"Has role tag?"}
    ROLE -->|"elb=1"| PUB["Select as public\nLB subnet"]
    ROLE -->|"internal-elb=1"| PRIV["Select as internal\nLB subnet"]
    ROLE -->|"No role tag"| FALLBACK["Fallback: cluster tag presence\nthen lexicographic subnet ID"]
    PUB --> CHECK{"Reachability\ncheck"}
    PRIV --> CHECK
    FALLBACK --> CHECK
    CHECK -->|"Public: has IGW route\nPrivate: no IGW route"| OK["Subnet selected"]
    CHECK -->|"Mismatch"| REJECT["Subnet rejected"]

    style OK fill:#5ba55b,color:white
    style REJECT fill:#e74c3c,color:white
```

#### Required Tags on User-Provided LB Subnets

**Internal Load Balancers:**
```
kubernetes.io/role/internal-elb = 1
kubernetes.io/cluster/<cluster-name> = shared
```

**Public Load Balancers:**
```
kubernetes.io/role/elb = 1
kubernetes.io/cluster/<cluster-name> = shared
```

#### Requirements

- ALBs: at least 2 subnets across different AZs
- NLBs: can use a single subnet
- Each LB subnet: minimum 8 available IP addresses
- Public subnets: must have route to Internet Gateway
- Private subnets: must NOT have route to Internet Gateway

### Implementation Approach

#### Reconcile Flow Changes

| Condition | Skip |
|-----------|------|
| `workersSubnetID` set | Worker subnet creation, route table, NAT gateway, elastic IP, internal subnet, public subnet |
| No `public` CIDR in zone | Public subnet, NAT gateway, elastic IP for that zone |
| No `internal` CIDR in zone | Internal subnet for that zone |
| `nodesSecurityGroupID` set | Nodes security group creation and rule management |
| No Gardener-managed public subnets anywhere | Main route table, Internet Gateway requirement |

```mermaid
flowchart TD
    START(["Reconcile Start"]) --> WID{"workersSubnetID\nset?"}
    WID -->|Yes| SKIP_W["SKIP: Worker subnet, route table,\nNAT GW, EIP, internal subnet,\npublic subnet"]
    WID -->|No| CREATE_W["CREATE: Worker subnet\nfrom CIDR"]

    CREATE_W --> PUB{"public CIDR\nset in zone?"}
    PUB -->|Yes| CREATE_P["CREATE: Public subnet,\nNAT GW, EIP"]
    PUB -->|No| SKIP_P["SKIP: Public subnet,\nNAT GW, EIP"]

    CREATE_P --> INT{"internal CIDR\nset in zone?"}
    SKIP_P --> INT
    INT -->|Yes| CREATE_I["CREATE:\nInternal subnet"]
    INT -->|No| SKIP_I["SKIP:\nInternal subnet"]

    SKIP_W --> SGID{"nodesSecurityGroupID\nset?"}
    CREATE_I --> SGID
    SKIP_I --> SGID
    SGID -->|Yes| SKIP_SG["SKIP: Security group\ncreation + rules"]
    SGID -->|No| CREATE_SG["CREATE: Nodes\nsecurity group"]

    SKIP_SG --> IGW{"Any managed\npublic subnets\nacross all zones?"}
    CREATE_SG --> IGW
    IGW -->|Yes| CREATE_IGW["CREATE: Internet Gateway,\nmain route table"]
    IGW -->|No| SKIP_IGW["SKIP: Internet Gateway,\nmain route table"]

    style SKIP_W fill:#888,color:white
    style SKIP_P fill:#888,color:white
    style SKIP_I fill:#888,color:white
    style SKIP_SG fill:#888,color:white
    style SKIP_IGW fill:#888,color:white
    style CREATE_W fill:#4a90d9,color:white
    style CREATE_P fill:#4a90d9,color:white
    style CREATE_I fill:#4a90d9,color:white
    style CREATE_SG fill:#4a90d9,color:white
    style CREATE_IGW fill:#4a90d9,color:white
```

#### Delete Flow

BYO resources are **never deleted**:
- Worker subnets referenced by `workersSubnetID` are not deleted
- Security groups referenced by `nodesSecurityGroupID` are not deleted
- VPC referenced by `VPC.ID` is already not deleted (existing behavior)

Cluster tags (`kubernetes.io/cluster/<name>=shared`) added to BYO subnets during reconciliation **are removed** on teardown to prevent stale tags from accumulating across cluster lifecycles.

#### VPC Gateway Endpoints in BYO Mode

VPC gateway endpoints configured via `vpc.gatewayEndpoints` (e.g., S3, DynamoDB) are **skipped** in BYO mode. Gateway endpoints are VPC-level resources that require route table associations to function -- without associations, AWS does not add the prefix list routes that direct traffic through the endpoint. Since Gardener does not create or manage route tables in BYO mode, it cannot associate endpoints with the user's route tables, making any created endpoint non-functional.

Users who need VPC gateway endpoints in BYO mode must create and manage them independently, including associating them with their own route tables.

#### Bastion Hosts

The current bastion controller creates a bastion EC2 instance in a **Gardener-managed public subnet** (`<cluster>-public-utility-z0`). In BYO mode where no public subnets are created by Gardener, bastion creation will fail. Users needing SSH access to worker nodes in BYO mode should use [AWS Systems Manager Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html) or a bastion host in a user-managed public subnet.

> **Future work:** The bastion controller should be updated to support BYO mode, potentially by using a worker subnet with a public IP or by integrating with SSM.

#### InfrastructureStatus

- `VPC.Subnets[purpose=nodes]`: reports BYO worker subnet ID (from `workersSubnetID`) or Gardener-created one
- `VPC.SecurityGroups[purpose=nodes]`: reports BYO security group ID or Gardener-created one
- CCM config: uses workers subnet as `SubnetID` fallback when no public subnet exists

## Alternatives

### Additive Security Group Model Instead of Full Replacement

Instead of the full replacement model (`NodesSecurityGroupID`), we could keep Gardener's base SG and let users attach additional SGs via `AdditionalNodesSecurityGroupIDs []string`. This was not chosen because:

- Users cannot make rules more restrictive than Gardener's base set (AWS SG rules are unioned)
- Corporate policies that mandate pre-approved-only SGs would still have Gardener creating one
- The full replacement model gives users complete control, which is what enterprise BYO scenarios require

The additive model remains a valid future addition for users who want a safety net.

### Accepting Explicit LB Subnet IDs

Instead of tag-based discovery, we could accept `internalSubnetID` and `publicSubnetID` per zone. This was rejected because:

- The CCM and LBC already discover subnets via tags -- this is the standard AWS pattern
- Users must tag subnets regardless (CCM/LBC require it)
- Accepting IDs would create a false sense that tagging isn't needed
- Users can always override per-Service via annotations

### Mixed BYO/Managed Subnets per Zone

Allowing `workersSubnetID` with `internal`/`public` CIDRs in the same configuration was rejected because:

- Creates conflicting infrastructure requirements (BYO routing vs Gardener-managed IGW/NAT)
- The BYO mode is designed as a clean boundary: user owns all network resources, Gardener owns compute
- Mixing ownership models increases complexity and creates an inconsistent network topology

## FAQ

### If I use BYO worker subnets, can I still have Gardener create internal or public subnets?

No. When `workersSubnetID` is used, **all subnets must be user-managed**. Specifying `internal` or `public` CIDRs alongside `workersSubnetID` is forbidden by validation. LB subnets are discovered via standard AWS tags.

### Can I add a BYO zone to an existing cluster that uses Gardener-managed subnets?

No. All zones must use the same approach. Adding a new zone with `workersSubnetID` to a cluster that uses `workers` CIDRs is forbidden by validation, and vice versa.

### What about IPv6 support with BYO subnets?

If `workersSubnetID` is provided, the extension will discover the IPv6 CIDR block from the subnet/VPC via the AWS API. The BYO subnet must have an IPv6 CIDR block when DualStack is enabled.

### What happens if LB subnets are not tagged?

The CCM/LBC will not find subnets for load balancers. NLB/CLB Services will fail to provision. The CCM service controller may be disabled entirely if no tagged subnets are discovered during infrastructure reconciliation.

### Does `nodesSecurityGroupID` replace Gardener's SG or add to it?

It replaces it entirely. When `nodesSecurityGroupID` is set, Gardener does **not** create a nodes security group. The user-provided SG is the only one attached to EC2 instances. The user is responsible for including all required rules (see [Security Group Requirements](#security-group-requirements)).

### Do I need to tag my route tables in BYO mode?

Only if network overlay is disabled. When overlay is disabled, the `aws-custom-route-controller` manages pod CIDR routes and discovers route tables via the `kubernetes.io/cluster/<cluster-name>=shared` tag. If overlay is enabled (default), no route table tagging is needed.

### Can I use bastion hosts in BYO mode?

Not with the current bastion controller. It requires a Gardener-managed public subnet which does not exist in BYO mode. Use AWS Systems Manager Session Manager or a bastion in a user-managed public subnet instead.

### Are VPC gateway endpoints managed by Gardener in BYO mode?

No. The `gatewayEndpoints` field in the VPC configuration is ignored in BYO mode. VPC gateway endpoints require route table associations to function, and since Gardener does not manage route tables in BYO mode, it cannot make endpoints functional. Users must create and manage their own VPC endpoints, including associating them with their route tables.

## Success Criteria

- Users can deploy clusters with pre-provisioned VPC + worker subnets + security group
- Users can deploy clusters without Internet Gateway or NAT gateways
- LB subnets are discovered via standard AWS tags (no explicit IDs needed)
- Zero breaking changes to existing clusters
- BYO resources are never modified or deleted by Gardener
