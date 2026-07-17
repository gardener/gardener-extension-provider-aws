# BYO Infrastructure — Open Gaps and Decisions

**Audience: coding agents assisting with PR [#1741](https://github.com/gardener/gardener-extension-provider-aws/pull/1741) (`byo-subnet3`).**

This file tracks the outstanding gaps identified during review of the BYO
infrastructure implementation, the options considered for each, and the current
decision. Update the corresponding entry when a gap is resolved.

Each entry follows the same shape:

- **Statement** — what is wrong or missing, in one paragraph
- **Evidence** — file:line references that let a reader verify without re-deriving
- **Options considered** — approaches discussed, with the trade-off that eliminated the rejected ones
- **Decision** — the direction we chose, or `pending`
- **Status** — `pending` / `in-progress` / `implemented` / `deferred`
- **Follow-ups** — related work to do afterwards, if any

Cross-references use `pkg/...:LINE` for code and `PR#1741 thread N` for review
threads (numbered chronologically, see the [thread index](#pr1741-thread-index)
at the bottom).

## Commit sequencing

Gaps are addressed in separate commits to keep each change surgical and
reviewable.

Landed on `byo-subnet3`:

1. **Gap A (Shape 2)** — reorder graph, cache subnet CIDRs in state, SG
   builder reads state. Closes Gaps A, B, K. Reduces Gap C to a no-op.
2. **Gap F step 1** — change EFS rule's CIDR source to workers subnet in
   both modes.
3. **Thread 8** — remove dead BYO error branch in
   `ensureSubnetCidrReservation` second loop.
4. **Thread 1** — restore `child.Delete(IdentifierZoneNATGateway)` after
   NAT deletion.
5. **Gap E + Gap G + Gap H (partial)** — stabilize service CIDR across
   reconciles; pin `getSubnetKey` state-write-first contract with unit
   tests; add `CreateDualStackSubnetInZone` integration helper.
6. **Gap J** — reject BYO subnets with multiple IPv6 CIDR associations.
7. **Gap E** — sort subnets by ID in `ensureSubnetCidrReservation` for deterministic selection when state is lost.
8. **Doc-1 through Doc-4** — proposal corrections and additions (CCM function name, NLBSecurityGroupMode, NodePort CIDR tightening scope, hybrid SG+BYO subsection).

Deferred (not planned in this PR):

- **Gap L** — drop the redundant narrow per-zone rules. Would break
  parity with SG contents of existing managed clusters.
- **Gap N** — managed-mode IPv6 offsets for internal/public LB rules are
  wrong. Silent bug; kept in place with explicit comments.

Retracted as not-a-bug:

- **Gap D** — `CidrBlock == ""` and `Ipv6Native == true` are defensive
  complementary checks, not redundant.
- **Gap G** — contract tests already present in `reconcile_getsubnetkey_test.go`
  (lines 138–149); invariant was already pinned before this pass.
- **Gap I** — a `::/0` route is not mandatory for BYO+IPv6 (specific
  prefixes, NAT64, hub-and-spoke are all legitimate); validating would
  violate the BYO principle "user manages routing". Requirement stays a
  documentation concern.

Pending (not addressed in this PR):

- **Alex thread replies** — per user direction, no GitHub replies were
  posted for the already-resolved threads.
- **Gap M** — convert `nodes_security_group_internal_test.go` to ginkgo
  (style-only follow-up).
- **Gap H (full)** — reconcile-level integration test for BYO+dual-stack.
  Helper is in place; test still needs to be written (requires AWS
  credentials to run).

Each commit corresponds to exactly one gap unless the doc note says
otherwise. Agents should update the corresponding entry's `Status` when
the commit lands, and record the commit SHA under a `Resolved by` line.

---

## Table of contents

- [Code gaps](#code-gaps)
  - [Gap A — BYO+IPv6 SG rules use derived VPC CIDRs, not the user's real subnet CIDRs](#gap-a--byoipv6-sg-rules-use-derived-vpc-cidrs-not-the-users-real-subnet-cidrs)
  - [Gap B — IPv4/IPv6 asymmetry in per-zone SG rules under BYO](#gap-b--ipv4ipv6-asymmetry-in-per-zone-sg-rules-under-byo)
  - [Gap C — `IdentifierVpcIPv6CidrBlock` stores a single string, misleading in BYO](#gap-c--identifiervpcipv6cidrblock-stores-a-single-string-misleading-in-byo)
  - [Gap D — `validateLBSubnetNotIPv6Native` redundant `CidrBlock == ""` check](#gap-d--validatelbsubnetnotipv6native-redundant-cidrblock---check)
  - [Gap E — `ensureSubnetCidrReservation` first-match across zones without conflict detection](#gap-e--ensuresubnetcidrreservation-first-match-across-zones-without-conflict-detection)
  - [Gap F — EFS ingress rule is dead code in every mode](#gap-f--efs-ingress-rule-is-dead-code-in-every-mode)
  - [Gap G — `getSubnetKey` fallback depends on state written earlier in the same reconcile](#gap-g--getsubnetkey-fallback-depends-on-state-written-earlier-in-the-same-reconcile)
  - [Gap H — No test coverage for BYO + IPv6/dual-stack reconcile paths](#gap-h--no-test-coverage-for-byo--ipv6dual-stack-reconcile-paths)
  - [Gap I — No validation of BYO route table IPv6 default route](#gap-i--no-validation-of-byo-route-table-ipv6-default-route)
  - [Gap J — Multiple IPv6 CIDRs on the same subnet handled non-deterministically](#gap-j--multiple-ipv6-cidrs-on-the-same-subnet-handled-non-deterministically)
  - [Gap K — Spurious dependency: `ensureZones` requires `ensureNodesSecurityGroup`](#gap-k--spurious-dependency-ensurezones-requires-ensurenodessecuritygroup)
  - [Gap L — Narrow per-zone NodePort SG rules are redundant with the base wide rules](#gap-l--narrow-per-zone-nodeport-sg-rules-are-redundant-with-the-base-wide-rules)
  - [Gap M — Test-style inconsistency in `pkg/controller/infrastructure/infraflow`](#gap-m--test-style-inconsistency-in-pkgcontrollerinfrastructureinfraflow)
  - [Gap N — Managed-mode IPv6 offsets for internal/public LB narrow rules are wrong](#gap-n--managed-mode-ipv6-offsets-for-internalpublic-lb-narrow-rules-are-wrong)
- [Review threads still open](#review-threads-still-open)
  - [Thread 1 — Removed state deletion in `deleteNATGateway`](#thread-1--removed-state-deletion-in-deletenatgateway)
  - [Thread 2 — Wrong field path in `nodesSecurityGroupID` immutability error](#thread-2--wrong-field-path-in-nodessecuritygroupid-immutability-error)
  - [Thread 5 — Duplicate doc file `docs/usage/flexible-network-configuration.md`](#thread-5--duplicate-doc-file-docsusageflexible-network-configurationmd)
  - [Thread 6 — Missing default value in CCM chart `values.yaml`](#thread-6--missing-default-value-in-ccm-chart-valuesyaml)
  - [Thread 8 — Redundant BYO error branch in second loop of `ensureSubnetCidrReservation`](#thread-8--redundant-byo-error-branch-in-second-loop-of-ensuresubnetcidrreservation)
  - [Thread 9 — Notify Alex that the pre-tagged-subnet issue is addressed](#thread-9--notify-alex-that-the-pre-tagged-subnet-issue-is-addressed)
  - [Thread 10 — Should mixed-zone BYO LB configuration be rejected?](#thread-10--should-mixed-zone-byo-lb-configuration-be-rejected)
  - [Thread 13 — Doc note: recommend >=8 free IPs per LB subnet](#thread-13--doc-note-recommend-8-free-ips-per-lb-subnet)
- [Proposal / documentation issues](#proposal--documentation-issues)
  - [Doc-1 — Proposal line 432 names non-existent CCM function](#doc-1--proposal-line-432-names-non-existent-ccm-function)
  - [Doc-2 — Proposal does not mention `NLBSecurityGroupMode`](#doc-2--proposal-does-not-mention-nlbsecuritygroupmode)
  - [Doc-3 — "or LB subnet CIDRs" wording overstates Gardener's tightening capability](#doc-3--or-lb-subnet-cidrs-wording-overstates-gardeners-tightening-capability)
  - [Doc-4 — No documented behavior for Gardener-managed SG combined with BYO subnets](#doc-4--no-documented-behavior-for-gardener-managed-sg-combined-with-byo-subnets)
- [PR#1741 thread index](#pr1741-thread-index)
- [Glossary](#glossary)

---

# Code gaps

## Gap A — BYO+IPv6 SG rules use derived VPC CIDRs, not the user's real subnet CIDRs

### Statement

In the `ensureNodesSecurityGroup` per-zone rule block, the IPv6 branch derives
"internal" and "public" subnet CIDRs from `IdentifierVpcIPv6CidrBlock` using
fixed offsets (`2+3*index`, `3+3*index`) — the layout Gardener would use if it
were creating the subnets itself. In BYO the user's subnets have arbitrary /64
slices within the VPC's /56; those derived CIDRs almost never match reality.
Result on a BYO+IPv6/dual-stack cluster: the emitted SG rules reference CIDRs
that do not correspond to any subnet the user actually has.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:698-716` — the derivation
- `pkg/controller/infrastructure/infraflow/reconcile.go:1089` — the same offset math used for managed subnet creation, confirming the derivation is Gardener's layout, not a real lookup

### Options considered

1. **Read the user's real IPv6 CIDRs from the subnet, direct fetch in the SG
   builder** (Shape 1). Fetch each BYO public/internal subnet via
   `awsClient.GetSubnets` inside `ensureNodesSecurityGroup`. Requires an extra
   AWS call because that task runs *before* `ensureZones` and state is not
   populated yet. Programs a tighter, real CIDR. Achieves parity with managed
   mode only for the explicit-LB-subnet case; the discovery case (user relies
   on pre-tagged subnets) still falls back to Shape 3 semantics because
   subnet IDs are not known before `ensureBYOZones` runs.

2. **Reorder the graph, cache subnet CIDRs in state, SG builder reads state**
   (Shape 2). Reverse the dependency at `reconcile.go:104`: make
   `ensureNodesSecurityGroup` depend on `ensureZones`. Extend `ensureBYOZones`
   (which already fetches subnets at `reconcile.go:839,861`) to cache
   `Ipv6CidrBlocks[0]` and `CidrBlock` per zone-and-purpose in state. SG
   builder reads those state entries. Handles explicit and discovery cases
   uniformly. Closes Gap K as a side effect. Managed mode is unaffected —
   its rule CIDRs still come from `zone.Public`/`zone.Internal` in config,
   which are already available before `ensureZones` runs.

3. **Skip the per-zone IPv6 rules in BYO, mirroring the IPv4 skip** (Shape 3).
   Symmetric with the current IPv4 behavior. No new AWS calls, no graph
   changes, smallest diff. Trades off SG-shape parity with managed mode: BYO
   emits fewer rules than managed. Functionally equivalent because the base
   wide rules cover the traffic.

### Decision

Adopt **Shape 2**. Preserve managed/BYO parity in emitted SG rule shape,
deduplicate AWS calls with `ensureBYOZones`, and close Gap K as a side
effect. The graph change is non-trivial but well-contained: one dependency
reversal, extend `ensureBYOZones` to cache subnet CIDRs, SG builder reads
from state.

### Status

`implemented` on `byo-subnet3` (pending commit).

**Resolved by**: `6cfdd544` — *Source BYO+IPv6 SG rules from real subnet CIDRs (not derived from VPC block)* (same commit resolves Gap B and Gap K).

Implementation summary:

- New state keys added in `context.go`: `IdentifierZoneSubnet{Workers,Public,Private}{CIDR,IPv6CIDR}`. Populated by `ensureBYOZones` for explicit BYO subnets and by `discoverTaggedSubnets` for pre-tagged LB subnets discovered in the VPC.
- Dependency graph in `buildReconcileGraph` (`reconcile.go`) reversed:
  - `ensureZones` no longer depends on `ensureNodesSecurityGroup` (Gap K closed).
  - `ensureNodesSecurityGroup` now depends on `ensureVpc, ensureZones` (was: `ensureVpc` only). The SG builder runs after `ensureZones` so per-zone subnet CIDRs are already in state when the rules are computed.
  - `ensureEfs` depends on `ensureNodesSecurityGroup` (transitively covers `ensureZones`).
- `ensureBYOZones` refactored: a single `fetchBYOSubnets` batch call replaces the two per-zone `GetSubnets` calls for public/internal subnets and additionally fetches worker subnets. A helper `cacheBYOSubnetCIDRs` writes CIDRs to zone-scoped state for every fetched subnet by purpose (workers, public, internal).
- `discoverTaggedSubnets` extended: builds a subnet-ID -> `*Subnet` map alongside the existing AZ-grouping, and calls `cacheBYOSubnetCIDRs` for every discovered LB subnet (matching the pre-tagged discovery path with the explicit-ID path in what it writes to state).
- New helper `resolveZoneLBCIDRs` in `reconcile.go`: single source of truth for per-zone LB CIDR resolution. In BYO reads from state; in managed reads config for IPv4 and derives from VPC block for IPv6 using the same offsets `ensureManagedZones` applies.
- SG rule builder now calls `resolveZoneLBCIDRs`. The derivation math is gone from the inline SG code path.
- Unit tests added in `reconcile_resolve_lb_cidrs_test.go`: 8 ginkgo specs covering managed IPv4, managed dual-stack derived-IPv6, empty VPC block, empty zone config, BYO dual-stack state read, BYO discovery-case empty-state fallback, IPv4-only BYO, and a negative test proving BYO does not fall back to config CIDRs.

### Follow-ups (separate commits after Shape 2 lands)

- Doc-4 below: document the Gardener-managed-SG-in-BYO behavior explicitly.
- Gap F: fix the EFS ingress rule's CIDR source (currently `zone.Internal`)
  to the workers subnet CIDR in managed mode; then drop the rule entirely.
- Gap L (new): drop the redundant narrow per-zone NodePort rules in both
  modes, since they're strict subsets of the wide base rules.

---

## Gap B — IPv4/IPv6 asymmetry in per-zone SG rules under BYO

### Statement

Under BYO today, the IPv4 branch at `reconcile.go:686-696` correctly skips
per-zone rules because `zone.Internal` and `zone.Public` are nil. The IPv6
branch at `reconcile.go:698-716` unconditionally emits derived CIDRs
regardless. So a BYO+IPv4 cluster is loose (base rules only) but a BYO+IPv6
cluster is loose *and* has wrong extra rules.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:686-696` (gated IPv4)
- `pkg/controller/infrastructure/infraflow/reconcile.go:698-716` (unconditional IPv6)

### Options considered

Subsumed by Gap A. Under **Shape 2** (chosen), both branches read from state
populated by `ensureBYOZones`, so both emit narrow rules per zone using the
real BYO subnet CIDRs. Managed mode continues to read from `zone.Public`/
`zone.Internal` config. Asymmetry closed for BYO+IPv6.

Note: the IPv4 skip in BYO at `reconcile.go:686-696` will need to be
extended to also read from state (real workers/public/internal CIDRs) once
Shape 2 lands, so IPv4 and IPv6 use the same source-of-truth. Currently the
IPv4 branch only checks `zone.Internal != nil` (a config value that is nil
in BYO) — under Shape 2 the equivalent check becomes "state has an entry
for this zone/purpose".

### Decision

Fixed as part of Gap A's Shape 2. Both branches (IPv4 and IPv6) read from
the same source: config in managed mode, state in BYO mode. Full symmetry.

### Status

`implemented` on `byo-subnet3` (same commit as Gap A).

---

## Gap C — `IdentifierVpcIPv6CidrBlock` stores a single string, misleading in BYO

### Statement

`ensureVpcIPv6CidrBlock` calls `WaitForIPv6Cidr(vpcID)` which returns *one*
IPv6 CIDR association from the VPC and stores it under
`IdentifierVpcIPv6CidrBlock`. A BYO VPC can have multiple IPv6 CIDR
associations (IPAM pool + Amazon-provided, or several IPAM allocations). If
the user's subnets carve from a /56 that is not the first association
returned, all consumers of that state key derive off the wrong block:

- `reconcile.go:509` — main route table `::/0` egress
- `reconcile.go:699` — per-zone SG rule CIDR derivation (Gap A)
- `reconcile.go:1089` — managed subnet creation (irrelevant in BYO)

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:263-273` — the setter
- `pkg/controller/infrastructure/infraflow/reconcile.go:509`, `:699`, `:1089` — consumers

### Options considered

1. **Store per-subnet IPv6 CIDRs in state** rather than one VPC-level string.
   Introduce `IdentifierZoneSubnet{Workers,Public,Private}IPv6CIDR` keys.
   Larger change, needed only if consumers actually depend on the block.
2. **Fix Gap A first, revisit Gap C afterwards.** Once Gap A adopts Shape 3
   the per-zone consumer (`:699`) no longer reads the VPC-level block. The
   remaining consumers are the main route table (`:509`, adds `::/0` egress
   route — the block value is irrelevant, only its presence gates the route)
   and managed subnet creation (`:1089`, unreachable in BYO). Gap C then
   effectively disappears in BYO.

### Decision

**Defer.** Under Gap A's Shape 2, the SG builder no longer reads
`IdentifierVpcIPv6CidrBlock` — it reads per-zone subnet CIDRs from state
instead. The remaining consumers are the main route table (`:509`, adds
`::/0` egress route — the block *value* is irrelevant, only its presence
gates the route) and managed subnet creation (`:1089`, unreachable in BYO).
No functional bug remains in BYO after Shape 2. Revisit only if a future
feature adds a BYO-relevant consumer that needs the value.

### Status

`deferred` pending resolution of Gap A.

### Follow-ups

- If a future change adds a BYO-relevant consumer of the value, promote back
  to `pending` and reconsider Option 1.

---

## Gap D — `validateLBSubnetNotIPv6Native` redundant `CidrBlock == ""` check

### Statement

Initial claim (retracted): `validateLBSubnetNotIPv6Native` at
`configvalidator.go:342` treats a subnet as IPv6-native when
`subnet.CidrBlock == ""` OR `Ipv6Native == true`. The initial claim was
that the first predicate was redundant and could false-positive.

### Evidence

- `pkg/controller/infrastructure/configvalidator.go:338-349` — the check
- `pkg/aws/client/client.go:2661-2689` — `fromSubnet` mapping shows
  `CidrBlock` is only set when AWS returns non-nil non-empty, and
  `Ipv6Native` uses `trueOrNil` (nil unless `true`).

### Decision

**Not a bug.** Re-reading the code, the two predicates are **defensive
complementary checks**, not a redundancy:

- `Ipv6Native == true` catches subnets explicitly marked as IPv6-native by AWS.
- `CidrBlock == ""` catches subnets with no IPv4 CIDR regardless of how AWS categorizes them.

Both mean "cannot host an ALB/NLB" and rejecting them is correct. There
is no realistic false-positive path: `s.CidrBlock` is only left empty
when the AWS response has no IPv4 CIDR, in which case rejection is
warranted.

### Status

`not-a-bug`. Current code is correct and robust.

### Follow-ups

None.

---

## Gap E — `ensureSubnetCidrReservation` first-match across zones without conflict detection

### Statement

`ensureSubnetCidrReservation` iterates all worker subnets and returns as
soon as it finds an existing CIDR reservation matching Gardener's computed
service CIDR. If two zones have *different* reservations already (state
restored from backup, hand-crafted setups), the code silently picks the
first one it walks without warning.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:1444-1475`

### Options considered

1. **Error on divergent reservations.** If two zones have inconsistent
   reservations, return an error listing both, requiring the operator to
   reconcile manually.
2. **Warn only.** Log a warning but proceed with the first match.
3. **Do nothing.** Rely on the fact that in normal operation Gardener writes
   the same value everywhere and this cannot diverge.

### Decision

Sort `subnets` by subnet ID immediately after `collectExistingSubnets`, before
either loop. Subnet IDs are stable AWS-assigned identifiers that never change,
so sorting gives a deterministic, reproducible selection order regardless of
what AWS returns. The state anchor (line 1695) makes the sort irrelevant on
normal reconciles; it only matters when state is absent and multiple subnets
already have reservations — exactly the edge case Gap E describes.

### Status

`implemented` on `byo-subnet3`.

**Resolved by**: sort `subnets` by `SubnetId` in `ensureSubnetCidrReservation`
(`reconcile.go`, after `collectExistingSubnets`).

---

## Gap F — EFS ingress rule is dead code in every mode

### Statement

`ruleEfsInboundNFS` opens TCP 2049 ingress on the nodes SG from `zone.Internal`
(IPv4) and from a derived internal /64 (IPv6). Analysis of the topology shows
the rule is redundant in every mode:

- Managed mode: mount target ENI is placed in the workers subnet
  (`reconcile.go:2371`) and attached to the nodes SG
  (`reconcile.go:2379`). The self-referencing base rule (`Self: true`,
  `Protocol: -1`) already allows all traffic between SG members, including
  the NFS traffic between node and mount target.
- BYO mode: `ensureEfs` short-circuits (`reconcile.go:2265-2267`); Gardener
  does not create mount targets. Whatever SG the user attaches to their
  mount target ENI is what controls NFS traffic, not the nodes SG.
- The `zone.Internal` CIDR is where the internal LB subnet lives, not where
  any NFS client to Gardener's mount target lives. No caller ever hits the
  rule.

An existing TODO at `reconcile.go:675-678` already flags this. Once Gap A's
Shape 3 lands, the BYO+IPv6 emission stops. Managed mode still emits the
dead rule.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:675-678` — the TODO
- `pkg/controller/infrastructure/infraflow/reconcile.go:679-728` — rule construction and gating
- `pkg/controller/infrastructure/infraflow/reconcile.go:2265-2287` — BYO EFS skip
- `pkg/controller/infrastructure/infraflow/reconcile.go:2371-2382` — managed mount target creation

### Options considered

1. **Fix the CIDR source to the workers subnet, keep the rule** (intermediate
   step). Managed and BYO both change `ruleEfsInboundNFS`'s source from
   `zone.Internal` / derived-internal-IPv6 to the workers subnet CIDR (from
   config in managed mode, from state after Gap A Shape 2 in BYO). Rule
   becomes semantically aligned with where the NFS client actually lives.
   Still redundant with the self-referencing base rule, so no functional
   change — but the emitted rule is no longer misleading.

2. **Drop the rule entirely (managed and BYO).** Cleanest end state.
   Superseded / subsumed by Gap L. Currently deferred because Gap L breaks
   parity with the existing SG contents on `origin/master` for managed
   clusters — see Gap L for rationale.

3. **Leave as-is.** Preserves history; keeps a rule with a source CIDR that
   corresponds to no NFS caller.

### Decision

Adopt **Option 1**. Change `ruleEfsInboundNFS` to source from the workers
subnet CIDR in both managed and BYO modes. Depends on Gap A Shape 2 for
BYO state availability. Full drop (Option 2) is deferred with Gap L.

### Status

`implemented` on `byo-subnet3`.

**Resolved by**: `721d1c42` — *Point EFS SG ingress rule at workers subnet CIDR, not internal LB subnet (Gap F step 1)*.

### Follow-ups

- Gap L (deferred): if we later revisit and decide to drop the narrow
  rules including EFS, this rule goes away entirely.

---

## Gap G — `getSubnetKey` fallback depends on state written earlier in the same reconcile

### Statement

`getSubnetKey` uses a fallback path for BYO / IPv6-single-stack that reads
subnet IDs from the flow state (`reconcile.go:2450-2457`). This works today
because `ensureSubnetCidrReservation` (which calls `getSubnetKey`) is a
dependency of `ensureZones` (which writes the state via `ensureBYOZones`).
The ordering is correct at present but nothing enforces it — a future
reordering could regress silently.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:112` — dependency graph
- `pkg/controller/infrastructure/infraflow/reconcile.go:2442-2489` — `getSubnetKey`
- `pkg/controller/infrastructure/infraflow/reconcile.go:790-889` — `ensureBYOZones` writes state

### Options considered

1. **Add a unit test** exercising `getSubnetKey` with empty state to document
   the invariant and fail fast if it regresses.
2. **Refactor** `getSubnetKey` to not depend on state at all (e.g., derive
   from subnet tags only).

### Decision

Option 1 implemented. Three `Entry` specs at the bottom of
`reconcile_getsubnetkey_test.go` (lines 138–149) cover BYO dual-stack with
empty state for each subnet purpose (workers, public, internal). They assert
that `getSubnetKey` returns an error when state has not been populated,
documenting the invariant that `ensureBYOZones` must run before any caller
of `getSubnetKey` in BYO mode.

### Status

`implemented` on `byo-subnet3` — contract tests already present in
`reconcile_getsubnetkey_test.go`.

---

## Gap H — No test coverage for BYO + IPv6/dual-stack reconcile paths

### Statement

Existing tests cover:

- `pkg/controller/infrastructure/infraflow/nodes_security_group_internal_test.go` — IPv6-only SG rule shape, no BYO
- `pkg/controller/infrastructure/infraflow/reconcile_getsubnetkey_test.go` — the `getSubnetKey` fix

There is no reconcile-level or integration-level test for BYO+IPv6-single-stack
or BYO+dual-stack. Given the fragility exposed by Gaps A, C, E, this is where
regressions will land unseen.

### Evidence

- `pkg/controller/infrastructure/infraflow/nodes_security_group_internal_test.go`
- `pkg/controller/infrastructure/infraflow/reconcile_getsubnetkey_test.go`
- `test/integration/infrastructure_test.go` — no dual-stack BYO scenario

### Options considered

1. **Unit test** on `ensureNodesSecurityGroup` (or the extracted rule builder)
   with a fake AWS client. Three cases: BYO+IPv4, BYO+dual-stack (with LB
   subnets), BYO+dual-stack (no LB subnets, pre-tagged only). Assert the
   emitted rule set explicitly.
2. **Integration test** in `test/integration/infrastructure_test.go` with a
   BYO+dual-stack scenario. Requires an AWS account; slower.
3. **Both.**

### Decision

`pending` — Option 1 mandatory alongside the Gap A fix; Option 2 as a
follow-up.

### Status

`pending`.

---

## Gap I — No validation of BYO route table IPv6 default route

### Statement

Initial claim (retracted): "For BYO+IPv6, worker nodes need IPv6 egress —
either an egress-only IGW route (private) or a full IGW route (public).
If the user's route table lacks a `::/0` route, nodes have no IPv6 egress.
The current configvalidator verifies IPv4 route tables but not the IPv6
default route."

### Evidence

- `pkg/controller/infrastructure/configvalidator.go` — no `::/0` route check
- BYO principle documented in the proposal: "In BYO mode, Gardener does
  **not** create any route tables, NAT gateways, or Internet Gateways.
  The user is fully responsible for all routing."
  (`docs/proposals/flexible-network-configuration.md:504`).

### Decision

**Not-a-bug / over-engineered.** A `::/0` route is the *standard* way to
provide IPv6 egress but is not the only way. Legitimate BYO
configurations may use:

- Specific-prefix routes only (to seed API server, container registries,
  AWS VPC endpoints)
- NAT64 setups routing `64:ff9b::/96` at a NAT64 gateway
- Hub-and-spoke via TGW/peering where the local table routes by specific
  prefix, not `::/0`

Gardener does not validate a `0.0.0.0/0` route for the IPv4 case either;
the BYO principle is "user manages routing". Symmetric behavior for
IPv6 = don't validate. Requirement stays a documentation concern.

A validator check would produce false positives for the legitimate
configurations above and violate the BYO principle. Retracted before
committing.

### Status

`not-a-bug`. Requirement should be captured in user-facing documentation
(usage guide or proposal FAQ), not enforced by the configvalidator.

### Follow-ups

- Consider adding a note to `docs/proposals/flexible-network-configuration.md`
  or a usage guide that IPv6 egress is the user's responsibility in BYO mode
  and that `::/0` via egress-only IGW / IGW is the simplest option; other
  routing shapes are equally valid.

---

## Gap J — Multiple IPv6 CIDRs on the same subnet handled non-deterministically

### Statement

`reconcile.go:1460`, `:1493`, `configvalidator.go:314` all read
`subnet.Ipv6CidrBlocks[0]` unconditionally. AWS allows multiple IPv6 CIDR
associations per subnet. If a BYO subnet has more than one, code silently
picks the first, which is neither deterministic across restarts nor
predictable for the user.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:1460`, `:1493`
- `pkg/controller/infrastructure/configvalidator.go:314`

### Options considered

1. **Error out** if `len(Ipv6CidrBlocks) > 1`, requiring the user to remove
   the ambiguity.
2. **Add a config field** to let the user select which CIDR to use.
3. **Do nothing.** Rely on documentation.

### Decision

**Option 1** implemented. Added an explicit check in
`validateSubnetIPv6Readiness` that errors when a BYO subnet has more than
one IPv6 CIDR association, listing the discovered CIDRs and asking the
user to remove the extras. The check is guarded by `requiresIPv6` in the
caller, so IPv4-only clusters are unaffected.

### Status

`resolved` by commit `8d743663`.

### Follow-ups

- Future extension: instead of hard-rejecting multiple IPv6 associations,
  disambiguate by matching against the shoot's networking spec
  (`shoot.spec.networking.nodes` / `.pods` / `.services`, or the
  `ipFamilies` order). If exactly one subnet IPv6 CIDR contains the
  shoot-declared node/pod network, pick that one; otherwise still error.
  Reasonable enhancement when a use case for multi-IPv6-CIDR BYO subnets
  emerges — until then, Option 1's hard reject is the safer default.

---

## Gap K — Spurious dependency: `ensureZones` requires `ensureNodesSecurityGroup`

### Statement

The dependency graph at `reconcile.go:104` declares that `ensureZones`
depends on `ensureNodesSecurityGroup`. Grepping for
`IdentifierNodesSecurityGroup` shows no reader inside the zones code path;
only `ensureEfs` (which already depends on `ensureZones`, not
`ensureNodesSecurityGroup` directly) and status computation use it. The
dependency appears to be historical inertia and adds artificial ordering.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:98-104` — declaration
- `pkg/controller/infrastructure/infraflow/reconcile.go` — no reads of
  `IdentifierNodesSecurityGroup` between lines 782 and 1400 (the zones code)

### Options considered

1. Remove the dependency, add a comment documenting the independence.
2. Leave as-is (conservative).
3. **Reverse the dependency**: make `ensureNodesSecurityGroup` depend on
   `ensureZones`. This is what Gap A's Shape 2 requires so the SG builder
   can read per-zone subnet CIDRs from state.

### Decision

Resolved by Gap A Shape 2 (Option 3). The dependency will be reversed as
part of Shape 2 implementation, and a comment will document that the SG
builder now needs the per-zone subnet CIDRs populated by `ensureBYOZones`.

### Status

`implemented` on `byo-subnet3` — resolved as part of Gap A Shape 2. The
graph now reads:

- `ensureZones` depends on `ensureVpc, ensureVpcIPv6CidrBloc, ensureMainRouteTable` (no longer depends on `ensureNodesSecurityGroup`).
- `ensureNodesSecurityGroup` depends on `ensureVpc, ensureZones` (SG moved after zones so per-zone subnet CIDRs are in state when the rules are built).
- `ensureEfs` depends on `ensureNodesSecurityGroup` (transitively covers `ensureZones` via the SG->zones dep).

---

## Gap L — Narrow per-zone NodePort SG rules are redundant with the base wide rules

### Statement

For each zone, `ensureNodesSecurityGroup` emits narrow per-zone rules that
allow TCP/UDP 30000-32767 ingress from `zone.Internal` and `zone.Public`
CIDRs (`reconcile.go:686-716`). The base rules at `reconcile.go:573-601`
already allow the same port range from `0.0.0.0/0` and `::/0`. The narrow
rules are therefore strict subsets of the base rules — they permit nothing
new. They exist in production today for both managed and BYO modes (BYO
IPv6 gets them with wrong CIDRs, per Gap A). Removing them changes
functionality zero.

This gap tracks the eventual cleanup: once Gap A Shape 2 lands and the
narrow rules are correctly populated in BYO with real subnet CIDRs, we can
audit whether they carry any value and, if not, drop them symmetrically in
both modes.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:573-601` — base rules with `0.0.0.0/0` / `::/0` NodePort ingress
- `pkg/controller/infrastructure/infraflow/reconcile.go:686-716` — narrow per-zone rules
- Proposal `docs/proposals/flexible-network-configuration.md:463` — documents `0.0.0.0/0` as the intended NodePort source

### Options considered

1. **Drop the narrow per-zone rules** in both managed and BYO modes. Rely on
   the base wide rules for NodePort ingress. Emits a smaller, cleaner SG.
2. **Keep the narrow rules and tighten the base rules.** Change the base
   NodePort ingress from `0.0.0.0/0` to something narrower (e.g., the union
   of all LB subnet CIDRs). Requires knowing all LB subnets at SG creation
   time, adds real security value, but is a proposal-level change (the
   proposal explicitly documents `0.0.0.0/0` as intended).
3. **Leave as-is.** No harm today; wastes rule slots and emits misleadingly
   "tight-looking" rules.

Option 2 is a genuine security tightening but out of scope for this PR — it
would require a proposal update and consideration of cross-AZ NLB traffic
patterns. Option 1 is a mechanical cleanup that reflects current reality.

### Decision

**Deferred.** Dropping the narrow rules would break parity with the SG
contents of existing managed clusters running today's `origin/master`.
Anyone auditing / counting SG rules would see 4-5 rules per zone disappear
on the first reconcile after the change. Functionally zero-impact
(base wide rules cover NodePort; self-ref covers EFS), but observably
different in a way that's hard to communicate and risky to ship without
external coordination.

Revisit only when there is an explicit reason to slim the SG (e.g.,
approaching the AWS 60-rule-per-SG default, or a compliance review flags
redundant rules as an issue).

### Status

`deferred`. Depends on parity requirements being relaxed.

### Follow-ups

- If revisited, the change is one commit: delete the narrow-rule block in
  `ensureNodesSecurityGroup` (`reconcile.go` around lines 686-728), delete
  `resolveZoneCIDRs`, and delete the BYO subnet CIDR state caching if no
  future consumer materializes (currently only the SG builder reads
  those state keys). Regression tests: update
  `nodes_security_group_internal_test.go` and delete
  `reconcile_resolve_cidrs_test.go`.
- Would also resolve Gap N (managed IPv6 offset bug) as a side effect.

---

## Gap M — Test-style inconsistency in `pkg/controller/infrastructure/infraflow`

### Statement

The package `pkg/controller/infrastructure/infraflow` contains tests in two
different styles:

- **Ginkgo/Gomega BDD** (`Describe` / `Context` / `It` /
  `DescribeTable+Entry`): `reconcile_getsubnetkey_test.go`,
  `reconcile_resolve_lb_cidrs_test.go` (added in this PR), and
  `utils_test.go` (partial — uses ginkgo suite bootstrap in
  `infraflow_suite_test.go`).
- **Plain `testing.T` + subtests + Gomega**:
  `nodes_security_group_internal_test.go` (introduced by PR#1833,
  `@shreyas-s-rao`, 2026-06-08).

Both styles are already wired into the suite (see
`infraflow_suite_test.go`'s `TestInfraflow` bootstrap which invokes
`RunSpecs` — ginkgo specs run there; the `testing.T`-based test runs in
parallel as an ordinary Go test). Neither approach is broken today, but
the mix increases cognitive load for reviewers and makes it harder to keep
tests uniform going forward (e.g., shared fixtures, table-driven
extension, focus/skip semantics differ).

The rest of the repository leans ginkgo/Gomega for controller tests, so
converging on ginkgo here is the natural direction.

### Evidence

- `pkg/controller/infrastructure/infraflow/infraflow_suite_test.go` — ginkgo suite bootstrap
- `pkg/controller/infrastructure/infraflow/nodes_security_group_internal_test.go` — plain `testing.T`
- `pkg/controller/infrastructure/infraflow/reconcile_getsubnetkey_test.go` — ginkgo
- `pkg/controller/infrastructure/infraflow/reconcile_resolve_lb_cidrs_test.go` — ginkgo (added in this PR)
- PR#1833 (`@shreyas-s-rao`) introduced the plain-`testing.T` file for the
  EFA egress rule regression test.

### Options considered

1. **Convert `nodes_security_group_internal_test.go` to ginkgo.** Rewrite
   the three `t.Run` blocks as `It` blocks under a `Describe("computeNodesSecurityGroupBaseRules")` group. Preserves all
   coverage; unifies the style. Small, mechanical diff.
2. **Convert the ginkgo tests to plain `testing.T`.** Larger change (four
   files affected, including two ginkgo-native `DescribeTable` structures);
   also diverges from the rest of the repo's controller-test convention.
3. **Leave as-is.** Both styles work; no functional problem.

### Decision

Option 1 implemented. Rewrote `nodes_security_group_internal_test.go` as four
`It` blocks under `Describe("computeNodesSecurityGroupBaseRules")`. All
assertions preserved verbatim; `testing` import dropped; `NewWithT(t)` calls
replaced with top-level `Expect`.

### Status

`implemented` on `byo-subnet3`.

### Follow-ups

- When implementing: preserve the exact assertions from
  `TestComputeNodesSecurityGroupBaseRules`'s three subtests. The IPv6-only
  subtest has an off-by-one bug that should be preserved verbatim during
  the conversion and handled in a separate commit if a fix is desired: it
  asserts `rules[3]` is the "v4 0.0.0.0/0 egress rule" but expects
  `CidrBlocks` to be `BeNil()` — for IPv4 that's the correct assertion, but
  for IPv6-only workers the rule at index 3 is the (nil-v4, ::/0-v6) egress
  rule, so the assertion still holds. No fix needed on rewrite — just be
  careful when transcribing.

---

## Gap N — Managed-mode IPv6 offsets for internal/public LB narrow rules are wrong

### Statement

The SG rule builder derives internal/public IPv6 CIDRs from the VPC's /56 using
offsets `2+3*index` (internal) and `3+3*index` (public). The managed subnet
creation code (`ensureManagedZones`) uses **different** offsets — `0+3*index`
for workers, `1+3*index` for internal, `2+3*index` for public. So on a managed
dual-stack cluster:

- The "internal LB" narrow SG rule references the CIDR of the **public** subnet (offset `2+3*index`, which is actually where the public subnet lives).
- The "public LB" narrow SG rule references a CIDR that is **out of range** for this zone (offset `3+3*index`, which corresponds to the next zone's workers subnet, or doesn't exist for the last zone).

This is a pre-existing bug on `origin/master` (predates PR#1741). Was preserved
verbatim in `resolveZoneLBCIDRs` when the SG code was refactored under Gap A
Shape 2 — my `derivedInternalV6Idx0` test constant literally asserts the buggy
value.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:1249-1305` — managed subnet creation. The loop at line 1253 computes `subnetCIDRs[i]` at offset `i+3*index` for i=0,1,2. Then the append order (line 1271) is workers, private, public. Then the assign loop (line 1300) writes `subnetCIDRs[i]` to `desired[i+3*index].Ipv6CidrBlocks`. Net: workers = offset 0, private = offset 1, public = offset 2.
- `pkg/controller/infrastructure/infraflow/reconcile.go:670-678` — `resolveZoneLBCIDRs` uses `internalV6 = cidrSubnet(*ipv6CidrBlock, 64, 2+3*index)` (should be 1) and `publicV6 = cidrSubnet(*ipv6CidrBlock, 64, 3+3*index)` (should be 2).
- `pkg/controller/infrastructure/infraflow/reconcile_resolve_lb_cidrs_test.go` — the test constants `derivedInternalV6Idx0` and `derivedPublicV6Idx0` encode the buggy offsets. Any fix must also update the test expectations.

### Impact

Silent. The narrow LB rules are strict subsets of the wide base rules (Gap L),
so the emitted rules point at wrong CIDRs that no traffic flows through. Base
rules cover the actual NLB traffic on `::/0` NodePort ingress. Only observable
effect: the emitted SG has bogus rule entries.

### Options considered

1. **Fix the offsets in `resolveZoneLBCIDRs`** (`2+3*index` → `1+3*index` for internal, `3+3*index` → `2+3*index` for public). Update the two test constants. Small mechanical change.
2. **Do nothing.** Gap L is scheduled to drop the narrow LB rules entirely, at which point the offsets don't matter. Fixing them just to delete the code shortly after is wasted motion.

### Decision

Adopt **Option 2 (do nothing)** for now. The bug is silent and Gap L
would eliminate the code that contains it — but Gap L is now `deferred`.
Left in place with explicit code comments in `resolveZoneCIDRs` and the
test suite so anyone reading the offsets understands they're preserved
knowingly. Test constants `derivedInternalV6Idx0` and `derivedPublicV6Idx0`
encode the buggy values with `Gap N` comments.

### Status

`accepted-as-silent-bug` — no fix planned in this PR. The observable
impact is zero (rules point at wrong CIDRs but no traffic flows through
them; wide base rules cover the actual traffic). Promoting to `pending`
requires a concrete reason to fix the offsets ahead of Gap L.

### Follow-ups

- If Gap L is later un-deferred, Gap N gets fixed automatically (rules
  deleted).
- If a security review flags "rules with wrong source CIDRs" as an issue,
  fix the offsets: `2+3*index -> 1+3*index` for internal,
  `3+3*index -> 2+3*index` for public. Update test constants
  `derivedInternalV6Idx0 -> 2001:db8:1234:5601::/64` and
  `derivedPublicV6Idx0 -> 2001:db8:1234:5602::/64`.

---

# Review threads still open

Below are Alex Hebel's (`@hebelsan`) review threads on PR#1741 that are not
yet closed. Some are already fixed in code but need a thread reply to close
the loop.

## Thread 1 — Removed state deletion in `deleteNATGateway`

### Statement

Alex noticed `child.Delete(IdentifierZoneNATGateway)` was removed from
`deleteNATGateway`. No reply from author, no code change since.

### Evidence

- PR#1741 discussion_r3111292541 (2026-04-20)
- `pkg/controller/infrastructure/infraflow/reconcile.go:1356` (as of the time of the comment)

### Decision

Restored. Investigation established:

- The removal was accidental — dropped by commit `f60d1612` (*Align cluster tag values with AWS convention (owned/shared)*), a commit unrelated to NAT lifecycle whose stated purpose is tag conventions.
- The pattern established by every sibling delete function (`deleteSubnet`, `deleteElasticIP`, `deletePrivateRoutingTable`) is to clear the corresponding state key after successful AWS deletion. `deleteNATGateway` was the outlier.
- The observable effect of the removal is nil — subsequent code paths (short-circuit at top of `deleteNATGateway` for retries; `FindExisting` fallback in `ensureRecreateNATGateway` → `ensureNATGateway` for the EIP-swap flow) either overwrite the stale state key or handle its staleness gracefully. But the removal defeated the intended short-circuit optimization and broke the sibling-pattern invariant *"if `IdentifierZoneNATGateway` is set, the NAT gateway exists in AWS"*.

Restored by adding `child.Delete(IdentifierZoneNATGateway)` after the successful `DeleteNATGateway` call, with an inline comment referencing the accidental removal.

### Status

`resolved` by commit `65b503d8` — *Restore child.Delete(IdentifierZoneNATGateway) after NAT deletion*.

---

## Thread 2 — Wrong field path in `nodesSecurityGroupID` immutability error

### Statement

The field path should be `field.NewPath("networks").Child("nodesSecurityGroupID")`.

### Evidence

- PR#1741 discussion_r3111404389 (2026-04-20)
- `pkg/apis/aws/validation/infrastructure.go:365`

### Decision

Resolved by commit `e1b874cc` (*Address review: dual-stack pre-flight, getSubnetKey BYO fix, validation improvements*) which changed
`field.NewPath("networks.nodesSecurityGroupID")` to
`field.NewPath("networks").Child("nodesSecurityGroupID")` at
`pkg/apis/aws/validation/infrastructure.go:420`.

### Status

`resolved`. No GitHub reply owed.

---

## Thread 5 — Duplicate doc file `docs/usage/flexible-network-configuration.md`

### Statement

Alex noted this file duplicates the proposal doc. No reply, file still
present.

### Evidence

- PR#1741 discussion_r3116344275 (2026-04-21)
- `docs/usage/flexible-network-configuration.md` (still exists)

### Decision

Resolved by commit `e1b874cc`. The duplicate file
`docs/usage/flexible-network-configuration.md` was deleted; the content
now lives only in `docs/proposals/flexible-network-configuration.md`.

### Status

`resolved`. No GitHub reply owed.

---

## Thread 6 — Missing default value in CCM chart `values.yaml`

### Statement

Add `disableServiceController: false` default in the CCM chart's
`values.yaml`.

### Evidence

- PR#1741 discussion_r3123247330 (2026-04-22)
- `charts/internal/seed-controlplane/charts/cloud-controller-manager/templates/deployment.yaml:49`

### Decision

Resolved by commit `e1b874cc`. `disableServiceController: false` is now
declared in `charts/internal/seed-controlplane/charts/cloud-controller-manager/values.yaml:8`.

### Status

`resolved`. No GitHub reply owed.

---

## Thread 8 — Redundant BYO error branch in second loop of `ensureSubnetCidrReservation`

### Statement

The first loop in `ensureSubnetCidrReservation` was made to error out in BYO
mode when the worker subnet has no IPv6 CIDR (thread 7 fix). The second
loop then contains an identical BYO-error branch that is dead code — the
first loop already errored.

### Evidence

- `pkg/controller/infrastructure/infraflow/reconcile.go:1486-1491`
- PR#1741 discussion_r3124474554 (2026-04-22), thread 8

### Decision

Resolved by commit `0e68128a` (*Remove dead BYO error branch in
ensureSubnetCidrReservation second loop*). The BYO-error branch in the
second loop was removed; a comment was added explaining that the first
loop already handles the BYO-with-missing-IPv6 case, so this branch was
unreachable.

### Status

`resolved`. No GitHub reply owed.

---

## Thread 9 — Notify Alex that the pre-tagged-subnet issue is addressed

### Statement

Alex flagged that pre-tagged LB subnets silently disabled the service
controller because `infraStatus.VPC.Subnets` never got populated. The fix
(`discoverTaggedSubnets` + state write + status computation) is implemented,
but Alex has not been notified. Author replied "let me double-check" but
did not follow up.

### Evidence

- PR#1741 discussion_r3136487969 (2026-04-24)
- `pkg/controller/infrastructure/infraflow/reconcile.go:971-1073` (discoverTaggedSubnets)
- `pkg/controller/infrastructure/infraflow/utils.go:286-300` (state → status mapping)
- `pkg/controller/controlplane/valuesprovider.go:660-664` (service-controller gate)

### Decision

Code fix already in place: `discoverTaggedSubnets` at
`pkg/controller/infrastructure/infraflow/reconcile.go:971-1073` writes
discovered LB subnets to per-zone state; `utils.go:286-300` maps those
state keys into `infraStatus.VPC.Subnets` with the correct purpose;
`pkg/controller/controlplane/valuesprovider.go:660-664` reads them and
keeps the service controller enabled when at least one public or internal
subnet is discovered.

Under Shape 2 (commit `6cfdd544`), the same code path also caches the
discovered LB subnet CIDRs, closing the parity gap between explicit-ID
and pre-tagged-discovery BYO variants at the SG-builder level too.

### Status

`resolved`. No GitHub reply owed — the code is done and if Alex wants
verification he can inspect the referenced lines.

---

## Thread 10 — Should mixed-zone BYO LB configuration be rejected?

### Statement

Alex asked whether it makes sense to allow one zone with public/internal
subnets and another without. For dual-stack in particular, inconsistent
IPv6-enabled LB subnets across AZs would leave certain zones unreachable
over IPv6.

### Evidence

- PR#1741 discussion_r3136593423 (2026-04-24)
- `pkg/apis/aws/validation/infrastructure.go` — no uniformity check across zones

### Options considered

1. **Require uniformity** across zones: either all zones have public/internal
   LB subnet IDs, or none do.
2. **Warn only**, allow the mix.
3. **Do nothing**, document the pitfall.

### Decision

**Option 1** — resolved by commit `e1b874cc`. Validation at
`pkg/apis/aws/validation/infrastructure.go:161-191` enforces that if any BYO
zone specifies `publicSubnetID`, all BYO zones must specify it; same for
`internalSubnetID`. Mixed configurations are rejected with a
`field.Required` error pointing at the missing entry.

### Status

`resolved` by commit `e1b874cc`.

---

## Thread 13 — Doc note: recommend >=8 free IPs per LB subnet

### Statement

The aws-load-balancer-controller enforces
`defaultMinimalAvailableIPAddressCount = 8` only during tag-based
auto-discovery, not for explicit subnet IDs. Alex agreed a doc note in the
usage guide is sufficient; the hard validator check was rejected.

### Evidence

- PR#1741 discussion_r3145593749 (2026-04-27) + author replies + Alex's
  2026-07-02T13:36:06Z reply

### Decision

Resolved by commit `e1b874cc`. The 8-IPs-per-LB-subnet recommendation is
now in the proposal at `docs/proposals/flexible-network-configuration.md`
(lines 307 and 625).

### Status

`resolved`. No GitHub reply owed.

---

# Proposal / documentation issues

## Doc-1 — Proposal line 432 names non-existent CCM function

### Statement

The proposal states that `DisableSecurityGroupIngress=true` disables the
CCM's `updateInstanceSecurityGroupForNLBTraffic` and
`updateInstanceSecurityGroupsForLoadBalancer` functions. The first function
name does not exist in `cloud-provider-aws`. The real function is
`updateInstanceSecurityGroupsForNLB` (plural "Groups", no "Traffic"
suffix), defined in `pkg/providers/v1/aws_loadbalancer.go`. The outcome
(both classic ELB and NLB node-SG mutations are disabled) is correct; only
the naming is wrong.

### Evidence

- `docs/proposals/flexible-network-configuration.md:432`
- cloud-provider-aws `pkg/providers/v1/aws.go:2980-2983` — classic ELB gate
- cloud-provider-aws `pkg/providers/v1/aws_loadbalancer.go:977-980` — NLB gate
  (both check `Global.DisableSecurityGroupIngress`)

### Decision

Corrected. The real function name is `updateInstanceSecurityGroupsForNLB`
(plural "Groups", no "Traffic" suffix).

### Status

`implemented` on `byo-subnet3`.

---

## Doc-2 — Proposal does not mention `NLBSecurityGroupMode`

### Statement

Beyond `DisableSecurityGroupIngress`, the CCM's NLB behavior is also
governed by `NLBSecurityGroupMode`. Gardener leaves this unset, which is
the "unmanaged" default: no SG is attached to the NLB, no rules programmed
on any per-service SG. Only `Managed` is a defined constant; any other
value errors out; empty means unmanaged. The proposal should reference this
knob so future changes to CCM config are made with full context.

### Evidence

- cloud-provider-aws `pkg/providers/v1/config/config.go:29-33`, `:228-236`
- `pkg/providers/v1/aws.go:2274-2325` — `ensureNLBSecurityGroup`
- `charts/internal/cloud-provider-config/templates/cloud-provider-config.yaml` — no `NLBSecurityGroupMode` set

### Decision

`implemented` — added a paragraph to point 3 of the Full Replacement Model
section explaining that `NLBSecurityGroupMode` is left unset (unmanaged default)
and what that means.

### Status

`implemented` on `byo-subnet3`.

---

## Doc-3 — "or LB subnet CIDRs" wording overstates Gardener's tightening capability

### Statement

The proposal (line 458-459) lists NodePort ingress source as "`0.0.0.0/0`
or LB subnet CIDRs." This applies to the Full Replacement Model (user
brings their own SG). For the case *Gardener-managed SG + BYO subnets*,
Gardener does not currently discover the user's LB subnet CIDRs and cannot
program the tighter alternative. Readers infer capability that does not
exist.

### Evidence

- `docs/proposals/flexible-network-configuration.md:456-459`
- `pkg/controller/infrastructure/infraflow/reconcile.go:686-716` — no BYO-aware CIDR discovery

### Decision

`implemented` — reworded the table rows to `0.0.0.0/0 (or your LB subnet CIDRs)`
and added a clarifying note to the NodePort callout that the tighter option
applies only when the user provides their own SG, not when Gardener manages it.

### Status

`implemented` on `byo-subnet3`.

---

## Doc-4 — No documented behavior for Gardener-managed SG combined with BYO subnets

### Statement

The proposal covers Full Replacement (BYO SG) and Additive (deferred) modes.
It does not cover the case in scope for this PR: Gardener creates and
manages the nodes SG, but the user brings the subnets. This mode has
distinct behavior — the per-zone LB-CIDR narrowing rules that make sense in
managed mode do not make sense here, and Gardener falls back to the base
wide rules (`0.0.0.0/0` / `::/0`) for NodePort ingress. Without documentation
this looks like an oversight rather than a design choice.

### Evidence

- `docs/proposals/flexible-network-configuration.md` — sections around lines 420-500 cover BYO SG modes but not the Gardener-SG-with-BYO-subnets hybrid.
- Post-Gap-A code: `pkg/controller/infrastructure/infraflow/reconcile.go:686-716` will skip per-zone rules in BYO for both IPv4 and IPv6.

### Decision

`implemented` — added a "Hybrid: Gardener-Managed SG with BYO Subnets"
subsection after the Additive Model section documenting the rule shape,
the absence of `DisableSecurityGroupIngress`, the authoritative reconcile
behaviour, and the NodePort-tightening limitation.

### Status

`implemented` on `byo-subnet3`.

---

# PR#1741 thread index

Chronological. Numbers match this document; the "status on branch" column
reflects the state of `byo-subnet3` as read on 2026-07-12.

| # | Reviewer | Date | File:line | Topic | Status on branch |
|---|---|---|---|---|---|
| 1 | hebelsan | 2026-04-20 | reconcile.go:1356 | Removed state deletion | resolved by `65b503d8` |
| 2 | hebelsan | 2026-04-20 | validation/infrastructure.go:365 | Wrong field path | resolved by `e1b874cc` |
| 3 | hebelsan | 2026-04-20 | reconcile.go:750 | `hasCIDRs` placement | addressed (utils.go:364) |
| 4 | hebelsan | 2026-04-20 | context.go:299 | Filter builder API | addressed (client/filter.go, reconcile.go:994) |
| 5 | hebelsan | 2026-04-21 | docs/usage/flexible-network-configuration.md | Duplicate doc | resolved by `e1b874cc` (file deleted) |
| 6 | hebelsan | 2026-04-22 | ccm chart deployment.yaml:49 | Missing values.yaml default | resolved by `e1b874cc` |
| 7 | hebelsan | 2026-04-22 | reconcile.go:1433 | Silent `continue` in `ensureSubnetCidrReservation` | addressed (BYO error branch added by `e1b874cc`) |
| 8 | hebelsan | 2026-04-22 | reconcile.go:1462 | Redundant second check | resolved by `0e68128a` |
| 9 | hebelsan | 2026-04-24 | valuesprovider.go:659 | Pre-tagged subnets disable service controller | resolved (discoverTaggedSubnets + Shape 2 CIDR caching) |
| 10 | hebelsan | 2026-04-24 | validation/infrastructure.go | Mixed zone LB config | resolved by `e1b874cc` |
| 11 | hebelsan | 2026-04-24 | example/30-infrastructure.yaml:66 | Auto-tag lifecycle | addressed (TagKeyManagedByGardener marker) |
| 12 | hebelsan | 2026-04-24 | configvalidator.go:268 | Shoot-level dual-stack validation | addressed (`requiresIPv6` from `ipFamilies`) |
| 13 | hebelsan | 2026-04-27 | configvalidator.go (file) | Prerequisite checks (DNS, node CIDR, 8 IPs, NAT/TGW/VPCE) | resolved by `e1b874cc` — DNS + node CIDR implemented; 8-IP doc note added to proposal; NAT/TGW/VPCE deferred with mutual agreement |

Alex's fix PR `kon-angelo/gardener-extension-provider-aws#1` ("Fix: subnet
key retrieval for BYO mode") is superseded by commit `e1b874cc` on this
branch.

---

# Pre-merge test scenarios

## T1 — Managed mode IPv4 (regression baseline)

No BYO fields. Expected: VPC, subnets, SG, NAT GW, IGW all created by
Gardener. Verifies existing managed-mode clusters are not broken by this PR.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t1-managed-ipv4
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          cidr: 10.180.0.0/16
        zones:
        - name: eu-west-1a
          workers: 10.180.0.0/19
          public: 10.180.32.0/20
          internal: 10.180.48.0/20
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t1
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T2 — Managed mode dual-stack (regression baseline)

Same as T1 but with `ipFamilies: [IPv4, IPv6]`. Expected: IPv6 CIDR block
associated with VPC and subnets; `/108` service CIDR reservation created on
the worker subnet.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t2-managed-ds
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          cidr: 10.180.0.0/16
        zones:
        - name: eu-west-1a
          workers: 10.180.0.0/19
          public: 10.180.32.0/20
          internal: 10.180.48.0/20
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t2
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
    ipFamilies:
    - IPv4
    - IPv6
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T3 — BYO full replacement: workers + LB subnets + BYO SG

The canonical BYO scenario. Gardener tags the subnets but creates nothing.
Expected: no VPC/subnet/SG/NAT resources created; cluster tags added to BYO
subnets; `infraStatus.VPC.Subnets` populated; service controller enabled.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: test-byo-full
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: vpc-0a505268b4eb6b992
        nodesSecurityGroupID: sg-0363704da788859a6
        zones:
        - name: eu-west-1a
          workersSubnetID: subnet-08d39a8417f63b266
          publicSubnetID: subnet-04c69738e600ab28f
          internalSubnetID: subnet-0769ddd7e067e26a4
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t3
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T4 — BYO hybrid: workers + LB subnets, Gardener-managed SG

User brings subnets; Gardener creates and manages the nodes SG.
Expected: SG created with base rules + narrow per-zone NodePort rules
sourced from real BYO subnet CIDRs; `DisableSecurityGroupIngress` NOT set.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: test-byo-hybrid
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: <vpc-id>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-eu-west-1a>
          publicSubnetID: <subnet-public-eu-west-1a>
          internalSubnetID: <subnet-internal-eu-west-1a>
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t4
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T5 — BYO workers only (no LB subnets, Gardener-managed SG)

Workers subnet only; no LB subnets. Expected: SG created with base rules
only (no narrow per-zone rules); service controller disabled in CCM config.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t5-byo-workers
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: <vpc-id>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-eu-west-1a>
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t5
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T6 — BYO + pre-tagged LB subnets (no explicit LB subnet IDs)

Workers subnet provided; LB subnets pre-tagged in AWS (not named in config).
Expected: `discoverTaggedSubnets` finds them; `infraStatus.VPC.Subnets`
populated; service controller enabled; SG narrow rules sourced from
discovered CIDRs.

Pre-tag the LB subnets in AWS before creating the shoot:
```
kubernetes.io/cluster/shoot--garden-remote--t6-byo-tagged = shared
kubernetes.io/role/elb = 1          # on the public LB subnet
kubernetes.io/role/internal-elb = 1 # on the internal LB subnet
```

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t6-byo-tagged
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: <vpc-id>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-eu-west-1a>
          # no publicSubnetID / internalSubnetID — discovery via tags
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t6
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T7 — BYO + dual-stack (IPv4+IPv6), single zone

Workers subnet has both IPv4 and IPv6 CIDRs. Expected:
`ensureSubnetCidrReservation` creates a `/108` reservation on the worker
subnet; `infraStatus` carries the service CIDR; SG rules contain both v4
and v6 CIDRs in per-zone rules.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t7-byo-ds
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: <vpc-id-with-ipv6>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-dualstack-eu-west-1a>   # must have an IPv6 CIDR block
          publicSubnetID: <subnet-public-dualstack-eu-west-1a>
          internalSubnetID: <subnet-internal-dualstack-eu-west-1a>
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t7
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
    ipFamilies:
    - IPv4
    - IPv6
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T8 — BYO + dual-stack, two zones (Gap E determinism)

Same as T7 but two zones. Verifies that the `/108` reservation is created
on exactly one worker subnet (the one with the lexicographically smallest
subnet ID after the Gap E sort) and the second zone's worker subnet gets no
conflicting reservation.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t8-byo-ds-mz
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: <vpc-id-with-ipv6>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-dualstack-eu-west-1a>
          publicSubnetID: <subnet-public-dualstack-eu-west-1a>
          internalSubnetID: <subnet-internal-dualstack-eu-west-1a>
        - name: eu-west-1b
          workersSubnetID: <subnet-workers-dualstack-eu-west-1b>
          publicSubnetID: <subnet-public-dualstack-eu-west-1b>
          internalSubnetID: <subnet-internal-dualstack-eu-west-1b>
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t8
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      - eu-west-1b
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
    ipFamilies:
    - IPv4
    - IPv6
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T9 — BYO + IPv6-only (single-stack)

Workers subnet is IPv6-native (no IPv4 CIDR). Expected: no IPv4 SG rules
emitted; `/108` reservation created; no IPv4 EFS NFS rule.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t9-byo-ipv6
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: <vpc-id-with-ipv6>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-ipv6native-eu-west-1a>  # Ipv6Native=true, no IPv4 CIDR
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t9
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    type: calico
    ipFamilies:
    - IPv6
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T10 — BYO + EFS enabled (Gap F fix)

Same topology as T4 but with EFS enabled. Expected: EFS NFS TCP 2049
ingress rule sourced from the workers subnet CIDR (not the internal LB
subnet CIDR — this is the Gap F fix).

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: test-byo-efs
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      elasticFileSystem:
        enabled: true
        id: <efs-fs-id>
      networks:
        vpc:
          id: <vpc-id>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-eu-west-1a>
          publicSubnetID: <subnet-public-eu-west-1a>
          internalSubnetID: <subnet-internal-eu-west-1a>
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t10
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T11 — BYO full replacement, three zones

Three zones each with workers + public + internal. Verifies cross-zone LB
uniformity check passes and narrow per-zone SG rules are emitted for all
three zones.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t11-byo-mz
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: <vpc-id>
        nodesSecurityGroupID: <sg-nodes-id>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-eu-west-1a>
          publicSubnetID: <subnet-public-eu-west-1a>
          internalSubnetID: <subnet-internal-eu-west-1a>
        - name: eu-west-1b
          workersSubnetID: <subnet-workers-eu-west-1b>
          publicSubnetID: <subnet-public-eu-west-1b>
          internalSubnetID: <subnet-internal-eu-west-1b>
        - name: eu-west-1c
          workersSubnetID: <subnet-workers-eu-west-1c>
          publicSubnetID: <subnet-public-eu-west-1c>
          internalSubnetID: <subnet-internal-eu-west-1c>
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t11
      minimum: 1
      maximum: 3
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      - eu-west-1b
      - eu-west-1c
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T12 — Rejection: mixed-zone LB config

Zone A has `publicSubnetID`, zone B does not. Expected: admission webhook
rejects the shoot with a `field.Required` error pointing at zone B's
missing `publicSubnetID`. Shoot creation should fail immediately.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t12-byo-mz-rej
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: <vpc-id>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-eu-west-1a>
          publicSubnetID: <subnet-public-eu-west-1a>   # present
        - name: eu-west-1b
          workersSubnetID: <subnet-workers-eu-west-1b>
          # publicSubnetID intentionally absent → rejected
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t12
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      - eu-west-1b
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## T13 — Rejection: multiple IPv6 CIDRs on BYO worker subnet (Gap J)

BYO worker subnet has two IPv6 CIDR associations. Expected: config
validator rejects with an error listing both CIDRs and asking the user to
remove the extras. Shoot reconciliation should fail at the configvalidator
step.

Preparation: associate a second IPv6 CIDR block with
`<subnet-workers-eu-west-1a>` in AWS before creating the shoot.

```yaml
kind: Shoot
apiVersion: core.gardener.cloud/v1beta1
metadata:
  name: t13-ipv6-rej
  namespace: garden-remote
spec:
  provider:
    type: aws
    infrastructureConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: InfrastructureConfig
      networks:
        vpc:
          id: <vpc-id-with-ipv6>
        zones:
        - name: eu-west-1a
          workersSubnetID: <subnet-workers-with-two-ipv6-cidrs>
    controlPlaneConfig:
      apiVersion: aws.provider.extensions.gardener.cloud/v1alpha1
      kind: ControlPlaneConfig
    workers:
    - name: worker-t13
      minimum: 1
      maximum: 2
      maxSurge: 1
      machine:
        type: m5.large
        image:
          name: gardenlinux
        architecture: amd64
      zones:
      - eu-west-1a
      cri:
        name: containerd
      volume:
        type: gp3
        size: 50Gi
  networking:
    nodes: 10.180.0.0/16
    type: calico
    ipFamilies:
    - IPv4
    - IPv6
  kubernetes:
    version: 1.35.5
  cloudProfile:
    name: aws
    kind: CloudProfile
  credentialsBindingName: shoot-operator-aws-team
  purpose: evaluation
  region: eu-west-1
  seedName: remote
  maintenance:
    autoUpdate:
      kubernetesVersion: true
      machineImageVersion: true
    timeWindow:
      begin: 040000+0200
      end: 050000+0200
```

---

## Summary table

| ID  | Mode | IPv6 | Zones | SG | LB subnets | Expected outcome |
|-----|------|------|-------|----|------------|-----------------|
| T1  | Managed | No | 1 | Gardener | Managed | Regression baseline — all resources created |
| T2  | Managed | Dual-stack | 1 | Gardener | Managed | `/108` reservation created |
| T3  | BYO full | No | 1 | BYO | Explicit | Nothing created; tags added; svc-ctrl enabled |
| T4  | BYO hybrid | No | 1 | Gardener | Explicit | SG created with real CIDR narrow rules |
| T5  | BYO hybrid | No | 1 | Gardener | None | SG created with base rules only; svc-ctrl disabled |
| T6  | BYO hybrid | No | 1 | Gardener | Pre-tagged | Discovery populates status; svc-ctrl enabled |
| T7  | BYO hybrid | Dual-stack | 1 | Gardener | Explicit | `/108` reservation; v4+v6 SG rules |
| T8  | BYO hybrid | Dual-stack | 2 | Gardener | Explicit | Single `/108` on lowest-ID worker subnet |
| T9  | BYO hybrid | IPv6-only | 1 | Gardener | None | IPv6-only SG rules; no IPv4 rules |
| T10 | BYO hybrid | No | 1 | Gardener | Explicit | EFS rule sources workers CIDR |
| T11 | BYO full | No | 3 | BYO | Explicit | All 3 zones tagged; per-zone rules for all |
| T12 | BYO hybrid | No | 2 | Gardener | Mixed | **Rejected** — mixed-zone LB consistency |
| T13 | BYO hybrid | Dual-stack | 1 | Gardener | None | **Rejected** — multiple IPv6 CIDRs on subnet |

---

# Glossary

- **BYO**: Bring Your Own — user provides existing AWS infrastructure
  (`workersSubnetID`, and optionally `publicSubnetID`, `internalSubnetID`,
  `nodesSecurityGroupID`).
- **Managed mode**: opposite of BYO — Gardener creates VPC, subnets, SG,
  route tables, NAT gateways, IGW.
- **Hybrid (Gardener-managed SG + BYO subnets)**: `workersSubnetID` set but
  `nodesSecurityGroupID` not set. Gardener creates and manages the SG but
  does not touch the subnets.
- **Node SG**: the security group attached to worker node ENIs. Gardener's
  managed one is reconciled authoritatively via `UpdateSecurityGroup` →
  `DiffRules`. User-owned rules will be revoked.
- **NLB / classic ELB / ALB**: AWS load balancer flavors. Gardener uses
  NLBs by default via the CCM; ALB-C manages ALBs.
- **Ipv6-single-stack**: `spec.networking.ipFamilies: [IPv6]`.
- **Dual-stack**: `spec.networking.ipFamilies: [IPv4, IPv6]` (or the legacy
  `dualStack.enabled: true`).
- **Full Replacement / Additive**: two SG design models discussed in the
  proposal; Full Replacement is preferred, Additive deferred.
- **Shape 1 / Shape 2 / Shape 3**: three approaches considered for Gap A,
  see that entry.
