# Zero-Trust Secret Access for AAP with SPIFFE and Vault

A proposed pattern for granular secret access in Ansible Automation
Platform, scoped to the full organization tree
(`organization / project / job template / playbook`), using
[SPIFFE](https://spiffe.io/) cryptographic workload identity and
HashiCorp Vault.

## Table of Contents

- [The Problem](#the-problem)
- [Architecture](#architecture)
- [Open Questions for AAP Product](#open-questions-for-aap-product)
- [Deployment Guide](#deployment-guide)
- [Demo Scenarios](#demo-scenarios)
- [References](#references)

---

## The Problem

### Granular Secret Access Across the Full Org Tree

Enterprise customers run multi-tenant AAP environments where secrets must
be scoped not just to an organization, but to the full hierarchy:

```
organization / project / job template / playbook
```

For example, a Vault policy should be able to say: "only the `deploy-prod`
playbook in the `cloud-infra` project of the `Platform-Ops` organization
can read the production AWS credentials." Today, AAP can only provide this
if an admin manually configures a credential on every single job template.

The goal of this pattern is **automatic, granular secret scoping** where
Vault can verify the full org tree of any running AAP job and grant access
accordingly, with no per-JT credential configuration.

### Target: Full Org Tree in Vault

The desired Vault path and policy structure maps directly to the AAP
org tree:

```
secret/data/aap/
  org/infra-corp/                              # org-wide secrets
    credentials                                # accessible by any job in this org
    project/network-automation/                # project-scoped
      credentials                              # only jobs in this project
      jt/configure-switches/                   # JT-scoped
        credentials                            # only this job template
        playbook/site.yml/                     # playbook-scoped
          credentials                          # only when running site.yml
```

To enforce this, the identity system (SPIRE or OIDC JWT) must know which
org, project, job template, and playbook is running inside each container.
Today, this information is not exposed on the container.

### What's Missing in AAP 2.7

| Capability | Status | What's Needed |
|---|---|---|
| Org-level secret scoping | Possible (manual credential per JT) | Automatic via workload identity |
| Project-level scoping | Not possible | Pod labels or JWT with project claim |
| JT-level scoping | Not possible without per-JT OIDC credential | Automatic JWT minting or pod labels |
| Playbook-level scoping | Not possible | Pod labels with playbook name |
| Infrastructure attestation | No pod/container labels at any level | Labels on K8s pods and podman containers |
| Cross-cluster trust | Separate config per cluster | SPIRE federation |

### Three Gaps Blocking Full-Tree Scoping

Each gap blocks a different execution model or auth path. All three must
be addressed for complete coverage.

| # | Gap | Execution Model | Blocks | Fix Complexity |
|---|---|---|---|---|
| 1 | No pod labels with org tree | K8s (OCP, EKS) | SPIRE, OPA, Istio, any infra-level identity | ~10 lines in `receptor.py` |
| 2 | No container labels with org tree | Podman (on-prem VMs) | SPIRE on VMs, systemd, any container attestation | `--label` flags + new `container_options_override` model field |
| 3 | OIDC JWT not automatically minted | Both (the JWT is generated in the controller) | Vault `bound_claims`, cloud IAM, any app-level auth that could use the JWT directly | Credential inheritance or auto-minting when feature flag is on |

**Gaps 1 and 2** are about making the org tree visible to
**infrastructure-level** systems. These systems operate outside AAP:
they see pods and containers, not job templates. Without labels, they
cannot tell one AAP job from another.

**Gap 3** is about making the org tree available to
**application-level** auth. The JWT claims already contain the full
hierarchy (`org:X/project:Y/jt:Z/playbook:P`). The code to populate
them exists and is tested. The only issue is activation: the JWT is
minted only when a specific credential type is manually attached to
each job template.

Gaps 1+2 and Gap 3 are complementary, not alternative. Labels enable
infrastructure attestation (SPIRE, mesh identity). JWT enables direct
Vault auth (no SPIRE needed). Using both provides defense in depth.

Details and source code references in
[Open Questions](#open-questions-for-aap-product).

---

## Architecture

This pattern uses SPIFFE/SPIRE to provide infrastructure-level workload
identity for AAP pods, and Vault JWT auth to exchange that identity for
scoped secret access.

**Current POC scope:** Demonstrates org-level isolation (4 orgs, each with
separate SPIFFE IDs, Vault roles, and secret paths). This is the deepest
level achievable today without changes to AWX, because AWX does not expose
project/JT/playbook information on the pod.

**Target with AWX changes:** If AWX adds pod labels for the full org tree
(see [Open Questions](#open-questions-for-aap-product)), SPIRE selectors
and Vault policies can scope secrets to any level:
`org → project → job template → playbook`.

### How It Works

```
┌─────────────────────────────────────────────────────────────────┐
│                        SPIRE Server                             │
│               (trust root, issues SVIDs, CA)                    │
│                    /              \                              │
│           SPIRE Agent      OIDC Discovery Provider              │
│          (Workload API)    (serves JWKS for Vault)              │
│               │                      │                          │
│        SPIFFE CSI Driver       Vault JWT Auth                   │
│       (mounts Workload API     (validates JWT against           │
│        into pods via CSI)       OIDC Discovery)                 │
│               │                      │                          │
│         spiffe-helper          Vault scoped token               │
│        (fetches JWT-SVID)      (per org/project/JT policy)      │
│               │                      │                          │
│            AAP EE Pod ───────────────┘                          │
│       (lookup plugin fetches secrets per call)                  │
└─────────────────────────────────────────────────────────────────┘
```

### End-to-End Flow

1. **Kyverno** intercepts AAP pod creation, injects sidecars + SPIFFE CSI volume
2. **SPIFFE CSI Driver** mounts the SPIRE Workload API socket into the pod
3. **SPIRE Agent** validates the pod via kubelet `k8s_psat` attestation
4. **init-spiffe-helper** fetches a JWT-SVID (5-min TTL) and writes to `/svids/jwt.token`
5. **init-spiffe-vault-client** POSTs the JWT to Vault `/v1/auth/jwt/login`
6. **Vault** validates the JWT signature via SPIRE's OIDC public keys, checks `sub` and `aud` claims
7. **Vault** returns a scoped token with only the policies for that SPIFFE identity
8. **init-spiffe-vault-client** reads secrets, writes to shared volume, exits
9. **AAP containers** start and consume credentials from the shared volume
10. **Sidecars** continuously rotate JWT-SVID and refresh secrets

### Components

| Component | Role | Deployed As |
|---|---|---|
| **SPIRE Server** | Trust root, issues SVIDs, serves as CA | StatefulSet in `spire-system` |
| **SPIRE Agent** | Attests workloads via kubelet, exposes Workload API | DaemonSet (every node) |
| **SPIFFE CSI Driver** | Mounts the Workload API socket into pods | DaemonSet (every node) |
| **OIDC Discovery** | Publishes JWKS so Vault can verify JWT-SVIDs | Sidecar in SPIRE Server |
| **Vault** | Stores secrets, validates JWTs via OIDC Discovery | StatefulSet in `vault` |
| **Kyverno** | Injects spiffe-helper + vault-client sidecars | Deployment in `kyverno` |
| **spiffe-helper** | Fetches JWT-SVID from Workload API | Injected init + sidecar |
| **spiffe-vault-client** | Exchanges JWT for Vault token, fetches secrets | Injected init + sidecar |

### SPIFFE CSI Driver

The SPIFFE CSI driver replaces `hostPath` mounts for the SPIRE agent socket.
Each pod gets the Workload API via a CSI ephemeral volume:

```yaml
volumes:
  - name: spiffe-workload-api
    csi:
      driver: csi.spiffe.io
      readOnly: true
```

This eliminates the need for `hostPath` volumes on workload pods and removes
the `fix-jwt-perms` init container that was previously required.

**OpenShift SELinux note:** On SELinux-enforcing clusters (all OCP), containers
that connect to the SPIRE agent socket need `seLinuxOptions.type: spc_t` because
the agent socket inherits the `container_var_run_t` label from the host. The
CSIDriver resource has `seLinuxMount: true` for Kubernetes-level SELinux support.
In production, consider using SPIRE's Delegated Identity API or relabeling
the socket to `container_file_t` to avoid `spc_t` on workloads.

### RBAC Model (Four Layers)

| Layer | Mechanism | Enforcement |
|---|---|---|
| 1. SPIRE selectors | `k8s:sa:` / `k8s:pod-label:` | Each pod type gets exactly one SPIFFE ID |
| 2. Vault bound_subject | JWT `sub` must match role | JWT for org A cannot auth to org B's role |
| 3. Kyverno + Container Groups | Per-workload sidecar config | Controller gets platform role, EE gets org role |
| 4. Lookup plugin | Per-call Vault auth | No ambient credentials, no pre-fetched cache |

### Secret Isolation: Current (Org-Level) and Target (Full Tree)

**What the POC demonstrates today** (org-level, no AWX changes needed):

| Organization | SPIFFE ID | Vault Path |
|---|---|---|
| Infra-Corp | `spiffe://.../org/infra-corp` | `secret/data/aap/org/infra-corp/*` |
| AppDev-Squad | `spiffe://.../org/appdev-squad` | `secret/data/aap/org/appdev-squad/*` |
| SecOps-Team | `spiffe://.../org/secops-team` | `secret/data/aap/org/secops-team/*` |
| Platform-Ops | `spiffe://.../org/platform-ops` | `secret/data/aap/org/platform-ops/*` |

Infra-Corp **cannot** read AppDev-Squad's secrets, even though they share the
same AAP instance. Verified via E2E tests: Vault returns HTTP 403 for cross-org
access attempts.

**What becomes possible with AWX pod labels** (full org tree):

If AWX labels EE pods with org/project/JT/playbook (see Gap 1), SPIRE
selectors can assign fine-grained SPIFFE IDs:

| Scope | SPIFFE ID | Vault Path | SPIRE Selector |
|---|---|---|---|
| Org | `spiffe://.../org/infra-corp` | `secret/data/aap/org/infra-corp/*` | `k8s:pod-label:aap-org:infra-corp` |
| Project | `spiffe://.../org/infra-corp/proj/cloud-infra` | `.../infra-corp/project/cloud-infra/*` | `+ k8s:pod-label:aap-project:cloud-infra` |
| JT | `spiffe://.../org/infra-corp/proj/cloud-infra/jt/deploy-prod` | `.../cloud-infra/jt/deploy-prod/*` | `+ k8s:pod-label:aap-jt:deploy-prod` |
| Playbook | `spiffe://.../org/infra-corp/.../playbook/site.yml` | `.../deploy-prod/playbook/site.yml/*` | `+ k8s:pod-label:aap-playbook:site.yml` |

This is the same pattern at every level; only the number of SPIRE selectors
and the depth of the Vault path change. No architecture changes are needed,
only the missing pod labels from AWX.

### Playbook Consumption

The `spiffe_vault` lookup plugin authenticates to Vault per call using the
pod's JWT-SVID. The Vault role determines the secret scope:

```yaml
# 1. Org-level secret (works today)
db_password: "{{ lookup('spiffe_vault',
    'secret/data/aap/org/infra-corp/credentials',
    field='cloud_password',
    vault_role='aap-org-infra-corp') }}"

# 2. Project-level secret (requires AWX pod labels, Gap 1)
deploy_key: "{{ lookup('spiffe_vault',
    'secret/data/aap/org/infra-corp/project/cloud-infra/credentials',
    field='deploy_key',
    vault_role='aap-org-infra-corp-proj-cloud-infra') }}"

# 3. Job-template-level secret (requires AWX pod labels, Gap 1)
staging_token: "{{ lookup('spiffe_vault',
    'secret/data/aap/org/infra-corp/project/cloud-infra/jt/deploy-staging/credentials',
    field='deploy_token',
    vault_role='aap-infra-corp-cloud-infra-deploy-staging') }}"

# 4. Playbook-level secret (requires AWX pod labels, Gap 1)
prod_aws_key: "{{ lookup('spiffe_vault',
    'secret/data/aap/org/infra-corp/project/cloud-infra/jt/deploy-prod/playbook/site.yml/credentials',
    field='aws_secret_key',
    vault_role='aap-infra-corp-cloud-infra-deploy-prod-site') }}"
```

Each level of scoping uses the same lookup plugin and the same
SPIRE-to-Vault flow. The only difference is the granularity of the
SPIFFE ID (determined by pod labels) and the Vault role/policy (configured
to match that SPIFFE ID).

---

## Open Questions for AAP Product

Source code analysis of AWX (verified against production-installed code on
a live cluster) identified three gaps that prevent granular secret scoping
below the organization level.

**Why these gaps matter:** The architecture described above works at every
level of the org tree (org, project, JT, playbook) with no changes. The
only missing piece is the identity data on the container itself. Without
it, SPIRE cannot assign a SPIFFE ID more specific than "this pod belongs
to org X," and Vault cannot enforce policies more specific than "org X
can read org X's secrets."

### Gap 1: No org/project/JT/playbook labels on K8s EE pods

**Source:** `awx/main/tasks/receptor.py` lines 772-776

AWX sets only two labels on execution environment pods: `ansible-awx`
(install UUID) and `ansible-awx-job-id`. No organization, project, job
template, or playbook labels are injected.

**What's needed:** Four additional labels on every EE pod:

```yaml
labels:
  aap.ansible.com/organization: "infra-corp"
  aap.ansible.com/project: "cloud-infra"
  aap.ansible.com/job-template: "deploy-prod"
  aap.ansible.com/playbook: "site.yml"
```

**Impact on this pattern:** Without these labels, SPIRE selectors can only
match at the org level (via Container Group labels). With them, SPIRE
selectors can match at any depth, and Vault policies can scope secrets to
`org/project/JT/playbook`.

**Fix complexity:** The data is available at pod creation time
(`self.task.instance.organization`, `.project`, `.unified_job_template`,
`.playbook`). Adding labels would be approximately 10 lines of code in
`receptor.py`.

### Gap 2: No container labels on podman execution (VM nodes)

**Source:** `awx/main/tasks/jobs.py` lines 360-413

`build_execution_environment_params()` passes no `--label` flags to podman.
There is no `container_options_override` field on `InstanceGroup` (unlike
`pod_spec_override` for K8s).

**What's needed:** The same four labels, passed as `--label` flags to
podman. And a `container_options_override` field on `InstanceGroup` for
operator customization.

**Impact on this pattern:** On-premise execution nodes running podman have
no mechanism for any identity system to identify the running job's org tree.
SPIRE on VM nodes (using the `docker` or `unix` workload attestor) cannot
differentiate AAP jobs at all.

### Gap 3: OIDC JWT requires per-JT credential configuration

**Source:** `awx/main/tasks/jobs.py` lines 286-330

AAP 2.7's OIDC workload identity JWT already contains the full org tree
as claims:

```json
{
  "aap_controller_organization_name": "Infra-Corp",
  "aap_controller_project_name": "cloud-infra",
  "aap_controller_job_template_name": "deploy-prod",
  "aap_controller_playbook_name": "site.yml",
  "aap_groups": [
    "org:Infra-Corp",
    "org:Infra-Corp/project:cloud-infra",
    "org:Infra-Corp/project:cloud-infra/jt:deploy-prod",
    "org:Infra-Corp/project:cloud-infra/jt:deploy-prod/playbook:site.yml"
  ]
}
```

These claims are exactly what Vault needs for full-tree scoping via
`bound_claims`. But the JWT is only minted when a "HashiCorp Vault Secret
Lookup (OIDC)" credential is explicitly attached to each job template.
There is no credential inheritance from org or project level, and no
default OIDC credential per organization.

**What's needed:** Either (a) credential inheritance so an OIDC credential
attached at the org level applies to all JTs in that org, or (b) a default
OIDC credential per organization, or (c) automatic JWT minting for all jobs
when `FEATURE_OIDC_WORKLOAD_IDENTITY_ENABLED` is on.

**Impact on this pattern:** The JWT path is the most direct route to
full-tree scoping because the claims already exist. If the JWT were
automatically minted, Vault could use `bound_claims` to match any
combination of org/project/JT/playbook, with no SPIRE selectors needed
at all.

### How the Gaps Map to Full-Tree Scoping

Each gap, once resolved, independently unlocks full org-tree scoping
through a different mechanism:

| Gap Fixed | What It Unlocks | Example |
|---|---|---|
| Gap 1 (K8s pod labels) | SPIRE assigns SPIFFE IDs at any tree depth on OCP/EKS | `k8s:pod-label:aap-project:cloud-infra` selector matches only that project's pods |
| Gap 2 (podman labels) | SPIRE (or systemd) assigns identities on VM execution nodes | `docker:label:aap-jt:deploy-prod` selector matches only that JT's containers |
| Gap 3 (auto JWT) | Vault `bound_claims` scopes secrets directly, no SPIRE needed | `"bound_claims": {"aap_controller_playbook_name": "site.yml"}` |
| Gaps 1+3 combined | Defense in depth: SPIRE attests at infra layer, JWT authorizes at app layer | Pod proven to be `deploy-prod` by kubelet, JWT proves `playbook:site.yml` cryptographically |

This POC uses Gap 1's workaround (Container Group labels at org level) +
SPIRE to demonstrate org-level isolation. With the AWX changes, the same
architecture extends to project, JT, and playbook level with no additional
components.

---

## Deployment Guide

### Prerequisites

- OCP 4.14+ cluster with AAP 2.7 deployed
- `oc` CLI authenticated to the cluster
- `ansible-playbook` with `kubernetes.core` collection
- `helm` CLI available

### Quick Start

```bash
git clone https://github.com/amasolov/aap-spiffe-vault-poc.git
cd aap-spiffe-vault-poc

export KUBECONFIG=/path/to/your/kubeconfig

# Deploy everything (SPIRE + CSI driver + Vault + integration + AAP config)
ansible-playbook deploy-poc.yml

# Run the demos
ansible-playbook demo-scenarios.yml --tags scenario1
ansible-playbook demo-scenarios.yml --tags scenario2
ansible-playbook demo-scenarios.yml --tags scenario3

# Teardown (leaves AAP untouched)
ansible-playbook teardown-poc.yml
```

### Deploy Individual Phases

```bash
ansible-playbook deploy-poc.yml --tags spire      # SPIRE + CSI driver + OIDC
ansible-playbook deploy-poc.yml --tags vault       # Vault + auto-unseal + seed
ansible-playbook deploy-poc.yml --tags integrate   # Wire SPIFFE JWT auth in Vault
ansible-playbook deploy-poc.yml --tags kyverno     # Kyverno policy engine
ansible-playbook deploy-poc.yml --tags aap         # Kyverno policy + Container Groups
```

### Adapting for Your Cluster

Edit `group_vars/all.yml`:

```yaml
cluster_domain: "apps.your-cluster.example.com"
aap_namespace: aap
```

### Repository Structure

```
ansible.cfg                       Ansible configuration
inventory/hosts.yml               Inventory (localhost)
group_vars/all.yml                Global variables (cluster, SPIFFE IDs, selectors)
deploy-poc.yml                    Full deployment playbook (4 phases)
demo-scenarios.yml                Three demo scenarios
teardown-poc.yml                  Cleanup playbook
scripts/
  spiffe-vault-client.py          Credential manager sidecar
lookup_plugins/
  spiffe_vault.py                 Ansible lookup plugin for per-job Vault auth
playbooks/
  demo-credential-isolation.yml   Demo: per-org credential isolation
```

### What Gets Deployed

The playbook deploys the following (all in dedicated namespaces, AAP is
not modified except for adding Container Groups):

| Phase | Tag | What It Creates |
|---|---|---|
| 1. SPIRE | `spire` | SPIRE server, agents, CSI driver, OIDC provider, workload entries |
| 2. Vault | `vault` | Vault server, auto-unseal CronJob, demo secrets (4 orgs + EDA) |
| 3. Integration | `integrate` | JWT auth method in Vault, per-identity roles and policies |
| 4. AAP Config | `aap` | Kyverno sidecar injection policy, per-org Container Groups |

### Production Considerations

This POC uses upstream SPIRE containers. For production on OpenShift,
consider the following path:

| POC | Production |
|---|---|
| Upstream SPIRE containers | Zero Trust Workload Identity Manager (ZTWIM, Red Hat supported) |
| Vault file backend + manual unseal | HA Raft backend + cloud KMS auto-unseal |
| SPIFFE CSI driver DaemonSet | ZTWIM operator-managed CSI driver |
| Manual entry registration | ClusterSPIFFEID CRD (auto-registers via ZTWIM) |
| Kyverno sidecar injection | ZTWIM operator or Kyverno |
| Per-agent entry registration | ZTWIM handles agent lifecycle automatically |

---

## Demo Scenarios

### Scenario 1: Platform Zero-Trust Identity

AAP's platform identity (`spiffe://.../sa/aap-controller`) authenticates
to Vault and reads platform-level secrets at `hub/aap/*`. The static
credential is replaced with a short-lived, auto-rotating SPIFFE JWT that
is cryptographically attested by the kubelet.

### Scenario 2: Multi-Org Secret Isolation

Each of 4 AAP organizations gets its own SPIFFE ID and Vault policy.
Infra-Corp can read its own secrets; attempting to read AppDev-Squad's
secrets returns HTTP 403. No shared tokens between organizations.

### Scenario 3: EDA Dynamic Credentials

An EDA rulebook activation gets AWS credentials from Vault at event time,
authenticated by the EDA pod's SPIFFE identity. Credentials are never
persisted in AAP. Every access has a cryptographic audit trail.

---

## References

- [SPIRE SPIFFE CSI Driver](https://github.com/spiffe/spiffe-csi)
- [Validated Patterns: Layered Zero Trust](https://github.com/validatedpatterns/layered-zero-trust)
- [SPIRE + Vault OIDC Tutorial](https://spiffe.io/docs/latest/keyless/vault/readme/)
- [Vault JWT/OIDC Auth Method](https://developer.hashicorp.com/vault/docs/auth/jwt)
- [AAP 2.7: OIDC for HashiCorp Vault](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.7/whats_new-oidc_authentication_for_hashicorp_vault)
- [Zero Trust Workload Identity Manager (ZTWIM)](https://docs.openshift.com/container-platform/latest/security/zero-trust-workload-identity.html)

## License

Apache-2.0
