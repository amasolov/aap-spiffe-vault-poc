# Zero-Trust Secret Access for AAP with SPIFFE and Vault

A proposed pattern for granular secret access in Ansible Automation
Platform, scoped to the full organization tree
(`organization / project / job template / playbook`), using
[SPIFFE](https://spiffe.io/) cryptographic workload identity and
HashiCorp Vault.

---

## The Problem

Enterprise customers run multi-tenant AAP environments where secrets must
be scoped not just to an organization, but to the full hierarchy:

```
organization / project / job template / playbook
```

For example, a Vault policy should be able to say: "only the `deploy-prod`
playbook in the `cloud-infra` project of the `Platform-Ops` organization
can read the production AWS credentials." Today, AAP can only provide this
if an admin manually configures a credential on every single job template.

### Target: Full Org Tree in Vault

```
secret/data/aap/
  org/infra-corp/                              # org-wide secrets
    project/network-automation/                # project-scoped
      jt/configure-switches/                   # JT-scoped
        playbook/site.yml/                     # playbook-scoped
```

To enforce this, the identity system must know which org, project, JT,
and playbook is running inside each container. Today, this information
is not exposed on the container.

### Three Gaps Blocking Full-Tree Scoping

| # | Gap | Execution Model | Blocks | Fix Complexity |
|---|---|---|---|---|
| 1 | No pod labels with org tree | K8s (OCP, EKS) | SPIRE, OPA, Istio | ~10 lines in `receptor.py` |
| 2 | No container labels with org tree | Podman (on-prem VMs) | SPIRE on VMs, systemd | `--label` flags + new model field |
| 3 | OIDC JWT not automatically minted | Both | Vault `bound_claims`, cloud IAM | Credential inheritance or auto-minting |

**Gaps 1+2** make the org tree visible to **infrastructure-level** systems
(SPIRE, Istio, OPA) that see pods/containers, not job templates.

**Gap 3** makes the org tree available to **application-level** auth.
The JWT claims already contain the full hierarchy
(`org:X/project:Y/jt:Z/playbook:P`). The code exists and is tested.
The only issue: the JWT is minted only when an OIDC credential is
manually attached to each job template.

Both layers are complementary. Labels enable infrastructure attestation.
JWT enables direct Vault auth. Using both provides defense in depth.

Source code references and fix details in
[Open Questions](#open-questions-for-aap-product).

---

## Architecture

This pattern uses SPIFFE/SPIRE for infrastructure-level workload identity
and Vault JWT auth to exchange that identity for scoped secret access.

**Current POC:** Org-level isolation (4 orgs with separate SPIFFE IDs,
Vault roles, and secret paths). This is the deepest level achievable
without AWX changes.

**Target with AWX changes:** The same architecture extends to
`org → project → JT → playbook` with no additional components, only
the missing pod labels.

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
2. **SPIFFE CSI Driver** mounts the SPIRE Workload API socket; **SPIRE Agent** attests the pod via kubelet
3. **init-spiffe-helper** fetches a JWT-SVID (5-min TTL) from the Workload API
4. **init-spiffe-vault-client** exchanges the JWT for a scoped Vault token (Vault validates signature via SPIRE OIDC keys, checks `sub` and `aud`)
5. **AAP containers** start and consume secrets from the shared volume
6. **Sidecars** continuously rotate JWT-SVID and refresh secrets

### RBAC Model (Four Layers)

| Layer | Mechanism | Enforcement |
|---|---|---|
| 1. SPIRE selectors | `k8s:sa:` / `k8s:pod-label:` | Each pod type gets exactly one SPIFFE ID |
| 2. Vault bound_subject | JWT `sub` must match role | JWT for org A cannot auth to org B's role |
| 3. Kyverno + Container Groups | Per-workload sidecar config | Controller gets platform role, EE gets org role |
| 4. Lookup plugin | Per-call Vault auth | No ambient credentials, no pre-fetched cache |

### Secret Isolation: Current and Target

The POC demonstrates org-level isolation across 4 organizations
(Infra-Corp, AppDev-Squad, SecOps-Team, Platform-Ops), each with its own
SPIFFE ID and Vault policy. Cross-org access is denied (HTTP 403, verified
via E2E tests).

With AWX pod labels (Gap 1), the same pattern extends to all 4 levels:

| Scope | SPIRE Selector | Vault Path |
|---|---|---|
| Org | `k8s:pod-label:aap-org:infra-corp` | `secret/data/aap/org/infra-corp/*` |
| Project | `+ k8s:pod-label:aap-project:cloud-infra` | `.../infra-corp/project/cloud-infra/*` |
| JT | `+ k8s:pod-label:aap-jt:deploy-prod` | `.../cloud-infra/jt/deploy-prod/*` |
| Playbook | `+ k8s:pod-label:aap-playbook:site.yml` | `.../deploy-prod/playbook/site.yml/*` |

### Playbook Consumption

The `spiffe_vault` lookup plugin authenticates to Vault per call:

```yaml
# Org-level (works today)
db_password: "{{ lookup('spiffe_vault',
    'secret/data/aap/org/infra-corp/credentials',
    field='cloud_password',
    vault_role='aap-org-infra-corp') }}"

# Playbook-level (requires AWX pod labels, Gap 1)
prod_aws_key: "{{ lookup('spiffe_vault',
    'secret/data/aap/org/infra-corp/project/cloud-infra/jt/deploy-prod/playbook/site.yml/credentials',
    field='aws_secret_key',
    vault_role='aap-infra-corp-cloud-infra-deploy-prod-site') }}"
```

Project-level and JT-level work identically; only the Vault path depth
and role name change.

**OpenShift note:** The SPIFFE CSI driver mounts the Workload API socket
as a CSI ephemeral volume (`csi.spiffe.io`). On SELinux-enforcing clusters,
containers need `seLinuxOptions.type: spc_t` to access the socket. In
production, use SPIRE's Delegated Identity API to avoid this.

---

## Open Questions for AAP Product

Source code analysis of AWX (verified against production-installed code on
a live cluster) identified three gaps that prevent granular secret scoping
below the organization level. The architecture works at every tree depth
with no changes; only the identity data on the container is missing.

### Gap 1: No org/project/JT/playbook labels on K8s EE pods

**Source:** `awx/main/tasks/receptor.py` lines 772-776

AWX sets only `ansible-awx` (install UUID) and `ansible-awx-job-id` on
EE pods. What's needed:

```yaml
labels:
  aap.ansible.com/organization: "infra-corp"
  aap.ansible.com/project: "cloud-infra"
  aap.ansible.com/job-template: "deploy-prod"
  aap.ansible.com/playbook: "site.yml"
```

The data is available at pod creation time (`self.task.instance.organization`,
`.project`, `.unified_job_template`, `.playbook`). ~10 lines in `receptor.py`.

### Gap 2: No container labels on podman execution (VM nodes)

**Source:** `awx/main/tasks/jobs.py` lines 360-413

`build_execution_environment_params()` passes no `--label` flags to podman.
No `container_options_override` field exists on `InstanceGroup` (unlike
`pod_spec_override` for K8s). On-prem execution nodes have no mechanism
for any identity system to identify the running job's org tree.

Needs: the same four labels as `--label` flags, plus a
`container_options_override` model field for operator customization.

### Gap 3: OIDC JWT requires per-JT credential configuration

**Source:** `awx/main/tasks/jobs.py` lines 286-330

The JWT already contains the full org tree:

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

But it is only minted when an OIDC credential is attached to each JT.
Needs: credential inheritance from org/project level, or automatic JWT
minting when `FEATURE_OIDC_WORKLOAD_IDENTITY_ENABLED` is on.

This is the most direct route to full-tree scoping: Vault `bound_claims`
can match any combination of org/project/JT/playbook, no SPIRE needed.

### How the Gaps Map to Full-Tree Scoping

| Gap Fixed | What It Unlocks | Example |
|---|---|---|
| Gap 1 (K8s labels) | SPIRE IDs at any tree depth on OCP/EKS | `k8s:pod-label:aap-project:cloud-infra` |
| Gap 2 (podman labels) | Identities on VM execution nodes | `docker:label:aap-jt:deploy-prod` |
| Gap 3 (auto JWT) | Vault scopes secrets directly, no SPIRE | `"bound_claims": {"aap_controller_playbook_name": "site.yml"}` |
| All combined | Defense in depth | SPIRE attests at infra layer, JWT authorizes at app layer |

---

## Deployment Guide

### Prerequisites

- OCP 4.14+ cluster with AAP 2.7 deployed
- `oc` CLI authenticated, `helm` CLI available
- `ansible-playbook` with `kubernetes.core` collection

### Quick Start

```bash
git clone https://github.com/amasolov/aap-spiffe-vault-poc.git
cd aap-spiffe-vault-poc
export KUBECONFIG=/path/to/your/kubeconfig

ansible-playbook deploy-poc.yml              # Full deploy
ansible-playbook demo-scenarios.yml          # Identity chain, isolation, full tree
ansible-playbook teardown-poc.yml            # Cleanup (AAP untouched)
```

### Individual Phases

```bash
ansible-playbook deploy-poc.yml --tags spire      # SPIRE + CSI driver + OIDC
ansible-playbook deploy-poc.yml --tags vault       # Vault + auto-unseal + seed
ansible-playbook deploy-poc.yml --tags integrate   # Wire SPIFFE JWT auth in Vault
ansible-playbook deploy-poc.yml --tags kyverno     # Kyverno policy engine
ansible-playbook deploy-poc.yml --tags aap         # Kyverno policy + Container Groups
```

### Cluster Configuration

Edit `group_vars/all.yml`:

```yaml
cluster_domain: "apps.your-cluster.example.com"
aap_namespace: aap
```

### What Gets Deployed

| Phase | Tag | Resources |
|---|---|---|
| 1. SPIRE | `spire` | Server, agents, CSI driver, OIDC provider, workload entries |
| 2. Vault | `vault` | Server, auto-unseal CronJob, demo secrets (4 orgs + EDA) |
| 3. Integration | `integrate` | JWT auth in Vault, per-identity roles and policies |
| 4. AAP Config | `aap` | Kyverno sidecar injection, per-org Container Groups |

### Production Path

| POC | Production |
|---|---|
| Upstream SPIRE | Zero Trust Workload Identity Manager (ZTWIM, Red Hat supported) |
| File backend + manual unseal | HA Raft + cloud KMS auto-unseal |
| Manual entry registration | ClusterSPIFFEID CRD (auto-registers) |
| Per-agent entries | ZTWIM handles agent lifecycle automatically |

---

## Demo Scenarios

Three progressive demos (`demo-scenarios.yml`), each building on the last:

1. **Identity Chain** (`--tags scenario1`): Prove the trust chain end-to-end:
   pod label → SPIRE attestation → JWT-SVID → Vault auth → scoped secret.

2. **Org-Level Isolation** (`--tags scenario2`): Infra-Corp reads its own
   secrets, then attempts cross-org access to SecOps-Team, AppDev-Squad,
   and Platform-Ops. All three return HTTP 403.

3. **Full Org-Tree Scoping** (`--tags scenario3`): Walk through the target
   architecture: what AWX pod labels, SPIRE entries, and Vault policies
   look like at project, JT, and playbook depth. Conceptual (requires
   Gap 1) but uses the exact same SPIRE/Vault infrastructure.

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
