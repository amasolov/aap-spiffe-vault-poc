# Zero-Trust Secret Access for AAP with SPIFFE and Vault

A proposed pattern for granular, per-workload secret access in Ansible
Automation Platform using [SPIFFE](https://spiffe.io/) cryptographic
workload identity and HashiCorp Vault.

## Table of Contents

- [The Problem](#the-problem)
- [Architecture](#architecture)
- [Open Questions for AAP Product](#open-questions-for-aap-product)
- [Deployment Guide](#deployment-guide)
- [Demo Scenarios](#demo-scenarios)
- [References](#references)

---

## The Problem

### Multi-Tenant AAP Needs Per-Workload Secret Scoping

Enterprise customers run multi-tenant AAP environments where different
organizations, projects, and job templates must access different secrets.
A single AAP instance serves multiple teams, each with their own cloud
credentials, SSH keys, and API tokens stored in HashiCorp Vault.

Today, AAP provides several Vault auth methods (AppRole, scoped tokens,
Kubernetes auth, OIDC workload identity). All of them require manual
credential configuration per job template. None of them provide
**infrastructure-level workload attestation**: the ability for an external
system to verify which AAP organization, project, or playbook is running
inside a given container, and to scope secret access based on that
verified identity.

### What's Missing

| Capability | Status in AAP 2.7 |
|---|---|
| Per-org Vault secret isolation | Requires manual credential per JT |
| Cryptographic workload identity | OIDC JWT exists but must be configured per JT |
| Infrastructure-level attestation | No pod/container labels for org/project/playbook |
| Cross-cluster trust federation | Separate config per cluster |
| Self-service secret access | Platform admin must configure each JT |

### Two Complementary Gaps

1. **Labels for external attestation**: AWX does not label K8s pods or
   podman containers with org/project/playbook metadata. SPIRE, Istio,
   OPA, and other infrastructure tools cannot differentiate AAP workloads.

2. **Activation for built-in OIDC JWT**: AAP 2.7's OIDC JWT already
   contains the full org hierarchy (`organization_name`, `project_name`,
   `playbook_name`, hierarchical `groups` claim). But it is only minted
   when a "HashiCorp Vault Secret Lookup (OIDC)" credential is explicitly
   attached to each job template. There is no credential inheritance or
   default OIDC credential per organization.

Both gaps are detailed in [Open Questions](#open-questions-for-aap-product)
below.

---

## Architecture

This pattern uses SPIFFE/SPIRE to provide infrastructure-level workload
identity for AAP pods, and Vault JWT auth to exchange that identity for
scoped secret access. The approach complements (not replaces) AAP's
built-in OIDC JWT.

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
│        (fetches JWT-SVID)      (per-org policy)                 │
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

### Multi-Org Secret Isolation

Each AAP organization gets its own SPIFFE ID and Vault policy:

| Organization | SPIFFE ID | Vault Path |
|---|---|---|
| Infra-Corp | `spiffe://.../org/infra-corp` | `secret/data/aap/org/infra-corp/*` |
| AppDev-Squad | `spiffe://.../org/appdev-squad` | `secret/data/aap/org/appdev-squad/*` |
| SecOps-Team | `spiffe://.../org/secops-team` | `secret/data/aap/org/secops-team/*` |
| Platform-Ops | `spiffe://.../org/platform-ops` | `secret/data/aap/org/platform-ops/*` |

Infra-Corp **cannot** read AppDev-Squad's secrets, even though they share the
same AAP instance. Verified via E2E tests: Vault returns HTTP 403 for cross-org
access attempts.

### Playbook Consumption

The `spiffe_vault` lookup plugin authenticates to Vault per call using the
pod's JWT-SVID:

```yaml
db_password: "{{ lookup('spiffe_vault',
    'secret/data/aap/org/infra-corp/credentials',
    field='cloud_password',
    vault_role='aap-org-infra-corp') }}"
```

Each org's Container Group labels the EE pod for SPIRE identity selection.
The lookup plugin reads the JWT, authenticates to Vault with the org's role,
and returns the secret. Cross-org access is denied by Vault's `bound_subject`.

---

## Open Questions for AAP Product

Source code analysis of AWX (verified against the production-installed code
on a live cluster) identified three gaps that prevent fully granular workload
attestation at the org/project/job template/playbook level.

### Gap 1: No org/project/playbook labels on K8s EE pods

**Source:** `awx/main/tasks/receptor.py` lines 772-776

AWX sets only two labels on execution environment pods: `ansible-awx`
(install UUID) and `ansible-awx-job-id`. No organization, project, job
template, or playbook labels are injected. SPIRE (and any external identity
system) cannot differentiate jobs by scope.

**Impact:** The SPIFFE identity for EE pods can only be scoped to the
organization level (via Container Group labels set at org level). It cannot
be scoped to project or playbook level because that data never appears on
the pod.

**Fix:** The data is available at pod creation time
(`self.task.instance.organization`, `.project`, `.playbook`). Adding labels
would be approximately 10 lines of code.

### Gap 2: No container labels on podman execution (VM nodes)

**Source:** `awx/main/tasks/jobs.py` lines 360-413

`build_execution_environment_params()` passes no `--label` flags to podman.
There is no `container_options_override` field on `InstanceGroup` (unlike
`pod_spec_override` for K8s). On-premise execution nodes running podman
have no mechanism for external identity systems to identify the running job.

**Impact:** SPIRE, systemd, or any container-aware attestation system on
VM execution nodes cannot differentiate AAP jobs.

### Gap 3: OIDC JWT requires per-JT credential configuration

**Source:** `awx/main/tasks/jobs.py` lines 286-330

AAP 2.7's OIDC workload identity JWT already contains the full org
hierarchy as claims:
- `aap_controller_organization_name`
- `aap_controller_project_name`
- `aap_controller_playbook_name`
- `aap_groups` (hierarchical: `org:X/project:Y/jt:Z/playbook:P`)

But the JWT is only minted when a "HashiCorp Vault Secret Lookup (OIDC)"
credential is explicitly attached to each job template. There is no
mechanism for credential inheritance from org or project level, and no
default OIDC credential per organization.

**Impact:** To use the rich claims that are already built into the JWT,
an admin must manually attach the OIDC credential to every job template.
This does not scale for large multi-tenant environments.

### Labels and JWT Are Complementary

| Mechanism | Audience | Strength |
|---|---|---|
| Pod/container labels | SPIRE, Istio, OPA, infrastructure tools | Enables infrastructure-level attestation |
| OIDC JWT claims | Vault, cloud IAM, application-level auth | Cryptographically signed, contains full org hierarchy |

Both are needed: labels for external attestation systems that operate at
the infrastructure layer; JWT for direct Vault authorization. This POC
uses labels + SPIRE as a bridge until the JWT activation gap is resolved.

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
