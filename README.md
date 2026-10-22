# AAP + SPIFFE/Vault Zero-Trust POC

Granular, per-workload secret access for Ansible Automation Platform using
[SPIFFE](https://spiffe.io/) cryptographic workload identity and HashiCorp Vault.

## Why SPIFFE for AAP?

AAP 2.7 supports several Vault auth methods natively: AppRole, scoped tokens,
Kubernetes auth, and the new OIDC workload identity credential. These work
well when a platform admin configures credentials per job template.

Enterprise customers with multi-tenant AAP environments need more:

| Need | Native AAP | This POC (SPIFFE) |
|---|---|---|
| Per-org secret isolation | Manual credential per JT | Automatic via pod labels |
| Cross-cluster trust | Separate config per cluster | SPIRE federation |
| Workload attestation | Bearer token (asserted) | Kubelet attestation (verified) |
| Self-service for teams | Admin configures each JT | Org label triggers identity |
| Playbook-level scoping | Vault bound_claims (requires per-JT OIDC credential) | CredentialComposer + SPIRE selectors |

SPIFFE adds infrastructure-level workload identity that complements AAP's
application-level OIDC JWT. Different AAP organizations get different SPIFFE
identities, different Vault policies, and different secret access, with
zero manual credential configuration per job template.

## Architecture

```
                    SPIRE Server
                   (trust root, CA)
                    /         \
            SPIRE Agent     OIDC Discovery Provider
           (workload API)   (serves JWKS for Vault)
                |                 |
          SPIFFE CSI Driver  Vault JWT Auth
         (mounts Workload    (validates JWT via
          API into pods)      OIDC Discovery)
                |                 |
          spiffe-helper      Vault Token
         (fetch JWT-SVID)    (scoped to org policy)
                |                 |
              AAP EE Pod ---------+
         (lookup plugin fetches secrets per call)
```

### Components

| Component | What It Does | Deployed As |
|---|---|---|
| SPIRE Server | Trust root, issues SVIDs, serves as CA | StatefulSet in `spire-system` |
| SPIRE Agent | Attests workloads via kubelet, exposes Workload API | DaemonSet on every node |
| SPIFFE CSI Driver | Mounts the Workload API socket into pods as a CSI volume | DaemonSet on every node |
| OIDC Discovery Provider | Publishes JWKS so Vault can verify JWT-SVIDs | Sidecar in SPIRE Server pod |
| Kyverno | Injects spiffe-helper + vault-client sidecars into AAP pods | Deployment in `kyverno` |
| Vault | Stores secrets, validates JWTs via OIDC Discovery | StatefulSet in `vault` |
| spiffe-helper | Fetches JWT-SVID from Workload API, writes to file | Injected init container + sidecar |
| spiffe-vault-client | Exchanges JWT for Vault token, fetches secrets | Injected init container + sidecar |

### SPIFFE CSI Driver

The SPIFFE CSI driver replaces hostPath mounts for the SPIRE Agent socket.
Instead of mounting `/run/spire/sockets` from the host (which requires
privileged containers), each pod gets the Workload API socket via a CSI
ephemeral volume:

```yaml
volumes:
  - name: spiffe-workload-api
    csi:
      driver: csi.spiffe.io
      readOnly: true
```

Benefits over hostPath:
- No privileged security context needed on workload containers
- No `fix-jwt-perms` init container (CSI handles permissions)
- Standard Kubernetes volume interface
- Compatible with Pod Security Standards (restricted profile)

### End-to-End Flow

1. **Kyverno** intercepts AAP pod creation and injects sidecars + CSI volume
2. **SPIFFE CSI Driver** mounts the Workload API socket into the pod
3. **SPIRE Agent** validates the pod via kubelet k8s_psat attestation
4. **init-spiffe-helper** fetches a JWT-SVID (5-min TTL) and writes to `/svids/jwt.token`
5. **init-spiffe-vault-client** POSTs the JWT to Vault `/v1/auth/jwt/login`
6. **Vault** validates the JWT signature via SPIRE's OIDC public keys, checks `sub` and `aud`
7. **Vault** returns a scoped token with only the policies for that SPIFFE identity
8. **init-spiffe-vault-client** reads secrets, writes to shared volume, exits
9. **AAP containers** start and consume credentials from the shared volume
10. **Sidecars** continuously rotate JWT-SVID and refresh secrets

## Demo Scenarios

### Scenario 1: Platform Zero-Trust Identity

AAP's platform identity (`spiffe://...ns/aap/sa/aap-controller`) authenticates
to Vault and reads platform-level secrets at `hub/aap/*`.

### Scenario 2: Multi-Org Secret Isolation

Each AAP organization gets its own SPIFFE ID and Vault policy:

| Organization | SPIFFE ID | Vault Path |
|---|---|---|
| Infra-Corp | `spiffe://...org/infra-corp` | `secret/data/aap/org/infra-corp/*` |
| AppDev-Squad | `spiffe://...org/appdev-squad` | `secret/data/aap/org/appdev-squad/*` |
| SecOps-Team | `spiffe://...org/secops-team` | `secret/data/aap/org/secops-team/*` |
| Platform-Ops | `spiffe://...org/platform-ops` | `secret/data/aap/org/platform-ops/*` |

Infra-Corp **cannot** read AppDev-Squad's secrets, even though they share the
same AAP instance. Verified via E2E tests on a live cluster.

### Scenario 3: EDA Dynamic Credentials

An EDA rulebook activation gets AWS credentials from Vault at event time,
authenticated by the EDA pod's SPIFFE identity. Credentials are never persisted.

## RBAC Model (Four Layers)

| Layer | Mechanism | What It Enforces |
|---|---|---|
| 1. SPIRE selectors | `k8s:sa:` / `k8s:pod-label:` | Each pod type gets exactly one SPIFFE ID |
| 2. Vault bound_subject | JWT `sub` must match role | JWT for org A can't auth to org B's role |
| 3. Kyverno + Container Groups | Per-workload sidecar/init config | Controller gets platform role, EE gets org role |
| 4. Lookup plugin | Per-call Vault auth | No ambient credentials, no pre-fetched cache |

## Playbook Consumption: spiffe_vault Lookup Plugin

```yaml
db_password: "{{ lookup('spiffe_vault',
    'secret/data/aap/org/infra-corp/credentials',
    field='cloud_password',
    vault_role='aap-org-infra-corp') }}"
```

Each org's Container Group labels the EE pod for SPIRE identity selection.
The lookup plugin reads the JWT, authenticates to Vault with the org's role,
and returns the secret. Cross-org access is denied by Vault's `bound_subject`.

## Open Questions: AWX Gaps for Granular Attestation

Source code analysis of AWX (verified against the production-installed code
on the lab cluster) identified gaps that prevent fully granular workload
attestation at the org/project/playbook level.

### Gap 1: No org/project/playbook labels on K8s EE pods

AWX `receptor.py` (line 772-776) sets only two labels on execution pods:
`ansible-awx` (install UUID) and `ansible-awx-job-id`. No organization,
project, job template, or playbook labels are injected. SPIRE (and any
external identity system) cannot differentiate jobs by scope.

The data is available at pod creation time (`self.task.instance.organization`,
`project`, `playbook`). Adding labels would be ~10 lines.

### Gap 2: No container labels on podman execution (VM nodes)

`build_execution_environment_params()` in `jobs.py` passes no `--label` flags
to podman. There is no `container_options_override` field on `InstanceGroup`
(unlike `pod_spec_override` for K8s).

### Gap 3: OIDC JWT requires per-JT credential configuration

AAP 2.7's OIDC JWT already contains the full org hierarchy as claims
(`organization_name`, `project_name`, `playbook_name`, hierarchical `groups`).
But the JWT is only minted when a "HashiCorp Vault Secret Lookup (OIDC)"
credential is explicitly attached to each job template. There is no mechanism
for credential inheritance from org/project level or a default OIDC credential
per organization.

### Complementary, Not Alternative

Pod/container labels benefit SPIRE and external attestation systems.
The OIDC JWT benefits Vault directly. Both are needed: labels for
infrastructure-level attestation, JWT for application-level authorization.

## Prerequisites

- OCP 4.x cluster with AAP 2.7 deployed
- `oc` CLI authenticated to the cluster
- `ansible-playbook` with `kubernetes.core` collection
- `helm` CLI available

## Quick Start

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

### Deploy individual phases

```bash
ansible-playbook deploy-poc.yml --tags spire      # SPIRE + CSI driver + OIDC
ansible-playbook deploy-poc.yml --tags vault       # Vault + auto-unseal + seed
ansible-playbook deploy-poc.yml --tags integrate   # Wire SPIFFE JWT auth in Vault
ansible-playbook deploy-poc.yml --tags kyverno     # Kyverno policy engine
ansible-playbook deploy-poc.yml --tags aap         # Kyverno policy + Container Groups
```

## Repository Structure

```
ansible.cfg                       Ansible configuration
inventory/hosts.yml               Inventory (localhost)
group_vars/all.yml                Global variables (cluster domain, SPIFFE IDs, selectors)
deploy-poc.yml                    Full deployment playbook
demo-scenarios.yml                Three demo scenarios
teardown-poc.yml                  Cleanup playbook
scripts/
  spiffe-vault-client.py          Credential manager (adapted from ZTVP qtodo pattern)
lookup_plugins/
  spiffe_vault.py                 Ansible lookup plugin for per-job Vault auth
playbooks/
  demo-credential-isolation.yml   Demo: per-org credential isolation
```

## Adapting for Your Cluster

Edit `group_vars/all.yml`:

```yaml
cluster_domain: "apps.your-cluster.example.com"
aap_namespace: aap
```

## Key References

- [SPIRE SPIFFE CSI Driver](https://github.com/spiffe/spiffe-csi)
- [layered-zero-trust pattern](https://github.com/validatedpatterns/layered-zero-trust)
- [SPIRE + Vault OIDC tutorial](https://spiffe.io/docs/latest/keyless/vault/readme/)
- [Vault SPIFFE auth method](https://developer.hashicorp.com/vault/docs/auth/spiffe/spiffe)
- [AAP OIDC for Vault](https://docs.redhat.com/en/documentation/red_hat_ansible_automation_platform/2.7/whats_new-oidc_authentication_for_hashicorp_vault)

## License

Apache-2.0
