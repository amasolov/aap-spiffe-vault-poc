# AAP + SPIFFE/Vault Zero-Trust POC

Replace Ansible Automation Platform's static Vault credentials with
[SPIFFE](https://spiffe.io/) cryptographic workload identity for short-lived,
least-privilege secret retrieval.

## The Problem

In Red Hat's [Zero Trust Validated Pattern](https://github.com/validatedpatterns/layered-zero-trust),
AAP currently authenticates to HashiCorp Vault using the **root Vault token**.
This gives AAP unrestricted access to every secret in Vault. The token never
expires and is never automatically rotated.

## The Solution

Replace the static Vault token with SPIFFE JWT authentication:

| | Before (Root Token) | After (SPIFFE JWT) |
|---|---|---|
| Stored secret | Root Vault token in AAP DB | Nothing. JWT minted on demand |
| Vault access scope | Everything | Only `secret/data/hub/aap/*` |
| Token lifetime | Infinite | 1 hour, auto-renewed |
| Rotation | Manual | Automatic (SPIRE handles it) |
| Revocation | Change root token, break everything | Remove SPIRE entry, instant |

## Architecture

```
                    SPIRE Server
                   (trust root)
                    /         \
            SPIRE Agent     OIDC Discovery Provider
           (workload API)   (serves JWKS for Vault)
                |                 |
          spiffe-helper      Vault JWT Auth
         (fetch JWT-SVID)    (validate JWT)
                |                 |
        spiffe-vault-client ------+
         (JWT -> Vault token -> secret)
                |
              AAP 2.7
         (consumes credentials)
```

### Components

**SPIRE Server** is the trust root. It issues short-lived cryptographic
identities (SVIDs) and serves as the certificate authority for the trust
domain. Runs as a StatefulSet in `spire-system`.

**SPIRE Agent** runs as a DaemonSet on every node. It attests workloads via
the kubelet (using projected service account tokens) and exposes the Workload
API as a Unix socket on the host at `/run/spire/sockets/agent.sock`.

**OIDC Discovery Provider** runs as a sidecar in the SPIRE Server pod. It
publishes a standard `/.well-known/openid-configuration` endpoint that serves
the public keys (JWKS) Vault uses to verify JWT-SVIDs. This is the bridge
that lets Vault trust SPIRE-issued tokens without a direct integration.

**spiffe-helper** is an init container (from the official SPIRE project) that
connects to the SPIRE Agent's Workload API and writes a JWT-SVID to a shared
volume (`/svids/jwt.token`). The JWT has a 5-minute TTL and contains the pod's
SPIFFE ID as the `sub` claim and the Vault audience as the `aud` claim. It
exits once the SVID is written (using `-exitWhenReady`).

**spiffe-vault-client** (`scripts/spiffe-vault-client.py`) is the credential
manager adapted from the Validated Pattern's
[qtodo sidecar](https://github.com/validatedpatterns/layered-zero-trust). It:

1. Reads the JWT-SVID file written by spiffe-helper
2. POSTs it to Vault's `/v1/auth/jwt/login` endpoint with the assigned role
3. Receives a scoped Vault token (1-hour TTL, specific policy)
4. Uses that token to read secrets from the allowed Vault path
5. Writes the secrets to a file that AAP can consume

It supports three modes: `--init` (fetch once and exit, used in the CronJob),
sidecar (continuous loop with automatic token renewal at 50% of lease), and
`--print-secrets` (one-shot demo output to stdout).

### End-to-End Flow

1. **SPIRE Agent** validates the AAP pod via the kubelet k8s_psat attestor
2. **spiffe-helper** init container fetches a JWT-SVID from the Workload API (5-min TTL)
3. **spiffe-vault-client** POSTs the JWT to Vault `/v1/auth/jwt/login`
4. **Vault** validates the JWT signature against SPIRE's OIDC public keys and checks
   the `sub` (SPIFFE ID) and `aud` (audience) claims match the configured role
5. **Vault** returns a scoped token (1-hour TTL) with only the policies assigned to that role
6. **spiffe-vault-client** uses the token to read secrets and writes them to a shared file
7. **AAP** consumes the credentials from the file

## Three Demo Scenarios

### Scenario 1: Platform Zero-Trust Identity

AAP's platform identity (`spiffe://...ns/aap/sa/aap-controller`) replaces
the root Vault token. The SPIFFE-scoped Vault token can only read `hub/aap/*`.

**The wow moment**: delete the SPIRE registration entry, re-run the job,
it fails immediately with "permission denied." Re-add the entry, it works
again. No tokens to rotate, no credentials to update.

### Scenario 2: Multi-Org Secret Isolation

Each AAP organization gets its own SPIFFE ID and Vault policy:

| Organization | SPIFFE ID | Vault Path |
|---|---|---|
| Infra-Corp | `spiffe://...org/infra-corp` | `secret/data/aap/org/infra-corp/*` |
| AppDev-Squad | `spiffe://...org/appdev-squad` | `secret/data/aap/org/appdev-squad/*` |
| SecOps-Team | `spiffe://...org/secops-team` | `secret/data/aap/org/secops-team/*` |
| Platform-Ops | `spiffe://...org/platform-ops` | `secret/data/aap/org/platform-ops/*` |

Infra-Corp **cannot** read AppDev-Squad's secrets, even though they share the
same AAP instance.

### Scenario 3: EDA Dynamic Credentials

An EDA rulebook activation needs AWS credentials to remediate an incident.
Instead of storing those credentials in AAP, the EDA pod's SPIFFE identity
fetches them from Vault at event time. Credentials are never persisted.

## Prerequisites

- OCP 4.x cluster with AAP 2.7 deployed
- `oc` CLI authenticated to the cluster
- `ansible-playbook` with `kubernetes.core` collection
- No OPP entitlement required (uses upstream SPIRE, not ZTWIM)

## Quick Start

```bash
# Clone
git clone https://github.com/amasolov/aap-spiffe-vault-poc.git
cd aap-spiffe-vault-poc

# Set kubeconfig
export KUBECONFIG=/path/to/your/kubeconfig

# Deploy everything (SPIRE + Vault + integration + AAP config)
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
ansible-playbook deploy-poc.yml --tags spire      # SPIRE server + agent + OIDC
ansible-playbook deploy-poc.yml --tags vault       # Vault in dev mode + seed secrets
ansible-playbook deploy-poc.yml --tags integrate   # Wire SPIFFE JWT auth in Vault
ansible-playbook deploy-poc.yml --tags aap         # Deploy sidecar in AAP namespace
```

## Repository Structure

```
ansible.cfg                       Ansible configuration
inventory/hosts.yml               Inventory (localhost)
group_vars/all.yml                Global variables (cluster domain, SPIFFE IDs, etc.)
deploy-poc.yml                    Full deployment playbook
demo-scenarios.yml                Three demo scenarios
teardown-poc.yml                  Cleanup playbook
scripts/
  spiffe-vault-client.py          Credential manager (adapted from ZTVP qtodo pattern)
```

## Adapting for Your Cluster

Edit `group_vars/all.yml`:

```yaml
cluster_domain: "apps.your-cluster.example.com"
aap_namespace: aap          # your AAP namespace
```

The SPIFFE trust domain defaults to the cluster domain. SPIRE registration
entries are created for all pods in the AAP namespace.

## Roadmap: Upstream Contribution

This POC is designed to be contributed to the
[layered-zero-trust](https://github.com/validatedpatterns/layered-zero-trust)
validated pattern:

| Target | Change |
|---|---|
| `overrides/values-vault-jwt.yaml` | Add AAP JWT policy + role |
| `charts/aap-config` | Add SPIFFE sidecar, remove root token |
| ClusterSPIFFEID | Register AAP pods for ZTWIM identity |
| `rhvp.cluster_utils` | No changes (vault_jwt tasks are generic) |
| Documentation | AAP SPIFFE integration guide |

## Key References

- [layered-zero-trust pattern](https://github.com/validatedpatterns/layered-zero-trust)
- [rhvp.cluster_utils vault_jwt.yaml](https://github.com/validatedpatterns/rhvp.cluster_utils/blob/main/roles/vault_utils/tasks/vault_jwt.yaml)
- [SPIRE + Vault OIDC tutorial](https://spiffe.io/docs/latest/keyless/vault/readme/)
- [Vault SPIFFE auth method](https://developer.hashicorp.com/vault/docs/auth/spiffe/spiffe)
- [AAP credential plugins](https://docs.ansible.com/projects/awx/en/24.6.1/userguide/credential_plugins.html)

## License

Apache-2.0
