"""
Ansible lookup plugin: authenticate to Vault using a SPIFFE JWT-SVID
and retrieve a secret. Each lookup performs its own JWT auth, ensuring
per-job credential isolation.

The JWT-SVID is written to a file by spiffe-helper (init container)
before the playbook runs. The SPIFFE ID in the JWT determines which
Vault role can be used and which secret paths are accessible.

Usage in playbooks:

    # Fetch a single field
    db_password: "{{ lookup('spiffe_vault',
        'secret/data/aap/org/infra-corp/creds',
        field='db_password',
        vault_role='aap-org-infra-corp') }}"

    # Fetch all fields as a dict
    all_secrets: "{{ lookup('spiffe_vault',
        'secret/data/aap/org/infra-corp/creds',
        vault_role='aap-org-infra-corp') }}"

Environment variables (overridable via kwargs):
    VAULT_URL:   Vault address (default: http://vault.vault.svc:8200)
    JWT_FILE:    Path to JWT-SVID (default: /svids/jwt.token)
"""

from __future__ import annotations

import json
import os
import ssl
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from ansible.errors import AnsibleError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

display = Display()

DOCUMENTATION = r"""
    name: spiffe_vault
    author: Alexey Masolov
    short_description: Fetch secrets from Vault using SPIFFE JWT-SVID
    description:
      - Authenticates to HashiCorp Vault using a SPIFFE JWT-SVID
        written by spiffe-helper, then reads the requested secret path.
      - Each call does its own authentication, so the Vault token scope
        matches the SPIFFE identity of the EE pod running the job.
    options:
      _terms:
        description: Vault KV v2 secret path (e.g. secret/data/aap/org/infra-corp/creds)
        required: true
      vault_role:
        description: Vault JWT auth role name
        required: true
      field:
        description: >
          Return only this key from the secret data dict. When omitted,
          the entire dict is returned as a JSON string.
        required: false
      vault_url:
        description: Vault HTTP address
        default: Value of VAULT_URL env var, or http://vault.vault.svc.cluster.local:8200
      jwt_file:
        description: Path to the JWT-SVID file written by spiffe-helper
        default: Value of JWT_FILE env var, or /svids/jwt.token
"""


class LookupModule(LookupBase):

    def _http(self, url, method="GET", data=None, headers=None, timeout=30):
        headers = headers or {}
        body = None
        if data is not None:
            body = json.dumps(data).encode()
            headers.setdefault("Content-Type", "application/json")

        ctx = ssl.create_default_context()
        ca_bundle = "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem"
        if os.path.exists(ca_bundle):
            ctx.load_verify_locations(ca_bundle)
        else:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        req = Request(url, data=body, headers=headers, method=method)
        try:
            resp = urlopen(req, context=ctx, timeout=timeout)
            return json.loads(resp.read().decode())
        except HTTPError as exc:
            text = exc.read().decode() if exc.fp else ""
            raise AnsibleError(
                f"Vault API error: HTTP {exc.code} from {url}: {text}"
            )

    def run(self, terms, variables=None, **kwargs):
        if not terms:
            raise AnsibleError("spiffe_vault lookup requires a Vault secret path")

        secret_path = terms[0]
        vault_role = kwargs.get("vault_role")
        if not vault_role:
            raise AnsibleError("spiffe_vault lookup requires vault_role=")

        field = kwargs.get("field")
        vault_url = kwargs.get(
            "vault_url",
            os.getenv("VAULT_URL", "http://vault.vault.svc.cluster.local:8200"),
        )
        jwt_file = kwargs.get(
            "jwt_file",
            os.getenv("JWT_FILE", "/svids/jwt.token"),
        )

        # 1. Read the JWT-SVID
        try:
            with open(jwt_file, "r") as f:
                jwt_token = f.read().strip()
        except FileNotFoundError:
            raise AnsibleError(
                f"JWT-SVID file not found at {jwt_file}. "
                f"Ensure spiffe-helper init container ran and the "
                f"svids volume is mounted on the EE container."
            )

        if not jwt_token:
            raise AnsibleError(f"JWT-SVID file {jwt_file} is empty")

        display.vvv(f"spiffe_vault: read JWT ({len(jwt_token)} chars) from {jwt_file}")

        # 2. Authenticate to Vault
        auth_url = f"{vault_url}/v1/auth/jwt/login"
        display.vvv(f"spiffe_vault: authenticating to {auth_url} with role={vault_role}")

        auth_resp = self._http(
            auth_url,
            method="POST",
            data={"role": vault_role, "jwt": jwt_token},
        )

        vault_token = auth_resp.get("auth", {}).get("client_token")
        if not vault_token:
            raise AnsibleError(
                f"Vault JWT auth returned no client_token. "
                f"Check that Vault role '{vault_role}' exists and the "
                f"SPIFFE ID in the JWT matches the role's bound_subject."
            )

        policies = auth_resp.get("auth", {}).get("token_policies", [])
        display.vvv(f"spiffe_vault: authenticated (policies: {policies})")

        # 3. Read the secret
        secret_url = f"{vault_url}/v1/{secret_path}"
        display.vvv(f"spiffe_vault: reading secret from {secret_url}")

        secret_resp = self._http(
            secret_url,
            headers={"X-Vault-Token": vault_token},
        )

        data = secret_resp.get("data", {}).get("data", {})
        if not data:
            raise AnsibleError(
                f"No secret data at {secret_path}. "
                f"The Vault token has policies {policies}; "
                f"verify the path exists and the policy allows read."
            )

        display.vvv(f"spiffe_vault: retrieved {len(data)} key(s)")

        # 4. Return requested field or entire dict
        if field:
            if field not in data:
                raise AnsibleError(
                    f"Field '{field}' not found in {secret_path}. "
                    f"Available fields: {list(data.keys())}"
                )
            return [data[field]]

        return [json.dumps(data)]
