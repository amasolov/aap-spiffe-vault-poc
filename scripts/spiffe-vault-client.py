#!/usr/bin/env python3
"""
SPIFFE-enabled Vault credential manager for AAP.

Adapted from the layered-zero-trust validated pattern's qtodo sidecar
(github.com/validatedpatterns/layered-zero-trust).

This script:
1. Reads a JWT-SVID from the SPIRE Workload API (via spiffe-helper)
2. Authenticates to HashiCorp Vault using the JWT
3. Retrieves secrets from Vault
4. Outputs them in a format consumable by AAP

Runs as:
- Init container: fetch once and exit (--init)
- Sidecar: continuous loop with automatic token renewal
- Standalone: one-shot fetch for demos (--init --verbose)
"""

import argparse
import json
import logging
import os
import ssl
import sys
import time
from datetime import datetime
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


class VaultCredentialManager:
    """Manages Vault authentication via SPIFFE JWT-SVIDs."""

    def __init__(self):
        self.vault_url = os.getenv("VAULT_URL")
        self.vault_secret_path = os.getenv("VAULT_CREDENTIAL_PATH")
        self.vault_role = os.getenv("VAULT_ROLE")
        self.credentials_file = os.getenv(
            "CREDENTIALS_FILE", "/run/secrets/credentials/vault-token"
        )
        self.jwt_token_file = os.getenv(
            "JWT_TOKEN_FILE", "/svids/jwt.token"
        )
        self.ca_bundle = os.getenv(
            "CA_BUNDLE",
            "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem",
        )

        required = {
            "VAULT_URL": self.vault_url,
            "VAULT_CREDENTIAL_PATH": self.vault_secret_path,
            "VAULT_ROLE": self.vault_role,
        }
        missing = [k for k, v in required.items() if not v]
        if missing:
            raise ValueError(f"Missing required env vars: {', '.join(missing)}")

        logger.info("VaultCredentialManager initialized")
        logger.info("  VAULT_URL: %s", self.vault_url)
        logger.info("  VAULT_ROLE: %s", self.vault_role)
        logger.info("  VAULT_CREDENTIAL_PATH: %s", self.vault_secret_path)
        logger.info("  JWT_TOKEN_FILE: %s", self.jwt_token_file)
        logger.info("  CREDENTIALS_FILE: %s", self.credentials_file)

        self.vault_token = None
        self.lease_duration = 0
        self.token_creation_time = None

        self.ssl_context = ssl.create_default_context()
        if os.path.exists(self.ca_bundle):
            self.ssl_context.load_verify_locations(self.ca_bundle)
            logger.info("Loaded CA bundle from: %s", self.ca_bundle)
        else:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE
            logger.warning("No CA bundle found; TLS verification disabled")

    def _http(self, url, method="GET", data=None, headers=None, timeout=30):
        """Make an HTTP request and return a response-like dict."""
        headers = headers or {}
        body = None
        if data is not None:
            body = json.dumps(data).encode() if isinstance(data, dict) else data
            headers.setdefault("Content-Type", "application/json")

        req = Request(url, data=body, headers=headers, method=method)
        try:
            resp = urlopen(req, context=self.ssl_context, timeout=timeout)
            text = resp.read().decode()
            return {"status": resp.getcode(), "text": text, "json": lambda: json.loads(text) if text else {}}
        except HTTPError as exc:
            text = exc.read().decode() if exc.fp else ""
            return {"status": exc.code, "text": text, "json": lambda: json.loads(text) if text else {}}

    def get_jwt(self):
        """Read the JWT-SVID written by spiffe-helper."""
        with open(self.jwt_token_file, "r") as f:
            jwt = f.read().strip()
        logger.info("Read JWT-SVID (%d chars)", len(jwt))
        return jwt

    def authenticate(self):
        """POST the JWT-SVID to Vault's /auth/jwt/login endpoint."""
        jwt = self.get_jwt()
        resp = self._http(
            f"{self.vault_url}/v1/auth/jwt/login",
            method="POST",
            data={"role": self.vault_role, "jwt": jwt},
        )
        if resp["status"] != 200:
            logger.error("Vault auth failed: %s %s", resp["status"], resp["text"])
            raise RuntimeError(f"Vault auth failed: {resp['status']}")

        auth = resp["json"]()["auth"]
        self.vault_token = auth["client_token"]
        self.lease_duration = auth["lease_duration"]
        self.token_creation_time = datetime.now()
        logger.info(
            "Authenticated to Vault (lease: %ds, policies: %s)",
            self.lease_duration,
            auth.get("token_policies", []),
        )

    def get_secret(self):
        """Read a secret from Vault using the authenticated token."""
        if not self.vault_token:
            raise RuntimeError("Not authenticated")

        resp = self._http(
            f"{self.vault_url}/v1/{self.vault_secret_path}",
            headers={"X-Vault-Token": self.vault_token},
        )
        if resp["status"] != 200:
            logger.error("Secret read failed: %s %s", resp["status"], resp["text"])
            raise RuntimeError(f"Secret read failed: {resp['status']}")

        data = resp["json"]().get("data", {}).get("data", {})
        logger.info("Retrieved %d secret key(s)", len(data))
        return data

    def write_output(self, secrets):
        """Write secrets to the output file."""
        os.makedirs(os.path.dirname(self.credentials_file), exist_ok=True)
        with open(self.credentials_file, "w") as f:
            f.write(f"# Fetched from Vault via SPIFFE JWT at {datetime.now().isoformat()}\n")
            f.write(f"# Role: {self.vault_role}\n")
            f.write(f"# Path: {self.vault_secret_path}\n\n")
            for key, value in secrets.items():
                f.write(f"{key}={value}\n")
        logger.info("Wrote credentials to %s", self.credentials_file)

    def needs_renewal(self):
        """Check if the Vault token needs renewal (at 50% of lease)."""
        if not self.token_creation_time or not self.lease_duration:
            return True
        elapsed = (datetime.now() - self.token_creation_time).total_seconds()
        return elapsed >= (self.lease_duration / 2)

    def run(self, init=False):
        """Main loop: authenticate, fetch, write, sleep, repeat."""
        logger.info("Starting credential manager (init=%s)", init)
        while True:
            try:
                if not self.vault_token or self.needs_renewal():
                    self.authenticate()
                secrets = self.get_secret()
                self.write_output(secrets)

                if init:
                    logger.info("Init complete")
                    return secrets

                sleep_time = min(max(self.lease_duration * 0.5, 30), 86400)
                logger.info("Sleeping %ds", int(sleep_time))
                time.sleep(sleep_time)
            except KeyboardInterrupt:
                logger.info("Shutting down")
                break
            except Exception:
                logger.exception("Error in main loop, retrying in 60s")
                time.sleep(60)


def main():
    parser = argparse.ArgumentParser(description="SPIFFE Vault credential manager for AAP")
    parser.add_argument("--init", action="store_true", help="Fetch once and exit")
    parser.add_argument("--verbose", action="store_true", help="Enable debug logging")
    parser.add_argument("--print-secrets", action="store_true", help="Print secrets to stdout (demo only)")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        mgr = VaultCredentialManager()
        secrets = mgr.run(init=args.init or args.print_secrets)
        if args.print_secrets and secrets:
            print("\n=== Secrets retrieved via SPIFFE JWT ===")
            for k, v in secrets.items():
                print(f"  {k}: {v}")
            print("========================================\n")
    except Exception as exc:
        logger.error("Fatal: %s", exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
