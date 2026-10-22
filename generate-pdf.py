#!/usr/bin/env python3
"""Generate a shareable PDF from the AAP SPIFFE/Vault POC deep dive content."""

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    PageBreak, KeepTogether,
)

OUTPUT = "aap-spiffe-vault-deep-dive.pdf"

RED_HAT_RED = HexColor("#EE0000")
DARK_BG = HexColor("#F5F5F5")
BORDER = HexColor("#DDDDDD")
ACCENT = HexColor("#0066CC")

styles = getSampleStyleSheet()
styles.add(ParagraphStyle("DocTitle", parent=styles["Title"], fontSize=22, spaceAfter=6, textColor=HexColor("#1A1A1A")))
styles.add(ParagraphStyle("DocSubtitle", parent=styles["Normal"], fontSize=11, textColor=HexColor("#666666"), spaceAfter=20))
styles.add(ParagraphStyle("SectionH", parent=styles["Heading1"], fontSize=16, spaceBefore=24, spaceAfter=10, textColor=HexColor("#1A1A1A")))
styles.add(ParagraphStyle("SubH", parent=styles["Heading2"], fontSize=13, spaceBefore=16, spaceAfter=6, textColor=HexColor("#333333")))
styles.add(ParagraphStyle("Body", parent=styles["Normal"], fontSize=10, leading=14, spaceAfter=8))
styles.add(ParagraphStyle("SmallBody", parent=styles["Normal"], fontSize=9, leading=12, spaceAfter=6, textColor=HexColor("#444444")))
styles.add(ParagraphStyle("CodeBlock", parent=styles["Code"], fontSize=8, leading=10, backColor=DARK_BG, borderColor=BORDER, borderWidth=0.5, borderPadding=6, spaceAfter=8))
styles.add(ParagraphStyle("Callout", parent=styles["Normal"], fontSize=9, leading=12, backColor=HexColor("#E8F4FD"), borderColor=ACCENT, borderWidth=1, borderPadding=8, spaceAfter=10))
styles.add(ParagraphStyle("CalloutSuccess", parent=styles["Normal"], fontSize=9, leading=12, backColor=HexColor("#E8F8E8"), borderColor=HexColor("#22AA22"), borderWidth=1, borderPadding=8, spaceAfter=10))

def make_table(headers, rows, col_widths=None):
    data = [headers] + rows
    if col_widths is None:
        col_widths = [460 / len(headers)] * len(headers)
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), HexColor("#2A2A2A")),
        ("TEXTCOLOR", (0, 0), (-1, 0), HexColor("#FFFFFF")),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, 0), 8),
        ("FONTSIZE", (0, 1), (-1, -1), 8),
        ("LEADING", (0, 0), (-1, -1), 10),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.5, BORDER),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [HexColor("#FFFFFF"), DARK_BG]),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
    ]))
    return t


def build():
    doc = SimpleDocTemplate(OUTPUT, pagesize=A4,
                            leftMargin=25*mm, rightMargin=25*mm,
                            topMargin=20*mm, bottomMargin=20*mm)
    story = []
    W = doc.width

    # Title page
    story.append(Spacer(1, 40))
    story.append(Paragraph("AAP + SPIFFE/Vault", styles["DocTitle"]))
    story.append(Paragraph("Zero-Trust Deep Dive", styles["DocTitle"]))
    story.append(Spacer(1, 8))
    story.append(Paragraph(
        "Replacing static Vault credentials with cryptographic workload identity "
        "for Ansible Automation Platform. Covers architecture, RBAC model, cluster "
        "verification, non-K8s execution, Vault Enterprise, and granular isolation.",
        styles["DocSubtitle"]))
    story.append(Spacer(1, 12))
    story.append(Paragraph("POC on OCP lab cluster (HyperShift KubeVirt)", styles["SmallBody"]))
    story.append(PageBreak())

    # --- 1. Why This Matters ---
    story.append(Paragraph("1. Why This Matters", styles["SectionH"]))
    story.append(Paragraph(
        "AAP natively supports several Vault auth methods (AppRole, scoped tokens, Kubernetes auth, "
        "and OIDC workload identity). But none of these methods provide granular, per-workload "
        "attestation at the infrastructure level. A compromised pod can impersonate any job "
        "because identity is asserted (bearer token), not attested (verified by the platform).",
        styles["Body"]))
    story.append(Paragraph(
        "Even with AppRole or K8s auth, you still have stored credentials (a secret_id or a "
        "service-account-scoped token), and identity is flat: every job running under the same SA "
        "or AppRole gets the same Vault access regardless of which AAP organization or playbook "
        "triggered it.", styles["Body"]))
    story.append(make_table(
        ["Approach", "Stored Secret", "Rotation", "Scope", "Identity Proof"],
        [
            ["Static credential", "Token or secret_id in AAP DB", "Manual", "Per-credential", "Bearer (asserted)"],
            ["AppRole (native AAP)", "secret_id in AAP DB", "Manual or wrapped", "Policy-scoped", "Shared secret"],
            ["K8s auth (native AAP)", "Nothing (SA token)", "Automatic", "Policy-scoped", "Pod SA token"],
            ["SPIFFE JWT (this POC)", "Nothing", "Automatic", "Policy-scoped, per-job", "Cryptographic attestation"],
        ],
        col_widths=[W*0.22, W*0.2, W*0.14, W*0.2, W*0.24],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Why SPIFFE, not just AppRole or K8s auth?</b> AppRole and K8s auth already eliminate the root "
        "token. SPIFFE adds three things: (1) identity is attested by the kubelet, not just asserted by a "
        "bearer token; (2) per-job granularity via pod labels, so different org EE pods get different "
        "identities even with the same service account; (3) portable trust that federates across clusters.",
        styles["Callout"]))

    # --- 2. Architecture ---
    story.append(Paragraph("2. Architecture", styles["SectionH"]))
    story.append(make_table(
        ["Namespace", "Component", "Type", "Role"],
        [
            ["spire-system", "SPIRE Server + OIDC sidecar", "StatefulSet", "Trust root, CA, OIDC key server"],
            ["spire-system", "SPIRE Agent", "DaemonSet", "Workload API on every node"],
            ["vault", "Vault", "StatefulSet", "Secret storage, JWT auth"],
            ["kyverno", "Kyverno", "Deployment", "Sidecar injection policy"],
            ["aap", "AAP 2.7", "Operator-managed", "Controller, Hub, EDA, Gateway"],
        ],
        col_widths=[W*0.15, W*0.3, W*0.15, W*0.4],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph("<b>OIDC Discovery Provider</b>: runs as a sidecar in the SPIRE Server pod. "
        "It publishes SPIRE's public signing keys as standard JWKS at /.well-known/openid-configuration. "
        "Vault fetches these keys to verify JWT-SVIDs. This is NOT the same as AAP Gateway's OIDC, which "
        "serves Gateway's own keys for human user SSO. They publish different key material for different purposes.",
        styles["Body"]))
    story.append(Paragraph("<b>How Vault trusts SPIRE</b>: Vault's JWT auth is configured with "
        "oidc_discovery_url pointing to the SPIRE OIDC Discovery Provider's internal K8s service URL. "
        "Vault periodically fetches the JWKS and uses the public keys to verify JWT-SVIDs locally. "
        "No direct SPIRE integration is needed; they communicate via standard OIDC.",
        styles["Body"]))

    # --- 3. End-to-End Flow ---
    story.append(Paragraph("3. End-to-End Flow", styles["SectionH"]))
    steps = [
        "1. Kyverno intercepts AAP pod creation, injects spiffe-helper + spiffe-vault-client as init containers and sidecars, plus SPIFFE CSI volume",
        "2. SPIFFE CSI driver mounts the Workload API socket into the pod (no hostPath, no privileged SCC)",
        "3. SPIRE Agent validates the pod via kubelet k8s_psat attestor",
        "4. init-spiffe-helper fetches a JWT-SVID (5-min TTL) from the Workload API and writes it to /svids/jwt.token",
        "5. init-spiffe-vault-client POSTs the JWT to Vault /v1/auth/jwt/login with role=aap-platform",
        "6. Vault validates JWT signature against SPIRE's OIDC keys, checks sub and aud claims, returns scoped token (1h TTL)",
        "7. init-spiffe-vault-client reads secrets, writes to shared volume, exits",
        "8. AAP containers start and consume credentials; sidecars continuously rotate JWT and refresh secrets",
    ]
    for s in steps:
        story.append(Paragraph(s, styles["SmallBody"]))

    # --- 4. RBAC Model ---
    story.append(Paragraph("4. RBAC Model (Four Layers)", styles["SectionH"]))
    story.append(make_table(
        ["Layer", "Mechanism", "What It Enforces"],
        [
            ["1. SPIRE selectors", "k8s:sa: / k8s:pod-label:", "Each pod type gets exactly one SPIFFE ID"],
            ["2. Vault bound_subject", "JWT sub must match role", "JWT for org A can't auth to org B's role"],
            ["3. Kyverno + Container Groups", "Per-workload sidecar/init config", "Controller gets platform role, EE gets org role"],
            ["4. Lookup plugin", "Per-call Vault auth", "No ambient credentials, no pre-fetched cache"],
        ],
        col_widths=[W*0.18, W*0.32, W*0.5],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "The multi-tenant tension: AAP's controller-task pod serves all orgs, but SPIFFE identity is "
        "per-pod. Resolution: the controller gets the platform SPIFFE identity (reads platform secrets), "
        "while per-org isolation happens at the EE layer via Container Groups with org-specific pod labels.",
        styles["Body"]))

    # --- 5. Playbook Consumption ---
    story.append(Paragraph("5. Playbook Consumption: spiffe_vault Lookup Plugin", styles["SectionH"]))
    story.append(Paragraph(
        "The spiffe_vault Ansible lookup plugin authenticates to Vault per-lookup using the EE pod's "
        "JWT-SVID. Zero external dependencies (stdlib only). Each call reads the JWT file, POSTs to "
        "Vault /v1/auth/jwt/login, fetches the secret, and returns the value.",
        styles["Body"]))
    story.append(Paragraph(
        'cloud_password: "{{ lookup(\'spiffe_vault\', \'secret/data/aap/org/infra-corp/credentials\', '
        'field=\'cloud_password\', vault_role=\'aap-org-infra-corp\') }}"',
        styles["CodeBlock"]))

    # --- 6. Cluster Verification ---
    story.append(Paragraph("6. Cluster Verification (October 2026)", styles["SectionH"]))
    story.append(Paragraph(
        "All 5 E2E tests passed on the live lab cluster. Test pod spiffe-e2e-test was created "
        "in the aap namespace with label spiffe.io/spiffe-id=org-infra-corp to simulate an EE pod.",
        styles["Body"]))
    story.append(make_table(
        ["#", "Test", "Result"],
        [
            ["1", "JWT-SVID has correct sub claim (org-infra-corp SPIFFE ID)", "PASS"],
            ["2", "Own-org Vault auth + secret read (infra-corp credentials)", "PASS"],
            ["3", "Cross-org auth denied (infra-corp JWT to appdev-squad role)", "PASS: invalid subject (sub) claim"],
            ["4", "Cross-role auth denied (infra-corp JWT to platform role)", "PASS: invalid subject (sub) claim"],
            ["5", "Cross-org secret read denied (infra-corp token reads appdev-squad path)", "PASS: 403 Forbidden"],
        ],
        col_widths=[W*0.05, W*0.6, W*0.35],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Note:</b> With the SPIFFE CSI driver, the Workload API socket permissions are managed "
        "by the CSI volume mount, eliminating the need for privileged containers or permission workarounds.",
        styles["Callout"]))

    story.append(PageBreak())

    # --- 7. Beyond Kubernetes ---
    story.append(Paragraph("7. Beyond Kubernetes: VM Execution Nodes", styles["SectionH"]))
    story.append(Paragraph(
        "AAP supports hybrid execution. On VM execution nodes, receptor launches EE containers "
        "using podman. SPIRE's docker workload attestor works with podman containers and can select "
        "on container labels, enabling the same per-org isolation model as K8s.",
        styles["Body"]))
    story.append(Paragraph("<b>The gap:</b> AWX currently has no per-Instance-Group mechanism to inject "
        "custom podman labels (container_options_override). A small upstream PR (one model field + ~4 lines) "
        "would mirror the existing pod_spec_override pattern for K8s Container Groups.",
        styles["Body"]))
    story.append(make_table(
        ["Platform", "Node Attestor", "Workload Attestor"],
        [
            ["AWS EC2", "aws_iid (Instance Identity Document)", "docker (container labels)"],
            ["Azure VM", "azure_msi (Managed Service Identity)", "docker (container labels)"],
            ["GCP", "gcp_iit (Instance Identity Token)", "docker (container labels)"],
            ["Bare metal", "tpm_devid (TPM 2.0)", "docker or unix (UID/binary path)"],
        ],
        col_widths=[W*0.2, W*0.4, W*0.4],
    ))

    # --- 8. Vault Enterprise ---
    story.append(Paragraph("8. Vault Enterprise 1.21: SPIFFE Without SPIRE", styles["SectionH"]))
    story.append(Paragraph(
        "Vault Enterprise 1.21 (GA March 2026) can act as a full SPIFFE server. The secrets/spiffe "
        "engine mints JWT-SVIDs, generates its own signing keys, and serves OIDC Discovery endpoints. "
        "The auth/spiffe method validates SVIDs from SPIRE or other issuers.",
        styles["Body"]))
    story.append(make_table(
        ["Aspect", "Current POC (OSS)", "Vault Enterprise 1.21"],
        [
            ["Trust root", "SPIRE Server", "Vault itself"],
            ["SVID issuer", "SPIRE (via spiffe-helper)", "Vault SPIFFE secrets engine"],
            ["OIDC Discovery", "SPIRE OIDC sidecar", "Vault built-in endpoints"],
            ["Components", "SPIRE Server + Agent + OIDC + Vault", "Vault only"],
            ["Attestation", "Kubelet-level (SPIRE Agent)", "Depends on initial auth method"],
            ["License", "All OSS", "Enterprise required (30-day trial available)"],
        ],
        col_widths=[W*0.2, W*0.4, W*0.4],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "Vault Enterprise also offers a CSI driver that mounts secrets directly into pods as files, "
        "bypassing etcd. Unlike the SPIFFE CSI driver (which mounts the Workload API socket), "
        "Vault CSI delivers the secrets themselves. Simpler, but no per-pod-label identity scoping.",
        styles["Body"]))

    # --- 9. Granular Isolation ---
    story.append(Paragraph("9. Granular Isolation: Org to Playbook", styles["SectionH"]))
    story.append(Paragraph(
        "For customers requiring isolation finer than per-org (per-project, per-playbook, per-YAML file), "
        "the architecture supports multiple approaches.",
        styles["Body"]))
    story.append(Paragraph("CredentialComposer: Signed Claims in the JWT", styles["SubH"]))
    story.append(Paragraph(
        "SPIRE's CredentialComposer plugin adds custom claims to JWT-SVIDs at mint time. The CEL "
        "composer (spire-credentialcomposer-cel) can derive claims from the SPIFFE ID path. These "
        "claims are cryptographically signed and cannot be tampered with by playbook authors.",
        styles["Body"]))
    story.append(Paragraph(
        "AWX knows the playbook filename, project name, and organization at pod creation time "
        "(Job.playbook, Job.project.name). A small upstream change (~10 lines in receptor.py) "
        "would add these as pod labels. SPIRE's k8s workload attestor selects on these labels, "
        "and the CredentialComposer adds them as signed JWT claims. Vault's bound_claims validates them.",
        styles["Body"]))
    story.append(make_table(
        ["Approach", "Granularity", "Complexity", "Tamper-Proof?"],
        [
            ["SPIFFE ID per scope + CredentialComposer", "Per playbook", "High (one SPIRE entry + Vault role per scope)", "Yes (signed JWT)"],
            ["AAP Credential injection + Vault paths", "Per job template", "Low (AAP config only)", "Yes (admin controls env var)"],
            ["SPIFFE per org + Vault bound_claims", "Per project", "Medium", "Yes (signed JWT for org, Vault policy for project)"],
        ],
        col_widths=[W*0.3, W*0.15, W*0.35, W*0.2],
    ))
    story.append(Spacer(1, 6))
    story.append(Paragraph(
        "<b>Customer decision point:</b> Where does the trust boundary need cryptographic enforcement, "
        "and where is policy-based enforcement sufficient? Cryptographic (SPIFFE ID per scope) gives the "
        "strongest guarantee but scales linearly with scope count. Policy-based (Vault paths + AAP credentials) "
        "is operationally simpler.",
        styles["Callout"]))

    # --- 10. Demo Scenarios ---
    story.append(PageBreak())
    story.append(Paragraph("10. Demo Scenarios", styles["SectionH"]))
    story.append(Paragraph("Scenario 1: Platform Zero-Trust Identity", styles["SubH"]))
    story.append(Paragraph(
        "AAP's platform identity (spiffe://...ns/aap/sa/aap-controller) replaces the root Vault token. "
        "Delete the SPIRE registration entry, re-run the job, it fails immediately. Re-add the entry, it "
        "works again. No tokens to rotate, no credentials to update.", styles["Body"]))
    story.append(Paragraph("Scenario 2: Multi-Org Secret Isolation", styles["SubH"]))
    story.append(Paragraph(
        "Each AAP org gets its own SPIFFE ID and Vault policy. Infra-Corp cannot read AppDev-Squad's "
        "secrets, even though they share the same AAP instance. Verified on the live cluster.",
        styles["Body"]))
    story.append(Paragraph("Scenario 3: EDA Dynamic Credentials", styles["SubH"]))
    story.append(Paragraph(
        "EDA rulebook activation needs AWS credentials to remediate an incident. The EDA pod's SPIFFE "
        "identity fetches them from Vault at event time. Credentials are never persisted.", styles["Body"]))

    # --- 11. Customer Talking Points ---
    story.append(Paragraph("11. Customer Talking Points", styles["SectionH"]))
    points = [
        "<b>Compliance and audit:</b> 'How do you authenticate to your secrets store?' changes from "
        "'we have a shared token' to 'each workload has a cryptographic identity scoped to its role.'",
        "<b>Blast radius:</b> If one AAP org is compromised, only that org's Vault path is exposed, "
        "not the entire secrets store.",
        "<b>Operational:</b> No more manual credential rotation per job template. "
        "No more emergency credential invalidation affecting unrelated workloads.",
        "<b>Multi-tenancy:</b> Organizations sharing the same AAP instance get cryptographically "
        "isolated secret access, not just RBAC isolation.",
        "<b>Standards-based:</b> SPIFFE is a CNCF graduated project. The OIDC bridge is "
        "standards-based. No vendor lock-in; SPIRE can be replaced by any SPIFFE-compliant issuer.",
    ]
    for p in points:
        story.append(Paragraph(p, styles["Body"]))

    # --- 12. Path to Production ---
    story.append(Paragraph("12. Path to Production", styles["SectionH"]))
    story.append(make_table(
        ["Area", "POC (Current)", "Production Target"],
        [
            ["SPIRE", "Upstream SPIRE containers", "ZTWIM operator (Red Hat supported, included with OCP)"],
            ["Vault storage", "File backend + manual unseal", "HA Raft + cloud KMS auto-unseal"],
            ["Socket sharing", "SPIFFE CSI driver (no privileged SCC)", "SPIFFE CSI driver (ZTWIM operator-managed)"],
            ["Entry registration", "Manual per-agent", "ClusterSPIFFEID (ZTWIM CRD, auto-registers)"],
            ["Sidecar injection", "Kyverno", "ZTWIM operator or Kyverno"],
            ["Vault deployment", "Custom StatefulSet", "Vault Helm chart with HA"],
            ["Playbook consumption", "spiffe_vault lookup plugin (stdlib)", "Ansible collection with tests + docs"],
        ],
        col_widths=[W*0.18, W*0.38, W*0.44],
    ))

    story.append(Spacer(1, 16))
    story.append(Paragraph(
        "The POC is running live on the OCP lab cluster (HyperShift, KubeVirt workers). "
        "All four AAP target pods have sidecars injected, are fetching credentials from Vault "
        "via SPIFFE JWT, and are continuously renewing.",
        styles["CalloutSuccess"]))

    doc.build(story)
    print(f"PDF generated: {OUTPUT}")


if __name__ == "__main__":
    build()
