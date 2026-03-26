from __future__ import annotations

import os
import re
from typing import Any

# ── Block extraction ───────────────────────────────────────────────

_BLOCK_RE = re.compile(
    r"""
    (resource|data)\s+         # block type
    "([^"]+)"\s+               # resource type  e.g. "aws_s3_bucket"
    "([^"]+)"\s*               # resource name  e.g. "my_bucket"
    \{                         # opening brace
    """,
    re.VERBOSE,
)

_SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv", "venv", ".terraform", "dist", "build"}


def _extract_blocks(content: str) -> list[tuple[str, str, str, str]]:
    """Return (block_type, resource_type, name, body) for every resource/data block."""
    blocks: list[tuple[str, str, str, str]] = []
    for match in _BLOCK_RE.finditer(content):
        block_type = match.group(1)
        resource_type = match.group(2)
        name = match.group(3)
        start = match.end()
        depth = 1
        pos = start
        while pos < len(content) and depth > 0:
            if content[pos] == "{":
                depth += 1
            elif content[pos] == "}":
                depth -= 1
            pos += 1
        body = content[start:pos - 1] if depth == 0 else content[start:]
        blocks.append((block_type, resource_type, name, body))
    return blocks


# ── Finding helper ─────────────────────────────────────────────────

def _finding(
    rule_id: str,
    severity: str,
    resource_type: str,
    resource_name: str,
    file_path: str,
    message: str,
    recommendation: str,
) -> dict[str, str]:
    return {
        "rule_id": rule_id,
        "severity": severity,
        "resource_type": resource_type,
        "resource_name": resource_name,
        "file": file_path,
        "message": message,
        "recommendation": recommendation,
    }


# ── Individual rules ───────────────────────────────────────────────

def _check_tf001(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """S3 bucket without server-side encryption."""
    if rtype != "aws_s3_bucket":
        return []
    if "server_side_encryption_configuration" not in body:
        return [_finding(
            "TF001", "HIGH", rtype, name, fp,
            f"S3 bucket '{name}' does not have server-side encryption configured.",
            "Add a server_side_encryption_configuration block with AES256 or aws:kms.",
        )]
    return []


def _check_tf002(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """S3 bucket without versioning."""
    if rtype != "aws_s3_bucket":
        return []
    if "versioning" not in body:
        return [_finding(
            "TF002", "MEDIUM", rtype, name, fp,
            f"S3 bucket '{name}' does not have versioning enabled.",
            "Add a versioning block with enabled = true.",
        )]
    return []


def _check_tf003(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """S3 bucket with public ACL."""
    if rtype != "aws_s3_bucket":
        return []
    if re.search(r"""acl\s*=\s*["'](?:public-read|public-read-write)["']""", body):
        return [_finding(
            "TF003", "CRITICAL", rtype, name, fp,
            f"S3 bucket '{name}' has a public ACL configured.",
            "Remove the public ACL or use aws_s3_bucket_public_access_block to restrict access.",
        )]
    return []


def _check_tf004(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """Security group ingress open to 0.0.0.0/0."""
    if rtype != "aws_security_group":
        return []
    findings: list[dict[str, str]] = []
    # Look for ingress blocks containing 0.0.0.0/0
    ingress_blocks = re.findall(r"ingress\s*\{([^}]*)\}", body, re.DOTALL)
    for block in ingress_blocks:
        if re.search(r"""["']0\.0\.0\.0/0["']""", block):
            findings.append(_finding(
                "TF004", "HIGH", rtype, name, fp,
                f"Security group '{name}' has ingress open to 0.0.0.0/0.",
                "Restrict ingress CIDR blocks to specific trusted IP ranges.",
            ))
            break
    return findings


def _check_tf005(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """Security group egress open to 0.0.0.0/0."""
    if rtype != "aws_security_group":
        return []
    findings: list[dict[str, str]] = []
    egress_blocks = re.findall(r"egress\s*\{([^}]*)\}", body, re.DOTALL)
    for block in egress_blocks:
        if re.search(r"""["']0\.0\.0\.0/0["']""", block):
            findings.append(_finding(
                "TF005", "MEDIUM", rtype, name, fp,
                f"Security group '{name}' has egress open to 0.0.0.0/0.",
                "Restrict egress CIDR blocks to required destinations only.",
            ))
            break
    return findings


def _check_tf006(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """IAM policy with wildcard action."""
    if rtype not in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_policy_document"):
        return []
    if re.search(r"""actions?\s*=\s*\[\s*["']\*["']""", body) or \
       re.search(r""""Action"\s*:\s*["']\*["']""", body) or \
       re.search(r""""Action"\s*:\s*\[\s*["']\*["']""", body):
        return [_finding(
            "TF006", "CRITICAL", rtype, name, fp,
            f"IAM policy '{name}' uses wildcard (*) actions.",
            "Follow the principle of least privilege and specify only required actions.",
        )]
    return []


def _check_tf007(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """IAM policy with wildcard resource."""
    if rtype not in ("aws_iam_policy", "aws_iam_role_policy", "aws_iam_policy_document"):
        return []
    if re.search(r"""resources?\s*=\s*\[\s*["']\*["']""", body) or \
       re.search(r""""Resource"\s*:\s*["']\*["']""", body) or \
       re.search(r""""Resource"\s*:\s*\[\s*["']\*["']""", body):
        return [_finding(
            "TF007", "HIGH", rtype, name, fp,
            f"IAM policy '{name}' uses wildcard (*) resources.",
            "Scope resource ARNs to the specific resources that are needed.",
        )]
    return []


def _check_tf008(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """RDS instance publicly accessible."""
    if rtype != "aws_db_instance":
        return []
    if re.search(r"publicly_accessible\s*=\s*true", body):
        return [_finding(
            "TF008", "CRITICAL", rtype, name, fp,
            f"RDS instance '{name}' is publicly accessible.",
            "Set publicly_accessible = false and use private subnets.",
        )]
    return []


def _check_tf009(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """RDS instance without storage encryption."""
    if rtype != "aws_db_instance":
        return []
    if "storage_encrypted" not in body or re.search(r"storage_encrypted\s*=\s*false", body):
        return [_finding(
            "TF009", "HIGH", rtype, name, fp,
            f"RDS instance '{name}' does not have storage encryption enabled.",
            "Set storage_encrypted = true and optionally specify a kms_key_id.",
        )]
    return []


def _check_tf010(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """EC2 instance without IMDSv2 enforcement."""
    if rtype != "aws_instance":
        return []
    if "metadata_options" not in body or "http_tokens" not in body:
        return [_finding(
            "TF010", "HIGH", rtype, name, fp,
            f"EC2 instance '{name}' does not enforce IMDSv2.",
            "Add metadata_options with http_tokens = \"required\" to enforce IMDSv2.",
        )]
    return []


def _check_tf011(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """CloudTrail with logging disabled."""
    if rtype != "aws_cloudtrail":
        return []
    if re.search(r"enable_logging\s*=\s*false", body):
        return [_finding(
            "TF011", "CRITICAL", rtype, name, fp,
            f"CloudTrail '{name}' has logging disabled.",
            "Set enable_logging = true to ensure audit trail capture.",
        )]
    return []


def _check_tf012(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """S3 bucket without logging."""
    if rtype != "aws_s3_bucket":
        return []
    if "logging" not in body:
        return [_finding(
            "TF012", "MEDIUM", rtype, name, fp,
            f"S3 bucket '{name}' does not have access logging configured.",
            "Add a logging block pointing to a dedicated logging bucket.",
        )]
    return []


def _check_tf013(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """EBS volume without encryption."""
    if rtype != "aws_ebs_volume":
        return []
    if "encrypted" not in body or re.search(r"encrypted\s*=\s*false", body):
        return [_finding(
            "TF013", "HIGH", rtype, name, fp,
            f"EBS volume '{name}' is not encrypted.",
            "Set encrypted = true and optionally specify a kms_key_id.",
        )]
    return []


def _check_tf014(rtype: str, name: str, body: str, fp: str) -> list[dict[str, str]]:
    """Subnet with map_public_ip_on_launch enabled."""
    if rtype != "aws_subnet":
        return []
    if re.search(r"map_public_ip_on_launch\s*=\s*true", body):
        return [_finding(
            "TF014", "MEDIUM", rtype, name, fp,
            f"Subnet '{name}' automatically assigns public IP addresses on launch.",
            "Set map_public_ip_on_launch = false unless instances explicitly need public IPs.",
        )]
    return []


def _check_tf015(content: str, fp: str) -> list[dict[str, str]]:
    """Hardcoded credentials in .tf files (file-level check)."""
    findings: list[dict[str, str]] = []
    patterns = [
        (r"""access_key\s*=\s*["'][A-Za-z0-9/+=]{16,}["']""", "access_key"),
        (r"""secret_key\s*=\s*["'][A-Za-z0-9/+=]{16,}["']""", "secret_key"),
    ]
    for pat, key_type in patterns:
        if re.search(pat, content):
            findings.append(_finding(
                "TF015", "CRITICAL", "provider/variable", "hardcoded", fp,
                f"Hardcoded {key_type} found in Terraform file.",
                "Use environment variables, AWS profiles, or a secrets manager instead of hardcoded keys.",
            ))
    return findings


# ── Rule registry ──────────────────────────────────────────────────

_BLOCK_RULES = [
    _check_tf001,
    _check_tf002,
    _check_tf003,
    _check_tf004,
    _check_tf005,
    _check_tf006,
    _check_tf007,
    _check_tf008,
    _check_tf009,
    _check_tf010,
    _check_tf011,
    _check_tf012,
    _check_tf013,
    _check_tf014,
]

_FILE_RULES = [
    _check_tf015,
]

_VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ── Public API ─────────────────────────────────────────────────────

def scan_terraform(path: str, severity: str = "") -> dict[str, Any]:
    """Scan Terraform (.tf) files for security misconfigurations.

    Args:
        path: Path to a single .tf file or a directory containing .tf files.
        severity: Optional severity filter (CRITICAL, HIGH, MEDIUM, LOW).

    Returns:
        Dict with summary stats and a list of findings.
    """
    if not os.path.exists(path):
        raise RuntimeError(f"Path does not exist: {path}")

    severity_filter = severity.upper().strip() if severity else ""
    if severity_filter and severity_filter not in _VALID_SEVERITIES:
        raise RuntimeError(
            f"Invalid severity filter '{severity}'. Must be one of: {', '.join(sorted(_VALID_SEVERITIES))}"
        )

    tf_files: list[str] = []
    if os.path.isfile(path):
        if path.endswith(".tf"):
            tf_files.append(path)
        else:
            raise RuntimeError(f"File is not a Terraform file (.tf): {path}")
    else:
        for root, dirs, files in os.walk(path):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fname in files:
                if fname.endswith(".tf"):
                    tf_files.append(os.path.join(root, fname))

    if not tf_files:
        return {
            "files_scanned": 0,
            "total_findings": 0,
            "summary": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
            "findings": [],
        }

    all_findings: list[dict[str, str]] = []

    for tf_file in tf_files:
        try:
            with open(tf_file, "r", encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            continue

        # Block-level rules
        blocks = _extract_blocks(content)
        for block_type, resource_type, name, body in blocks:
            for rule_fn in _BLOCK_RULES:
                all_findings.extend(rule_fn(resource_type, name, body, tf_file))

        # File-level rules
        for file_rule_fn in _FILE_RULES:
            all_findings.extend(file_rule_fn(content, tf_file))

    # Apply severity filter
    if severity_filter:
        all_findings = [f for f in all_findings if f["severity"] == severity_filter]

    # Build summary
    summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = f["severity"]
        if sev in summary:
            summary[sev] += 1

    return {
        "files_scanned": len(tf_files),
        "total_findings": len(all_findings),
        "summary": summary,
        "findings": all_findings,
    }
