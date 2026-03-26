import os
import tempfile
import unittest

from tools.security.terraform import scan_terraform


class TestTerraformScanner(unittest.TestCase):
    """Tests for the Terraform security scanner."""

    def _write_tf(self, content: str, dirname: str | None = None) -> str:
        """Write content to a temp .tf file and return its path."""
        fd, path = tempfile.mkstemp(suffix=".tf", dir=dirname)
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
        return path

    # ── TF001: S3 encryption ───────────────────────────────────────

    def test_detects_unencrypted_s3(self) -> None:
        path = self._write_tf("""
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}
""")
        try:
            result = scan_terraform(path)
            rule_ids = [f["rule_id"] for f in result["findings"]]
            self.assertIn("TF001", rule_ids)
        finally:
            os.unlink(path)

    # ── TF003: public ACL ──────────────────────────────────────────

    def test_detects_public_acl(self) -> None:
        path = self._write_tf("""
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
""")
        try:
            result = scan_terraform(path)
            rule_ids = [f["rule_id"] for f in result["findings"]]
            self.assertIn("TF003", rule_ids)
        finally:
            os.unlink(path)

    # ── TF004: open security group ─────────────────────────────────

    def test_detects_open_security_group(self) -> None:
        path = self._write_tf("""
resource "aws_security_group" "wide_open" {
  name = "allow-all"
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""")
        try:
            result = scan_terraform(path)
            rule_ids = [f["rule_id"] for f in result["findings"]]
            self.assertIn("TF004", rule_ids)
        finally:
            os.unlink(path)

    # ── TF006/TF007: wildcard IAM ──────────────────────────────────

    def test_detects_wildcard_iam(self) -> None:
        path = self._write_tf("""
resource "aws_iam_policy" "admin" {
  name   = "admin-policy"
  policy = <<EOF
{
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "*",
      "Resource": "*"
    }
  ]
}
EOF
}
""")
        try:
            result = scan_terraform(path)
            rule_ids = [f["rule_id"] for f in result["findings"]]
            self.assertIn("TF006", rule_ids)
            self.assertIn("TF007", rule_ids)
        finally:
            os.unlink(path)

    # ── TF008: public RDS ──────────────────────────────────────────

    def test_detects_public_rds(self) -> None:
        path = self._write_tf("""
resource "aws_db_instance" "mydb" {
  engine               = "mysql"
  instance_class       = "db.t3.micro"
  publicly_accessible  = true
}
""")
        try:
            result = scan_terraform(path)
            rule_ids = [f["rule_id"] for f in result["findings"]]
            self.assertIn("TF008", rule_ids)
            self.assertIn("TF009", rule_ids)
        finally:
            os.unlink(path)

    # ── TF015: hardcoded secrets ───────────────────────────────────

    def test_detects_hardcoded_secrets(self) -> None:
        path = self._write_tf("""
provider "aws" {
  access_key = "AKIAIOSFODNN7EXAMPLE"
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
  region     = "us-east-1"
}
resource "aws_s3_bucket" "x" { bucket = "b" }
""")
        try:
            result = scan_terraform(path)
            rule_ids = [f["rule_id"] for f in result["findings"]]
            self.assertIn("TF015", rule_ids)
        finally:
            os.unlink(path)

    # ── Clean file ─────────────────────────────────────────────────

    def test_clean_file_returns_empty(self) -> None:
        path = self._write_tf("""
resource "aws_s3_bucket" "secure" {
  bucket = "my-secure-bucket"
  acl    = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  logging {
    target_bucket = "my-log-bucket"
  }
}
""")
        try:
            result = scan_terraform(path)
            self.assertEqual(result["total_findings"], 0)
            self.assertEqual(result["findings"], [])
        finally:
            os.unlink(path)

    # ── Severity filter ────────────────────────────────────────────

    def test_severity_filter(self) -> None:
        path = self._write_tf("""
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
  acl    = "public-read"
}
""")
        try:
            result = scan_terraform(path, severity="CRITICAL")
            for f in result["findings"]:
                self.assertEqual(f["severity"], "CRITICAL")
            # TF003 (CRITICAL) should be present, TF001 (HIGH) should not
            rule_ids = [f["rule_id"] for f in result["findings"]]
            self.assertIn("TF003", rule_ids)
            self.assertNotIn("TF001", rule_ids)
        finally:
            os.unlink(path)

    # ── Missing path ───────────────────────────────────────────────

    def test_raises_on_missing_path(self) -> None:
        with self.assertRaises(RuntimeError):
            scan_terraform("/nonexistent/terraform/project")

    # ── Directory scan ─────────────────────────────────────────────

    def test_directory_scan(self) -> None:
        tmpdir = tempfile.mkdtemp()
        self._write_tf("""
resource "aws_s3_bucket" "a" { bucket = "a" }
""", dirname=tmpdir)
        self._write_tf("""
resource "aws_ebs_volume" "vol" {
  availability_zone = "us-east-1a"
  size              = 40
}
""", dirname=tmpdir)
        try:
            result = scan_terraform(tmpdir)
            self.assertEqual(result["files_scanned"], 2)
            self.assertGreater(result["total_findings"], 0)
        finally:
            for f in os.listdir(tmpdir):
                os.unlink(os.path.join(tmpdir, f))
            os.rmdir(tmpdir)


if __name__ == "__main__":
    unittest.main()
