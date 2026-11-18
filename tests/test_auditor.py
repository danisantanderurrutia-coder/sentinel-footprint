"""
Unit tests for Web & App Security Auditor modules.
"""
import os
import tempfile
import pytest
from sentinel.core.models import Severity
from sentinel.modules.auditor.secrets import scan_local_secrets
from sentinel.modules.auditor.dependencies import parse_requirements_txt


def test_secret_scanner_detects_credentials():
    with tempfile.TemporaryDirectory() as tmpdir:
        test_file = os.path.join(tmpdir, "config.py")
        with open(test_file, "w") as f:
            f.write("""
# Archivo de prueba con credenciales inseguras
GITHUB_PAT = "ghp_123456789012345678901234567890123456"
PASSWORD = "SuperSecretPassword123!"
""")
        findings = scan_local_secrets(tmpdir)
        finding_ids = [f.id for f in findings]

        assert any("GITHUB_TOKEN" in fid for fid in finding_ids)
        assert any("PASSWORD" in fid for fid in finding_ids)
        # Verificar enmascaramiento
        for f in findings:
            if "GITHUB_TOKEN" in f.id:
                assert "***" in f.details or "*" in f.details
                assert "ghp_123456789012345678901234567890123456" not in f.details


def test_parse_requirements():
    content = """
requests==2.28.1
urllib3 == 1.26.15 # comentario
flask==2.2.0
# ignored line
"""
    pkgs = parse_requirements_txt(content)
    assert ("requests", "2.28.1") in pkgs
    assert ("urllib3", "1.26.15") in pkgs
    assert ("flask", "2.2.0") in pkgs
