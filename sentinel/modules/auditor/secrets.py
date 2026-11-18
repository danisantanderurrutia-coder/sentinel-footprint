"""
Secret and Credential Leak Detector.
Scans source files, config files, and git repositories for hardcoded credentials.
"""
from __future__ import annotations
import os
import re
from typing import List, Tuple
from sentinel.core.models import Finding, Severity
from sentinel.modules.auditor.knowledge_base import AUDITOR_KNOWLEDGE_BASE

SECRET_PATTERNS: List[Tuple[str, str, Severity, re.Pattern]] = [
    (
        "PRIVATE_KEY",
        "Clave Privada Criptográfica (RSA/EC/SSH)",
        Severity.CRITICAL,
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----")
    ),
    (
        "AWS_ACCESS_KEY",
        "AWS Access Key ID",
        Severity.HIGH,
        re.compile(r"(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])")
    ),
    (
        "AWS_SECRET_KEY",
        "AWS Secret Access Key",
        Severity.CRITICAL,
        re.compile(r"(?i)aws_?(?:secret)?_?(?:access)?_?(?:key)?\s*[:=]\s*['\"][A-Za-z0-9/+=]{40}['\"]")
    ),
    (
        "GITHUB_TOKEN",
        "Token de Acceso Personal de GitHub",
        Severity.CRITICAL,
        re.compile(r"(?:gh[pousr]_[A-Za-z0-9_]{36,255}|github_pat_[A-Za-z0-9_]{82})")
    ),
    (
        "SLACK_TOKEN",
        "Token de API de Slack",
        Severity.HIGH,
        re.compile(r"xox[baprs]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}")
    ),
    (
        "STRIPE_KEY",
        "Clave de API de Stripe",
        Severity.CRITICAL,
        re.compile(r"(?:sk|rk)_live_[0-9a-zA-Z]{24}")
    ),
    (
        "GOOGLE_API_KEY",
        "Google Cloud / Firebase API Key",
        Severity.HIGH,
        re.compile(r"AIza[0-9A-Za-z\\-_]{35}")
    ),
    (
        "DB_CONNECTION_STRING",
        "Cadena de Conexión a Base de Datos con Credenciales",
        Severity.CRITICAL,
        re.compile(r"(?:postgres|postgresql|mysql|mongodb(?:\+srv)?):\/\/[a-zA-Z0-9_]+:[^@\s]+@[a-zA-Z0-9.-]+")
    ),
    (
        "GENERIC_PASSWORD_ASSIGNMENT",
        "Contraseña o Token Asignado en Código",
        Severity.HIGH,
        re.compile(r"(?i)(password|secret_key|client_secret|auth_token)\s*[:=]\s*['\"][^'\"]{8,}['\"]")
    ),
    (
        "ENV_FILE_EXPOSURE",
        "Archivo de Variables de Entorno (.env)",
        Severity.MEDIUM,
        re.compile(r"^#\s*Generated .env file", re.IGNORECASE)
    )
]

IGNORE_DIRS = {".git", ".svn", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".idea", ".vscode"}
IGNORE_EXTS = {".png", ".jpg", ".jpeg", ".ico", ".gif", ".pdf", ".zip", ".tar.gz", ".pyc", ".woff", ".woff2", ".ttf"}


def scan_local_secrets(target_path: str) -> List[Finding]:
    """
    Scan a directory or file for hardcoded secrets, API keys, and sensitive tokens.
    """
    findings: List[Finding] = []
    abs_target = os.path.abspath(target_path)

    if not os.path.exists(abs_target):
        return [Finding(
            id="PATH_NOT_FOUND",
            name="Ruta objetivo no encontrada",
            severity=Severity.LOW,
            category="File System",
            target=target_path,
            details=f"La ruta {target_path} no existe en el sistema."
        )]

    files_to_scan = []
    if os.path.isfile(abs_target):
        files_to_scan.append(abs_target)
    else:
        for root, dirs, files in os.walk(abs_target):
            dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
            for file in files:
                # Alerta inmediata si existe un archivo .env no ignorado
                if file.startswith(".env") and not file.endswith((".example", ".sample")):
                    findings.append(Finding(
                        id="EXPOSED_ENV_FILE",
                        name="Archivo .env detectado en el repositorio",
                        severity=Severity.HIGH,
                        category="Secret Management",
                        target=os.path.join(root, file),
                        details="Los archivos .env suelen contener credenciales de producción. Deben estar en .gitignore.",
                        educational_card=AUDITOR_KNOWLEDGE_BASE.get("HARDCODED_SECRET")
                    ))

                ext = os.path.splitext(file)[1].lower()
                if ext not in IGNORE_EXTS:
                    files_to_scan.append(os.path.join(root, file))

    for file_path in files_to_scan:
        rel_path = os.path.relpath(file_path, abs_target) if os.path.isdir(abs_target) else os.path.basename(file_path)
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line_idx, line in enumerate(f, start=1):
                    # Omitir líneas excesivamente largas (posibles minified js)
                    if len(line) > 1000:
                        continue
                    for secret_id, secret_name, severity, pattern in SECRET_PATTERNS:
                        match = pattern.search(line)
                        if match:
                            # Mascarar el secreto en el reporte por seguridad
                            matched_str = match.group(0)
                            masked = matched_str[:4] + "*" * (len(matched_str) - 8) + matched_str[-4:] if len(matched_str) > 10 else "***"
                            findings.append(Finding(
                                id=f"SECRET_{secret_id}",
                                name=secret_name,
                                severity=severity,
                                category="Secret Leak",
                                target=f"{rel_path}:{line_idx}",
                                details=f"Posible credencial detectada: '{masked}' en la línea {line_idx}.",
                                educational_card=AUDITOR_KNOWLEDGE_BASE.get("HARDCODED_SECRET")
                            ))
        except (OSError, UnicodeDecodeError):
            continue

    return findings
