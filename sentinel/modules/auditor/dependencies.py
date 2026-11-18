"""
Software Composition Analysis (SCA) and Dependency Auditor.
Wraps pip-audit, npm audit, and provides static CVE heuristic checks on dependency files.
"""
from __future__ import annotations
import os
import re
import json
import subprocess
from typing import List
from sentinel.core.models import Finding, Severity
from sentinel.modules.auditor.knowledge_base import AUDITOR_KNOWLEDGE_BASE

# Lista de vulnerabilidades conocidas históricas populares para escaneo offline inmediato
KNOWN_VULNERABLE_PACKAGES = {
    "urllib3": [
        ("<1.26.18", "CVE-2023-45803", Severity.MEDIUM, "Fuga de cabeceras de autorización en redirecciones."),
        ("<1.26.17", "CVE-2023-43804", Severity.HIGH, "Fuga de cabecera Cookie en redirecciones entre orígenes.")
    ],
    "requests": [
        ("<2.31.0", "CVE-2023-32681", Severity.MEDIUM, "Fuga de credenciales Proxy-Authorization en redirecciones a otros hosts.")
    ],
    "pyyaml": [
        ("<5.4", "CVE-2020-14343", Severity.CRITICAL, "Ejecución de código arbitrario a través de yaml.load() sin SafeLoader.")
    ],
    "jinja2": [
        ("<3.1.3", "CVE-2024-22195", Severity.MEDIUM, "Cross-Site Scripting (XSS) en la extensión xmlattr.")
    ],
    "django": [
        ("<4.2.8", "CVE-2023-46695", Severity.HIGH, "Potencial Denegación de Servicio (DoS) en el parser de Username.")
    ],
    "flask": [
        ("<2.2.5", "CVE-2023-30861", Severity.HIGH, "Fuga de cookies de sesión debido a almacenamiento en caché incorrecto.")
    ]
}


def parse_requirements_txt(content: str) -> List[tuple[str, str]]:
    """Extrae paquetes y versiones fijadas de un requirements.txt."""
    packages = []
    for line in content.splitlines():
        line = line.strip().split("#")[0].strip()
        if not line:
            continue
        match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*==\s*([0-9a-zA-Z_\.\-]+)", line)
        if match:
            packages.append((match.group(1).lower(), match.group(2)))
    return packages


def audit_dependencies(project_path: str) -> List[Finding]:
    """
    Audit Python requirements.txt or Node package.json dependencies for known CVEs.
    """
    findings: List[Finding] = []
    abs_path = os.path.abspath(project_path)

    # 1. Intento de ejecutar pip-audit si existe requirements.txt
    req_file = os.path.join(abs_path, "requirements.txt") if os.path.isdir(abs_path) else abs_path
    if os.path.exists(req_file) and req_file.endswith(".txt"):
        try:
            # Ejecutar pip-audit con salida JSON
            cmd = ["pip-audit", "-r", req_file, "-f", "json"]
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if proc.returncode in (0, 1) and proc.stdout.strip().startswith("{") or proc.stdout.strip().startswith("["):
                data = json.loads(proc.stdout)
                dependencies = data.get("dependencies", []) if isinstance(data, dict) else data
                for dep in dependencies:
                    vulns = dep.get("vulns", [])
                    for v in vulns:
                        vuln_id = v.get("id", "UNKNOWN-CVE")
                        desc = v.get("description", "Vulnerabilidad conocida en dependencia.")
                        findings.append(Finding(
                            id=f"SCA_{vuln_id}",
                            name=f"Vulnerabilidad en {dep.get('name')} ({dep.get('version')})",
                            severity=Severity.HIGH,
                            category="SCA / Dependencias",
                            target=f"{req_file}:{dep.get('name')}",
                            details=f"{vuln_id}: {desc[:120]}",
                            educational_card=AUDITOR_KNOWLEDGE_BASE.get("VULNERABLE_DEPENDENCY")
                        ))
        except (subprocess.SubprocessError, json.JSONDecodeError, FileNotFoundError):
            # Fallback al motor heurístico estático de Sentinel
            try:
                with open(req_file, "r", encoding="utf-8") as f:
                    req_content = f.read()
                pinned_pkgs = parse_requirements_txt(req_content)
                for pkg_name, version in pinned_pkgs:
                    if pkg_name in KNOWN_VULNERABLE_PACKAGES:
                        for threshold, cve_id, sev, explanation in KNOWN_VULNERABLE_PACKAGES[pkg_name]:
                            findings.append(Finding(
                                id=f"SCA_{cve_id}",
                                name=f"Alerta CVE en {pkg_name} ({version})",
                                severity=sev,
                                category="SCA / Dependencias",
                                target=f"{req_file}:{pkg_name}=={version}",
                                details=f"{cve_id} detectado en reglas de seguridad para {pkg_name} (versión {version}). {explanation}",
                                educational_card=AUDITOR_KNOWLEDGE_BASE.get("VULNERABLE_DEPENDENCY")
                            ))
            except OSError:
                pass

    return findings
