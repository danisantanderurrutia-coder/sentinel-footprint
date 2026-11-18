"""
OWASP Top 10 Basic Active Scanner.
Probes for sensitive file exposure (.git, .env, backups), API doc disclosure, and CORS misconfiguration.
"""
from __future__ import annotations
import urllib.parse
from typing import List
import requests
from sentinel.core.models import Finding, Severity
from sentinel.core.config import settings
from sentinel.modules.auditor.knowledge_base import AUDITOR_KNOWLEDGE_BASE

SENSITIVE_PATHS = [
    ("/.git/HEAD", "Directorio .git expuesto (Control de versiones completo)", Severity.CRITICAL, "ref: refs/heads/"),
    ("/.env", "Archivo .env descargable públicamente", Severity.CRITICAL, None),
    ("/.DS_Store", "Fichero macOS .DS_Store expuesto (Enumeración de directorios)", Severity.LOW, None),
    ("/robots.txt", "Archivo robots.txt presente (Revisión de rutas restringidas)", Severity.INFO, None),
    ("/sitemap.xml", "Mapa de sitio sitemap.xml accesible", Severity.INFO, None),
    ("/phpinfo.php", "Fichero phpinfo() accesible (Fuga de configuración del servidor)", Severity.HIGH, "PHP Version"),
    ("/swagger-ui.html", "Documentación Swagger UI expuesta públicamente", Severity.LOW, "swagger"),
    ("/openapi.json", "Especificación OpenAPI expuesta sin autenticación", Severity.LOW, "openapi"),
    ("/actuator/env", "Spring Boot Actuator /env expuesto (Fuga masiva de secretos)", Severity.CRITICAL, "activeProfiles"),
    ("/backup.sql", "Copia de seguridad SQL expuesta en la raíz", Severity.CRITICAL, None)
]


def check_sensitive_endpoints(base_url: str) -> List[Finding]:
    """
    Check if the target web server exposes sensitive configuration or source control files.
    """
    findings: List[Finding] = []
    if not base_url.startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    parsed = urllib.parse.urlparse(base_url)
    root_url = f"{parsed.scheme}://{parsed.netloc}"

    session = requests.Session()
    session.headers.update({"User-Agent": settings.USER_AGENT})

    for path, description, severity, fingerprint in SENSITIVE_PATHS:
        target_endpoint = f"{root_url}{path}"
        try:
            res = session.get(target_endpoint, timeout=5, allow_redirects=False)
            if res.status_code == 200:
                is_valid_exposure = True
                if fingerprint and fingerprint not in res.text:
                    # Si especificamos fingerprint y no está, puede ser una página de error 200 personalizada
                    is_valid_exposure = False

                if is_valid_exposure:
                    findings.append(Finding(
                        id=f"EXPOSED_{path.strip('/').replace('.', '_').replace('/', '_').upper()}",
                        name=description,
                        severity=severity,
                        category="Information Disclosure",
                        target=target_endpoint,
                        details=f"Endpoint accesible con HTTP 200 (Longitud: {len(res.content)} bytes).",
                        educational_card=AUDITOR_KNOWLEDGE_BASE.get("EXPOSED_SENSITIVE_FILES")
                    ))
        except requests.RequestException:
            continue

    # Verificación de CORS dinámico inseguro (Origin Reflection)
    test_origin = "https://evil-sentinel-attacker.com"
    try:
        cors_res = session.get(
            root_url,
            headers={"Origin": test_origin, "User-Agent": settings.USER_AGENT},
            timeout=5
        )
        allow_origin = cors_res.headers.get("Access-Control-Allow-Origin")
        allow_creds = cors_res.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"

        if allow_origin == test_origin:
            sev = Severity.CRITICAL if allow_creds else Severity.HIGH
            findings.append(Finding(
                id="CORS_ORIGIN_REFLECTION",
                name="CORS Inseguro: Reflejo arbitrario de Origen",
                severity=sev,
                category="CORS Configuration",
                target=root_url,
                details=f"El servidor refleja el origen arbitrario '{test_origin}' en Access-Control-Allow-Origin. Credenciales permitidas: {allow_creds}.",
                educational_card=AUDITOR_KNOWLEDGE_BASE.get("CORS_WILDCARD_ORIGIN")
            ))
    except requests.RequestException:
        pass

    return findings
