"""
HTTP Headers and Transport Security Auditor.
Analyzes HSTS, CSP, X-Content-Type-Options, Referrer-Policy, CORS, and Cookies.
"""
from __future__ import annotations
import urllib.parse
from typing import List, Dict, Any, Tuple
import requests
from sentinel.core.models import Finding, Severity
from sentinel.core.config import settings
from sentinel.modules.auditor.knowledge_base import AUDITOR_KNOWLEDGE_BASE


def analyze_security_headers(url: str, verify_ssl: bool = True) -> Tuple[List[Finding], Dict[str, str]]:
    """
    Perform deep audit of HTTP response headers, CORS configuration, and Set-Cookie flags.
    """
    findings: List[Finding] = []
    
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    parsed = urllib.parse.urlparse(url)
    is_https = parsed.scheme.lower() == "https"

    try:
        response = requests.get(
            url,
            timeout=settings.DEFAULT_TIMEOUT,
            allow_redirects=True,
            verify=verify_ssl,
            headers={"User-Agent": settings.USER_AGENT}
        )
    except requests.exceptions.SSLError as ssl_err:
        findings.append(Finding(
            id="SSL_CERT_ERROR",
            name="Error en Certificado TLS/SSL",
            severity=Severity.CRITICAL,
            category="Transport Security",
            target=url,
            details=f"Fallo en la validación del certificado SSL: {ssl_err}",
            educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_HSTS")
        ))
        return findings, {}
    except requests.RequestException as req_err:
        findings.append(Finding(
            id="CONNECTION_ERROR",
            name="Error de Conexión HTTP",
            severity=Severity.HIGH,
            category="Transport Security",
            target=url,
            details=f"No se pudo completar la petición HTTP a {url}: {req_err}"
        ))
        return findings, {}

    raw_headers = response.headers
    headers = {k.lower(): v for k, v in raw_headers.items()}

    # 1. HSTS (Strict-Transport-Security)
    if is_https:
        if "strict-transport-security" not in headers:
            findings.append(Finding(
                id="MISSING_HSTS",
                name="Falta cabecera Strict-Transport-Security (HSTS)",
                severity=Severity.HIGH,
                category="HTTP Headers",
                target=url,
                details="El servidor no envía la cabecera HSTS, exponiendo a los clientes a ataques SSL-Strip.",
                educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_HSTS")
            ))
        else:
            hsts_val = headers["strict-transport-security"]
            if "max-age" not in hsts_val:
                findings.append(Finding(
                    id="HSTS_INVALID_MAX_AGE",
                    name="HSTS sin directiva max-age válida",
                    severity=Severity.MEDIUM,
                    category="HTTP Headers",
                    target=url,
                    details=f"Valor HSTS: '{hsts_val}'. Debe incluir 'max-age=31536000'."
                ))
    else:
        findings.append(Finding(
            id="INSECURE_HTTP_TRANSPORT",
            name="Protocolo HTTP No Cifrado",
            severity=Severity.CRITICAL,
            category="Transport Security",
            target=url,
            details="La URL utiliza HTTP en texto claro en lugar de HTTPS con cifrado TLS.",
            educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_HSTS")
        ))

    # 2. CSP (Content-Security-Policy)
    if "content-security-policy" not in headers:
        findings.append(Finding(
            id="MISSING_CSP",
            name="Falta cabecera Content-Security-Policy (CSP)",
            severity=Severity.HIGH,
            category="HTTP Headers",
            target=url,
            details="No existe política CSP. El navegador no tiene restricciones contra inyección de scripts externos.",
            educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_CSP")
        ))
    else:
        csp_val = headers["content-security-policy"]
        if "unsafe-inline" in csp_val:
            findings.append(Finding(
                id="CSP_UNSAFE_INLINE",
                name="CSP contiene 'unsafe-inline'",
                severity=Severity.MEDIUM,
                category="HTTP Headers",
                target=url,
                details="La directiva CSP incluye 'unsafe-inline', lo cual debilita notablemente la protección contra XSS.",
                educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_CSP")
            ))

    # 3. X-Content-Type-Options
    if "x-content-type-options" not in headers:
        findings.append(Finding(
            id="MISSING_X_CONTENT_TYPE_OPTIONS",
            name="Falta cabecera X-Content-Type-Options",
            severity=Severity.MEDIUM,
            category="HTTP Headers",
            target=url,
            details="No se especifica 'nosniff', permitiendo a ciertos navegadores interpretar MIME types erróneamente.",
            educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_X_CONTENT_TYPE_OPTIONS")
        ))
    elif headers["x-content-type-options"].strip().lower() != "nosniff":
        findings.append(Finding(
            id="INVALID_X_CONTENT_TYPE_OPTIONS",
            name="Valor inválido en X-Content-Type-Options",
            severity=Severity.LOW,
            category="HTTP Headers",
            target=url,
            details=f"Valor actual: '{headers['x-content-type-options']}'. El único valor seguro es 'nosniff'."
        ))

    # 4. X-Frame-Options o frame-ancestors
    has_frame_ancestors = "content-security-policy" in headers and "frame-ancestors" in headers["content-security-policy"]
    if "x-frame-options" not in headers and not has_frame_ancestors:
        findings.append(Finding(
            id="MISSING_X_FRAME_OPTIONS",
            name="Falta protección contra Clickjacking (X-Frame-Options)",
            severity=Severity.MEDIUM,
            category="HTTP Headers",
            target=url,
            details="No se detecta X-Frame-Options ni CSP frame-ancestors. El sitio puede ser incrustado en iframes maliciosos.",
            educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_X_FRAME_OPTIONS")
        ))

    # 5. Referrer-Policy
    if "referrer-policy" not in headers:
        findings.append(Finding(
            id="MISSING_REFERRER_POLICY",
            name="Falta cabecera Referrer-Policy",
            severity=Severity.LOW,
            category="HTTP Headers",
            target=url,
            details="No se define política de referencia, pudiendo filtrar rutas internas en solicitudes salientes.",
            educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_REFERRER_POLICY")
        ))

    # 6. Server Banner / Technology Disclosure
    for banner_key in ["server", "x-powered-by", "x-aspnet-version"]:
        if banner_key in headers:
            findings.append(Finding(
                id=f"EXPOSED_{banner_key.upper().replace('-', '_')}",
                name=f"Exposición de tecnología en cabecera '{banner_key}'",
                severity=Severity.LOW,
                category="Information Disclosure",
                target=url,
                details=f"El servidor expone '{banner_key}: {headers[banner_key]}', facilitando el reconocimiento a atacantes.",
                educational_card=AUDITOR_KNOWLEDGE_BASE.get("SERVER_BANNER_DISCLOSURE")
            ))

    # 7. CORS Analysis (Access-Control-Allow-Origin)
    if "access-control-allow-origin" in headers:
        cors_origin = headers["access-control-allow-origin"]
        if cors_origin == "*":
            findings.append(Finding(
                id="CORS_WILDCARD_ORIGIN",
                name="CORS con origen comodín (*)",
                severity=Severity.MEDIUM,
                category="CORS Configuration",
                target=url,
                details="Access-Control-Allow-Origin está configurado como '*', permitiendo que cualquier dominio lea respuestas si no hay auth adicional.",
                educational_card=AUDITOR_KNOWLEDGE_BASE.get("CORS_WILDCARD_ORIGIN")
            ))

    # 8. Cookies Security Check (Set-Cookie)
    cookies_raw = response.headers.get("set-cookie")
    if cookies_raw:
        cookies_list = response.raw.headers.getlist('Set-Cookie') if hasattr(response.raw, 'headers') and hasattr(response.raw.headers, 'getlist') else [cookies_raw]
        for cookie_str in cookies_list:
            cookie_lower = cookie_str.lower()
            name_part = cookie_str.split(";")[0]
            cookie_name = name_part.split("=")[0] if "=" in name_part else name_part

            issues = []
            if "httponly" not in cookie_lower:
                issues.append("Falta 'HttpOnly' (accesible vía JavaScript)")
            if "secure" not in cookie_lower and is_https:
                issues.append("Falta 'Secure' (transmisible en HTTP claro)")
            if "samesite" not in cookie_lower:
                issues.append("Falta 'SameSite' (vulnerable a CSRF)")

            if issues:
                findings.append(Finding(
                    id=f"COOKIE_INSECURE_{cookie_name.strip()}",
                    name=f"Cookie insegura detectada: '{cookie_name.strip()}'",
                    severity=Severity.HIGH if "httponly" not in cookie_lower else Severity.MEDIUM,
                    category="Cookie Security",
                    target=url,
                    details=f"Problemas en atributos de cookie: {', '.join(issues)}.",
                    educational_card=AUDITOR_KNOWLEDGE_BASE.get("INSECURE_COOKIE")
                ))

    return findings, dict(raw_headers)
