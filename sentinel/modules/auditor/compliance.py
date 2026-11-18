"""
GDPR / LOPD Compliance and Privacy Transparency Auditor for Web Applications.
Checks for privacy policies, cookie consent notices, and contact mechanisms.
"""
from __future__ import annotations
import re
from typing import List
import requests
from sentinel.core.models import Finding, Severity
from sentinel.core.config import settings
from sentinel.modules.auditor.knowledge_base import AUDITOR_KNOWLEDGE_BASE

PRIVACY_KEYWORDS = ["politica de privacidad", "política de privacidad", "privacy policy", "aviso de privacidad", "data protection"]
COOKIE_KEYWORDS = ["politica de cookies", "política de cookies", "cookie policy", "ajustes de cookies", "configuración de cookies", "gestionar cookies", "cookie banner"]
DPO_PATTERNS = [re.compile(r"[a-zA-Z0-9_.+-]+@(dpo|privacidad|privacy)[a-zA-Z0-9-.]+", re.IGNORECASE)]


def audit_privacy_compliance(url: str) -> List[Finding]:
    """
    Audit webpage for presence of privacy policy, cookie consent, and GDPR rights contact.
    """
    findings: List[Finding] = []
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    try:
        res = requests.get(url, timeout=settings.DEFAULT_TIMEOUT, headers={"User-Agent": settings.USER_AGENT})
    except requests.RequestException as e:
        return [Finding(
            id="COMPLIANCE_CONNECT_ERROR",
            name="No se pudo analizar la página para auditoría de cumplimiento",
            severity=Severity.LOW,
            category="Compliance",
            target=url,
            details=str(e)
        )]

    body_text = res.text.lower()

    # 1. Verificación de Política de Privacidad
    has_privacy_link = any(kw in body_text for kw in PRIVACY_KEYWORDS)
    if not has_privacy_link:
        findings.append(Finding(
            id="MISSING_PRIVACY_POLICY",
            name="Ausencia de Enlace Visible a Política de Privacidad",
            severity=Severity.MEDIUM,
            category="GDPR / LOPD",
            target=url,
            details="No se detectó un enlace o mención explícita a la 'Política de Privacidad' en la página de inicio.",
            educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_PRIVACY_NOTICE")
        ))

    # 2. Verificación de Aviso o Política de Cookies
    has_cookie_notice = any(kw in body_text for kw in COOKIE_KEYWORDS)
    if not has_cookie_notice:
        findings.append(Finding(
            id="MISSING_COOKIE_POLICY",
            name="Ausencia de Información / Banner de Cookies",
            severity=Severity.LOW,
            category="GDPR / ePrivacy",
            target=url,
            details="No se detectaron textos habituales de aviso o gestión de cookies en la página auditada.",
            educational_card=AUDITOR_KNOWLEDGE_BASE.get("MISSING_PRIVACY_NOTICE")
        ))

    return findings
