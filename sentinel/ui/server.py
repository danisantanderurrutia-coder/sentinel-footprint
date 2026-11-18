"""
FastAPI Server for Sentinel & Footprint Visual Dashboard.
"""
from __future__ import annotations
import os
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from sentinel.modules.auditor.headers import analyze_security_headers
from sentinel.modules.auditor.owasp_checks import check_sensitive_endpoints
from sentinel.modules.auditor.compliance import audit_privacy_compliance
from sentinel.modules.auditor.secrets import scan_local_secrets
from sentinel.modules.auditor.knowledge_base import AUDITOR_KNOWLEDGE_BASE
from sentinel.modules.footprint.hibp import check_password_leak_k_anonymity
from sentinel.modules.footprint.gdpr_engine import generate_erasure_request_es, generate_erasure_request_en
from sentinel.modules.footprint.tracker import (
    list_tracked_accounts,
    add_account_to_tracker,
    update_account_status,
    remove_tracked_account,
)
from sentinel.core.models import Finding, ScanSummary, Severity

app = FastAPI(title="Sentinel & Footprint Visual Dashboard")

# Paths
TEMPLATE_PATH = os.path.join(os.path.dirname(__file__), "templates", "index.html")


@app.get("/", response_class=HTMLResponse)
def get_dashboard_html():
    if not os.path.exists(TEMPLATE_PATH):
        raise HTTPException(status_code=404, detail="Template no encontrado")
    with open(TEMPLATE_PATH, "r", encoding="utf-8") as f:
        return f.read()


class WebAuditRequest(BaseModel):
    url: str

@app.post("/api/audit-web")
def api_audit_web(payload: WebAuditRequest):
    findings: List[Finding] = []
    # 1. Cabeceras
    hdr_findings, _ = analyze_security_headers(payload.url)
    findings.extend(hdr_findings)
    # 2. Rutas sensibles
    active_findings = check_sensitive_endpoints(payload.url)
    findings.extend(active_findings)
    # 3. Cumplimiento
    comp_findings = audit_privacy_compliance(payload.url)
    findings.extend(comp_findings)

    crit = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    high = sum(1 for f in findings if f.severity == Severity.HIGH)
    med = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    low = sum(1 for f in findings if f.severity == Severity.LOW)
    info = sum(1 for f in findings if f.severity == Severity.INFO)

    return {
        "target": payload.url,
        "total_findings": len(findings),
        "critical_count": crit,
        "high_count": high,
        "medium_count": med,
        "low_count": low,
        "info_count": info,
        "findings": [f.model_dump() for f in findings]
    }


class SecretsScanRequest(BaseModel):
    path: str = "."

@app.post("/api/scan-secrets")
def api_scan_secrets(payload: SecretsScanRequest):
    findings = scan_local_secrets(payload.path)
    return [f.model_dump() for f in findings]


class PwnedCheckRequest(BaseModel):
    password: str

@app.post("/api/check-pwned")
def api_check_pwned(payload: PwnedCheckRequest):
    is_leaked, count, prefix = check_password_leak_k_anonymity(payload.password)
    return {
        "is_leaked": is_leaked,
        "count": count,
        "prefix": prefix
    }


class GdprRequest(BaseModel):
    name: str
    id_num: str
    email: str
    service: str
    user: Optional[str] = ""

@app.post("/api/gdpr-letter")
def api_gdpr_letter(payload: GdprRequest):
    letter = generate_erasure_request_es(
        full_name=payload.name,
        id_number=payload.id_num,
        email=payload.email,
        service_name=payload.service,
        username_or_account=payload.user or None
    )
    return {"letter": letter}


@app.get("/api/tracker")
def api_get_tracker():
    items = list_tracked_accounts()
    return [item.model_dump() for item in items]


class TrackerAddRequest(BaseModel):
    platform: str
    username: str
    notes: Optional[str] = ""

@app.post("/api/tracker/add")
def api_add_tracker(payload: TrackerAddRequest):
    item = add_account_to_tracker(payload.platform, payload.username, payload.notes or "")
    return item.model_dump()


class TrackerUpdateRequest(BaseModel):
    id: str
    status: str

@app.post("/api/tracker/update")
def api_update_tracker(payload: TrackerUpdateRequest):
    success = update_account_status(payload.id, payload.status)
    return {"success": success}


class TrackerRemoveRequest(BaseModel):
    id: str

@app.post("/api/tracker/remove")
def api_remove_tracker(payload: TrackerRemoveRequest):
    success = remove_tracked_account(payload.id)
    return {"success": success}


@app.get("/api/learning-hub")
def api_learning_hub():
    cards = []
    for card in AUDITOR_KNOWLEDGE_BASE.values():
        cards.append(card.model_dump())
    return cards
