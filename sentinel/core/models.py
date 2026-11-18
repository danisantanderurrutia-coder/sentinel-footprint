"""
Pydantic data models for Sentinel & Footprint.
"""
from __future__ import annotations
from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime
from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class EducationalCard(BaseModel):
    title: str
    concept: str
    danger_scenario: str
    remediation: str
    code_before: Optional[str] = None
    code_after: Optional[str] = None
    references: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str
    name: str
    severity: Severity
    category: str
    target: str
    details: str
    educational_card: Optional[EducationalCard] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ScanSummary(BaseModel):
    target: str
    scan_type: str
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    info_count: int
    findings: List[Finding]
    scan_date: datetime = Field(default_factory=datetime.utcnow)


class AccountTrackerItem(BaseModel):
    id: str
    platform_name: str
    email_or_username: str
    status: str = "Pending"  # Pending, Requested, In Progress, Deleted
    request_date: Optional[str] = None
    confirmation_date: Optional[str] = None
    notes: Optional[str] = ""
