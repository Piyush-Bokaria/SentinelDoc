from pydantic import BaseModel
from typing import Optional


class FindingOut(BaseModel):
    entity_type: str
    risk_tier: str
    confidence: float
    masked_value: str


class RiskBreakdown(BaseModel):
    high_risk_findings: int
    medium_risk_findings: int
    low_risk_findings: int


class UploadResponse(BaseModel):
    doc_id: str
    filename: str
    doc_type: str
    total_findings: int
    counts_by_type: dict[str, int]
    risk_level: str
    risk_score: int
    risk_breakdown: RiskBreakdown
    summary: str


class ReportResponse(BaseModel):
    doc_id: str
    filename: str
    risk_level: str
    risk_score: int
    total_findings: int
    findings: list[FindingOut]
    counts_by_type: dict[str, int]
    summary: str


class AskRequest(BaseModel):
    doc_id: str
    question: str


class AskResponse(BaseModel):
    doc_id: str
    question: str
    answer: str


class AuditLogEntry(BaseModel):
    doc_id: Optional[str]
    action: str
    detail: str
    timestamp: str