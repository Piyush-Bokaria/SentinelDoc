import uuid
import shutil
from pathlib import Path
from fastapi import FastAPI, UploadFile, File, HTTPException, Query
from fastapi.responses import PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from app.ingestion.extractor import DocumentExtractor
from app.detection.detector import detect_sensitive_data
from app.detection.anonymizer import anonymize_text
from app.risk.scorer import calculate_risk
from app.redaction.mask import redact_document
from app.llm.summary import generate_compliance_summary
from app.llm.rag import answer_question
from app.audit.logger import log_action, get_audit_log
from app.models import (
    UploadResponse, ReportResponse, AskRequest, AskResponse,
    RiskBreakdown, FindingOut,
)
from presidio_anonymizer.entities import OperatorConfig

app = FastAPI(title="SentinelDoc - Sensitive Data Detection & Compliance Assistant")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("data/uploads")
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

# In-memory store: doc_id -> full document state
_DOCUMENTS: dict[str, dict] = {}

SUPPORTED_EXTENSIONS = {".pdf", ".txt", ".csv"}


@app.post("/upload", response_model=UploadResponse)
async def upload_document(file: UploadFile = File(...)):
    ext = Path(file.filename).suffix.lower()
    if ext not in SUPPORTED_EXTENSIONS:
        raise HTTPException(400, f"Unsupported file type '{ext}'. Supported: PDF, TXT, CSV")

    doc_id = str(uuid.uuid4())[:8]
    saved_path = UPLOAD_DIR / f"{doc_id}{ext}"
    with open(saved_path, "wb") as f:
        shutil.copyfileobj(file.file, f)

    log_action("upload", doc_id, f"filename={file.filename}")

    try:
        extraction = DocumentExtractor.extract(str(saved_path))
        detection = detect_sensitive_data(extraction["full_text"])
        risk = calculate_risk(detection)
        redaction = redact_document(extraction, detection["findings"])
        summary = generate_compliance_summary(detection, risk, extraction["type"])
    except Exception as e:
        raise HTTPException(500, f"Processing failed: {e}")

    _DOCUMENTS[doc_id] = {
        "filename": file.filename,
        "doc_type": extraction["type"],
        "raw_text": extraction["full_text"],
        "redacted_text": redaction["redacted_full_text"],
        "detection": detection,
        "risk": risk,
        "summary": summary,
    }

    log_action("detect", doc_id, f"total_findings={detection['total_findings']}, risk={risk['risk_level']}")
    log_action("summarize", doc_id)

    return UploadResponse(
        doc_id=doc_id,
        filename=file.filename,
        doc_type=extraction["type"],
        total_findings=detection["total_findings"],
        counts_by_type=detection["counts_by_type"],
        risk_level=risk["risk_level"],
        risk_score=risk["risk_score"],
        risk_breakdown=RiskBreakdown(**risk["breakdown"]),
        summary=summary,
    )


@app.get("/report/{doc_id}", response_model=ReportResponse)
async def get_report(doc_id: str):
    doc = _DOCUMENTS.get(doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    log_action("view_report", doc_id)

    findings = [
        FindingOut(
            entity_type=f["entity_type"],
            risk_tier=f["risk_tier"],
            confidence=f["confidence"],
            masked_value=f["masked_value"],
        )
        for f in doc["detection"]["findings"]
    ]

    return ReportResponse(
        doc_id=doc_id,
        filename=doc["filename"],
        risk_level=doc["risk"]["risk_level"],
        risk_score=doc["risk"]["risk_score"],
        total_findings=doc["detection"]["total_findings"],
        findings=findings,
        counts_by_type=doc["detection"]["counts_by_type"],
        summary=doc["summary"],
    )


@app.post("/ask", response_model=AskResponse)
async def ask_question(req: AskRequest):
    doc = _DOCUMENTS.get(req.doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    try:
        answer = answer_question(
            req.doc_id,
            doc["redacted_text"],
            doc["raw_text"],
            req.question,
            doc["detection"],
        )
    except Exception as e:
        raise HTTPException(500, f"Q&A failed: {e}")

    log_action("ask", req.doc_id, f"question={req.question[:100]}")

    return AskResponse(doc_id=req.doc_id, question=req.question, answer=answer)

@app.get("/anonymize/{doc_id}", response_class=PlainTextResponse)
async def anonymize_document(
    doc_id: str,
    strategy: str = Query(
        "replace",
        description="Anonymization strategy: replace | mask | hash | redact",
    ),
):
    """
    Alternative anonymization pass using Presidio's native AnonymizerEngine,
    demonstrating configurable per-strategy anonymization (replace/mask/hash/
    redact) as opposed to the fixed placeholder redaction used by default in
    /download-redacted.
    """
    doc = _DOCUMENTS.get(doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    if strategy not in ("replace", "mask", "hash", "redact"):
        raise HTTPException(400, f"Unsupported strategy '{strategy}'. Use: replace, mask, hash, redact")

    try:
        if strategy == "replace":
            operators = None 
        elif strategy == "mask":
            operators = {
                "DEFAULT": OperatorConfig(
                    "mask", {"masking_char": "*", "chars_to_mask": 100, "from_end": False}
                )
            }
        elif strategy == "hash":
            operators = {"DEFAULT": OperatorConfig("hash", {"hash_type": "sha256"})}
        else:  # redact
            operators = {"DEFAULT": OperatorConfig("redact", {})}

        anonymized_text = anonymize_text(
            doc["raw_text"], doc["detection"]["findings"], operators=operators
        )
    except Exception as e:
        raise HTTPException(500, f"Anonymization failed: {e}")

    log_action("anonymize", doc_id, f"strategy={strategy}")

    return anonymized_text

@app.get("/download-redacted/{doc_id}", response_class=PlainTextResponse)
async def download_redacted(doc_id: str):
    doc = _DOCUMENTS.get(doc_id)
    if not doc:
        raise HTTPException(404, "Document not found")

    log_action("download_redacted", doc_id)
    return doc["redacted_text"]


@app.get("/audit-log")
async def audit_log(doc_id: str | None = None):
    return get_audit_log(doc_id)


@app.get("/health")
async def health():
    return {"status": "ok"}


# Serve frontend static files
app.mount("/", StaticFiles(directory="frontend", html=True), name="frontend")