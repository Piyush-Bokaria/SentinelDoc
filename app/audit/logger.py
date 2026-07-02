from datetime import datetime, timezone

_AUDIT_LOG: list[dict] = []


def log_action(action: str, doc_id: str | None = None, detail: str = ""):
    _AUDIT_LOG.append({
        "doc_id": doc_id,
        "action": action,
        "detail": detail,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


def get_audit_log(doc_id: str | None = None, limit: int = 100) -> list[dict]:
    entries = _AUDIT_LOG if doc_id is None else [e for e in _AUDIT_LOG if e["doc_id"] == doc_id]
    return list(reversed(entries))[:limit]