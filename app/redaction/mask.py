def redact_text(original_text: str, findings: list[dict]) -> str:
    """
    Replace each detected sensitive span in the original text with
    [ENTITY_TYPE_REDACTED], working right-to-left so earlier offsets
    aren't shifted by replacements.
    """
    redacted = original_text
    # sort by start descending so we can replace without messing up earlier indices
    for f in sorted(findings, key=lambda x: -x["start"]):
        placeholder = f"[{f['entity_type']}_REDACTED]"
        redacted = redacted[:f["start"]] + placeholder + redacted[f["end"]:]
    return redacted


def redact_document(extraction_result: dict, findings: list[dict]) -> dict:
    """Apply redaction across all pages of an extracted document."""
    full_redacted = redact_text(extraction_result["full_text"], findings)

    # If page-level granularity matters later (e.g. for PDF re-export), redact per page too.
    # For now, findings are indexed against full_text, so page-level redaction from findings
    # directly isn't offset-accurate; full_text redaction is the reliable source of truth.
    return {
        "redacted_full_text": full_redacted,
        "original_page_count": len(extraction_result.get("pages", [])),
    }