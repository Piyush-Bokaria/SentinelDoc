import sys
import uuid

from app.ingestion.extractor import DocumentExtractor
from app.detection.detector import detect_sensitive_data
from app.risk.scorer import calculate_risk
from app.redaction.mask import redact_document
from app.llm.summary import generate_compliance_summary
from app.llm.rag import answer_question


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m tests.cli_test <path_to_file>")
        sys.exit(1)

    file_path = sys.argv[1]
    doc_id = str(uuid.uuid4())[:8]

    print(f"\n{'='*60}\n1. EXTRACTING TEXT\n{'='*60}")
    extraction = DocumentExtractor.extract(file_path)
    print(f"Document type: {extraction['type']}")
    print(f"Extracted {len(extraction['full_text'])} characters")

    print(f"\n{'='*60}\n2. DETECTING SENSITIVE DATA\n{'='*60}")
    detection = detect_sensitive_data(extraction["full_text"])
    print(f"Total findings: {detection['total_findings']}")
    print(f"By type: {detection['counts_by_type']}")
    for f in detection["findings"]:
        print(f"  - {f['entity_type']:22s} [{f['risk_tier']:6s}] conf={f['confidence']}  {f['masked_value']}")

    print(f"\n{'='*60}\n3. RISK SCORING\n{'='*60}")
    risk = calculate_risk(detection)
    print(f"Risk Level: {risk['risk_level']}")
    print(f"Risk Score: {risk['risk_score']}")
    print(risk["explanation"])

    print(f"\n{'='*60}\n4. REDACTION\n{'='*60}")
    redaction = redact_document(extraction, detection["findings"])
    print(redaction["redacted_full_text"])

    print(f"\n{'='*60}\n5. AI COMPLIANCE SUMMARY (Gemini)\n{'='*60}")
    try:
        summary = generate_compliance_summary(detection, risk, extraction["type"])
        print(summary)
    except Exception as e:
        print(f"[Summary generation failed - check GEMINI_API_KEY] {e}")

    print(f"\n{'='*60}\n6. INTERACTIVE Q&A (type 'exit' to quit)\n{'='*60}")
    while True:
        question = input("\nAsk a question about the document: ").strip()
        if question.lower() in ("exit", "quit", ""):
            break
        try:
            answer = answer_question(
                doc_id,
                redaction["redacted_full_text"],
                extraction["full_text"],
                question,
                detection,
            )
            print(f"\n> {answer}")
        except Exception as e:
            print(f"[Q&A failed] {e}")


if __name__ == "__main__":
    main()