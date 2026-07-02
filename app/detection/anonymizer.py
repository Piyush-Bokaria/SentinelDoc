from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import OperatorConfig, RecognizerResult

anonymizer_engine = AnonymizerEngine()

DEFAULT_OPERATORS = {
    "AADHAAR_NUMBER": OperatorConfig("replace", {"new_value": "<AADHAAR_NUMBER>"}),
    "PAN_NUMBER": OperatorConfig("replace", {"new_value": "<PAN_NUMBER>"}),
    "API_KEY": OperatorConfig("replace", {"new_value": "<API_KEY>"}),
    "PASSWORD": OperatorConfig("replace", {"new_value": "<PASSWORD>"}),
    "CREDIT_CARD": OperatorConfig("mask", {
        "masking_char": "*", "chars_to_mask": 12, "from_end": False,
    }),
    "PHONE_NUMBER": OperatorConfig("mask", {
        "masking_char": "*", "chars_to_mask": 10, "from_end": False,
    }),
    "EMAIL_ADDRESS": OperatorConfig("replace", {"new_value": "<EMAIL_ADDRESS>"}),
    "DEFAULT": OperatorConfig("replace", {"new_value": "<REDACTED>"}),
}

def _to_recognizer_results(findings: list[dict]) -> list[RecognizerResult]:
    """Convert our internal finding dicts back into Presidio RecognizerResult objects."""
    return [
        RecognizerResult(
            entity_type=f["entity_type"],
            start=f["start"],
            end=f["end"],
            score=f["confidence"],
        )
        for f in findings
    ]


def anonymize_text(text: str, findings: list[dict], operators: dict | None = None) -> str:
    """
    Anonymize text using Presidio's AnonymizerEngine, which handles span
    offsets/overlaps internally (safer than manual string slicing).
    """
    results = _to_recognizer_results(findings)
    anonymized = anonymizer_engine.anonymize(
        text=text,
        analyzer_results=results,
        operators=operators or DEFAULT_OPERATORS,
    )
    return anonymized.text