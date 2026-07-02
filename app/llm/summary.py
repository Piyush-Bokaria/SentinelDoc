from app.llm.gemini_client import generate_text

SYSTEM_INSTRUCTION = """You are a data compliance and security analyst assistant.
You are given a structured report of sensitive data findings from a document scan.
You NEVER see or need the actual raw sensitive values - only entity types, counts, and risk levels.
Generate a professional compliance summary. Be specific, concise, and actionable."""


def build_summary_prompt(detection_result: dict, risk_result: dict, doc_type: str) -> str:
    counts = detection_result["counts_by_type"]
    counts_str = "\n".join(f"- {etype}: {count} occurrence(s)" for etype, count in counts.items())

    prompt = f"""
Document type: {doc_type}
Total sensitive data findings: {detection_result['total_findings']}
Risk level: {risk_result['risk_level']} (score: {risk_result['risk_score']})

Findings breakdown by type:
{counts_str}

Risk tier breakdown:
- High risk findings: {risk_result['breakdown']['high_risk_findings']}
- Medium risk findings: {risk_result['breakdown']['medium_risk_findings']}
- Low risk findings: {risk_result['breakdown']['low_risk_findings']}

Based on this, produce a compliance summary with exactly these three sections:

## Compliance Observations
(What sensitive data categories are present and what regulations/policies they typically fall under - e.g. Aadhaar/PAN relate to India's DPDP Act, credit card data relates to PCI-DSS, etc.)

## Security Risks
(What could go wrong if this document is leaked, mishandled, or shared without controls)

## Suggested Remediation Steps
(Concrete, prioritized actions - e.g. redact before sharing, restrict access, encrypt at rest, rotate exposed API keys, etc.)

Keep each section to 3-5 bullet points. Do not restate raw counts already given above verbatim; add analytical value.
"""
    return prompt


def generate_compliance_summary(detection_result: dict, risk_result: dict, doc_type: str) -> str:
    prompt = build_summary_prompt(detection_result, risk_result, doc_type)
    return generate_text(prompt, system_instruction=SYSTEM_INSTRUCTION)