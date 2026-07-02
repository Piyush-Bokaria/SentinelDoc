from presidio_analyzer import Pattern, PatternRecognizer

# Aadhaar Number Patten: 12 digits, optionally space/hyphen separated in groups of 4
aadhaar_pattern = Pattern(
    name="aadhaar_pattern",
    regex=r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
    score=0.7,
)
AADHAAR_RECOGNIZER = PatternRecognizer(
    supported_entity="AADHAAR_NUMBER",
    patterns=[aadhaar_pattern],
    context=["aadhaar", "uidai", "aadhar", "identity"],
)

# PAN Number Pattern: 5 letters, 4 digits, 1 letter
pan_pattern = Pattern(
    name="pan_pattern",
    regex=r"\b[A-Z]{5}[0-9]{4}[A-Z]\b",
    score=0.85,
)
PAN_RECOGNIZER = PatternRecognizer(
    supported_entity="PAN_NUMBER",
    patterns=[pan_pattern],
    context=["pan", "income tax", "permanent account"],
)

# IFSC code Pattern: 4 letters, 0, 6 alphanumeric
ifsc_pattern = Pattern(
    name="ifsc_pattern",
    regex=r"\b[A-Z]{4}0[A-Z0-9]{6}\b",
    score=0.75,
)
IFSC_RECOGNIZER = PatternRecognizer(
    supported_entity="IFSC_CODE",
    patterns=[ifsc_pattern],
    context=["ifsc", "bank", "branch"],
)

# Bank account number Pattern: 9-18 digits (broad, relies on context words to reduce false positives)
bank_account_pattern = Pattern(
    name="bank_account_pattern",
    regex=r"\b\d{9,18}\b",
    score=0.4,
)
BANK_ACCOUNT_RECOGNIZER = PatternRecognizer(
    supported_entity="BANK_ACCOUNT_NUMBER",
    patterns=[bank_account_pattern],
    context=["account", "a/c", "bank", "acc no"],
)

# Employee ID Pattern: e.g. EMP1234, EMP-001234 (adjust prefix to match your org convention)
employee_id_pattern = Pattern(
    name="employee_id_pattern",
    regex=r"\b(EMP|EID|ID)[-_]?\d{3,7}\b",
    score=0.6,
)
EMPLOYEE_ID_RECOGNIZER = PatternRecognizer(
    supported_entity="EMPLOYEE_ID",
    patterns=[employee_id_pattern],
    context=["employee", "emp id", "staff"],
)

# API keys / secrets Pattern: common prefixes used by major providers
api_key_pattern = Pattern(
    name="api_key_pattern",
    regex=r"\b(sk-[A-Za-z0-9]{20,}|AIza[A-Za-z0-9_\-]{30,}|ghp_[A-Za-z0-9]{30,}|AKIA[A-Z0-9]{16})\b",
    score=0.9,
)
API_KEY_RECOGNIZER = PatternRecognizer(
    supported_entity="API_KEY",
    patterns=[api_key_pattern],
    context=["key", "token", "secret", "api"],
)

# Generic password assignment in text/config Pattern: password=..., pwd:..., etc.
password_pattern = Pattern(
    name="password_pattern",
    regex=r"(?i)\b(password|pwd|passwd)\s*[:=]\s*\S{4,}",
    score=0.7,
)
PASSWORD_RECOGNIZER = PatternRecognizer(
    supported_entity="PASSWORD",
    patterns=[password_pattern],
    context=["password", "login", "credential"],
)

ALL_CUSTOM_RECOGNIZERS = [
    AADHAAR_RECOGNIZER,
    PAN_RECOGNIZER,
    IFSC_RECOGNIZER,
    BANK_ACCOUNT_RECOGNIZER,
    EMPLOYEE_ID_RECOGNIZER,
    API_KEY_RECOGNIZER,
    PASSWORD_RECOGNIZER,
]