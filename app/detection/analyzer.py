from presidio_analyzer import AnalyzerEngine, RecognizerRegistry
from presidio_analyzer.nlp_engine import NlpEngineProvider
from app.detection.recognizers import ALL_CUSTOM_RECOGNIZERS

DEFAULT_ENTITIES = [
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "CREDIT_CARD",
    "PERSON",
    "IBAN_CODE",
    "IP_ADDRESS",
    "LOCATION",
    "US_SSN",
]

CUSTOM_ENTITIES = [
    "AADHAAR_NUMBER",
    "PAN_NUMBER",
    "IFSC_CODE",
    "BANK_ACCOUNT_NUMBER",
    "EMPLOYEE_ID",
    "API_KEY",
    "PASSWORD",
]

ALL_ENTITIES = DEFAULT_ENTITIES + CUSTOM_ENTITIES


def build_analyzer() -> AnalyzerEngine:
    nlp_configuration = {
        "nlp_engine_name": "spacy",
        "models": [{"lang_code": "en", "model_name": "en_core_web_lg"}],
    }
    nlp_engine = NlpEngineProvider(nlp_configuration=nlp_configuration).create_engine()

    registry = RecognizerRegistry()
    registry.load_predefined_recognizers(nlp_engine=nlp_engine)

    for recognizer in ALL_CUSTOM_RECOGNIZERS:
        registry.add_recognizer(recognizer)

    return AnalyzerEngine(registry=registry, nlp_engine=nlp_engine, supported_languages=["en"])

_analyzer_instance = None

def get_analyzer() -> AnalyzerEngine:
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = build_analyzer()
    return _analyzer_instance