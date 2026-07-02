from app.detection.analyzer import get_analyzer, ALL_ENTITIES
from app.detection.detector import detect_sensitive_data
from app.risk.scorer import calculate_risk

text = """
Employee ID: EMP12345
Aadhaar: 1234 5678 9012
PAN: ABCDE1234F
Email: john.doe@company.com
Phone: +91 9876543210
API Key: sk-abc123def456ghi789jkl012mno345
"""

analyzer = get_analyzer()
results = analyzer.analyze(text=text, entities=ALL_ENTITIES, language="en")
for r in results:
    print(r.entity_type, r.start, r.end, r.score, text[r.start:r.end])

result = detect_sensitive_data(text)
print(result)

risk = calculate_risk(result)
print(risk)