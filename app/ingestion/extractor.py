import pdfplumber
import pandas as pd
from pathlib import Path


class DocumentExtractor:
    """Extracts plain text from PDF, TXT, and CSV files for downstream detection."""

    @staticmethod
    def extract(file_path: str) -> dict:
        ext = Path(file_path).suffix.lower()

        if ext == ".pdf":
            return DocumentExtractor._extract_pdf(file_path)
        elif ext == ".txt":
            return DocumentExtractor._extract_txt(file_path)
        elif ext == ".csv":
            return DocumentExtractor._extract_csv(file_path)
        else:
            raise ValueError(f"Unsupported file type: {ext}")

    @staticmethod
    def _extract_pdf(file_path: str) -> dict:
        pages = []
        with pdfplumber.open(file_path) as pdf:
            for i, page in enumerate(pdf.pages):
                text = page.extract_text() or ""
                pages.append({"page": i + 1, "text": text})
        full_text = "\n".join(p["text"] for p in pages)
        return {"full_text": full_text, "pages": pages, "type": "pdf"}

    @staticmethod
    def _extract_txt(file_path: str) -> dict:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        return {"full_text": text, "pages": [{"page": 1, "text": text}], "type": "txt"}

    @staticmethod
    def _extract_csv(file_path: str) -> dict:
        df = pd.read_csv(file_path, dtype=str, keep_default_na=False)
        # Flatten to text for entity scanning, but keep structured df for column-level checks
        text = df.to_csv(index=False)
        return {
            "full_text": text,
            "pages": [{"page": 1, "text": text}],
            "type": "csv",
            "dataframe": df,
            "columns": list(df.columns),
        }