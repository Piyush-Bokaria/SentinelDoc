FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

RUN python -m spacy download en_core_web_sm 

COPY app/ ./app/
COPY frontend/ ./frontend/

RUN mkdir -p data/uploads

EXPOSE 8000

ENV PORT=8000
CMD uvicorn app.main:app --host 0.0.0.0 --port ${PORT}