FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY api/ ./api/
COPY judge_engine/ ./judge_engine/
COPY scripts/ ./scripts/
COPY policy_packs/ ./policy_packs/

ENV TITAN_SIGNING_KEY=""
ENV PORT=8000

EXPOSE 8000

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT}"]
