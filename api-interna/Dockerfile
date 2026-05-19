FROM ghcr.io/alvpiqueras/qcs-liboqs-base:latest

ENV PYTHONPATH=/workspace

WORKDIR /workspace

COPY api-interna/API /workspace/API
COPY api-interna/requirements.txt /workspace/API/requirements.txt

WORKDIR /workspace/API

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["sh", "-c", "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"]