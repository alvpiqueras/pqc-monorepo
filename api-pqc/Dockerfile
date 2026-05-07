FROM qcs-liboqs-base

WORKDIR /workspace

COPY api-pqc/API /workspace/API

WORKDIR /workspace/API

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]