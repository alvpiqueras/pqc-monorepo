FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /workspace

RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copiamos liboqs local
COPY liboqs /workspace/liboqs

# Compilamos liboqs
RUN cmake -S /workspace/liboqs -B /tmp/liboqs-build \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    && cmake --build /tmp/liboqs-build --parallel 1 \
    && cmake --install /tmp/liboqs-build

# Variables necesarias para liboqs-python
ENV OQS_INSTALL_PATH=/opt/liboqs
ENV LD_LIBRARY_PATH=/opt/liboqs/lib
ENV PATH="/opt/liboqs/bin:${PATH}"
ENV PYTHONPATH=/workspace

# Copiamos la API
COPY API /workspace/API

WORKDIR /workspace/API

# Instalamos dependencias Python
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["sh", "-c", "uvicorn API.app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]