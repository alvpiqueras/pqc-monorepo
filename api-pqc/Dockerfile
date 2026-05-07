FROM python:3.11-slim

WORKDIR /workspace

RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY . .

RUN cmake -S /workspace/liboqs -B /tmp/liboqs-build \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    && cmake --build /tmp/liboqs-build --parallel 1 \
    && cmake --install /tmp/liboqs-build

ENV OQS_INSTALL_PATH=/opt/liboqs
ENV LD_LIBRARY_PATH=/opt/liboqs/lib
ENV PATH="/opt/liboqs/bin:${PATH}"

WORKDIR /workspace/API

RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port ${PORT:-8000}"]