FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

WORKDIR /workspace

RUN apt-get update && apt-get install -y \
    cmake \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

COPY liboqs /workspace/liboqs

RUN cmake -S /workspace/liboqs -B /tmp/liboqs-build \
    -DBUILD_SHARED_LIBS=ON \
    -DOQS_BUILD_ONLY_LIB=ON \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=/opt/liboqs \
    && cmake --build /tmp/liboqs-build --parallel 1 \
    && cmake --install /tmp/liboqs-build \
    && rm -rf /tmp/liboqs-build /workspace/liboqs

ENV OQS_INSTALL_PATH=/opt/liboqs
ENV LD_LIBRARY_PATH=/opt/liboqs/lib
ENV PATH="/opt/liboqs/bin:${PATH}"