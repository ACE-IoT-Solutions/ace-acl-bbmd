FROM python:3.13-slim AS rust-builder

# Install Rust toolchain and build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
        curl build-essential pkg-config \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}"

# Install maturin
RUN pip install --no-cache-dir maturin

# Build the Rust ACL engine extension
WORKDIR /build/rust
COPY rust/Cargo.toml rust/pyproject.toml ./
COPY rust/src/ ./src/
RUN maturin build --release --out /build/wheels


# ---------- Runtime stage ----------
FROM python:3.13-slim

LABEL org.opencontainers.image.source="https://github.com/ACE-IoT-Solutions/ace-acl-bbmd"
LABEL org.opencontainers.image.description="ACL-enabled BACnet/IP Broadcast Management Device"

WORKDIR /app

# Install the Python package
COPY pyproject.toml README.md ./
COPY src/ ./src/

RUN pip install --no-cache-dir .

# Install the pre-built Rust extension wheel
COPY --from=rust-builder /build/wheels/*.whl /tmp/
RUN pip install --no-cache-dir /tmp/*.whl && rm -f /tmp/*.whl

# Copy default config and entrypoint
COPY config/ ./config/
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Create directories for runtime data
RUN mkdir -p /app/logs /app/metrics

# BACnet/IP default port + Prometheus metrics port
EXPOSE 47808/udp
EXPOSE 9090/tcp

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["ace-acl-bbmd", "--config", "/app/config/runtime.yaml"]
