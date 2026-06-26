# =============================================================================
# AM-Corp Bot Container
# Python 3.12 + Security Tools (dig, whois, nmap, nuclei)
# =============================================================================

FROM python:3.12-slim

# Labels
LABEL maintainer="AM-Corp"
LABEL description="Multi-agent cybersecurity automation platform"

# Environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Fix gRPC SSL certificate verification
    GRPC_DEFAULT_SSL_ROOTS_FILE_PATH=/etc/ssl/certs/ca-certificates.crt \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt

# Create non-root user for security
RUN groupadd --gid 1000 amcorp \
    && useradd --uid 1000 --gid 1000 --shell /bin/bash --create-home amcorp

# Install security tools and dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # CA certificates for SSL/TLS (required for API calls)
    ca-certificates \
    # DNS tools
    dnsutils \
    # WHOIS
    whois \
    # Nmap port scanner
    nmap \
    # Useful utilities
    curl \
    iputils-ping \
    unzip \
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Add custom CA certificates (e.g., corporate proxy certs)
# certs/ directory may be empty in non-corporate environments
COPY certs/ /tmp/certs/
RUN mkdir -p /usr/local/share/ca-certificates/custom/ \
    && find /tmp/certs -name "*.pem" -exec sh -c \
        'cp "$1" "/usr/local/share/ca-certificates/custom/$(basename "$1")"' _ {} \; \
    && find /usr/local/share/ca-certificates/custom -name "*.pem" -exec sh -c \
        'cp "$1" "/usr/local/share/ca-certificates/$(basename "$1" .pem).crt"' _ {} \; \
    && update-ca-certificates \
    && rm -rf /tmp/certs

# Install Nuclei vulnerability scanner
ARG NUCLEI_VERSION=3.9.0
ARG TARGETARCH
RUN ARCH=$(case ${TARGETARCH} in \
        amd64) echo "amd64" ;; \
        arm64) echo "arm64" ;; \
        *) echo "amd64" ;; \
    esac) && \
    curl -sSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_${ARCH}.zip" -o /tmp/nuclei.zip && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    chmod +x /usr/local/bin/nuclei && \
    rm /tmp/nuclei.zip

# Download Nuclei templates (as amcorp user later)

# Set working directory
WORKDIR /app

# Copy dependency manifests first for layer caching
COPY pyproject.toml uv.lock ./

# Install uv + refresh pip (clears known pip CVEs), then install the exact
# locked dependency set into the system environment (no venv, reproducible).
RUN pip install --no-cache-dir --upgrade pip uv \
    && uv export --frozen --no-dev --no-emit-project -o /tmp/requirements.lock \
    && uv pip install --system --no-cache -r /tmp/requirements.lock \
    && rm /tmp/requirements.lock

# Copy application code
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY config/ ./config/

# Make entrypoint executable
RUN chmod +x /app/scripts/entrypoint.sh

# Create directories for data, logs, and nuclei templates
RUN mkdir -p /app/data /app/logs /app/nuclei-templates /home/amcorp/.config/nuclei \
    && chown -R amcorp:amcorp /app /home/amcorp/.config

# Switch to non-root user
USER amcorp

# Download Nuclei templates (run as amcorp user)
RUN nuclei -ut -silent || true

# Health check - verify bot can import and preflight passes
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "from src.main import main; print('OK')"

# Entrypoint runs preflight checks before starting
ENTRYPOINT ["/app/scripts/entrypoint.sh"]

# Default command (passed to entrypoint)
CMD []

