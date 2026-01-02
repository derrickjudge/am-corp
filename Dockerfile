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
    && rm -rf /var/lib/apt/lists/* \
    # Update CA certificates
    && update-ca-certificates

# Install Nuclei vulnerability scanner
ARG NUCLEI_VERSION=3.3.7
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

# Copy requirements first for layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY scripts/ ./scripts/
COPY config/ ./config/

# Create directories for data, logs, and nuclei templates
RUN mkdir -p /app/data /app/logs /app/nuclei-templates /home/amcorp/.config/nuclei \
    && chown -R amcorp:amcorp /app /home/amcorp/.config

# Switch to non-root user
USER amcorp

# Download Nuclei templates (run as amcorp user)
RUN nuclei -ut -silent || true

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
CMD ["python", "src/main.py"]

