# =============================================================================
# AM-Corp Bot Container
# Python 3.12 + Security Tools (dig, whois, nmap)
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
    # Cleanup
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    # Update CA certificates
    && update-ca-certificates

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

# Create directories for data and logs
RUN mkdir -p /app/data /app/logs \
    && chown -R amcorp:amcorp /app

# Switch to non-root user
USER amcorp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Default command
CMD ["python", "src/main.py"]

