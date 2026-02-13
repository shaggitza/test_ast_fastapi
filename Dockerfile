# Dockerfile for secure VM-based execution of FastAPI endpoint analysis
FROM python:3.10-slim

# Set working directory
WORKDIR /analysis

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy and install the package
COPY pyproject.toml /tmp/
COPY src/ /tmp/src/

# Install the package with dependencies
RUN pip install --no-cache-dir /tmp/

# Create a non-root user for security
RUN useradd -m -u 1000 analyzer && \
    chown -R analyzer:analyzer /analysis

USER analyzer

# Set the entrypoint to the CLI
ENTRYPOINT ["fastapi-endpoint-detector"]
CMD ["--help"]
