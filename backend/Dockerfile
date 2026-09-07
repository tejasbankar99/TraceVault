FROM python:3.11-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
# Note: Debian Trixie renames:
#   libgdk-pixbuf2.0-0   → libgdk-pixbuf-xlib-2.0-0
#   mime-support         → media-types
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    libpq-dev \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libcairo-gobject2 \
    libgdk-pixbuf-xlib-2.0-0 \
    libffi-dev \
    libglib2.0-0 \
    shared-mime-info \
    media-types \
    curl \
    libmagic1 \
    fonts-liberation \
    fonts-dejavu-core \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
# Uses CPU-only PyTorch index to avoid 1GB+ CUDA downloads
COPY requirements.txt .
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r requirements.txt \
        --extra-index-url https://download.pytorch.org/whl/cpu

# Download spaCy English model (~12MB, CPU)
RUN python -m spacy download en_core_web_sm || true

# Copy application source
COPY app/ ./app/
COPY migrations/ ./migrations/
COPY alembic.ini .
COPY templates/ ./templates/

# Create runtime directories
RUN mkdir -p /app/evidence_store /app/reports

# Run as non-root user
RUN groupadd -r tracevault && useradd -r -g tracevault tracevault && \
    chown -R tracevault:tracevault /app

USER tracevault

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
