FROM python:3.12-slim

# Install system dependencies untuk conntrack
RUN apt-get update && apt-get install -y \
    conntrack \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first untuk layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY app.py .
COPY conntrack_parser.py .
COPY database.py .
COPY anomaly_detector.py .
COPY static/ ./static/

# Expose port
EXPOSE 8000

# Run as non-root user (capabilities akan diberikan saat container dijalankan)
RUN useradd -m -u 1000 appuser && \
    chown -R appuser:appuser /app

# Note: Container harus dijalankan dengan --cap-add=NET_ADMIN --cap-add=NET_RAW
# atau dengan network_mode: host untuk akses conntrack
# USER appuser  # Commented karena conntrack memerlukan capabilities

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/api/summary')" || exit 1

# Run application
CMD ["python", "app.py"]

