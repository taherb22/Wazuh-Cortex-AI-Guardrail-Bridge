FROM python:3.9-slim

WORKDIR /app
ENV PYTHONUNBUFFERED=1

# Install libmagic for Cortex
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# COPY ALL SCRIPTS (main.py AND mock_guardrail.py)
COPY . .

# We don't set a CMD here, we set it in docker-compose