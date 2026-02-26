FROM python:3.12-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libmariadb-dev \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install step CLI for mTLS certificate operations (Phase 2)
RUN wget -q https://dl.smallstep.com/cli/docs-cli-install/latest/step-cli_amd64.deb \
    && dpkg -i step-cli_amd64.deb \
    && rm step-cli_amd64.deb

# Create directories for certs and CRL
RUN mkdir -p /app/certs /app/crl

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
