FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for nmap, sslyze, etc.
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    nmap \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
