FROM python:3.11-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    traceroute \
    iputils-ping \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements-minimal.txt .
RUN pip install --no-cache-dir -r requirements-minimal.txt

# App files
COPY . .

RUN mkdir -p reports

EXPOSE 5000

CMD ["python", "app.py"]
