FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends nmap iproute2 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY scanner.py .

CMD ["python", "-u", "scanner.py"]
