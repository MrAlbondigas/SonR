FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY enricher.py conftest.py test_enricher.py .

CMD ["python", "-u", "enricher.py"]
