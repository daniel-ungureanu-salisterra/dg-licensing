FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=/app

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
RUN pip install --no-cache-dir \
        "fastapi>=0.110" \
        "uvicorn[standard]>=0.29" \
        "sqlalchemy>=2.0" \
        "psycopg2-binary>=2.9" \
        "pydantic>=2.6" \
        "pydantic-settings>=2.2" \
        "python-multipart>=0.0.9" \
        "cryptography>=42"

COPY app/ app/
COPY VERSION ./

CMD ["uvicorn", "app.web.app:app", "--host", "0.0.0.0", "--port", "8080"]
