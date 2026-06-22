# ADMAP M1 — IOC Extractor (FastAPI, port 8000).
# Installation standard du paquet via pyproject (`pip install -e .`), comme M3/M5.
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# libmagic1 : requis par python-magic (détection de type de fichier) ;
# build-essential : sécurité de compilation si un wheel manque pour la plateforme.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY admap_m1/ ./admap_m1/
RUN pip install --no-cache-dir -e .

EXPOSE 8000
CMD ["uvicorn", "admap_m1.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
