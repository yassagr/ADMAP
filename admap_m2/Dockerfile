# ADMAP M2 — C2 Detector (FastAPI, port 8001).
# Build-backend valide (setuptools.build_meta) -> installation standard du paquet
# (`pip install -e .`), qui tire scapy / dpkt / numpy / scipy depuis le pyproject.
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# libpcap + tcpdump : dépendances système de scapy ; build-essential : sécurité
# de compilation si un wheel manque pour la plateforme.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY admap_m2/ ./admap_m2/
RUN pip install --no-cache-dir -e .

EXPOSE 8001
CMD ["uvicorn", "admap_m2.api.main:app", "--host", "0.0.0.0", "--port", "8001"]
