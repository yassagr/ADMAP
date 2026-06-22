# ADMAP Gateway — BFF FastAPI (port 9000).
#
# Le paquet `admap_gateway` utilise des imports relatifs (`from .routers ...`) :
# il doit donc être importable sous le nom `admap_gateway`. On copie les sources
# dans /app/admap_gateway et on lance uvicorn depuis /app.
#
# Les URLs des modules sont lues par pydantic-settings (settings.py) depuis les
# variables d'environnement M1_URL..M5_URL (fallback localhost). Elles sont
# fournies par le docker-compose racine -> AUCUN changement de code requis.
FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sources du paquet (main.py, routers/, ws/, settings.py, __init__.py).
COPY . ./admap_gateway/

EXPOSE 9000
CMD ["uvicorn", "admap_gateway.main:app", "--host", "0.0.0.0", "--port", "9000"]
