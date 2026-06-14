FROM python:3.11-slim

WORKDIR /app
COPY pyproject.toml .
COPY admap_m3/ ./admap_m3/

RUN pip install --no-cache-dir -e .

# Volumes montés en lecture seule pour le corpus (security-by-design)
VOLUME ["/corpus/malware", "/corpus/benign", "/output"]

EXPOSE 8002

CMD ["admap-m3", "serve", "--host", "0.0.0.0", "--port", "8002"]
