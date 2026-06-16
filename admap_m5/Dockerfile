FROM python:3.11-slim

WORKDIR /app

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
# Create a dummy package to install dependencies first
RUN mkdir admap_m5 && touch admap_m5/__init__.py
RUN pip install -e .

COPY . .

# Generate a synthetic XGBoost model during build if none exists
RUN python -c "from admap_m5.core.xgb_classifier import generate_synthetic_xgb_model; from admap_m5.core.apt_kb import APTKnowledgeBase; from pathlib import Path; kb = APTKnowledgeBase(Path('data/apt_kb.json')); generate_synthetic_xgb_model(kb.groups, Path('models_store/xgb_attributor.joblib'))"

EXPOSE 8004

CMD ["admap-m5", "serve", "--host", "0.0.0.0", "--port", "8004"]
