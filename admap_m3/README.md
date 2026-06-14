# ADMAP M3 — YARA Signature Generator

Module M3 de la plateforme ADMAP.  
Génération automatique de règles YARA compilables depuis un corpus malware/bénin
via un algorithme TF-IDF discriminant implémenté manuellement (zéro sklearn).

## Démarrage rapide

```bash
# Installation
pip install -e ".[dev]"

# Lancement du serveur API (port 8002)
admap-m3 serve

# Génération CLI depuis des dossiers locaux
admap-m3 generate \
    --malware-dir ./corpus/malware \
    --benign-dir ./corpus/benign \
    --output-dir ./output \
    --format all

# Validation d'un fichier YARA existant
admap-m3 validate rules.yar

# Tests
pytest tests/ -v
```

## Architecture

| Couche         | Rôle                                            |
|----------------|-------------------------------------------------|
| `models/`      | Modèles Pydantic v2 (frozen, type-safe)         |
| `analyzers/`   | Extraction features PE / ELF / texte / generic  |
| `core/`        | TF-IDF, scoring, rule builder, pipeline         |
| `exporters/`   | YARA .yar, JSON, STIX 2.1, CSV                  |
| `integrations/`| Client M1 pour enrichissement IOC               |
| `api/`         | FastAPI REST + worker async                      |
| `cli/`         | CLI Click (generate, validate, serve)            |

## API Endpoints

- `GET  /health` — Healthcheck
- `GET  /ready` — Readiness probe
- `POST /api/v1/generate` — Lancer une génération (multipart)
- `GET  /api/v1/jobs/{id}` — Statut d'un job
- `GET  /api/v1/jobs/{id}/result` — Résultat (YaraRuleSet)
- `GET  /api/v1/export/{id}/{format}` — Export (yar/json/stix/csv/all)
- `GET  /api/v1/generate/capabilities` — Capacités du moteur

## Configuration

Toutes les variables d'environnement sont préfixées `ADMAP_M3_`.  
Voir `.env.example` pour la liste complète.

## Docker

```bash
docker-compose up --build
```

Le service écoute sur le port **8002**.
