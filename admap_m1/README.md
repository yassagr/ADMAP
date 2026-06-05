# ADMAP M1 - Static IOC Extractor

**Version:** 3.0.0
**Project:** Advanced Detection & Malware Analysis Platform (ADMAP)

Le module **M1** est le premier composant de la plateforme ADMAP. Son rôle est l'extraction statique d'Indicateurs de Compromission (IOCs) à partir de fichiers suspects.

## 🚀 Fonctionnalités Principales

- **Extraction Statique Avancée :** Parsing structuré (PE, ELF, Office, Archives) et fallback générique.
- **Désobfuscation Intégrée :** Décodage Base64, XOR (1-byte brute force), ROT, PowerShell.
- **Contextualisation & Scoring :** Attribution d'un score de confiance (0-100) basé sur des heuristiques (imports PE, macro autoexec, voisinage API).
- **Filtrage Intelligent :** Liste blanche intégrée, défanging automatique.
- **Enrichissement :** Intégration asynchrone avec l'API VirusTotal v3.
- **Export CTI :** Formats JSON, STIX 2.1, OpenIOC, MISP Event, Cytomic Orion.
- **Architecture Moderne :** Backend asynchrone (FastAPI + Asyncio Queue) et modèle de données strict (Pydantic v2).

## 🛠 Installation

### Prérequis

- Python 3.11+
- Poetry (recommandé) ou pip

### Commandes

```bash
# Via Poetry
poetry install

# Via Pip
pip install -r requirements.txt
```

### Configuration

Renommez `.env.example` en `.env` et ajustez les paramètres :

```ini
VT_API_KEY=votre_cle_virustotal
VT_MAX_PER_TYPE=5
LOG_LEVEL=INFO
API_PORT=8000
```

## 💻 Utilisation

### Mode API (FastAPI)

Démarrez le serveur :

```bash
python -m admap_m1.api.main
```

L'API sera disponible sur `http://localhost:8000`.
Documentation Swagger : `http://localhost:8000/docs`.

### Mode CLI (Ligne de commande)

M1 dispose d'une interface console riche pour une analyse instantanée :

```bash
# Analyse standard
python -m admap_m1.cli.main malware_sample.exe

# Analyse avec VirusTotal et export STIX
python -m admap_m1.cli.main malware_sample.exe --vt --format stix21 --out result.json
```

## 🏗 Architecture

Le pipeline de traitement M1 est décomposé en 7 étapes :

1.  **Parsing** : Identification du type de fichier et extraction des métadonnées.
2.  **Extraction d'Archives** : Décompression récursive (avec limite anti-bomb).
3.  **Désobfuscation** : Recherche de données cachées (XOR, Base64).
4.  **Extraction (Raw)** : Application des extracteurs (Regex, PE, VBA).
5.  **Scoring & Filtres** : Dédoublonnage, contextualisation et notation.
6.  **Enrichissement** : Requêtes asynchrones vers VirusTotal.
7.  **Finalisation** : Defanging et génération de l'IOC Bundle.

## 🧪 Tests

Les tests unitaires et d'intégration couvrent plus de 80% du code.

```bash
pytest tests/ -v --cov=admap_m1
```

## 📄 Licence

Projet PFA (Projet de Fin d'Année) - Usage académique et interne.
