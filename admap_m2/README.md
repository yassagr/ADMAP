# ADMAP M2 - C2 Detector

Ce module est responsable de l'analyse réseau (PCAP) pour détecter des trafics C2. Il agit de manière complémentaire au module M1 (IOC statiques).

## Installation
```bash
pip install -e .
```

## Utilisation CLI
```bash
admap-m2 analyze /path/to/capture.pcap
admap-m2 export /path/to/bundle.json --format stix
admap-m2 serve
```
