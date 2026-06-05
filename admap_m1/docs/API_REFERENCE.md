# API Reference - ADMAP M1

Cette documentation décrit les endpoints de l'API REST de M1, basée sur FastAPI.
L'API suit une approche asynchrone (Job Queue) pour gérer les fichiers lourds sans bloquer le serveur.

## Endpoints

### 1. `POST /api/v1/analyze`
Soumet un fichier pour analyse.

**Requête (multipart/form-data) :**
- `file` (File) : Le fichier binaire à analyser.
- `enable_vt` (Boolean, default=False) : Activer l'enrichissement VirusTotal.
- `enable_deobfuscation` (Boolean, default=True) : Activer les désobfuscateurs.

**Réponse (200 OK) :**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "QUEUED",
  "message": "Analyse acceptée et mise en file d'attente.",
  "status_url": "/api/v1/jobs/550e8400-e29b-41d4-a716-446655440000"
}
```

---

### 2. `GET /api/v1/jobs/{job_id}`
Vérifie le statut d'un job.

**Réponse (200 OK) :**
```json
{
  "job_id": "550e8400-e29b-41d4-a716-446655440000",
  "filename": "malware.exe",
  "status": "RUNNING",
  "progress": 45,
  "current_stage": "Étape 4: Extraction des IOCs bruts",
  "error": null
}
```
Statuts possibles : `QUEUED`, `RUNNING`, `COMPLETED`, `FAILED`, `CANCELLED`.

---

### 3. `GET /api/v1/jobs/{job_id}/result`
Récupère le résultat complet au format interne ADMAP (JSON).

**Réponse (200 OK) :** (Retourne l'objet `IOCBundle` complet)
```json
{
  "bundle_id": "...",
  "metadata": { ... },
  "iocs": [
    {
      "type": "ipv4",
      "value_defanged": "192[.]168[.]1[.]1",
      "confidence_score": 60,
      ...
    }
  ],
  "analysis_stats": { ... }
}
```

---

### 4. `DELETE /api/v1/jobs/{job_id}`
Annule un job en cours d'exécution.

**Réponse (200 OK) :**
```json
{
  "message": "Job annulé avec succès"
}
```

---

### 5. `GET /api/v1/export/{job_id}?format={fmt}`
Exporte le résultat d'un job terminé dans un format CTI standard.

**Paramètres query :**
- `format` (String) : `stix21`, `openioc`, `misp`, ou `cytomic`.

**Réponse (200 OK) :**
Le contenu du fichier dans le format demandé (Content-Type : `application/json` ou `application/xml`).

---

### 6. `GET /health`
Vérifie l'état de santé du service.

**Réponse (200 OK) :**
```json
{
  "status": "ok",
  "service": "ADMAP M1"
}
```
