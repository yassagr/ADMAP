# PROMPT DE SPÉCIFICATION — ADMAP DASHBOARD
## Document destiné à l'agent d'exécution chargé de réaliser le dashboard web ADMAP

---

## CONTEXTE DU PROJET

Tu dois construire le **dashboard web de la plateforme ADMAP** (Advanced Detection & Malware Analysis Platform), une application SOC/CERT industrielle composée de 5 microservices Python FastAPI indépendants déjà terminés et fonctionnels :

| Module | Nom | Port | Rôle |
|--------|-----|------|------|
| M1 | IOC Extractor | 8000 | Parse PE/ELF/texte → extrait IOCs (IP, hash, domaine, URL, mutex, registre...) → exporte STIX 2.1, OpenIOC, MISP JSON, CSV |
| M2 | C2 Detector | 8001 | Analyse PCAP → détecte beaconing, DNS tunneling, DGA, JA3/JA3S → mapping MITRE ATT&CK |
| M3 | YARA Generator | 8002 | Génère règles YARA compilables depuis corpus malware/bénin via TF-IDF discriminant |
| M4 | APT Mapper | 8003 | Extrait TTPs MITRE ATT&CK → clustering DBSCAN → APTMapReport avec cartographie |
| M5 | Attribution | 8004 | Top-k acteurs APT probables avec scores de confiance XGBoost + cosinus |

Le dashboard est une **application web** (pas desktop) qui orchestre ces 5 microservices via leurs endpoints REST existants. Il ne contient **aucune logique métier propre** — il consomme uniquement les APIs déjà exposées.

---

## STACK TECHNOLOGIQUE OBLIGATOIRE

```
Frontend  : React 18+ avec Vite
UI        : Tailwind CSS + shadcn/ui
Graphiques : Recharts (graphiques de données) + D3.js (visualisations custom complexes)
Animations : Framer Motion
Routing   : React Router v6
État      : Zustand (store global léger)
HTTP      : Axios avec intercepteurs
Icônes    : Lucide React
Temps réel : WebSocket natif ou Server-Sent Events (SSE) pour le polling des jobs
```

**Interdictions strictes :**
- Aucun framework CSS autre que Tailwind
- Aucune bibliothèque de composants autre que shadcn/ui
- Aucun appel direct aux microservices depuis le frontend en production sans passer par un BFF (Backend For Frontend) léger — voir section Architecture ci-dessous

---

## ARCHITECTURE GLOBALE

```
┌──────────────────────────────────────────────────────────┐
│                    NAVIGATEUR (React SPA)                 │
│   Dashboard Web — port 3000                              │
└────────────────────────┬─────────────────────────────────┘
                         │ HTTP/WebSocket
                         ▼
┌──────────────────────────────────────────────────────────┐
│              BFF — FastAPI Gateway (port 9000)            │
│   /api/m1/**, /api/m2/**, /api/m3/**, /api/m4/**,        │
│   /api/m5/**, /api/pipeline/**, /ws/jobs/**              │
│   Rôles : proxy inverse, CORS, agrégation statuts,       │
│   orchestration pipeline complet M1→M2→M3→M4→M5         │
└────┬────────┬────────┬────────┬────────┬─────────────────┘
     │        │        │        │        │
  :8000    :8001    :8002    :8003    :8004
   M1       M2       M3       M4       M5
```

Le **BFF (Backend For Frontend)** est un microservice FastAPI minimaliste (`admap_gateway`) sur le port 9000. Il :
1. Proxie les requêtes vers les 5 microservices
2. Agrège les `/health` et `/ready` de chaque module en un seul endpoint `/api/status`
3. Expose un endpoint `/api/pipeline/full` qui orchestre le pipeline complet M1→M2→M4→M5 (M3 optionnel)
4. Gère les WebSockets `/ws/jobs/{job_id}` pour le polling de progression en temps réel
5. Gère CORS pour autoriser le frontend React sur port 3000

**Structure de fichiers du BFF :**
```
admap_gateway/
├── main.py              # FastAPI app, lifespan, CORS, router inclusion
├── settings.py          # pydantic-settings : URLs des 5 microservices
├── routers/
│   ├── status.py        # GET /api/status — agrégation health de M1–M5
│   ├── m1.py            # proxy /api/m1/**
│   ├── m2.py            # proxy /api/m2/**
│   ├── m3.py            # proxy /api/m3/**
│   ├── m4.py            # proxy /api/m4/**
│   ├── m5.py            # proxy /api/m5/**
│   └── pipeline.py      # POST /api/pipeline/full — orchestration complète
├── ws/
│   └── jobs.py          # WebSocket /ws/jobs/{job_id} — polling progression
└── requirements.txt
```

---

## DESIGN SYSTEM ET IDENTITÉ VISUELLE

### Thème général
- **Thème sombre exclusivement** — aucun mode clair. Fond de base : `#0a0f1a` (navy très foncé).
- **Palette principale :**
  ```
  --bg-primary:    #0a0f1a   (fond global)
  --bg-secondary:  #0d1526   (cartes, panels)
  --bg-tertiary:   #111d35   (inputs, hover states)
  --border:        #1e2d4a   (séparateurs)
  --accent-cyan:   #00d4ff   (actions primaires, highlights)
  --accent-green:  #00ff88   (succès, "safe", score bas)
  --accent-orange: #ff6b35   (warning, "suspicious")
  --accent-red:    #ff2d55   (critical, danger)
  --accent-purple: #8b5cf6   (IA/ML features — réservé pour Phase 2)
  --text-primary:  #e2e8f0
  --text-secondary:#94a3b8
  --text-muted:    #475569
  ```
- **Typographie :** `Inter` pour le texte courant, `JetBrains Mono` pour les données techniques (hashes, IPs, code YARA).
- **Effets visuels :**
  - Glassmorphism léger sur les cartes (`backdrop-blur-sm`, `bg-opacity-60`)
  - Bordures avec subtle glow sur les éléments actifs (`box-shadow: 0 0 12px rgba(0,212,255,0.3)`)
  - Gradients de fond subtils sur les headers de section
  - Animations d'entrée de page (`Framer Motion` — `fadeInUp`, durée 300ms)
  - Transitions de hover sur tous les éléments interactifs (200ms ease)

### Sévérité / Scores — Codage couleur universel
Ce codage s'applique **sur toutes les pages** de manière cohérente :
```
CRITICAL  (score ≥ 80)  → rouge      #ff2d55  + badge pulsant
HIGH      (score ≥ 60)  → orange     #ff6b35
MEDIUM    (score ≥ 40)  → jaune      #f59e0b
LOW       (score ≥ 20)  → bleu-gris  #64748b
INFO      (score  < 20) → gris       #475569
```

---

## STRUCTURE DE L'APPLICATION — PAGES ET NAVIGATION

### Navigation principale (sidebar fixe gauche)
```
┌─────────────────┐
│  ◈ ADMAP        │  logo + version
├─────────────────┤
│  ⊞ Overview     │  page d'accueil / statut global
├─────────────────┤
│  M1 IOC Extract │
│  M2 C2 Detect   │
│  M3 YARA Gen    │  ← section "MODULES"
│  M4 APT Map     │
│  M5 Attribution │
├─────────────────┤
│  ⟳ Pipeline     │  orchestration M1→M2→M4→M5
├─────────────────┤
│  ◉ Jobs         │  historique de tous les jobs
├─────────────────┤
│  ⚙ Settings    │  configuration URLs microservices
└─────────────────┘
```

Chaque item de navigation affiche un **indicateur de statut coloré** (vert/rouge/gris) basé sur le résultat du dernier appel `/health` du microservice correspondant. Ce polling se fait automatiquement toutes les 30 secondes en arrière-plan.

---

## PAGE 1 — OVERVIEW (/)

### Objectif
Vue d'ensemble en temps réel de l'état de la plateforme et des dernières analyses.

### Composants

**1.1 — Barre de statut des modules (top)**
Une rangée de 5 cartes compactes, une par module, affichant :
- Nom du module (M1, M2... + nom court)
- Indicateur santé : `●` vert si `/health` répond OK, rouge sinon, gris si injoignable
- Version du service (extraite de la réponse `/health`)
- Nombre de jobs actifs (extrait de `/ready` → `queue_size`)

Animation : un pulse discret sur les indicateurs verts. Un badge "OFFLINE" animé rouge sur les modules injoignables.

**1.2 — Statistiques globales (KPI cards)**
4 cartes de métriques en grille 2×2 :
- Total analyses lancées (session courante)
- IOCs extraits (cumul M1)
- Alertes C2 détectées (cumul M2)
- Attributions APT résolues (cumul M5)

Chaque carte affiche une mini-sparkline animée (graphique linéaire minimaliste, 8 dernières valeurs).

**1.3 — Pipeline Flow Diagram**
Diagramme SVG animé représentant le flux M1 → M2 → M3 → M4 → M5 :
- Chaque nœud est une boîte cliquable (navigue vers la page du module)
- Les flèches s'animent (flux de particules) quand un pipeline est en cours d'exécution
- Les nœuds offline sont grisés et barrés
- Flèches optionnelles (M3 → M4, M1 → M4) représentées en pointillés

**1.4 — Dernières activités (Activity Feed)**
Liste chronologique des 20 dernières actions (jobs créés, complétés, erreurs) avec :
- Timestamp relatif ("il y a 3 min")
- Module concerné (badge coloré)
- Statut (icône + couleur)
- Lien vers le job detail

**1.5 — Slot réservé Phase 2 IA**
Une section visuellement distincte (bordure purple, badge "COMING SOON — AI Phase") avec placeholder pour les KPIs ML futurs (précision du modèle M2-IA, distribution des prédictions XGBoost M5, etc.). Elle est rendue mais non interactive pour l'instant.

---

## PAGE 2 — M1 : IOC EXTRACTOR (/m1)

### Objectif
Soumettre un fichier PE/ELF/texte, visualiser les IOCs extraits, exporter les résultats.

### Composants

**2.1 — Zone de soumission**
- Drag & Drop zone avec animation de survol (bordure cyan pulsante)
- Formats acceptés affichés : `.exe`, `.dll`, `.elf`, `.so`, `.txt`, `.pdf`, `.docx`
- Taille max affichée
- Bouton "Analyze" avec état de chargement animé (spinner + "Extracting IOCs...")
- Appel : `POST /api/m1/api/v1/analyze` (multipart)

**2.2 — Progression du job**
Barre de progression animée pendant l'analyse avec polling WebSocket `/ws/jobs/{job_id}`.
Affiche les stages successifs avec check animé à chaque étape terminée :
```
[ ✓ ] File validation
[ ✓ ] PE/ELF parsing  
[ ✓ ] String extraction
[ ✓ ] IOC classification
[ ⟳ ] VirusTotal enrichment...
[   ] Export generation
```

**2.3 — Résultats : IOC Summary Cards**
Après complétion, grille de cartes par catégorie d'IOC :
- IPs (avec géolocalisation flag emoji si disponible)
- Domaines
- Hashes (MD5 / SHA1 / SHA256 / SSDeep / IMPHASH)
- URLs
- Clés de registre Windows
- Mutex
- Commandes suspectes

Chaque carte affiche le count total de la catégorie et les 5 premiers éléments avec bouton "Show all".

**2.4 — Table IOCs complète**
DataTable paginée (50 par page) avec :
- Colonnes : Type | Valeur | Score | Source | Actions
- Tri sur toutes les colonnes
- Filtre par type (multi-select)
- Recherche texte full-text
- Score de risque avec badge coloré (cf. codage sévérité)
- Bouton copie par ligne (copie la valeur dans le clipboard)

**2.5 — Panel d'export**
4 boutons d'export, chacun déclenche `GET /api/m1/api/v1/export/{job_id}/{format}` :
- `STIX 2.1` (JSON)
- `OpenIOC XML`
- `MISP JSON`
- `CSV Cytomic Orion`

Chaque bouton affiche un état de chargement pendant le téléchargement.

**2.6 — Slot Phase 2 IA (M1-IA)**
Section collapsed par défaut avec badge purple "AI Enhancement — Phase 2" :
- Placeholder pour NER spaCy/DistilBERT sur texte libre CTI
- Description de ce que la fonctionnalité apportera
- Interface prête (inputs, boutons) mais boutons disabled avec tooltip "Available in Phase 2"

---

## PAGE 3 — M2 : C2 DETECTOR (/m2)

### Objectif
Soumettre un fichier PCAP, visualiser les alertes C2 détectées, explorer les flux réseau.

### Composants

**3.1 — Zone de soumission PCAP**
- Drag & Drop avec aperçu du nom de fichier et taille
- Option "Link to M1 bundle" : champ facultatif pour coller un `bundle_id` M1 (active la corrélation IOC M1→M2)
- Appel : `POST /api/m2/api/v1/analyze`

**3.2 — Progression job** (même pattern que M1, stages M2-spécifiques)
```
[ ] PCAP parsing
[ ] Flow reconstruction
[ ] Beaconing detection
[ ] DGA / DNS tunnel detection
[ ] JA3/JA3S fingerprinting
[ ] IOC correlation (M1)
[ ] Export generation
```

**3.3 — Alert Summary Banner**
Barre récapitulative post-analyse :
```
[ CRITICAL: 3 ]  [ HIGH: 7 ]  [ MEDIUM: 12 ]  [ LOW: 5 ]  [ INFO: 2 ]
```
Chaque badge est cliquable et filtre la table ci-dessous.

**3.4 — Distribution des types d'alertes (graphique)**
Donut chart (Recharts) avec les 10 `AlertType` :
`beaconing`, `dns_tunnel`, `dga`, `http_c2`, `tls_suspect`, `irc_c2`, `port_scan`, `ioc_match`, `large_upload`, `custom_protocol`
Légende interactive : clic sur un type filtre la table.

**3.5 — Timeline des alertes**
Graphique linéaire (Recharts `AreaChart`) montrant la distribution temporelle des alertes sur l'intervalle `first_seen` → `last_seen`. Coloré par sévérité.

**3.6 — Table des alertes C2**
DataTable avec :
- Colonnes : ID | Type | Severity | Score | Src IP | Dst IP | Protocol | First Seen | Evidence count | Actions
- Badge de sévérité coloré + pulse sur CRITICAL
- Ligne expandable → détail de l'alerte (evidence list, ioc_matches, metadata JSON viewer)
- Filtre multi-select par type et sévérité
- Tri par score (desc par défaut)

**3.7 — Top IPs Suspectes**
Liste des `top_suspicious_ips` avec pour chaque IP :
- Score de risque estimé
- Nombre d'alertes associées
- Bouton "Search IOC" qui pré-remplit la recherche M1

**3.8 — Graphe de réseau (D3.js force-directed)**
Visualisation des flux réseau sous forme de graphe :
- Nœuds = IPs (taille proportionnelle au nombre d'alertes)
- Arêtes = flux détectés (épaisseur = score de risque)
- Couleur des nœuds = sévérité max associée
- Interactif : zoom, pan, clic sur un nœud pour voir ses alertes

**3.9 — Panel d'export**
`JSON` | `CSV SIEM` | `STIX 2.1`

**3.10 — Slot Phase 2 IA (M2-IA)**
Section collapsed, badge purple :
- Placeholder Random Forest + LSTM sur `NetworkFeature` (36 champs)
- Affichage simulé : "ML Confidence Score", "Model: RandomForest v2.1 (not loaded)"
- Boutons disabled

---

## PAGE 4 — M3 : YARA GENERATOR (/m3)

### Objectif
Soumettre un corpus malware + bénin, visualiser les règles YARA générées, valider et exporter.

### Composants

**4.1 — Zone de soumission double corpus**
Deux zones drag & drop côte à côte :
- Zone gauche : "Malware samples" (fond rouge subtil)
- Zone droite : "Benign samples" (fond vert subtil)
- Chacune accepte plusieurs fichiers (multi-upload)
- Compteur de fichiers déposés sur chaque zone
- Appel : `POST /api/m3/api/v1/generate`

**4.2 — Options de génération**
Panel d'options configurable :
- Seuil score discriminant (slider 0.0 → 1.0, défaut 0.30)
- Longueur min token (input number, défaut 6)
- Nombre max de strings par règle (défaut 20)
- Nom de la règle (text input)
- Auteur, TLP level (select)

**4.3 — Progression job** (stages M3-spécifiques)
```
[ ] Corpus validation
[ ] Token extraction (malware)
[ ] Token extraction (benign)
[ ] TF-IDF scoring (Δi = μmalware - maxbenign)
[ ] Rule assembly
[ ] yara.compile() validation
[ ] Export generation
```

**4.4 — Résultats : Règles YARA générées**
Pour chaque règle générée :
- Nom de la règle + metadata (auteur, date, TLP, hash corpus)
- Badge "✓ COMPILED" (vert) ou "✗ COMPILE ERROR" (rouge)
- Score discriminant moyen
- Nombre de strings
- **Viewer syntaxique** : affichage de la règle YARA avec coloration syntaxique (JetBrains Mono, thème cybersecurity dark)
- Bouton "Copy rule" | "Download .yar"

**4.5 — Distribution des scores TF-IDF**
Histogramme (Recharts) montrant la distribution des scores discriminants Δi pour les tokens retenus. Ligne verticale sur le seuil configuré.

**4.6 — Panel d'export**
`JSON (YaraRuleSet)` | `Bundle .yar` (toutes les règles en un fichier) | `CSV metadata`

---

## PAGE 5 — M4 : APT MAPPER (/m4)

### Objectif
Soumettre un AlertBundle M2, visualiser les clusters de campagnes, explorer la cartographie MITRE ATT&CK.

### Composants

**5.1 — Zone de soumission**
- Champ "AlertBundle (M2)" : upload JSON ou paste bundle_id si job M2 existant
- Champ optionnel "IOCBundle (M1)" : upload JSON
- Champ optionnel "YaraRuleSet (M3)" : upload JSON
- Appel : `POST /api/m4/api/v1/analyze`

**5.2 — Progression job** (stages M4-spécifiques)
```
[ ] AlertBundle parsing
[ ] TTP extraction (MITRE mapping)
[ ] TF-IDF vectorization
[ ] DBSCAN clustering
[ ] Campaign profiling
[ ] ATT&CK mapping
[ ] Export generation
```

**5.3 — Campaign Cluster Overview**
Grille de cartes, une par cluster (`CampaignCluster`) :
- Cluster ID + label (ou "Noise" si label = -1)
- Score de confiance : jauge arc animée (gauge chart)
- Dominant techniques (top 5, badges)
- Dominant tactics (badges colorés par tactic ATT&CK)
- Nombre d'IPs impliquées
- Tags YARA associés (si M3 connecté)
- Timeline first_seen → last_seen

**5.4 — MITRE ATT&CK Heatmap**
Représentation de la matrice MITRE ATT&CK Enterprise sous forme de heatmap :
- Colonnes = tactiques (14 tactiques ATT&CK)
- Lignes = techniques
- Cellule colorée si la technique est couverte dans le rapport (intensité = fréquence)
- Tooltip au survol : liste des clusters concernés, nombre d'occurrences
- Clic sur une cellule : filtre les clusters qui utilisent cette technique

Cette visualisation est construite en **D3.js** sur une grille SVG. C'est la visualisation phare de la page M4 — elle doit être esthétiquement soignée.

**5.5 — Graphe de clusters (D3.js force-directed)**
Visualisation des relations entre clusters :
- Nœuds = clusters (taille proportionnelle au nombre de membres)
- Arêtes = techniques partagées entre clusters (épaisseur = nb techniques communes)
- Couleur des nœuds = tactique dominante

**5.6 — Table des TTPs**
DataTable de tous les `TTPProfile` extraits :
- Colonnes : Alert ID | Alert Type | Techniques | Tactics | Confidence | IPs | YARA Tags
- Filtre par tactic et technique

**5.7 — Panel d'export**
`JSON (APTMapReport)` | `CSV SIEM` | `STIX 2.1`

---

## PAGE 6 — M5 : ATTRIBUTION (/m5)

### Objectif
Soumettre un APTMapReport M4, visualiser le top-k d'acteurs APT candidats avec scores de confiance.

### Composants

**6.1 — Zone de soumission**
- Champ "APTMapReport (M4)" : upload JSON ou paste report_id si job M4 existant
- Champs optionnels : IOCBundle (M1), AlertBundle (M2)
- Options : top-k (slider 1–10, défaut 3)
- Appel : `POST /api/m5/api/v1/analyze`

**6.2 — Progression job** (stages M5-spécifiques)
```
[ ] APTMapReport parsing
[ ] Feature extraction (multi-source)
[ ] TF-IDF embedding (cosine)
[ ] XGBoost classification
[ ] Top-k ranking
[ ] Export generation
```

**6.3 — Top Global Candidate Banner**
Si `top_global_candidate` existe : bannière pleine largeur avec :
- Nom du groupe APT (`apt_name`) en gros + `apt_id`
- Score de confiance global (grand gauge arc animé)
- XGBoost probability (barre)
- Cosine similarity (barre)
- Lien externe vers `mitre_group_url`
- Evidence summary (texte)

**6.4 — Attribution Results par cluster**
Accordéon : un item par `AttributionResult` (un par cluster M4).
En-tête : Cluster ID | Label | Nb candidats | Top candidate name | Top score
Expandé :
- Liste des candidats APT (`APTCandidate`) sous forme de tableau classé :
  - Rang | Nom APT | ID | Score confiance | XGB prob | Cosine | Techniques matchées | Tactics matchées
  - Bouton vers MITRE ATT&CK Groups pour chaque APT

**6.5 — Radar Chart de comparaison APT**
Pour les top-3 candidats du cluster sélectionné : radar chart (Recharts `RadarChart`) sur 6 dimensions :
- Score global, XGB probability, Cosine similarity, Techniques matched %, Tactics matched %, YARA tags matched %

**6.6 — Knowledge Base APT Overview**
Panel collapsible affichant les 10 groupes APT de la knowledge base embarquée avec leurs tactiques principales et techniques signatures.

**6.7 — Slot Phase 2 IA avancée**
Section avec badge purple réservée pour :
- Modèle XGBoost réel (remplaçant le synthétique)
- Embedding n-grams d'opcodes + graphes d'appels
- Confidence intervals (Monte Carlo)

**6.8 — Panel d'export**
`JSON (AttributionReport)` | `CSV SIEM` | `STIX 2.1`

---

## PAGE 7 — PIPELINE COMPLET (/pipeline)

### Objectif
Lancer une analyse de bout en bout M1 → M2 → (M3 optionnel) → M4 → M5 en une seule opération.

### Composants

**7.1 — Wizard de soumission (3 étapes)**

Étape 1 — Fichier cible :
- Upload du fichier à analyser (PE/ELF/texte pour M1)

Étape 2 — PCAP réseau :
- Upload du PCAP pour M2
- Option : lier automatiquement la sortie M1 → M2 (bundle_id auto-propagé)

Étape 3 — Options avancées :
- Activer M3 (toggle) : si activé, upload corpus malware/bénin pour YARA
- Top-k attribution (M5) : slider
- Bouton "Launch Full Pipeline"

**7.2 — Pipeline Progress Board**
Vue temps réel de la progression de toute la chaîne :
```
M1 [████████████] ✓ Completed — 47 IOCs extracted
  ↓ (bundle_id: abc123 propagated)
M2 [████████░░░░] ⟳ Running  — Stage 4/6: JA3 fingerprinting
  ↓ (waiting for M2...)
M4 [            ] ○ Waiting
  ↓
M5 [            ] ○ Waiting
```
Chaque module affiche son stage courant, le temps écoulé, et les métriques intermédiaires dès qu'elles sont disponibles.

**7.3 — Summary Report final**
Quand le pipeline complet est terminé : vue consolidée avec KPIs de chaque module, liens vers les pages individuelles pour le détail, et bouton "Export Full Bundle (ZIP)" qui télécharge tous les exports STIX/JSON.

---

## PAGE 8 — JOBS HISTORY (/jobs)

### Objectif
Historique de tous les jobs lancés, toutes modules confondus, avec accès aux résultats.

### Composants

**8.1 — Table de tous les jobs**
DataTable avec :
- Colonnes : Job ID | Module | Status | Soumis le | Durée | Actions
- Filtre par module (M1–M5), par status (`pending`, `running`, `completed`, `failed`)
- Badge de status animé (spinner pour `running`, check pour `completed`, X pour `failed`)
- Bouton "View Result" → navigue vers la page du module avec le job pré-chargé
- Bouton "Delete" avec confirmation modale

**8.2 — Métriques globales**
Graphique (Recharts `BarChart`) : nombre de jobs par module et par jour (7 derniers jours).

---

## PAGE 9 — SETTINGS (/settings)

### Objectif
Configurer les URLs des microservices et tester la connectivité.

### Composants

**9.1 — Configuration des endpoints**
Pour chaque module (M1–M5) + Gateway :
- Champ texte : URL base (défaut : `http://localhost:8000`, etc.)
- Bouton "Test Connection" → appel `/health`, affiche ✓ ou ✗ avec le message d'erreur
- Badge de version affiché si connecté

**9.2 — Section Thème / Préférences**
- Toggle "Animations" (peut désactiver Framer Motion pour machines lentes)
- Toggle "Auto-refresh status" (30s polling actif/inactif)
- Polling interval (slider 5s–120s)

**9.3 — Section Phase 2 IA (placeholder)**
- Futur : URLs MLflow, endpoints modèles entraînés, seuils de confiance ML
- Affichage "Phase 2 — Not configured" avec description

---

## COMPOSANTS TRANSVERSAUX (réutilisables)

Ces composants sont utilisés sur plusieurs pages et doivent être développés une seule fois dans `src/components/shared/` :

### JobStatusBadge
Badge avec icône et couleur selon le status : `pending` (gris), `running` (bleu + spinner), `completed` (vert), `failed` (rouge).

### SeverityBadge
Badge couleur conforme au codage sévérité défini plus haut. Prop `severity: "critical"|"high"|"medium"|"low"|"info"`. CRITICAL affiche un subtle pulse animation.

### ScoreGauge
Gauge arc animé affichant un score 0–100. Couleur dégradée (vert → jaune → rouge selon valeur). Animation d'entrée : sweep de 0 jusqu'à la valeur en 600ms.

### FileDropZone
Zone drag & drop réutilisable. Props : `accept` (extensions), `label`, `multiple`, `onFiles`. Animation de survol avec bordure cyan pulsante.

### JobProgressSteps
Affichage step-by-step des stages d'un job. Props : `steps: Array<{label, status: "done"|"running"|"pending"|"error"}>`. Chaque step avec icône animée selon son état.

### MitreAttackBadge
Badge pour une technique MITRE ATT&CK (ex. `T1071.001`). Hover → tooltip avec nom complet de la technique et lien ATT&CK.

### IpRiskBadge
Badge pour une adresse IP avec score de risque coloré. Hover → tooltip avec nombre d'alertes associées.

### DataTable
DataTable générique réutilisable. Props : `columns`, `data`, `pageSize`, `searchable`, `filterable`. Pagination, tri, recherche intégrés.

### JsonViewer
Viewer JSON collapsible avec coloration syntaxique. Props : `data: object`, `initialDepth`. Utilisé partout où des données brutes JSON sont affichées.

### ExportPanel
Panel de boutons d'export. Props : `formats: Array<{label, url, icon}>`. Gère l'état de chargement de chaque téléchargement.

### AIPhaseSlot
Placeholder réutilisable pour les fonctionnalités Phase 2 IA. Props : `title`, `description`, `mockFeatures`. Affiche un cadre avec bordure purple, badge "AI Phase 2", description, et éléments d'UI disabled.

---

## GESTION D'ÉTAT (ZUSTAND)

Structure du store global (`src/store/index.ts`) :

```typescript
interface AdmapStore {
  // Statut des modules
  moduleStatus: Record<"m1"|"m2"|"m3"|"m4"|"m5", ModuleHealth>

  // Jobs actifs (toutes pages)
  activeJobs: Record<string, JobState>

  // Résultats en cache (par job_id)
  jobResults: Record<string, unknown>

  // Préférences UI
  settings: {
    moduleUrls: Record<string, string>
    animationsEnabled: boolean
    autoRefresh: boolean
    pollInterval: number
  }

  // Actions
  updateModuleStatus: (module: string, health: ModuleHealth) => void
  upsertJob: (job: JobState) => void
  setJobResult: (jobId: string, result: unknown) => void
  updateSettings: (partial: Partial<Settings>) => void
}
```

---

## ADAPTABILITÉ PHASE 2 IA — RÈGLES DE CONCEPTION

Le dashboard **doit être conçu dès maintenant** pour absorber les fonctionnalités IA Phase 2 sans refonte majeure. Les règles suivantes sont **obligatoires** :

1. **Chaque page de module contient un `<AIPhaseSlot>`** avec les features IA prévues pour ce module (cf. descriptions dans chaque page).

2. **La palette `--accent-purple`** est réservée exclusivement aux éléments IA/ML. Aucun élément heuristique Phase 1 ne doit l'utiliser.

3. **Le store Zustand inclut `aiModels: Record<string, AIModelStatus>`** même vide pour la Phase 1. Prêt à être peuplé quand les modèles ML seront disponibles.

4. **Les composants `ScoreGauge` et `SeverityBadge` acceptent une prop `aiEnhanced?: boolean`** qui affiche un indicateur purple "AI" quand le score est issu d'un modèle ML (vs heuristique).

5. **La page Pipeline contient une étape "AI Enhancement" disabled** dans le wizard, avec toggle "Enable AI models (Phase 2)" inactif et tooltip explicatif.

6. **La Settings page contient une section "AI / ML Configuration" collapsed** avec les placeholders pour MLflow URL, model endpoints, confidence thresholds.

---

## GESTION DES ERREURS — COMPORTEMENT OBLIGATOIRE

- **Module offline** : toutes les zones de soumission du module concerné affichent un banner d'avertissement non-bloquant "Module M2 is currently offline — analysis unavailable".
- **Job failed** : affichage du message d'erreur JSON retourné par le microservice dans un `JsonViewer` collapsible. Bouton "Retry" qui relance le même job.
- **Timeout réseau** : toast notification ("Connection timeout — retrying in 5s") avec retry automatique 3 fois puis message d'erreur permanent.
- **Validation fichier** : validation côté frontend avant upload — vérification extension + taille max. Message d'erreur inline immédiat sous la DropZone.
- **Toutes les erreurs** s'affichent via un système de **toast notifications** (top-right, durée 5s, dismissable) — ne jamais utiliser `alert()` ou redirections page.

---

## ANIMATIONS — SPÉCIFICATIONS FRAMER MOTION

Chaque animation a une spécification précise. Ne pas improviser :

```
Page enter          : fadeInUp — y: 20→0, opacity: 0→1, duration: 0.3s
Card hover          : scale: 1→1.02, duration: 0.2s
Badge pulse (CRIT.) : opacity: 1→0.5→1, repeat: infinity, duration: 1.5s
Job progress bar    : width: 0%→n%, duration: 0.5s ease-out
Score gauge sweep   : custom SVG arc animation 0→value, duration: 0.6s
Pipeline node active: border glow pulse, duration: 2s repeat
Sidebar item hover  : x: 0→4, duration: 0.15s
Toast entry         : x: 100%→0, opacity: 0→1, duration: 0.25s
D3 nodes entry      : r: 0→final, opacity: 0→1, staggered 50ms
```

---

## STRUCTURE DU PROJET REACT

```
admap-dashboard/
├── public/
│   └── admap-logo.svg
├── src/
│   ├── main.tsx
│   ├── App.tsx                    # Router setup
│   ├── store/
│   │   └── index.ts               # Zustand store
│   ├── api/
│   │   ├── client.ts              # Axios instance configurée
│   │   ├── gateway.ts             # appels /api/status, /api/pipeline/full
│   │   ├── m1.ts                  # appels proxy M1
│   │   ├── m2.ts
│   │   ├── m3.ts
│   │   ├── m4.ts
│   │   ├── m5.ts
│   │   └── ws.ts                  # WebSocket helper pour jobs polling
│   ├── components/
│   │   ├── layout/
│   │   │   ├── Sidebar.tsx
│   │   │   ├── TopBar.tsx
│   │   │   └── Layout.tsx
│   │   └── shared/
│   │       ├── JobStatusBadge.tsx
│   │       ├── SeverityBadge.tsx
│   │       ├── ScoreGauge.tsx
│   │       ├── FileDropZone.tsx
│   │       ├── JobProgressSteps.tsx
│   │       ├── MitreAttackBadge.tsx
│   │       ├── IpRiskBadge.tsx
│   │       ├── DataTable.tsx
│   │       ├── JsonViewer.tsx
│   │       ├── ExportPanel.tsx
│   │       ├── AIPhaseSlot.tsx
│   │       └── ToastProvider.tsx
│   ├── pages/
│   │   ├── Overview.tsx           # Page 1
│   │   ├── M1Page.tsx             # Page 2
│   │   ├── M2Page.tsx             # Page 3
│   │   ├── M3Page.tsx             # Page 4
│   │   ├── M4Page.tsx             # Page 5
│   │   ├── M5Page.tsx             # Page 6
│   │   ├── PipelinePage.tsx       # Page 7
│   │   ├── JobsPage.tsx           # Page 8
│   │   └── SettingsPage.tsx       # Page 9
│   ├── hooks/
│   │   ├── useModuleHealth.ts     # polling /health toutes les 30s
│   │   ├── useJobPolling.ts       # WebSocket / SSE polling d'un job
│   │   └── useExport.ts           # gestion téléchargements export
│   └── types/
│       ├── m1.ts                  # types TS calqués sur les modèles Pydantic M1
│       ├── m2.ts                  # C2Alert, AlertBundle, AlertType, AlertSeverity
│       ├── m3.ts                  # YaraRuleSet
│       ├── m4.ts                  # APTMapReport, CampaignCluster, ClusterBundle
│       ├── m5.ts                  # AttributionReport, APTCandidate
│       └── common.ts              # JobState, ModuleHealth, etc.
├── tailwind.config.ts
├── vite.config.ts
├── tsconfig.json
└── package.json
```

---

## TYPES TYPESCRIPT OBLIGATOIRES

Les types doivent être **fidèles aux modèles Pydantic v2 des microservices**. Exemples clés :

```typescript
// common.ts
export type JobStatus = "pending" | "running" | "completed" | "failed" | "cancelled";
export type AlertSeverity = "critical" | "high" | "medium" | "low" | "info";
export type AlertType = "beaconing" | "dns_tunnel" | "dga" | "http_c2" | "tls_suspect" |
                        "irc_c2" | "port_scan" | "ioc_match" | "large_upload" | "custom_protocol";

export interface JobState {
  job_id: string;
  status: JobStatus;
  module: "m1" | "m2" | "m3" | "m4" | "m5";
  created_at: string;
  completed_at?: string;
  error?: string;
}

export interface ModuleHealth {
  status: "ok" | "error" | "unknown";
  version?: string;
  queue_size?: number;
  last_checked: number; // timestamp ms
}

// m2.ts (exemple)
export interface C2Alert {
  alert_type: AlertType;
  severity: AlertSeverity;
  confidence_score: number;
  src_ip: string;
  dst_ip: string;
  src_port: number;
  dst_port: number;
  protocol: string;
  first_seen: string;
  last_seen: string;
  evidence: string[];
  ioc_matches: string[];
  metadata: Record<string, unknown>;
}

export interface AlertBundle {
  bundle_id: string;
  pcap_filename: string;
  pcap_sha256: string;
  alerts: C2Alert[];
  alerts_by_type: Record<AlertType, number>;
  alerts_by_severity: Record<AlertSeverity, number>;
  top_suspicious_ips: string[];
  m1_bundle_id?: string;
  ioc_hits: number;
}
```

Définir les équivalents complets pour M1, M3, M4, M5 en suivant exactement les contrats documentés.

---

## BFF — GATEWAY FASTAPI (admap_gateway)

Le BFF est un microservice Python FastAPI minimal. Règles d'implémentation :

1. **Aucune logique métier** — proxy pur + agrégation statuts + orchestration pipeline
2. **Conformes aux invariants ADMAP** : structlog JSON, pydantic-settings + `@lru_cache`, `asyncio`, pas de `print()`
3. **`httpx.AsyncClient`** pour les appels vers les microservices (pas `requests`)
4. **Timeout** configuré sur tous les appels sortants (défaut : 30s, 300s pour pipeline complet)
5. **CORS** configuré pour autoriser `http://localhost:3000` (et domaine de production si défini)

Endpoint `/api/pipeline/full` — logique d'orchestration :
```
1. Upload fichier → POST /api/m1/api/v1/analyze → poll jusqu'à completed → récupère IOCBundle
2. Upload PCAP + bundle_id M1 → POST /api/m2/api/v1/analyze → poll → récupère AlertBundle
3. (optionnel) Upload corpus → POST /api/m3/api/v1/generate → poll → récupère YaraRuleSet
4. AlertBundle + [IOCBundle] + [YaraRuleSet] → POST /api/m4/api/v1/analyze → poll → récupère APTMapReport
5. APTMapReport + [IOCBundle] + [AlertBundle] → POST /api/m5/api/v1/analyze → poll → récupère AttributionReport
6. Retourne un PipelineResult {m1_job_id, m2_job_id, m3_job_id, m4_job_id, m5_job_id, completed_at}
```

WebSocket `/ws/jobs/{job_id}` :
- Reçoit un `module` query param (`m1`–`m5`)
- Proxie le polling `GET /api/{module}/api/v1/jobs/{job_id}` toutes les 1s
- Push l'état au client WebSocket jusqu'à `completed` ou `failed`
- Ferme la connexion proprement à la fin

---

## CHECKLIST FINALE DE VALIDATION

Avant de livrer le dashboard, vérifier chaque point :

- [ ] Les 5 pages de modules (M1–M5) sont fonctionnelles avec upload, progression, résultats et export
- [ ] La page Overview affiche correctement les statuts de santé de tous les modules
- [ ] La page Pipeline orchestre la chaîne complète M1→M2→M4→M5
- [ ] Les WebSockets fonctionnent et la progression est temps réel
- [ ] Le codage sévérité est cohérent sur toutes les pages (même couleurs pour CRITICAL/HIGH/MEDIUM/LOW/INFO partout)
- [ ] Les visualisations D3.js (graphe réseau M2, heatmap MITRE M4, force-directed M4) sont interactives
- [ ] Toutes les animations Framer Motion respectent les spécifications de durée et easing
- [ ] Les composants `AIPhaseSlot` sont présents sur chaque page de module (M1, M2, M4, M5) et sur la page Pipeline
- [ ] La palette `--accent-purple` n'est utilisée que pour les éléments IA Phase 2
- [ ] Les types TypeScript sont complets et correspondent exactement aux contrats des microservices
- [ ] Le BFF Gateway est fonctionnel et proxie correctement vers les 5 microservices
- [ ] La Settings page permet de configurer les URLs et de tester la connectivité
- [ ] L'application est responsive (sidebar se collapse sur mobile, pas de scroll horizontal)
- [ ] Aucun `console.log` en production — logging structuré via une fonction utilitaire
- [ ] Les erreurs de réseau et les modules offline sont gérés visuellement sans crash
- [ ] Tous les téléchargements d'export fonctionnent (JSON, CSV, STIX, ZIP pipeline)