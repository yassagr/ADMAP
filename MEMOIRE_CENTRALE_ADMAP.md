# MÉMOIRE CENTRALE — PROJET ADMAP
## Document de contexte global pour sessions Claude

> **Destinataire de ce document : Claude (toi-même).**
> Ce fichier n'est PAS un livrable académique. C'est un fichier d'orientation technique
> à charger en début de toute nouvelle session liée au projet ADMAP, pour retrouver
> instantanément : qui fait quoi, quel module en est où, quels contrats d'interface
> existent déjà, quelles règles architecturales sont non négociables, et quel est le
> workflow de travail attendu avec Yasser.
>
> **Statut de ce document** : vivant. Il doit être mis à jour à chaque fin de cycle
> de correction de module (M1, M2, M3...) pour refléter l'état réel du code, PAS
> l'état "idéal" décrit dans un rapport académique.

---

## 0. MÉTA — Comment utiliser ce document

1. **Lire en entier avant toute action sur le projet.** Ne pas se contenter de
   scanner les titres : les sous-sections "Pièges connus" et "Contrats d'interface"
   contiennent des informations critiques qui ne sont nulle part ailleurs.
2. **Ne jamais supposer que l'état décrit dans un rapport académique (.tex, PFE,
   soutenance) reflète l'état réel du code.** Les rapports décrivent une vision
   cible / une narration pour le jury. Ce document décrit la réalité du code tel
   qu'il existe dans les sessions de correction. En cas de conflit entre un
   rapport `.tex` fourni et ce document → **ce document est la source de vérité
   sur l'état du code**, le rapport `.tex` est une source d'idées/pratiques/
   vocabulaire à réutiliser, pas une spécification figée.
3. **Toute nouvelle session sur M3, M4 ou M5 doit d'abord lire les sections
   "Contrats exposés par M1" et "Contrats exposés par M2"** avant de concevoir
   quoi que ce soit, car ces modules doivent consommer ces contrats.
4. **Le format de sortie attendu par Yasser pour les corrections de code est
   strictement défini en section 6.** Ne pas dévier de ce format même si la
   demande semble simple.

---

## 1. IDENTITÉ DU PROJET

**Nom** : ADMAP — Advanced Detection & Malware Analysis Platform

**Cadre académique** : Projet de Fin d'Année (PFA), 4ème année Ingénierie
Informatique et Réseaux, filière 4CIRA, EMSI (École Marocaine des Sciences de
l'Ingénieur), groupe G3-A3, année universitaire 2025-2026.

**Réalisateurs** : Yasser Aguezzar (interlocuteur principal de Claude) et Mourad
Modakir. Encadrant académique : Pr. M. Afouaar.

**Pitch en une phrase** : Une plateforme SOC/CERT industrielle, composée de
microservices Python indépendants, qui automatise les tâches CTI chronophages
(extraction d'IOC, détection C2, génération YARA, cartographie APT, attribution)
en hybridant heuristiques cyber éprouvées et modèles IA, avec une discipline
d'ingénierie logicielle stricte (zéro interactivité terminal, typage complet,
exposition REST systématique, observabilité JSON).

**Vision narrative à 5 modules (issue du rapport académique, à garder en tête
comme cadre de référence conceptuel, mais sans s'y enchaîner mécaniquement
pour les détails d'implémentation)** :

| Module | Nom complet | Rôle fonctionnel | Stack ML/heuristique cible |
|---|---|---|---|
| **M1** | IOC Extractor | Parse PE/ELF/texte → extrait IOCs (IP, hash, domaine, URL, mutex, registre...) → exporte STIX 2.1, OpenIOC, MISP JSON, CSV Cytomic Orion → enrichissement VirusTotal | Phase 1 : heuristiques pures. Phase 2 (M1-IA) : NER spaCy/DistilBERT sur texte libre CTI |
| **M2** | C2 Detector | Analyse PCAP → détecte beaconing, DNS tunneling/DGA, fingerprinting JA3/JA3S → mapping MITRE ATT&CK | Phase 1 : heuristiques statistiques (jitter, entropie de Shannon). Phase 2 (M2-IA) : Random Forest + LSTM sur `NetworkFeature` (36 champs) |
| **M3** | YARA Signature Generator | Génère règles YARA compilables depuis corpus malware/bénin | Moteur TF-IDF discriminant ($\Delta_i = \mu_{malware,i} - \max_{bénin,i}$), validation `yara.compile()` |
| **M4** | APT Mapper / Clustering | Extrait TTPs → mapping MITRE ATT&CK → clustering non supervisé des campagnes | DBSCAN/HDBSCAN sur vecteurs TF-IDF de TTPs |
| **M5** | Attribution | Propose top-3 acteurs APT probables avec score de confiance | XGBoost + similarité cosinus sur embeddings (n-grams d'opcodes, graphes d'appel, SSDeep) |

> **Note de cadrage importante** : le rapport académique présente une architecture
> à hub central unique (une seule API FastAPI orchestrant les 5 modules, dashboard
> Streamlit, PostgreSQL + Elasticsearch + MLflow). Le travail réel mené avec Claude
> jusqu'ici a porté sur des **microservices Python indépendants** (M1, M2...), chacun
> exposant son propre FastAPI avec `/health` et `/ready`. Les deux visions ne sont
> **pas contradictoires** : les microservices décrits ici sont les briques que le hub
> central (couche Présentation/Orchestration du rapport) viendra fédérer plus tard.
> Tant que ce hub n'est pas explicitement mis en chantier, **chaque module reste un
> microservice FastAPI autonome**, conforme aux invariants de la section 2.

---

## 2. INVARIANTS ARCHITECTURAUX TRANSVERSAUX (NON NÉGOCIABLES)

Ces règles s'appliquent à **TOUS** les modules (M1 à M5), sans exception. Toute
correction de code, tout nouveau fichier généré par l'agent d'exécution doit
les respecter. Une violation de l'une de ces règles = défaut critique.

1. **Zéro interactivité terminal** : aucun `input()`, aucun menu interactif.
   CLI exclusivement via **Click**.
2. **100% OOP Python 3.11+** programmatique, avec **typing complet** (type hints
   partout — paramètres, retours, attributs de classe).
3. **Zéro IA/ML dans M1 à M4** : ces modules reposent uniquement sur des
   heuristiques et règles expertes. L'IA/ML (Phase 2 / M1-IA, M2-IA, M4 clustering,
   M5) est **strictement cantonnée à des modules/phases dédiés**, jamais mélangée
   dans le cœur heuristique de M1-M4.
4. **Security-by-design** : tout fichier reçu par la plateforme est traité comme
   **potentiellement malveillant** (lecture en mode binaire prudent, pas
   d'exécution, validation stricte avant tout traitement).
5. **Exposition FastAPI systématique** : chaque module est un microservice REST
   FastAPI.
6. **Endpoints obligatoires sur chaque module** : `GET /health` et `GET /ready`.
   - `/health` : liveness simple (le process répond).
   - `/ready` : readiness — vérifie que les dépendances internes (queue, settings,
     ressources chargées) sont opérationnelles.
7. **Logging structuré** : `structlog` en JSON, remplaçant **tout** `print()`.
   - Les **logs** (diagnostics, erreurs, traces) vont sur **stderr**.
   - Les **sorties JSON applicatives** (résultats, rapports) vont sur **stdout**.
8. **Validation Pydantic v2** pour absolument tous les modèles de données
   (entrées API, configurations, structures internes échangées entre composants).
9. **Files d'attente asynchrones** : toute job queue est basée sur `asyncio`,
   initialisée dans le **lifespan FastAPI**, et stockée dans `app.state`
   (pas de variable globale module-level pour l'état mutable).
10. **Configuration via `pydantic-settings`**, avec `@lru_cache` sur les
    fonctions `get_settings()` pour éviter les ré-instanciations répétées.

### Pièges connus / erreurs récurrentes à vérifier systématiquement

- **`detector_name`** : chaque classe de type "détecteur" (dans M2 notamment)
  doit exposer une propriété `detector_name` correctement implémentée
  (souvent en tant que `@property`, retournant une string non vide, cohérente
  avec le nom de la classe). C'est le défaut **le plus récurrent** rencontré
  dans les cycles de correction M2 V1 et V2. Toute correction de module
  contenant des "détecteurs" doit inclure une commande `grep` de vérification
  explicite de cette propriété sur toutes les classes concernées.
- **`asyncio.get_event_loop()` vs `asyncio.get_running_loop()`** : utiliser
  systématiquement `get_running_loop()` dans le code asynchrone moderne ;
  `get_event_loop()` est déprécié et source de bugs subtils.
- **Scores codés en dur ("hardcoded")** dans les classes de corrélation
  (ex. `IOCCorrelator`) : tout score de confiance/corrélation doit être
  calculé dynamiquement à partir de données réelles (configuration, contexte),
  jamais une constante en dur dans le code métier.
- **Gestion d'erreur des exporteurs** : un exporteur (ex. `STIXExporter`) ne
  doit **jamais** lever une `RuntimeError` brute en cas d'échec d'export. Il
  doit retourner un **JSON d'erreur structuré** cohérent avec le reste de
  l'API (codes d'erreur, message, contexte), pour que l'appelant (API, autre
  module, dashboard) puisse traiter l'échec proprement.
- **Signatures de constructeurs incompatibles avec les fixtures de test** :
  toute modification de la signature `__init__` d'une classe pivot
  (ex. `AnalysisPipeline`) doit être vérifiée contre les fixtures pytest
  existantes. Une signature qui "semble plus propre" mais casse les tests
  existants est un défaut critique, pas une amélioration.

---

## 3. ÉTAT RÉEL D'AVANCEMENT (à mettre à jour à chaque session)

### M1 — IOC Extractor — ✅ TERMINÉ (v3.0.0)

- Origine : refactoring de `extracteur.py`, `main.py` et cinq exporteurs
  (~55 fichiers au total) vers une architecture microservice propre.
- Une analyse de conformité complète a été menée : **12 violations identifiées
  ont toutes été vérifiées comme corrigées**.
- M1 est considéré comme le **module de référence** : il sert de modèle
  d'architecture pour les modules suivants (structure de projet, conventions
  de nommage, organisation des dossiers, style de tests).

**Action recommandée pour toute nouvelle session** : si une question porte sur
"comment structurer un module conformément aux standards ADMAP", se référer en
priorité à la structure de M1 plutôt qu'au rapport académique.

### M2 — C2 Detector — ✅ TERMINÉ (v1.0.0)

- Rôle : analyse de fichiers PCAP pour détecter du trafic Command & Control,
  via `dpkt` et `scapy`. FastAPI sur le port **8001**.
- **Historique des cycles de correction** : 4 passes (V1 → V4).
  - V1 : 49 critiques + 76 mineurs. V2 : 38 critiques + 33 mineurs.
  - V3 : résolution complète de tous les défauts critiques et mineurs.
  - V4 (patch polish) : fix bug STIX IPv6 (`ipv6-addr` vs `ipv4-addr`),
    factorisation `_score_to_severity` dans `core/scoring.py` (DRY),
    restauration du logging GeoCorrelator.
- **Tous les tests passent. Couverture ≥ 80 %.**

**Action recommandée pour toute nouvelle session** : M2 est clos. Passer
directement à la section 4 pour lire les contrats exposés, puis démarrer M3.

### M3 — YARA Signature Generator — ✅ TERMINÉ (v1.0.0)

- Rôle : génère des règles YARA compilables depuis un corpus malware/bénin
  via un algorithme TF-IDF discriminant implémenté manuellement (zéro sklearn).
  FastAPI sur le port **8002**.
- **Historique des cycles de correction** : 2 passes (V1 → V2).
  - V1 : 6 critiques + 4 mineurs.
  - V2 : résolution complète — annotations `File(...)` multipart, Stage 4
    pipeline corrigé (append vs extend), scorer `int()` cohérent, coverage
    sans exclusions, lifespan tests propre, nettoyage des temporaires.
- **Tous les tests passent. Couverture ≥ 80 %.**
- **Nouveaux fichiers de test** : `test_api_export.py`, `test_pipeline_coverage.py`,
  `test_analyzer_coverage.py`, `test_cli.py`, `test_worker.py`.

**Action recommandée pour toute nouvelle session** : M3 est clos. Lire les
contrats exposés en section 4, puis démarrer la spécification de M4.

### M4 — APT Mapper / Clustering — ✅ TERMINÉ (v2.0.0)

- Rôle : reçoit des AlertBundle M2 (+ IOCBundle M1 et YaraRuleSet M3 en option),
  extrait les TTPs MITRE ATT&CK, les vectorise via TF-IDF manuel (zéro scikit-learn),
  les regroupe via DBSCAN manuel, et produit un APTMapReport avec mapping ATT&CK.
  FastAPI sur le port **8003**.
- Historique des cycles de correction : 2 passes (V1 → V2).
  - V1 : couverture 79%, code mort dans models/alert.py, branches de routes.py
    non testées, stix_exporter.py à 49%.
  - V2 : résolution complète — couverture 94%, 68 tests passent.
- Fichiers de test : test_ttp_extractor.py, test_tfidf_vectorizer.py,
  test_dbscan_clusterer.py, test_mitre_mapper.py, test_pipeline.py,
  test_exporters.py, test_api.py, test_api_extra.py, test_cli.py,
  test_worker.py, test_models.py.

### M5 — Attribution — ✅ TERMINÉ (v1.0.0)

- Rôle : reçoit un APTMapReport M4 (+ IOCBundle M1 et AlertBundle M2 en option),
  extrait des features multi-sources, les vectorise via TF-IDF manuel (zéro scikit-learn
  pour l'embedding), les compare à une knowledge base statique de 10 groupes APT via
  similarité cosinus, et classifie via XGBoost pré-entraîné (modèle .joblib synthétique
  embarqué). Produit un AttributionReport avec top-k candidats APT et scores de confiance.
  FastAPI sur le port 8004.
- Historique des cycles de correction : 3 passes (V1 → V3).
  - V1 : 49 critiques + 76 mineurs (génération initiale).
  - V2 : 7 critiques + 2 mineurs résolus ; 2 critiques + 4 mineurs résiduels.
  - V3 (patch final) : résolution complète — output.py utcnow, fixtures lifespan, 
    __init__.py, fix_tests.py, imports inutilisés.
- Tous les tests passent. Couverture >= 80%.
- Fichiers de test : test_apt_kb.py, test_embedder.py, test_feature_extractor.py,
  test_xgb_classifier.py, test_pipeline.py, test_exporters.py, test_api.py,
  test_api_extra.py, test_cli.py, test_worker.py, test_models.py.

---

## 4. CONTRATS D'INTERFACE EXPOSÉS PAR LES MODULES TERMINÉS

> Cette section est **LA plus importante pour M3/M4/M5**. Elle documente ce que
> les modules amont produisent et exposent, afin que les modules avals sachent
> exactement avec quelles structures de données ils doivent interagir.

### Contrats exposés par M1 (v3.0.0)

- M1 produit des **rapports d'IOC structurés** (modèles Pydantic v2) couvrant :
  adresses IPv4/IPv6 (filtrage RFC 1918), domaines, URLs, hashes
  MD5/SHA1/SHA256/SSDeep, IMPHASH, clés de registre Windows, mutex, commandes
  suspectes.
- M1 expose des **exports** vers STIX 2.1, OpenIOC XML, MISP JSON, CSV Cytomic
  Orion — ces formats de sortie sont la référence à respecter si M3/M4/M5
  doivent eux aussi produire des exports CTI compatibles.
- M1 expose `GET /health` et `GET /ready` conformément à l'invariant section 2.
- *(À compléter : si une session future extrait les noms exacts des classes
  Pydantic, des chemins d'endpoints REST, et des schémas JSON de M1, les
  ajouter ici verbatim — ce sont les "vrais" contrats que M3/M4/M5
  consommeront, pas une paraphrase du rapport académique.)*

### Contrats exposés par M2 (v1.0.0) — STABILISÉ

**Package** : `admap_m2` — port FastAPI : **8001**

**Modèles Pydantic v2 exportés (consommables par M3/M4/M5) :**
- `C2Alert` (`admap_m2.models.alert`) — frozen=True :
  champs clés : `alert_type` (enum `AlertType`), `severity` (enum
  `AlertSeverity`), `confidence_score` (int 0-100), `src_ip`, `dst_ip`,
  `src_port`, `dst_port`, `protocol`, `first_seen`, `last_seen`,
  `evidence` (list[str]), `ioc_matches` (list[str]), `metadata` (dict).
- `AlertBundle` (`admap_m2.models.alert`) — contrat de sortie principal :
  champs clés : `bundle_id`, `pcap_filename`, `pcap_sha256`, `alerts`
  (list[C2Alert]), `alerts_by_type` (dict), `alerts_by_severity` (dict),
  `top_suspicious_ips` (list[str]), `m1_bundle_id`, `ioc_hits`.
- `AlertType` (enum) : `beaconing`, `dns_tunnel`, `dga`, `http_c2`,
  `tls_suspect`, `irc_c2`, `port_scan`, `ioc_match`, `large_upload`,
  `custom_protocol`.
- `AlertSeverity` (enum) : `critical` (≥80), `high` (≥60), `medium` (≥40),
  `low` (≥20), `info` (<20).
- `NetworkFlow` (`admap_m2.models.flow`) : représente un flux réseau
  reconstruit depuis un PCAP — candidat d'entrée pour M4.

**Endpoints REST exposés :**
- `GET /health` → `{"status": "ok", "version": "1.0.0"}`
- `GET /ready` → `{"status", "version", "queue_size", "scapy_available", "m1_integration"}`
- `POST /api/v1/analyze` → 202 `{"job_id", "status", "status_url"}`
- `GET /api/v1/jobs/{job_id}` → `AnalysisJob`
- `GET /api/v1/jobs/{job_id}/result` → `AlertBundle`
- `DELETE /api/v1/jobs/{job_id}` → annulation
- `GET /api/v1/export/{job_id}/json|csv|stix|all`
- `GET /api/v1/analyze/capabilities`

**Classes pivots consommables par les modules aval :**
- `AnalysisPipeline(settings=None, options=None)` — pipeline asynchrone 6
  stages, retourne `AlertBundle`.
- `IOCCorrelator(settings, m1_bundle_path=None)` — corrèle flux PCAP avec
  IOCBundle M1 ; score M2 = `min(100, score_M1 × 0.9 + 10)`.
- `GeoCorrelator(settings)` — enrichissement géo (logging uniquement,
  retourne toujours `[]`).
- `C2Scorer.aggregate_alerts(alerts)` — fusionne alertes par endpoint avec
  décroissance logarithmique : `s1 + s2×0.7 + s3×0.49 + ...` plafonné à 100.
- `score_to_severity(score)` (`admap_m2.core.scoring`) — mapping canonique
  partagé, importable directement par M3/M4/M5.

**Exports CTI produits par M2 :**
- JSON natif ADMAP (`AlertBundle.model_dump_json()`)
- CSV SIEM (colonnes : id, alert_type, severity, score, src_ip, dst_ip,
  src_port, dst_port, protocol, first_seen, description)
- STIX 2.1 (Indicators CRITICAL/HIGH uniquement ; patterns `ipv4-addr`,
  `ipv6-addr` ou `domain-name` selon `dst_ip` ; Identity "ADMAP Platform M2")

**Intégration M1→M2 :** M2 consomme un `IOCBundle` M1 (JSON) via
`m1_bundle_path`. Les IOCs (IP, domaine, URL) sont corrélés flux par flux
en Stage 5 du pipeline.

**Candidat d'entrée pour M4 :** `C2Alert.alert_type` + `C2Alert.metadata`
contiennent les TTPs détectés (beaconing, DGA, DNS tunnel...) — vectorisables
en TF-IDF pour le clustering DBSCAN de M4.


### Contrats exposés par M4 (v2.0.0) — STABILISÉ

**Package** : `admap_m4` — port FastAPI : **8003**

**Modèles Pydantic v2 exportés (consommables par M5) :**
- `CampaignCluster` (`admap_m4.models.cluster`) — frozen=True :
  champs clés : `cluster_id`, `cluster_label` (int, -1=bruit), `member_profile_ids`,
  `dominant_techniques` (list[str], top 5), `dominant_tactics` (list[str]),
  `confidence_score` (float 0-100, calculé dynamiquement), `involved_ips`,
  `yara_tags`, `first_seen`, `last_seen`, `metadata`.
- `ClusterBundle` (`admap_m4.models.cluster`) — frozen=True :
  champs clés : `bundle_id`, `source_bundle_id` (bundle_id de l'AlertBundle M2),
  `clusters` (list[CampaignCluster]), `noise_profile_ids`, `total_profiles`,
  `total_clusters`, `noise_count`, `created_at`.
- `APTMapReport` (`admap_m4.models.report`) — frozen=True :
  champs clés : `report_id`, `source_bundle_id`, `cluster_bundle` (ClusterBundle),
  `mitre_coverage` (dict[tactic, list[technique]]), `top_techniques` (list[tuple[str,int]]),
  `top_tactics`, `campaign_count`, `noise_count`, `analysis_duration_seconds`,
  `options_used` (AnalysisOptions), `created_at`, `version="1.0.0"`.
- `TTPProfile` (`admap_m4.models.ttp`) — frozen=True :
  représente un TTP extrait d'une C2Alert — candidat d'entrée pour M5.
  Champs clés : `alert_id`, `alert_type`, `techniques` (list MITRE), `tactics`,
  `confidence_score`, `src_ip`, `dst_ip`, `timestamp`, `yara_tags`.

**Endpoints REST exposés :**
- `GET /health` → `{"status": "ok", "version": "1.0.0", "module": "M4-APTMapper"}`
- `GET /ready` → `{"status", "version", "queue_size", "m2_integration", "m3_integration"}`
- `POST /api/v1/analyze` → 202 `{"job_id", "status", "status_url"}`
  Body: multipart — `alert_bundle` (obligatoire), `ioc_bundle` (opt), `yara_ruleset` (opt), `options` (opt JSON)
- `GET /api/v1/jobs/{job_id}` → AnalysisJob
- `GET /api/v1/jobs/{job_id}/result` → APTMapReport
- `DELETE /api/v1/jobs/{job_id}` → annulation
- `GET /api/v1/export/{job_id}/json|csv|stix|all`
- `GET /api/v1/capabilities`

**Classes pivots consommables par M5 :**
- `AnalysisPipeline(settings=None, options=None)` — pipeline asynchrone 6 stages,
  retourne `APTMapReport`.
- `ManualTFIDFVectorizer` — TF-IDF pur Python (formule : log((1+N)/(1+df))+1),
  méthode statique `cosine_similarity(v1, v2)` importable directement par M5.
- `ManualDBSCANClusterer` — DBSCAN pur Python sur distance cosinus.
- Score de cluster : `min(100, avg_confidence × 0.7 + cluster_density × 30)`.

**Mapping AlertType → TTPs MITRE (défini dans `admap_m4.core.ttp_extractor`) :**
- Tables `ALERT_TYPE_TO_TTPS` et `TECHNIQUE_TO_TACTIC` importables directement.
- 22 techniques couverts sur 7 tactiques ATT&CK.

**Exports CTI produits par M4 :**
- JSON natif ADMAP (`APTMapReport.model_dump(mode="json")`)
- CSV SIEM (colonnes : cluster_id, cluster_label, confidence_score, dominant_techniques,
  dominant_tactics, member_count, involved_ips, first_seen, last_seen)
- STIX 2.1 (IntrusionSet + AttackPattern + Relationship pour clusters confidence >= 40 ;
  Identity "ADMAP Platform M4")

**Intégration amont :**
- M2 → M4 : `AlertBundle` JSON via `alert_bundle_json` (obligatoire).
- M1 → M4 : `IOCBundle` JSON via `ioc_bundle_json` (optionnel, non utilisé dans le
  cœur du pipeline V2, réservé pour enrichissement futur).
- M3 → M4 : `YaraRuleSet` JSON via `yara_ruleset_json` (optionnel) ; les tags YARA
  sont propagés dans chaque `TTPProfile.yara_tags` puis agrégés dans `CampaignCluster.yara_tags`.

**Candidat d'entrée pour M5 :**
- `CampaignCluster.dominant_techniques` + `CampaignCluster.involved_ips` +
  `CampaignCluster.yara_tags` → features vectorisables pour l'attribution APT.
- `APTMapReport.mitre_coverage` → carte tactique complète exploitable par M5.


### Contrats exposés par M5 (v1.0.0) — STABILISÉ

**Package** : `admap_m5` — port FastAPI : **8004**

**Modèles Pydantic v2 exportés :**
- `APTCandidate` (`admap_m5.models.output`) — frozen=True :
  champs clés : `rank` (int), `apt_name`, `apt_id`, `confidence_score` (float 0-100,
  calculé dynamiquement), `xgb_probability` (float 0-1), `cosine_similarity` (float 0-1),
  `matched_techniques` (list[str]), `matched_tactics` (list[str]),
  `matched_yara_tags` (list[str]), `matched_ips` (list[str]),
  `evidence_summary` (str), `mitre_group_url` (str).
- `AttributionResult` (`admap_m5.models.output`) — frozen=True :
  champs clés : `cluster_id`, `cluster_label` (int), `candidates` (list[APTCandidate]),
  `feature_vector_size` (int), `analysis_method` (str).
- `AttributionReport` (`admap_m5.models.output`) — frozen=True — contrat de sortie principal :
  champs clés : `report_id`, `source_report_id` (report_id de l'APTMapReport M4),
  `results` (list[AttributionResult]), `top_global_candidate` (APTCandidate | None),
  `total_clusters_analyzed` (int), `noise_clusters_skipped` (int),
  `analysis_duration_seconds` (float), `options_used` (dict),
  `created_at` (datetime), `version="1.0.0"`, `module="M5-Attribution"`.

**Endpoints REST exposés :**
- `GET /health` → `{"status": "ok", "version": "1.0.0", "module": "M5-Attribution"}`
- `GET /ready` → `{"status", "version", "queue_size", "apt_kb_available", "xgb_model_available", "m4_integration"}`
- `POST /api/v1/analyze` → 202 `{"job_id", "status", "status_url"}` — multipart :
  `apt_map_report` (obligatoire), `ioc_bundle` (opt), `alert_bundle` (opt), `options` (opt JSON Form)
- `GET /api/v1/jobs/{job_id}` → AttributionJob
- `GET /api/v1/jobs/{job_id}/result` → AttributionReport
- `DELETE /api/v1/jobs/{job_id}` → annulation
- `GET /api/v1/export/{job_id}/json|csv|stix|all`
- `GET /api/v1/capabilities`

**Classes pivots :**
- `AttributionPipeline(settings=None, options=None)` — pipeline asynchrone 5 stages,
  retourne `AttributionReport`. Lazy init de KB et XGBoost.
- `CosineEmbedder` — TF-IDF pur Python, `cosine_similarity(v1, v2)` importable.
- `APTKnowledgeBase(kb_path)` — charge `data/apt_kb.json` (10 groupes APT).
- `XGBAttributor(model_path)` — fallback uniforme si modèle absent ou XGBoost non installé.
- `generate_synthetic_xgb_model(apt_groups, model_path)` — génère un modèle XGBoost
  synthétique au build Docker si aucun modèle réel n'existe.

**Exports CTI produits par M5 :**
- JSON natif ADMAP (`AttributionReport.model_dump(mode="json")`)
- CSV SIEM (colonnes : cluster_id, cluster_label, rank, apt_name, apt_id,
  confidence_score, xgb_probability, cosine_similarity, matched_techniques,
  matched_tactics, matched_yara_tags, evidence_summary, analysis_method, mitre_group_url)
- STIX 2.1 (ThreatActor + AttackPattern + Relationship pour candidats confidence >= 30.0 ;
  Identity "ADMAP Platform M5")

**Intégration amont :**
- M4 → M5 : `APTMapReport` JSON via `apt_map_report` (obligatoire).
- M1 → M5 : `IOCBundle` JSON via `ioc_bundle` (optionnel — enrichit les features
  avec sha256, ssdeep, imphash, strings).
- M2 → M5 : `AlertBundle` JSON via `alert_bundle` (optionnel — enrichit avec
  alert_types et suspicious_ips).

**Knowledge base APT embarquée :** 10 groupes (APT28, Lazarus Group, APT17, APT29,
APT41, APT32, Fancy Bear, Sandworm, APT1, Aqua Blizzard) dans `data/apt_kb.json`.


### Pour M3/M4/M5 — Points d'ancrage suggérés par le rapport académique

Ces éléments sont des **idées issues du rapport**, à valider/adapter au moment
de la spécification réelle de chaque module (pas une obligation) :

- **M3 (YARA)** : entrée = corpus malware/bénin (potentiellement enrichi par
  les hashes/strings extraits par M1) ; sortie = règles YARA + métadonnées
  (auteur, date, hash du corpus, niveau TLP) + statut de validation
  `yara.compile()`. Algorithme suggéré : score discriminant TF-IDF
  $\Delta_i = \mu_{malware,i} - \max_{bénin,i}$, avec filtres (score ≥ 0.30,
  longueur token ≥ 6, absence stricte côté bénin).
- **M4 (APT/Clustering)** : entrée = TTPs MITRE ATT&CK (potentiellement
  produits par M2 via `SuspiciousFinding.mitre_techniques` /
  `mitre_tactics`) ; sortie = clusters de campagnes + mapping ATT&CK.
  Algorithme suggéré : vectorisation TF-IDF des TTPs + DBSCAN/HDBSCAN.
- **M5 (Attribution)** : entrée = features de binaire (n-grams d'opcodes,
  graphes d'appel, chaînes de caractères, métadonnées PE — recoupant
  potentiellement les sorties de M1) ; sortie = top-3 acteurs APT + score de
  confiance. Algorithme suggéré : XGBoost + similarité cosinus sur embeddings.

---

## 5. WORKFLOW DE TRAVAIL ÉTABLI AVEC YASSER

Ce workflow est **strict** et a été validé empiriquement sur M1 et M2. Le
respecter pour M3, M4, M5 et toute correction future.

1. **Spécification architecturale détaillée en amont** : avant tout code,
   Yasser (ou Claude sur sa demande) fournit/élabore une spécification
   complète du module (responsabilités, classes, endpoints, modèles
   Pydantic, invariants spécifiques au module en plus des invariants
   transversaux de la section 2).
2. **Génération de code par un agent d'exécution externe** : un agent
   (différent de la session Claude de revue) génère le code complet à
   partir de la spécification.
3. **Analyse de conformité profonde par Claude** : Claude relit l'intégralité
   du code généré et catégorise chaque écart en **défaut critique** ou
   **défaut mineur**, par rapport :
   - aux invariants transversaux (section 2),
   - à la spécification du module,
   - aux conventions établies par M1 (module de référence).
4. **Production du prompt de correction final** : Claude produit **un unique
   bloc de sortie**, le prompt destiné à l'agent d'exécution, **sans aucun
   texte introductif ni commentaire** (cf. format détaillé en section 6).
5. **Itération** jusqu'à conformité totale avant de passer au module suivant.

**Principe directeur : "maximum encadrement" (maximum constraint)**. L'objectif
est de réduire au strict minimum le degré de liberté laissé à l'agent
d'exécution, car celui-ci répète systématiquement les mêmes erreurs
(cf. "Pièges connus" section 2) s'il dispose de la moindre latitude
d'interprétation.

---

## 6. FORMAT EXACT DES PROMPTS DE CORRECTION (À RESPECTER À LA LETTRE)

Quand Claude produit un prompt de correction pour l'agent d'exécution, ce
prompt **EST** la réponse de Claude. Aucun texte avant, aucun texte après.

Le prompt doit contenir, dans cet ordre :

1. **Contenu complet des fichiers** à créer ou modifier — **jamais de diffs,
   jamais de patches partiels**. Chaque fichier impacté est fourni dans son
   intégralité, prêt à être écrit tel quel sur disque.
2. **Code correct explicite pour chaque méthode** identifiée comme
   défaillante — pas de description abstraite ("corrige la méthode X pour
   qu'elle fasse Y"), mais le **code source exact** à substituer.
3. **Rappel des règles architecturales** pertinentes (extraites de la
   section 2 de ce document) qui s'appliquent aux fichiers concernés.
4. **Checklist explicite des noms de détecteurs** (`detector_name`) — lister
   chaque classe concernée et la valeur attendue de sa propriété
   `detector_name`.
5. **Commandes `grep` de vérification** — des commandes shell concrètes que
   l'agent (ou Yasser) peut exécuter pour confirmer mécaniquement que chaque
   correction a bien été appliquée (ex. `grep -rn "get_event_loop" ...` doit
   retourner zéro résultat ; `grep -rn "detector_name" ...` doit montrer
   chaque détecteur avec la bonne valeur).
6. **Liste de cases à cocher finale** récapitulant chaque correction attendue,
   pour permettre une revue rapide poste-exécution.

**Rappel** : ce format s'applique uniquement aux **prompts de correction de
code**. Pour les autres types de demandes (questions, analyses, discussions
de specs, génération de ce document lui-même), Claude répond normalement.

---

## 7. STACK TECHNOLOGIQUE DE RÉFÉRENCE

| Domaine | Outils retenus |
|---|---|
| Langage | Python 3.11+ |
| API / microservices | FastAPI, `asyncio`, Pydantic v2, `pydantic-settings` |
| CLI | Click |
| Logging | `structlog` (JSON, stderr) |
| Analyse réseau | `dpkt`, `scapy` |
| Analyse binaire | `pefile` (PE), ELF parsing, `ppdeep`/SSDeep |
| Détection pattern | `yara-python` (`yara.compile()`) |
| Formats CTI | STIX 2.1, OpenIOC, MISP JSON, CSV Cytomic Orion |
| ML classique (Phase 2/M3-M5) | scikit-learn (TF-IDF, DBSCAN/HDBSCAN), XGBoost |
| Deep Learning (Phase 2/M1-IA, M2-IA) | PyTorch, HuggingFace Transformers, spaCy |
| Tracking ML | MLflow 2.x |
| Conteneurisation | Docker / Docker Compose, sandbox réseau `none`, volumes `read-only` |
| Tests | pytest, pytest-cov (objectif ≥ 80% de couverture) |

---

## 8. GLOSSAIRE RAPIDE (issu du rapport, utile pour le vocabulaire)

| Acronyme | Signification |
|---|---|
| IOC | Indicator of Compromise |
| C2 / C&C | Command and Control |
| TTP | Tactics, Techniques and Procedures |
| APT | Advanced Persistent Threat |
| DGA | Domain Generation Algorithm |
| JA3 / JA3S | Fingerprinting TLS (Client Hello / Server Hello) |
| STIX | Structured Threat Information eXpression |
| TAXII | Trusted Automated eXchange of Intelligence Information |
| MISP | Malware Information Sharing Platform |
| SSDeep | Fuzzy hashing |
| TF-IDF | Term Frequency–Inverse Document Frequency |
| DBSCAN/HDBSCAN | Clustering non supervisé basé sur la densité |
| SOC / CERT | Security Operations Center / Computer Emergency Response Team |

---

## 9. CE QUE CE DOCUMENT N'EST PAS

- Ce n'est **pas** une spécification figée à respecter au mot près pour M3/M4/M5 :
  la section 1 (tableau des 5 modules) et la section 4 ("points d'ancrage
  suggérés") sont des **idées de cadrage**, pas des contrats.
- Ce n'est **pas** une description fidèle de l'architecture finale (hub
  central unique, Streamlit, PostgreSQL/Elasticsearch) tant que ce travail
  n'a pas été explicitement engagé — voir la note de cadrage en section 1.
- Ce n'est **pas** un substitut au rapport académique `.tex` pour la
  rédaction du PFA : c'est un outil de continuité technique entre sessions
  Claude.

---

## 10. PROCHAINES ÉTAPES IMMÉDIATES (à la date de dernière mise à jour)

1. ✅ M2 V4 conforme et clos — contrats documentés en section 4.
2. ✅ M3 V2 conforme et clos — YARA Signature Generator opérationnel sur port 8002.
3. ✅ M4 V2 conforme et clos — APTMapReport, CampaignCluster, ClusterBundle
   documentés en section 4. Port 8003. Couverture 94%, 68 tests passent.
4. ✅ M5 V3 conforme et clos — AttributionReport, APTCandidate, AttributionResult
   documentés en section 4. Port 8004. Couverture >= 80%, 11 fichiers de test.
5. Tous les modules M1–M5 sont terminés. ADMAP est fonctionnellement complet
   en mode microservices indépendants. Prochaine étape optionnelle : hub central