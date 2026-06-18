# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Identity

**ADMAP — Advanced Detection & Malware Analysis Platform**

Academic project (PFA, 4CIRA, EMSI 2025-2026) by Yasser Aguezzar and Mourad Modakir. A SOC/CERT platform composed of 5 independent Python microservices + a BFF Gateway + a React dashboard.

**Read `MEMOIRE_CENTRALE_ADMAP.md` before any non-trivial work on this project.** It is the authoritative source of truth for architecture decisions, module status, inter-module contracts, and known pitfalls. If it conflicts with a report `.tex` file — trust this document, not the report.

---

## Repository Layout

```
admap_m1/          IOC Extractor          — FastAPI port 8000  (v3.0.0 ✅)
admap_m2/          C2 Detector            — FastAPI port 8001  (v1.0.0 ✅)
admap_m3/          YARA Generator         — FastAPI port 8002  (v1.0.0 ✅)
admap_m4/          APT Mapper/Clustering  — FastAPI port 8003  (v1.0.0 ✅)
admap_m5/          Attribution (XGBoost)  — FastAPI port 8004  (v1.0.0 ✅)
admap_gateway/     BFF FastAPI proxy      — port 9000
admap-dashboard/   React + Vite frontend  — port 3000
```

All 5 microservices are complete. The gateway and dashboard are in progress.

---

## Commands

### Python Microservices (M1–M5)

Each module is an independent Python package. Run commands from inside the module directory (e.g., `cd admap_m1`).

```bash
# Install (use pip or poetry — each module has pyproject.toml)
pip install -e ".[dev]"

# Run tests with coverage (all modules use the same pattern)
pytest tests/ -v --cov=admap_m1      # replace admap_m1 with the module name

# Run a single test file
pytest tests/unit/test_filters.py -v

# Run a single test by name
pytest tests/unit/test_filters.py::TestWhitelist::test_known_safe_domain -v

# Start a microservice (example for M1)
python -m admap_m1.api.main           # or: uvicorn admap_m1.api.main:app --reload --port 8000

# CLI usage (example M1)
python -m admap_m1.cli.main <file>
python -m admap_m1.cli.main <file> --vt --format stix21 --out result.json
```

Coverage target for all modules: **≥ 80%**.

### Gateway (BFF)

```bash
# Run from the repository root — admap_gateway is a Python package (relative imports).
pip install -r admap_gateway/requirements.txt
uvicorn admap_gateway.main:app --reload --port 9000
```

### Dashboard (React + Vite)

```bash
cd admap-dashboard
npm install
npm run dev          # dev server on port 3000
npm run build        # production build
npm run lint         # ESLint
```

---

## Non-Negotiable Architectural Invariants

These apply to **all modules** without exception:

1. **No `input()`, no interactive menus.** CLI exclusively via **Click**.
2. **100% OOP Python 3.11+** with complete type hints everywhere (params, returns, class attributes).
3. **No ML/AI in M1–M4.** Heuristics only. ML is strictly confined to M5.
4. **All files treated as potentially malicious** — read in binary mode, never executed, validated before processing.
5. **Every module is a standalone FastAPI microservice** with `GET /health` (liveness) and `GET /ready` (readiness + dependency check).
6. **Logging: `structlog` JSON only**, replacing all `print()`. Logs → stderr. JSON application output → stdout.
7. **Pydantic v2** for all data models (API input, config, internal structures).
8. **Async job queues via `asyncio`**, initialized in the FastAPI `lifespan`, stored in `app.state` — no module-level mutable globals.
9. **Config via `pydantic-settings`** with `@lru_cache` on `get_settings()`.

---

## Known Recurring Bugs (check these on every module correction)

- **`detector_name` property**: every detector class must expose a non-empty `detector_name` property. Most common bug in M2 corrections.
- **`asyncio.get_running_loop()`** not `asyncio.get_event_loop()` — the latter is deprecated.
- **No hardcoded confidence scores** in correlator classes — always calculated dynamically.
- **Exporters must return structured JSON errors**, never raise `RuntimeError` on failure.
- **Constructor signature changes** must be verified against existing pytest fixtures — a "cleaner" signature that breaks tests is a critical defect.

---

## Inter-Module Data Contracts

The pipeline flows: **M1 → M2 → M3 (optional) → M4 → M5**

Key output types consumed across modules:
- M1 produces `IOCBundle` (STIX 2.1, OpenIOC, MISP JSON, Cytomic CSV)
- M2 produces `AlertBundle` (frozen Pydantic v2) with `C2Alert` list
- M3 produces `YaraRuleSet`
- M4 produces `APTMapReport` containing `ClusterBundle` + `CampaignCluster` list
- M5 produces `AttributionReport` with `APTCandidate` top-k list

Full field-level contracts for each module are in `MEMOIRE_CENTRALE_ADMAP.md` section 4.

---

## Gateway Architecture

`admap_gateway/` is a **thin BFF proxy** — no business logic. It:
- Proxies all requests via `routers/proxy_utils.py:forward_request()` (streaming)
- Aggregates `/health` and `/ready` from all 5 modules at `GET /api/status`
- Orchestrates the full pipeline M1→M2→M4→M5 at `POST /api/pipeline/full`
- Serves WebSocket job polling at `ws/jobs/{job_id}`
- Configured via `settings.py` (pydantic-settings, reads `.env`): `m1_url`–`m5_url` default to `localhost:8000`–`8004`

---

## Dashboard Architecture

`admap-dashboard/` is a React 19 + Vite SPA:
- **State**: Zustand (`src/store/`)
- **HTTP**: Axios client in `src/api/client.ts` — base URL `http://localhost:9000/api`
- **UI**: Tailwind CSS + shadcn/ui components in `src/lib/`
- **Charts**: Recharts for data charts, Framer Motion for animations
- **Routing**: React Router v7

No direct calls to microservices — all traffic goes through the gateway on port 9000.

---

## M1 as Reference Module

M1 (`admap_m1/`) is the **architecture reference** for all modules. When uncertain about how to structure a new module, mirror M1's:
- Directory layout (`parsers/`, `extractors/`, `deobfuscators/`, `filters/`, `heuristics/`, `enrichers/`, `exporters/`, `pipeline/`, `api/`, `cli/`, `core/`, `models/`)
- `pyproject.toml` structure (build system, dev extras, `[tool.pytest.ini_options]`, `[tool.ruff]`, `[tool.mypy]`)
- Test organization (`tests/unit/`, `tests/integration/`)


## Style de communication
- Sois direct, factuel, technique. Pas de flatterie ni de formules de politesse
  superflues.
- Si je propose une approche non fonctionnelle, inefficace ou non
  professionnelle, INTERROMPS-MOI et propose la meilleure méthode, même si
  ça contredit ma demande.
- Priorise la justesse technique sur le fait de me faire plaisir.
- Quand tu n'es pas sûr, dis-le. N'invente jamais.