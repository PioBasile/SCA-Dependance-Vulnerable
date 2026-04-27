# Backend — Vulnerability Aggregator

FastAPI service that queries multiple vulnerability databases (EUVD, OSV, NVD,
GitHub Advisory) with a local AI fallback, and exposes a unified API for the
frontend.

## Architecture

```
core/        Shared infrastructure (config, logging, types, exceptions)
models/      SQLAlchemy ORM + Pydantic schemas
sources/     One adapter per vulnerability source
matching/    CPE parsing & version range comparison
services/    Aggregator + query service (business logic)
cvss_prediction/  Local DistilBERT model used as AI fallback
main.py      FastAPI entry point
```

## Quick start (local)

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

cp .env.example .env      # then fill in DATABASE_URL / NVD_API_KEY / GITHUB_TOKEN

uvicorn main:app --reload
```

The CVSS prediction model file (`cvss_prediction/model/cvss_model.pt`) must be
downloaded separately from <https://urlix.me/cvss-models>.

## Quick start (Docker)

```bash
docker compose up --build
```

The compose stack provisions a MySQL 8 instance and the API on port 8000. The
model is fetched automatically during the image build.

## Endpoints

| Method | Path                          | Description                           |
|--------|-------------------------------|---------------------------------------|
| GET    | `/`                           | Service status                        |
| GET    | `/health`                     | Per-source health check               |
| GET    | `/sync/status`                | Database sync status                  |
| POST   | `/query`                      | Query one CPE                         |
| POST   | `/query/bulk`                 | Query a list of CPEs (concurrent)     |
| GET    | `/cve/{cve_id}`               | CVE detail                            |
| GET    | `/cve/search?q=...`           | Search CVEs by ID or description      |
| GET    | `/config_nodes_cpe_match/`    | Frontend-compatible CPE query         |

## Source chain

Sources are tried in priority order: **EUVD → OSV → NVD → GitHub → AI**. For
each source, if a vulnerability is confirmed for the queried version, the
result is stored and the chain stops. The AI source is the local
CVSS-prediction model and only runs when the previous four came up empty
*and* `AI_FALLBACK_ENABLED=true` in `.env`. When still nothing is found, an
`UNKNOWN` marker is stored to avoid re-querying.

## Configuration

All runtime configuration lives in `.env`:

```ini
DATABASE_URL=mysql+pymysql://user:password@host:3306/db
NVD_API_KEY=...
GITHUB_TOKEN=...
DEBUG=false
LOG_LEVEL=INFO
AI_FALLBACK_ENABLED=false
```
