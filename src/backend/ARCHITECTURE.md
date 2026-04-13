
### Architecture Overview

```
├── core/                          # Shared infrastructure
│   ├── config.py                 # Configuration management
│   ├── exceptions.py             # Exception hierarchy
│   ├── logger.py                 # Logging setup
│   └── types.py                  # Type definitions
│
├── models/                        # Database & Serialization
│   ├── database.py               # SQLAlchemy ORM models
│   └── schemas.py                # Pydantic request/response models
│
├── sources/                       # Vulnerability Source Adapters
│   ├── base.py                   # Abstract base class + mixins
│   ├── euvd.py                   # EUVD source
│   ├── osv.py                    # OSV source
│   ├── nvd.py                    # NVD source
│   ├── github.py                 # GitHub Advisory source (stub)
│   └── jvn.py                    # JVN source (stub)
│
├── services/                      # Business Logic Layer
│   ├── aggregator.py             # Core aggregation orchestrator
│   └── vulnerability_service.py   # CVE query/search service
│
├── matching/                      # CPE & Version Matching
│   ├── cpe.py                    # CPE parsing & normalization
│   ├── version.py                # Version comparison logic
│   └── normalizer.py             # Data normalization (planned)
│
├── routers/                       # FastAPI Route Handlers
│   ├── health.py                 # Health check endpoints
│   ├── query.py                  # CPE query endpoints
│   ├── sync.py                   # Sync & status endpoints
│   └── debug.py                  # Debug endpoints
│
├── utils/                         # Utility Functions
│   ├── http.py                   # HTTP utilities with retry logic
│   └── validators.py             # Validation functions
│
├── main.py                        # FastAPI application entry point
├── aggregator.py                  # Backward compatibility wrapper
└── requirements.txt              # Dependencies
```


### Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure environment
cp .env.example .env
# Edit .env with your settings

# 4. Run server
uvicorn main:app --reload
```

### 🔌 Vulnerability Sources

- **EUVD**: European Vulnerability Database
- **OSV**: Open Source Vulnerabilities (Google)
- **NVD**: National Vulnerability Database (US)
- **GitHub Advisory**: GitHub's security advisories
- **JVN**: Japan Vulnerability Notes
- **AI Fallback**: AI-based CVVS score prediction