# 🛡️ TraceVault — AI-Powered Email Threat Detection & Forensic Intelligence Platform

> **SIH 2026 · Problem Statement ID 26106 · AICTE Cyber Security Cell**

TraceVault is a production-grade, AI-powered email threat detection and forensic intelligence platform. It enables security analysts to investigate suspicious emails from evidence preservation through to court-ready forensic reports — with full blockchain chain of custody, Gemini AI analysis, and real-time investigation dashboards.

---

## 🏆 Key Features

| Feature | Description |
|---|---|
| **Digital Evidence Preservation** | SHA-256 + SHA-3-256 hash, unique Case ID (`TV-YYYYMMDD-XXXXXXXX`), cryptographic integrity verification |
| **AI Threat Detection** | 3-layer scoring: rule engine + scikit-learn ML + Gemini 2.0 Flash LLM with multi-agent orchestration |
| **Header Forensics** | Full relay chain analysis, SPF/DKIM/DMARC validation, cloud ESP spoofing checks, RFC violation detection |
| **IOC Extraction** | IPs, domains, URLs (with redirect following), email addresses, file hashes, adaptive lookalike domain detection |
| **Geo Intelligence & Mapping** | IP geolocation, ISP/ASN/WHOIS, domain origin vs outbound MTA routing, Leaflet dark map, VPN/TOR/Proxy detection |
| **Threat Correlation** | NetworkX IOC graph, campaign detection across cases, shared indicator clustering |
| **Blockchain Custody** | Tamper-evident SHA-256 hash-chain ledger + optional Polygon Amoy testnet anchoring |
| **Forensic PDF Reports** | 13-section Jinja2 + WeasyPrint reports with evidence certificates and in-browser HTML preview |
| **Real-time SSE** | Live 9-stage analysis progress streaming via Server-Sent Events |
| **Investigation Dashboard** | React 18 + Cytoscape.js + Leaflet — real-time risk posture gauge, threat graph, geo map, relay path, chain of custody |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                         TRACEVAULT PLATFORM                         │
├─────────────────────────────────────────────────────────────────────┤
│  Frontend (React 18 + Vite)           Backend (FastAPI + Python 3.11)│
│  ┌──────────────────────┐             ┌────────────────────────────┐ │
│  │ Dashboard            │  REST API   │ Email Parser (mail-parser)  │ │
│  │ Upload + SSE Stream  │ ◄────────► │ Header Forensics            │ │
│  │ Case Detail (8 tabs) │             │ SPF/DKIM/DMARC Validator   │ │
│  │ Cytoscape.js Graph   │             │ IOC Extractor               │ │
│  │ Leaflet Geo Map      │             │ AI Threat Engine            │ │
│  │ Chain of Custody     │             │ Geo Intelligence            │ │
│  └──────────────────────┘             │ Threat Correlator           │ │
│                                       │ Blockchain Ledger           │ │
│  ┌──────────┐  ┌──────────┐          │ Report Generator            │ │
│  │PostgreSQL│  │  Redis   │          │ Analysis Pipeline (SSE)     │ │
│  │  (data)  │  │ (queues) │          └────────────────────────────┘ │
│  └──────────┘  └──────────┘                                          │
└─────────────────────────────────────────────────────────────────────┘
```

---

## ⚡ Quick Start (Docker Compose)

### Prerequisites
- Docker Desktop installed and running
- Google Gemini API key (free at [ai.google.dev](https://ai.google.dev))

### Option A: One-Click Launcher (Windows PowerShell)
Run the built-in launcher script from the project root:
```powershell
.\start.ps1
```
This script checks Docker availability, starts all containers, waits for health checks, displays service URLs, and opens your browser directly to the dashboard.

---

### Option B: Manual Setup

#### 1. Set up environment
```bash
# Copy env template
copy backend\.env.example backend\.env
```

Edit `backend/.env` and configure:
```env
GOOGLE_API_KEY=your_gemini_api_key_here
SECRET_KEY=your_random_secret_key_at_least_32_characters
```

#### 2. Launch all services
```bash
docker compose up --build -d
```

This starts:
- **PostgreSQL 16** on port `5432`
- **Redis 7** on port `6379`
- **Backend API** on port `8000`
- **Frontend** on port `3000`

#### 3. Run database tables migration (if needed)
Database tables are automatically initialized on startup, but you can also run:
```bash
docker compose exec backend alembic upgrade head
```

#### 4. Access the platform
- **Dashboard:** [http://localhost:3000](http://localhost:3000)
- **API Documentation (Swagger):** [http://localhost:8000/api/docs](http://localhost:8000/api/docs)
- **API Health Check:** [http://localhost:8000/health](http://localhost:8000/health)

Register an analyst account, then upload one of the sample `.eml` files from `seed_data/`.

---

## 🖥️ Local Development (Without Docker)

### Backend
```bash
cd backend

# Create virtual environment
python -m venv venv
venv\Scripts\activate       # Windows
# source venv/bin/activate  # Linux/macOS

# Install dependencies
pip install -r requirements.txt

# Setup .env
copy .env.example .env
# Edit .env with your keys

# Start PostgreSQL and Redis (can use Docker for just these)
docker run -d --name pg -e POSTGRES_PASSWORD=tracevault_secure_2024 -e POSTGRES_USER=tracevault -e POSTGRES_DB=tracevault -p 5432:5432 postgres:16-alpine
docker run -d --name redis -p 6379:6379 redis:7-alpine

# Run migrations
alembic upgrade head

# Start API server
uvicorn app.main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev
```
→ Frontend at **http://localhost:3000** (proxies `/api` requests to port 8000).

---

## 🔑 API Key Setup

### Google Gemini (Required for AI Analysis)
1. Visit [https://ai.google.dev](https://ai.google.dev)
2. Click **"Get API key"** → **"Create API key"**
3. Copy the key into `backend/.env`:
   ```
   GOOGLE_API_KEY=AIzaSy...your_key_here
   ```

**Free tier:** 15 requests/min · 1M tokens/day · Gemini 2.0 Flash  
*The platform works without it (falls back to rule + ML scoring only), but AI narrative requires the key.*

### ipinfo.io (Optional — for enhanced geo data)
1. Register at [https://ipinfo.io](https://ipinfo.io)
2. Free tier: 50,000 requests/month
3. Add to `.env`: `IPINFO_TOKEN=your_token`

---

## 📁 Project Structure

```
TraceVault/
├── start.ps1                     # Windows quick launcher script
├── docker-compose.yml            # Container orchestration (Postgres, Redis, Backend, Frontend)
├── seed_data/                    # Sample .eml forensic test emails
│   ├── sample_paypal_phishing.eml
│   ├── sample_bec_wire_fraud.eml
│   ├── sample_m365_credential_theft.eml
│   ├── sample_hr_phishing_attachment.eml
│   └── sample_benign_amazon_notification.eml
│
├── backend/
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── alembic.ini
│   ├── .env                      # Local environment configuration
│   ├── templates/
│   │   └── forensic_report.html  # 13-section PDF template
│   ├── migrations/
│   │   └── versions/001_initial_schema.py
│   └── app/
│       ├── main.py               # FastAPI entry point, CORS, routers & lifecycle
│       ├── config.py             # Pydantic Settings
│       ├── database.py           # Async SQLAlchemy engine + Redis client
│       ├── models/               # SQLAlchemy ORM models (8 models: case, analysis, ioc, geo, blockchain, etc.)
│       ├── schemas/              # Pydantic v2 schemas (10 schemas: geo, case, stats, ioc, report, etc.)
│       ├── api/v1/               # REST API endpoints (auth, cases, analysis, iocs, blockchain, reports, stats, graph, campaigns)
│       ├── services/             # Core forensics and intelligence services (14 services)
│       │   └── agents/           # Multi-agent analysis modules (header_agent, ioc_agent)
│       └── utils/                # Helper utilities (lookalike, defang, hash verification)
│
└── frontend/
    ├── Dockerfile
    ├── nginx.conf
    ├── package.json
    ├── vite.config.ts
    ├── tailwind.config.js
    └── src/
        ├── main.tsx
        ├── App.tsx
        ├── index.css             # Dark theme & dark-mode OSM tile filters
        ├── types/index.ts        # TypeScript interfaces
        ├── lib/
        │   ├── api.ts            # Axios client & API queries
        │   └── utils.ts          # Formatting & styling helpers
        ├── stores/
        │   └── authStore.ts      # Zustand JWT state store
        ├── pages/
        │   ├── LoginPage.tsx
        │   ├── DashboardPage.tsx # Fleet analytics & Threat Environment Gauge
        │   ├── CasesPage.tsx     # Investigation case inventory
        │   ├── UploadPage.tsx    # Evidence submission & live SSE progress
        │   ├── CaseDetailPage.tsx# 8-tab deep forensic inspection view
        │   └── CampaignsPage.tsx # Correlated threat campaigns
        └── components/
            ├── layout/Layout.tsx
            └── investigation/
                ├── ThreatGraph.tsx # Cytoscape.js interactive network graph
                └── GeoIntelMap.tsx # Leaflet geo-routing map with dark mode
```

---

## 🔬 Analysis Pipeline

The 9-step pipeline streams real-time progress via SSE:

| Step | Service | Output |
|---|---|---|
| 1. Parse Email (10%) | `email_parser.py` | MIME structure, headers, body |
| 2. Header Forensics (20%) | `header_forensics.py` | Relay chain, spoofing indicators |
| 3. Auth Validation (30%) | `auth_validator.py` | SPF/DKIM/DMARC results |
| 4. IOC Extraction (45%) | `ioc_extractor.py` | IPs, domains, URLs, hashes |
| 5. AI Analysis (60%) | `ai_threat_engine.py` | Rules + ML + Gemini threat score |
| 6. Geo Intelligence (75%) | `geo_intelligence.py` | IP location, VPN/TOR detection |
| 7. Correlation (88%) | `threat_correlator.py` | Campaign detection, IOC graph |
| 8. Blockchain Log (95%) | `blockchain_ledger.py` | Chain of custody entry |
| 9. Finalize (100%) | `analysis_pipeline.py` | Case status update |

### Threat Scoring Formula
```
Score = rule×0.35 + ml×0.35 + gemini×0.30  (with Gemini)
Score = rule×0.50 + ml×0.50                 (fallback)

CRITICAL: ≥ 80
HIGH:     ≥ 60
MEDIUM:   ≥ 40
LOW:      ≥ 20
BENIGN:   < 20
```

---

## 🔗 API Reference

**Base URL:** `http://localhost:8000/api/v1`  
**Swagger UI:** [http://localhost:8000/api/docs](http://localhost:8000/api/docs)  
**ReDoc:** [http://localhost:8000/api/redoc](http://localhost:8000/api/redoc)  
**Authentication:** `Authorization: Bearer <jwt_token>`

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/auth/register` | Register analyst account |
| `POST` | `/auth/login` | Authenticate analyst & receive JWT |
| `GET` | `/auth/me` | Current authenticated user profile |
| `POST` | `/cases/upload` | Upload `.eml` or raw email for evidence intake |
| `GET` | `/cases` | List all investigation cases (filtered, paginated, includes subjects) |
| `GET` | `/cases/{id}` | Full case detail with all associated records |
| `DELETE`| `/cases/{id}` | Soft delete case |
| `POST` | `/analysis/{id}/analyze` | Trigger or restart analysis pipeline |
| `GET` | `/analysis/{id}/stream` | Server-Sent Events (SSE) real-time progress stream |
| `GET` | `/analysis/{id}/analysis` | Analysis results, threat scores, and AI findings |
| `GET` | `/analysis/{id}/headers` | Parsed header details and RFC anomalies |
| `GET` | `/analysis/{id}/relay-path` | Ordered SMTP transmission relay hops |
| `GET` | `/analysis/{id}/geo` | IP Geolocation, ASN, WHOIS, and proxy/VPN indicators |
| `GET` | `/iocs` | List and filter extracted IOCs |
| `GET` | `/iocs/search` | Search IOCs across cases |
| `GET` | `/iocs/case/{case_id}` | Retrieve all IOCs for a specific case |
| `GET` | `/blockchain/{case_id}` | Retrieve chain of custody blocks for case |
| `POST` | `/blockchain/verify` | Verify cryptographic hash chain integrity |
| `GET` | `/reports/{case_id}/download` | Download court-ready forensic PDF report |
| `GET` | `/reports/{case_id}/html` | Preview report in browser |
| `GET` | `/graph/{case_id}` | Cytoscape.js threat intelligence network graph |
| `GET` | `/campaigns` | Clustered threat campaigns across cases |
| `GET` | `/stats` | Fleet dashboard stats, average threat score, and trend |

---

## 🧪 Testing with Sample Emails

The `seed_data/` directory contains 5 test emails:

| File | Type | Expected Severity |
|---|---|---|
| `sample_paypal_phishing.eml` | PayPal lookalike credential theft | CRITICAL |
| `sample_bec_wire_fraud.eml` | Business Email Compromise (wire fraud) | CRITICAL |
| `sample_m365_credential_theft.eml` | Microsoft 365 credential harvesting | HIGH |
| `sample_hr_phishing_attachment.eml` | HR phishing with PDF attachment | HIGH |
| `sample_benign_amazon_notification.eml` | Legitimate Amazon shipping email | BENIGN |

Upload these through the **New Investigation** page to see the full analysis pipeline.

---

## ⛓️ Blockchain Evidence Chain

Every investigation action is recorded in a tamper-evident hash-chain:

```json
{
  "block_index": 3,
  "prev_hash": "sha256_of_block_2",
  "timestamp": "2024-01-15T09:23:14Z",
  "case_id": "TV-20240115-A3F7C2D1",
  "action": "ANALYSIS_COMPLETED",
  "actor": "system",
  "data": { "threat_score": 94, "severity": "CRITICAL" },
  "data_hash": "sha256_of_data",
  "block_hash": "sha256_of_all_above"
}
```

**Verification:** Any modification of any block breaks the hash chain, which is detected instantly via `POST /blockchain/verify`.

**Optional Polygon anchoring:** Set `ENABLE_BLOCKCHAIN_ANCHORING=true` in `.env` to anchor case hashes to the Polygon Amoy testnet.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| **Backend** | Python 3.11, FastAPI, SQLAlchemy 2.0 (Async), Alembic |
| **Database & Cache** | PostgreSQL 16, Redis 7 |
| **AI / ML** | Google Gemini 2.0 Flash, scikit-learn (TF-IDF + Random Forest), SHAP |
| **Email Parsing** | mail-parser, Python stdlib `email` |
| **Auth Forensics** | pyspf, dkimpy, checkdmarc, email-validator |
| **Network Intel** | ipwhois (RDAP), python-whois, dnspython, ipinfo.io, Levenshtein |
| **Blockchain** | SHA-256 hash chain (PostgreSQL), optional web3.py + Polygon Amoy |
| **PDF Reporting** | Jinja2 + WeasyPrint |
| **Frontend** | React 18, Vite, TypeScript, Tailwind CSS |
| **State Management** | TanStack Query v5, Zustand |
| **Visualizations** | Cytoscape.js (graph), React-Leaflet (geo map), Recharts, SVG Gauge |
| **Real-time Streaming**| Server-Sent Events (SSE) |
| **Containerization** | Docker Desktop, Docker Compose, nginx |

## 👨‍💻 Development Notes

- **JWT tokens** are stored in Zustand persisted to localStorage (acceptable for analyst-only dashboard)
- **SSE streaming** uses native EventSource API; nginx is configured with `proxy_buffering off` for proper streaming
- **Gemini responses** are parsed as JSON and treated as untrusted input (prompt injection guards in place)
- **IP geolocation data** reflects infrastructure location, NOT attacker identity — explicitly noted in reports
- **Blockchain** is a pure software hash chain — no gas fees, no external dependency required for basic functionality

---

## 📄 License

Built for SIH 2026 — Problem Statement 26106 — AICTE Cyber Security Cell  
© 2026 TraceVault Team. All rights reserved.
