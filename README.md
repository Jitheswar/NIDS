<p align="center">
  <img src="https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12" />
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white" alt="FastAPI" />
  <img src="https://img.shields.io/badge/Docker-Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white" alt="Docker" />
  <img src="https://img.shields.io/badge/Keycloak-26.0-4D4D4D?style=for-the-badge&logo=keycloak&logoColor=white" alt="Keycloak" />
  <img src="https://img.shields.io/badge/MariaDB-11.4-003545?style=for-the-badge&logo=mariadb&logoColor=white" alt="MariaDB" />
  <img src="https://img.shields.io/badge/Redis-7-DC382D?style=for-the-badge&logo=redis&logoColor=white" alt="Redis" />
  <img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License" />
</p>

<h1 align="center">🛡️ AI-Based Network Intrusion Detection System</h1>

<p align="center">
  <strong>A production-grade, zero-trust network intrusion detection system with AI-driven anomaly detection, mutual TLS, hash-chained audit logging, and enterprise-grade identity management.</strong>
</p>

<p align="center">
  <a href="#-features">Features</a> •
  <a href="#-architecture">Architecture</a> •
  <a href="#-tech-stack">Tech Stack</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-api-reference">API Reference</a> •
  <a href="#-security-model">Security Model</a> •
  <a href="#-deployment">Deployment</a> •
  <a href="#-testing">Testing</a>
</p>

---

## ✨ Features

### 🤖 AI-Driven Anomaly Detection
- **Credential stuffing detection** — Identifies mass login attempts from a single IP targeting different usernames
- **Impossible travel analysis** — Flags logins from geographically impossible IP locations in short timeframes
- **Brute-force escalation patterns** — Detects rapid failure rate increases before account lockout triggers
- **Off-hours access monitoring** — Alerts on successful authentications outside configured business hours
- **Session anomaly detection** — Identifies abnormal session creation rates per user
- **Dynamic risk scoring** — Computes a 0–100 risk score per user/IP based on weighted anomaly signals

### 🔐 Zero Trust Security
- **Mutual TLS (mTLS)** — Bidirectional certificate-based authentication for all sensor-to-server communication
- **Private PKI** — Automated certificate lifecycle via [step-ca](https://smallstep.com/docs/step-ca/) with ACME protocol
- **Zero Trust Network Access (ZTNA)** — Device identity verification, geo-allowlisting, user-agent filtering, and risk-score-based access gating
- **CRL (Certificate Revocation List)** — Real-time revocation with 60-second refresh intervals

### 🏢 Enterprise Identity & Access Management
- **Keycloak SSO** — OIDC/OAuth2 integration with MFA support for all administrative access
- **Role-Based Access Control (RBAC)** — Four distinct roles: `Super Admin`, `Security Analyst`, `Auditor`, `Sensor Manager`
- **PII Data Masking** — Automatic field-level masking based on JWT role claims
- **Session Management** — Redis-backed sessions with idle timeout (15 min), absolute timeout (8 hrs), and concurrent session limits

### 📋 Tamper-Proof Audit Logging
- **Hash-chained logs** — SHA-256 chain linking each entry to its predecessor, making tampering detectable
- **Append-only storage** — Immutable log shipping to [Grafana Loki](https://grafana.com/oss/loki/)
- **Structured logging** — JSON-structured events via `structlog` for every authentication attempt, config change, and data access

### 🔑 Secrets Management & Rotation
- **Centralized secrets** — Runtime secret injection via [Infisical](https://infisical.com/) (self-hosted)
- **Automated rotation health checks** — Continuous monitoring of certificate expiry, API key age, and secret staleness
- **SOPS + age encryption** — Encrypted secrets at rest in configuration files

### 🛰️ Sensor Network Management
- **UUID-based sensor identity** — Each sensor registered with unique identifiers
- **Short-lived certificates** — 30-day auto-rotating certificates via ACME protocol
- **Bootstrap enrollment** — Single-use, 1-hour API keys for initial sensor onboarding
- **CRUD operations** — Full sensor lifecycle management through the REST API

---

## 🏗 Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        NIDS Architecture                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌──────────┐    mTLS     ┌──────────────────────────────────────┐  │
│  │  Sensor   │◄──────────►│           FastAPI App (:8000)        │  │
│  │  Network  │            │  ┌────────┬─────────┬────────────┐   │  │
│  └──────────┘             │  │ Auth   │ Sensors │ Security   │   │  │
│                           │  │ Router │ Router  │ Router     │   │  │
│  ┌──────────┐   OIDC/     │  ├────────┴─────────┴────────────┤   │  │
│  │Dashboard │◄──JWT──────►│  │      Middleware Layer          │   │  │
│  │  (User)  │             │  │  ZTNA │ Audit │ Rate Limit    │   │  │
│  └──────────┘             │  ├───────┴───────┴───────────────┤   │  │
│                           │  │      Service Layer             │   │  │
│                           │  │  Anomaly │ mTLS │ Rotation    │   │  │
│                           │  │  Lockout │ CRL  │ Session     │   │  │
│                           │  └──────────────────────────────────┘ │  │
│                           └────────┬───────┬───────┬─────────────┘  │
│                                    │       │       │                 │
│                 ┌──────────────────┼───────┼───────┼──────────┐     │
│                 │                  │       │       │          │     │
│           ┌─────▼─────┐    ┌──────▼──┐ ┌──▼───┐ ┌─▼──────┐  │     │
│           │ MariaDB   │    │Keycloak │ │Redis │ │ Loki   │  │     │
│           │  11.4     │    │  26.0   │ │  7   │ │ 3.0    │  │     │
│           └───────────┘    └─────────┘ └──────┘ └────────┘  │     │
│                 │                                            │     │
│           ┌─────▼─────┐    ┌──────────┐   ┌──────────────┐  │     │
│           │ step-ca   │    │Infisical │   │  fail2ban    │  │     │
│           │  (PKI)    │    │(Secrets) │   │(IP Blocking) │  │     │
│           └───────────┘    └──────────┘   └──────────────┘  │     │
│                 │                                            │     │
│                 └────────────nids-internal────────────────────┘     │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Network Isolation

| Network | Access | Services |
|:--------|:-------|:---------|
| `nids-internal` | Private (no external access) | MariaDB, Redis, Loki, step-ca, Infisical |
| `nids-frontend` | Bridged (external access) | FastAPI App, Keycloak |

---

## 🧰 Tech Stack

| Layer | Technology | Purpose |
|:------|:-----------|:--------|
| **API Framework** | FastAPI 0.115+ | Async REST API with automatic OpenAPI docs |
| **Language** | Python 3.12 | Core application runtime |
| **Database** | MariaDB 11.4 | Persistent storage for sensors, API keys, audit state |
| **Cache / Sessions** | Redis 7 (Alpine) | Session storage, rate limiting, anomaly event streams |
| **Identity Provider** | Keycloak 26.0 | OIDC/OAuth2 SSO, MFA, user federation |
| **PKI / mTLS** | step-ca (Smallstep) | Private CA, automated cert issuance & renewal |
| **Audit Logging** | Grafana Loki 3.0 | Append-only, immutable log aggregation |
| **Secrets Management** | Infisical | Centralized runtime secret injection |
| **IP Blocking** | fail2ban | Network-level brute-force protection |
| **Service Mesh** | Linkerd | Internal mTLS, per-route metrics, retries (K8s) |
| **Migrations** | Alembic | Database schema versioning |
| **ORM** | SQLAlchemy 2.0 | Async database operations |
| **Structured Logging** | structlog | JSON-formatted, contextual logging |
| **Containerization** | Docker + Compose | Multi-service orchestration |
| **Orchestration** | Kubernetes | Production deployment with NetworkPolicies |

---

## 🚀 Quick Start

### Prerequisites

- [Docker](https://docs.docker.com/get-docker/) ≥ 24.0
- [Docker Compose](https://docs.docker.com/compose/) ≥ 2.20
- Git

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/NIDS.git
cd NIDS
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Open `.env` and replace all `change_me_*` values with strong, unique passwords:

```env
DB_ROOT_PASSWORD=<strong-password>
DB_PASSWORD=<strong-password>
REDIS_PASSWORD=<strong-password>
KEYCLOAK_ADMIN_PASSWORD=<strong-password>
KEYCLOAK_CLIENT_SECRET=<generated-secret>
STEP_CA_PASSWORD=<strong-password>
INFISICAL_ENCRYPTION_KEY=<32-byte-hex-key>
INFISICAL_AUTH_SECRET=<strong-secret>
```

> [!TIP]
> Generate secure random passwords with:
> ```bash
> openssl rand -base64 32
> ```

### 3. Start the Services

**Development** (with hot-reload):
```bash
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

**Production**:
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d
```

### 4. Verify All Services Are Running

```bash
docker compose ps
```

| Service | URL | Description |
|:--------|:----|:------------|
| **NIDS API** | `http://localhost:8000` | FastAPI application |
| **API Docs** | `http://localhost:8000/docs` | Swagger UI |
| **Keycloak** | `http://localhost:8080` | Admin console |
| **Loki** | `http://localhost:3100` | Log aggregation |
| **step-ca** | `https://localhost:9000` | Certificate authority |
| **Infisical** | `http://localhost:8085` | Secrets dashboard |

### 5. Health Check

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "healthy",
  "database": "connected",
  "redis": "connected",
  "keycloak": "reachable",
  "loki": "reachable"
}
```

---

## 📡 API Reference

Base URL: `http://localhost:8000`

### Authentication

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| `POST` | `/auth/login` | Authenticate user via Keycloak | None |
| `POST` | `/auth/logout` | Revoke session and tokens | Bearer JWT |
| `POST` | `/auth/refresh` | Rotate refresh token | Refresh Token |
| `GET` | `/auth/sessions` | List active sessions | Bearer JWT |
| `DELETE` | `/auth/sessions/{id}` | Revoke a specific session | Bearer JWT |

### Sensors

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| `POST` | `/sensors/register` | Register a new sensor | Bearer JWT (Sensor Manager+) |
| `GET` | `/sensors/` | List all sensors | Bearer JWT |
| `GET` | `/sensors/{id}` | Get sensor details | Bearer JWT |
| `PUT` | `/sensors/{id}` | Update sensor metadata | Bearer JWT (Sensor Manager+) |
| `DELETE` | `/sensors/{id}` | Decommission a sensor | Bearer JWT (Super Admin) |
| `POST` | `/sensors/data` | Submit sensor telemetry | mTLS Certificate |
| `POST` | `/sensors/{id}/api-key` | Generate bootstrap API key | Bearer JWT (Sensor Manager+) |
| `POST` | `/sensors/{id}/certificate` | Issue mTLS certificate | API Key (Bootstrap) |

### Audit

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| `GET` | `/audit/logs` | Query audit logs | Bearer JWT (Auditor+) |
| `GET` | `/audit/chain/verify` | Verify hash-chain integrity | Bearer JWT (Super Admin) |

### Security

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| `GET` | `/security/anomalies` | List detected anomalies | Bearer JWT (Analyst+) |
| `GET` | `/security/risk-score` | Get risk score for user/IP | Bearer JWT (Analyst+) |
| `GET` | `/security/rotation-status` | Check secret/cert rotation health | Bearer JWT (Super Admin) |

### Health

| Method | Endpoint | Description | Auth |
|:-------|:---------|:------------|:-----|
| `GET` | `/health` | System health check | None |
| `GET` | `/health/ready` | Readiness probe (K8s) | None |

> [!NOTE]
> Full interactive API documentation is available at `/docs` (Swagger UI) and `/redoc` (ReDoc) when the server is running.

---

## 🔒 Security Model

### Defense in Depth

The security architecture is organized into three progressive phases:

```
Phase 1 — Foundation          Phase 2 — Enhanced            Phase 3 — Advanced
─────────────────────         ────────────────────          ──────────────────────
✅ Keycloak SSO + MFA          ✅ mTLS via step-ca            ✅ AI Anomaly Detection
✅ RBAC (4 roles)               ✅ CRL Revocation              ✅ ZTNA Policy Engine
✅ Redis Sessions               ✅ Hash-Chained Audit Logs     ✅ Infisical Secrets
✅ Brute-Force Protection       ✅ JWT Token Lifecycle          ✅ Linkerd Service Mesh
✅ fail2ban IP Blocking          ✅ Data Masking (PII)          ✅ Rotation Health Checks
✅ SOPS + age Encryption        ✅ Environment-Aware CORS      ✅ Dynamic Risk Scoring
```

### RBAC Matrix

| Capability | Super Admin | Security Analyst | Auditor | Sensor Manager |
|:-----------|:-----------:|:----------------:|:-------:|:--------------:|
| Manage users & global config | ✅ | ❌ | ❌ | ❌ |
| View dashboards & alerts | ✅ | ✅ | ❌ | ❌ |
| Investigate incidents | ✅ | ✅ | ❌ | ❌ |
| Read audit logs | ✅ | ❌ | ✅ | ❌ |
| Generate/revoke API keys | ✅ | ❌ | ❌ | ✅ |
| View sensor health | ✅ | ❌ | ❌ | ✅ |
| Unmask PII fields | ✅ | ❌ | ❌ | ❌ |
| View raw payloads | ✅ | ❌ | ❌ | ❌ |

### Data Masking Rules

| Data Type | Super Admin | Analyst | Auditor | Sensor Manager |
|:----------|:-----------:|:-------:|:-------:|:--------------:|
| IP Addresses | Full | Masked | Masked | N/A |
| Hostnames | Full | Masked | Masked | N/A |
| Raw Payloads | Full | Metadata only | Hidden | N/A |
| Usernames | Full | Masked | Masked | N/A |
| Sensor Metadata | Full | Full | Read-only | Full |

---

## 🚢 Deployment

### Docker Compose (Recommended for Single-Node)

```bash
# Production with optimized settings
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

# View logs
docker compose logs -f app

# Stop all services
docker compose down

# Stop and remove volumes (⚠️ destroys data)
docker compose down -v
```

### Kubernetes (Production Multi-Node)

The `k8s/` directory provides Linkerd service mesh configuration with:

- **Namespace-level mTLS injection** — All pods in the `nids` namespace get automatic mTLS sidecars
- **Deny-all NetworkPolicies** — Only explicitly allowed service-to-service traffic is permitted
- **ServiceProfile** — Per-route metrics and retry policies for the NIDS API
- **ServerAuthorization** — Only authenticated mesh identities can reach the API

```bash
# Install Linkerd
curl -fsL https://run.linkerd.io/install | sh
linkerd install --crds | kubectl apply -f -
linkerd install | kubectl apply -f -
linkerd check

# Apply NIDS manifests
kubectl apply -f k8s/linkerd-annotations.yml

# Verify mesh injection
linkerd viz stat deploy -n nids
```

### Environment Profiles

| Variable | Development | Staging | Production |
|:---------|:------------|:--------|:-----------|
| `ENVIRONMENT` | `development` | `staging` | `production` |
| `MTLS_ENABLED` | `false` | `true` | `true` |
| `ZTNA_ENABLED` | `false` | `false` | `true` |
| `ANOMALY_DETECTION_ENABLED` | `true` | `true` | `true` |
| `CORS_ORIGINS` | `http://localhost:3000` | `https://staging-*` | `https://dashboard.*` |

---

## 🧪 Testing

The project includes a comprehensive test suite covering all security layers:

```bash
# Run all tests
docker compose exec app pytest tests/ -v

# Run specific test modules
docker compose exec app pytest tests/test_anomaly.py -v       # AI anomaly detection
docker compose exec app pytest tests/test_auth.py -v           # Authentication flows
docker compose exec app pytest tests/test_lockout.py -v        # Brute-force protection
docker compose exec app pytest tests/test_ztna.py -v           # Zero Trust policies
docker compose exec app pytest tests/test_loki.py -v           # Audit logging
docker compose exec app pytest tests/test_rotation.py -v       # Secret rotation

# Run with coverage
docker compose exec app pytest tests/ --cov=. --cov-report=html
```

### Test Coverage

| Module | Tests | Coverage Area |
|:-------|:------|:--------------|
| `test_anomaly.py` | Credential stuffing, impossible travel, brute-force escalation, risk scoring |
| `test_auth.py` | Login, logout, token refresh, session management |
| `test_auth_flow.py` | End-to-end authentication workflows |
| `test_lockout.py` | Progressive lockout, permanent lock, exponential backoff |
| `test_ztna.py` | Device ID enforcement, user-agent filtering, geo-allowlist |
| `test_loki.py` | Log shipping, hash-chain integrity, structured events |
| `test_rotation.py` | Certificate expiry warnings, secret age checks, health metrics |
| `test_data_masking.py` | PII masking per role, unmask audit trail |
| `test_sensors.py` | Sensor CRUD, bootstrap enrollment, certificate issuance |
| `test_session_keycloak.py` | Idle/absolute timeouts, concurrent session limits |
| `test_token_revocation.py` | JWT blacklisting, refresh token rotation |
| `test_rate_limits.py` | Per-IP and per-token rate limiting |
| `test_compose_security.py` | Docker Compose security configuration validation |
| `test_security_regressions.py` | Regression tests for previously fixed vulnerabilities |

---

## 📁 Project Structure

```
NIDS/
├── app/
│   ├── main.py                    # FastAPI application entry point
│   ├── config.py                  # Pydantic settings with env validation
│   ├── database.py                # SQLAlchemy async engine & session
│   ├── Dockerfile                 # Production container image
│   ├── Dockerfile.dev             # Development image with hot-reload
│   ├── requirements.txt           # Python dependencies
│   ├── alembic/                   # Database migration scripts
│   ├── models/                    # SQLAlchemy ORM models
│   │   ├── sensor.py              #   Sensor registration & metadata
│   │   ├── api_key.py             #   Bootstrap API key model
│   │   ├── audit_log.py           #   Audit log entries
│   │   └── audit_chain_state.py   #   Hash-chain state tracking
│   ├── schemas/                   # Pydantic request/response schemas
│   ├── routers/                   # API route handlers
│   │   ├── auth.py                #   Authentication endpoints
│   │   ├── sensors.py             #   Sensor management endpoints
│   │   ├── audit.py               #   Audit log queries
│   │   ├── health.py              #   Health & readiness probes
│   │   └── security.py            #   Anomaly & risk score endpoints
│   ├── services/                  # Business logic layer
│   │   ├── anomaly_service.py     #   AI-driven anomaly detection engine
│   │   ├── keycloak_service.py    #   Keycloak admin API integration
│   │   ├── mtls_service.py        #   mTLS certificate operations
│   │   ├── crl_service.py         #   CRL refresh loop
│   │   ├── loki_service.py        #   Audit log shipping to Loki
│   │   ├── session_service.py     #   Redis session management
│   │   ├── lockout_service.py     #   Brute-force lockout logic
│   │   ├── rotation_service.py    #   Secret & cert rotation health
│   │   ├── infisical_service.py   #   Centralized secrets fetching
│   │   ├── sensor_service.py      #   Sensor data processing
│   │   ├── audit_service.py       #   Audit chain operations
│   │   └── token_revocation_service.py  # JWT blacklisting
│   ├── middleware/                 # Request processing pipeline
│   │   ├── ztna.py                #   Zero Trust access enforcement
│   │   ├── audit.py               #   Request/response audit logging
│   │   ├── data_masking.py        #   PII field masking per role
│   │   └── rate_limit.py          #   Rate limiting configuration
│   ├── dependencies/              # FastAPI dependency injection
│   └── utils/                     # Shared utilities
├── tests/                         # Comprehensive test suite (19 modules)
├── keycloak/
│   └── realm-export.json          # Pre-configured Keycloak realm
├── loki/
│   └── loki-config.yml            # Loki storage & retention config
├── fail2ban/
│   ├── jail.local                 # fail2ban jail configuration
│   └── filter.d/                  # Custom filter rules
├── k8s/
│   └── linkerd-annotations.yml    # Kubernetes + Linkerd manifests
├── secrets/                       # SOPS-encrypted secrets (gitignored)
├── docker-compose.yml             # Base service definitions
├── docker-compose.dev.yml         # Development overrides
├── docker-compose.prod.yml        # Production overrides
├── init-db.sql                    # Database initialization script
├── auth-map.md                    # Authentication strategy documentation
├── .env.example                   # Environment template
└── .gitignore
```

---

## ⚙️ Configuration Reference

All configuration is managed via environment variables with sensible defaults. See [`.env.example`](.env.example) for the full list.

### Key Configuration Groups

<details>
<summary><strong>🗄️ Database</strong></summary>

| Variable | Default | Description |
|:---------|:--------|:------------|
| `DB_HOST` | `mariadb` | Database hostname |
| `DB_PORT` | `3306` | Database port |
| `DB_NAME` | `nids` | Database name |
| `DB_USER` | `nids` | Database user |
| `DB_PASSWORD` | — | Database password (required) |

</details>

<details>
<summary><strong>🔐 Keycloak</strong></summary>

| Variable | Default | Description |
|:---------|:--------|:------------|
| `KEYCLOAK_URL` | `http://keycloak:8080` | Keycloak base URL |
| `KEYCLOAK_REALM` | `nids` | Realm name |
| `KEYCLOAK_CLIENT_ID` | `nids-api` | OIDC client ID |
| `KEYCLOAK_CLIENT_SECRET` | — | OIDC client secret (required) |

</details>

<details>
<summary><strong>🤖 Anomaly Detection</strong></summary>

| Variable | Default | Description |
|:---------|:--------|:------------|
| `ANOMALY_DETECTION_ENABLED` | `true` | Enable/disable anomaly engine |
| `ANOMALY_WINDOW` | `3600` | Sliding window in seconds |
| `ANOMALY_FAILED_LOGIN_THRESHOLD` | `10` | Failed logins before flagging |
| `ANOMALY_OFF_HOURS_START` | `22` | Off-hours start (24h) |
| `ANOMALY_OFF_HOURS_END` | `6` | Off-hours end (24h) |

</details>

<details>
<summary><strong>🛡️ ZTNA</strong></summary>

| Variable | Default | Description |
|:---------|:--------|:------------|
| `ZTNA_ENABLED` | `false` | Enable Zero Trust enforcement |
| `ZTNA_REQUIRE_DEVICE_ID` | `false` | Require device identity header |
| `ZTNA_GEO_ALLOWLIST` | `""` | Comma-separated country codes |
| `ZTNA_RISK_SCORE_THRESHOLD` | `70` | Block if risk score ≥ this value |

</details>

<details>
<summary><strong>🔄 Rotation & Certificates</strong></summary>

| Variable | Default | Description |
|:---------|:--------|:------------|
| `ROTATION_CHECK_INTERVAL` | `3600` | Health check interval (seconds) |
| `CERT_EXPIRY_WARNING_DAYS` | `7` | Days before cert expiry to warn |
| `SECRET_MAX_AGE_DAYS` | `90` | Max secret age before rotation alert |
| `CERT_VALIDITY_DAYS` | `30` | Sensor certificate validity period |

</details>

---

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Commit your changes: `git commit -m 'feat: add my feature'`
4. Push to the branch: `git push origin feature/my-feature`
5. Open a Pull Request

> [!IMPORTANT]
> All contributions must include tests. Run the full test suite before submitting a PR.

---

## 📄 License

This project is licensed under the MIT License — see the [LICENSE](LICENSE) file for details.

---

<p align="center">
  Built with security-first principles • Every layer verified • Zero trust by default
</p>
