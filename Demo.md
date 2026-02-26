# NIDS Demo Guide (For Classroom / Teacher Evaluation)

This guide is a step-by-step script to:

1. Set up the project correctly.
2. Run it reliably.
3. Present it clearly to your teacher with technical explanations.

Estimated demo time: 10 to 15 minutes.

---

## 1) What You Are Demonstrating

You are demonstrating an AI-enabled NIDS backend with:

- Identity and access control via Keycloak (RBAC roles).
- API security with login/session flow.
- Sensor provisioning workflow (create, enroll, activate).
- Tamper-aware audit logging (DB + Loki pipeline).
- Security health/rotation checks.

Core services started by Docker Compose:

- `mariadb` (database)
- `redis` (sessions, lockout, fast state)
- `keycloak` (authentication/roles)
- `loki` (audit log backend)
- `step-ca` (PKI service)
- `infisical` (secrets service)
- `app` (FastAPI backend)

---

## 2) Prerequisites

Install these before demo day:

- Docker + Docker Compose plugin
- `curl`
- `jq`

Check quickly:

```bash
docker --version
docker compose version
curl --version
jq --version
```

---

## 3) One-Time Environment Setup

From project root:

```bash
cd ~/NIDS
cp .env.example .env
```

Edit `.env` and set all required values.

Important values for a successful demo:

- `DB_USER=nids` (must be `nids`, not `root`)
- `KEYCLOAK_CLIENT_SECRET=change_me_client_secret`

Why this matters:

- `DB_USER=root` breaks initial MariaDB bootstrap flow.
- Keycloak client secret must match `keycloak/realm-export.json` for `/auth/login` to work.

Suggested demo-safe baseline:

```dotenv
DB_ROOT_PASSWORD=root
DB_USER=nids
DB_PASSWORD=nids_password
REDIS_PASSWORD=redis_password
KEYCLOAK_ADMIN_USER=admin
KEYCLOAK_ADMIN_PASSWORD=admin
KEYCLOAK_CLIENT_SECRET=change_me_client_secret
STEP_CA_PASSWORD=stepcapassword
INFISICAL_ENCRYPTION_KEY=0123456789abcdef0123456789abcdef
INFISICAL_AUTH_SECRET=demo_auth_secret
ENVIRONMENT=development
MTLS_ENABLED=false
ZTNA_ENABLED=false
```

---

## 4) Clean Startup (Recommended Before Presentation)

Run this once before demo to avoid stale volumes/old lockouts:

```bash
cd ~/NIDS
docker compose down -v
docker compose up -d --build
```

Check service status:

```bash
docker compose ps
```

Expected: most services `Up` and healthy; `app` should be `Up`.

Health check:

```bash
curl -sS http://localhost:8000/health/ready | jq
```

Expected:

- `"status": "ready"`
- components database/redis/keycloak are `"up"`.

---

## 5) UI Endpoints to Open in Browser

Open these tabs before starting explanation:

- API docs: `http://localhost:8000/docs`
- Keycloak: `http://localhost:8080`

These two tabs make the demo visually clear for teachers.

---

## 6) Live Demo Script (Copy/Paste)

Run this in terminal during demo.

```bash
cd ~/NIDS

# 0) Optional safety: clear admin lockout state
source .env
docker exec nids-redis sh -lc \
  "REDISCLI_AUTH='$REDIS_PASSWORD' redis-cli DEL lockout:temp:admin lockout:failures:admin lockout:perm:admin"

# 1) Show system readiness
curl -sS http://localhost:8000/health/ready | jq

# 2) Login as seeded admin user from realm import
TOKEN=$(curl -sS -X POST http://localhost:8000/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"Admin@nids2024!"}' | jq -r '.access_token')

echo "Token length: ${#TOKEN}"

# 3) Show identity and RBAC role
curl -sS http://localhost:8000/auth/me \
  -H "Authorization: Bearer $TOKEN" | jq

# 4) Create a sensor
SENSOR_NAME="demo-sensor-$(date +%s)"
SENSOR=$(curl -sS -X POST http://localhost:8000/sensors/ \
  -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d "{\"name\":\"$SENSOR_NAME\",\"network_segment\":\"172.28.10.0/24\"}")
echo "$SENSOR" | jq

SENSOR_ID=$(echo "$SENSOR" | jq -r '.id')

# 5) Enroll sensor (single-use API key)
ENROLL=$(curl -sS -X POST http://localhost:8000/sensors/$SENSOR_ID/enroll \
  -H "Authorization: Bearer $TOKEN")
echo "$ENROLL" | jq

API_KEY=$(echo "$ENROLL" | jq -r '.api_key')

# 6) Activate sensor using enrollment key
curl -sS -X POST http://localhost:8000/sensors/activate \
  -H 'Content-Type: application/json' \
  -d "{\"api_key\":\"$API_KEY\"}" | jq

# 7) Show sensor inventory count
curl -sS http://localhost:8000/sensors/ \
  -H "Authorization: Bearer $TOKEN" | jq '{total, sensors: [.sensors[].status]}'

# 8) Show recent audit logs
curl -sS "http://localhost:8000/audit/logs?limit=5" \
  -H "Authorization: Bearer $TOKEN" | jq '{total, latest_event: .logs[0].event_type}'

# 9) Trigger security rotation check
curl -sS -X POST http://localhost:8000/security/rotation-health/run \
  -H "Authorization: Bearer $TOKEN" | jq '{total,critical,warning}'
```

---

## 7) What to Say to Your Teacher (Presentation Talk Track)

Use this short narrative while running the commands:

1. "First I verify readiness. This confirms DB, Redis, and Keycloak are reachable by the API."
2. "Now I authenticate through Keycloak. Access control is role-based."
3. "The `/auth/me` call proves the JWT claims include `super_admin` role."
4. "I create a sensor record in pending state."
5. "Enrollment generates a single-use activation key, which is safer than static keys."
6. "Activation moves the sensor to active state."
7. "All actions are recorded in audit logs."
8. "I trigger rotation-health checks to show operational security monitoring."

If asked "Where is AI?":

- Point to anomaly endpoints in Swagger:
  - `GET /security/anomalies`
  - `GET /security/anomalies/risk-score`
- Explain that anomaly features are part of security analytics pipeline and can be inspected via those endpoints.

---

## 8) Common Demo-Day Issues and Quick Fixes

### Issue A: `app` not starting

Check logs:

```bash
docker compose logs --tail=100 app
```

Fix:

- Ensure `.env` has `DB_USER=nids`.
- Ensure `KEYCLOAK_CLIENT_SECRET=change_me_client_secret`.
- Re-run clean start:

```bash
docker compose down -v
docker compose up -d --build
```

### Issue B: `/auth/login` gives lockout response (`423 Locked`)

Clear lockout keys:

```bash
source .env
docker exec nids-redis sh -lc \
  "REDISCLI_AUTH='$REDIS_PASSWORD' redis-cli DEL lockout:temp:admin lockout:failures:admin lockout:perm:admin"
```

### Issue C: Services unhealthy

```bash
docker compose ps
docker compose logs --tail=150 keycloak mariadb redis loki
```

### Issue D: step-ca warning in rotation check

You may see a critical warning when `STEP_CA_FINGERPRINT` is not configured.
This is acceptable for demo if mTLS enrollment is not being actively shown.

---

## 9) Ending the Demo

To stop containers:

```bash
docker compose down
```

To stop and remove all demo data:

```bash
z```

---

## 10) Optional: 60-Second Summary You Can Speak

"This NIDS backend uses a defense-in-depth model. Authentication is centralized with Keycloak, authorization is role-based, sensor onboarding is controlled via single-use enrollment keys, and every critical action is audit logged. The platform also includes rotation and anomaly endpoints for ongoing security monitoring. In this demo I showed end-to-end flow from user authentication to sensor lifecycle and audit visibility."

