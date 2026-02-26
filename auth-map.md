# Authentication Map for AI-Based NIDS

This document outlines the authentication and authorization strategy for the AI-Based Network Intrusion Detection System (NIDS).

## 1. Overview
Security is paramount for a NIDS. The system must protect sensitive network data and ensure that only authorized entities (users and sensors) can interact with the infrastructure.

## 2. User Authentication (Human Access)
Target Audience: Administrators, Security Analysts, Auditors.

### Strategy
- **Primary Method**: Multi-Factor Authentication (MFA) is mandatory for all administrative access.
- **Protocol**: OIDC (OpenID Connect) / OAuth2 for SSO integration (e.g., Google Workspace, GitHub, Azure AD).
- **Identity Provider**: [Keycloak](https://www.keycloak.org/) (open-source, self-hosted).
- **Fallback**: Strong password policies (minimum 14 chars, complexity rules) with Argon2id hashing for local accounts (if external IdP is unavailable).

### Session Management
- **Idle Timeout**: 15 minutes of inactivity triggers re-authentication.
- **Absolute Timeout**: Sessions expire after 8 hours regardless of activity.
- **Concurrent Sessions**: Maximum 2 active sessions per user. New logins revoke the oldest session.
- **Session Storage**: Server-side sessions stored in Redis (open-source).

### Brute-Force & Lockout Policy
- **Temporary Lockout**: Account locked for 15 minutes after 5 failed login attempts.
- **Progressive Delay**: Exponential backoff on repeated failures.
- **Permanent Lock**: After 20 failed attempts in 24 hours, account requires manual unlock by a Super Admin.
- **Alerting**: Failed login bursts trigger an alert to the Security Analyst dashboard.
- **Tool**: [fail2ban](https://github.com/fail2ban/fail2ban) (open-source) for IP-level blocking.

### Roles & Permissions (RBAC)
| Role | Description | Capabilities | Data Visibility |
| :--- | :--- | :--- | :--- |
| **Super Admin** | Full system control | Manage users, configure global settings, deploy updates, view all logs. | Full access |
| **Security Analyst** | Operational monitoring | View dashboards, investigate alerts, acknowledge incidents, generate reports. | Masked PII, masked raw payloads |
| **Auditor** | Compliance & Review | Read-only access to audit logs and configuration history. | Masked PII, no raw payloads |
| **Sensor Manager** | Device provisioning | Generate/Revoke sensor API keys, view sensor health status. | Sensor metadata only |

### Data Masking Policy
- **PII Fields** (IPs, hostnames, usernames in captured traffic): Masked for Analyst and Auditor roles by default. Super Admin can unmask with an audit log entry.
- **Raw Payloads**: Visible only to Super Admin. Analysts see metadata and alert summaries.
- **Tool**: Application-level masking in the API response layer based on RBAC role claims in the JWT.

## 3. Sensor Authentication (Machine-to-Machine)
Target Entities: Distributed network sensors/agents collecting traffic.

### Strategy
- **Primary Method**: **Mutual TLS (mTLS)** using a private PKI (Public Key Infrastructure).
    - *Why*: Ensures both the server and the sensor verify each other's identity. Prevents rogue sensors/servers.
    - **PKI Tool**: [step-ca](https://smallstep.com/docs/step-ca/) (open-source) for automated certificate issuance and renewal.
- **Alternative/Bootstrap**: **API Keys** (High Entropy, 256-bit) used *only* for initial enrollment (CSR generation).
    - Keys are **single-use** and expire after **1 hour**.
    - Keys allow a new sensor to request a certificate signing.
    - Once signed, the bootstrap key is immediately revoked.
    - Once signed, the certificate is used for all data transmission.

### Identity Management
- Each sensor is assigned a unique UUID.
- Certificates are short-lived (e.g., 30 days) and automatically rotated by the sensor agent via ACME protocol (supported by step-ca).

### Certificate Revocation
- **Method**: CRL (Certificate Revocation List) published by step-ca, checked by the server on each connection.
- **Emergency Revocation**: Super Admin or Sensor Manager can instantly revoke a sensor cert via the dashboard. The server reloads the CRL within 60 seconds.
- **Automatic Revocation**: Sensor certificates are revoked if the sensor fails 3 consecutive health checks (indicates possible compromise or decommissioning).

## 4. API Security (Backend Interfaces)
The backend API serves both the Dashboard (Users) and Sensors.

### Public/External Endpoints
- **Authentication**: JWT (JSON Web Tokens) in `Authorization: Bearer <token>` header.
- **Token Lifecycle**:
    - **Access Tokens**: Short-lived (15 minutes).
    - **Refresh Tokens**: Longer-lived (7 days), stored server-side, rotated on each use (rotation invalidates old token).
    - **Revocation**: Refresh tokens can be revoked immediately via the API (e.g., on logout, password change, or detected compromise). Stored in Redis for fast lookup.
    - **Signing**: RS256 using keys managed by Keycloak.
- **Protection**:
    - **Rate Limiting**: Per IP/Token to prevent DoS. Tool: [Nginx](https://nginx.org/) rate limiting module (open-source) or application-level with [Flask-Limiter](https://github.com/alisaifee/flask-limiter) / [express-rate-limit](https://github.com/express-rate-limit/express-rate-limit).
    - **Input Validation**: Strict schema validation (Pydantic for Python / Zod for TypeScript) to prevent injection attacks.
    - **CORS**: Environment-aware allowlist:
        - Production: `https://dashboard.example.com`
        - Staging: `https://staging-dashboard.example.com`
        - Development: `http://localhost:3000`

### Internal Services (Microservices)
- **Authentication**: mTLS with certificates issued by step-ca, or Service Mesh (e.g., [Linkerd](https://linkerd.io/) — open-source, CNCF graduated).
- **Network Policy**: Deny-all by default. Only allow necessary service-to-service communication.
- **Service Certificate Rotation**: Automatic via step-ca, 7-day expiry for internal service certs.

## 5. Secrets Management
- **Tool**: [Mozilla SOPS](https://github.com/getsops/sops) (open-source) for encrypting secrets in config files at rest, combined with [age](https://github.com/FiloSottile/age) encryption.
- **Alternative for runtime secrets**: [Infisical](https://infisical.com/) (open-source, self-hosted) for centralized secret injection into services.
- **Secrets Covered**:
    - Database credentials
    - JWT signing keys (managed by Keycloak)
    - CA root key (step-ca — stored offline or in HSM if available)
    - Bootstrap API key generation secrets
- **Policy**:
    - No secrets in source code or environment variables in plain text.
    - All secrets rotated on a defined schedule (90 days for DB creds, signing keys managed by Keycloak automatically).

## 6. Data Privacy & Integrity
- **Encryption in Transit**: TLS 1.3 for all communications (HTTPS/gRPC).
- **Encryption at Rest**:
    - Database volumes encrypted using LUKS (Linux Unified Key Setup — built-in, free).
    - Sensitive fields (e.g., captured payloads, passwords) encrypted at the application level using AES-256-GCM.
- **Audit Logging**:
    - All authentication attempts (success/failure), configuration changes, and data access events are logged.
    - **Tamper-proof strategy**:
        - Logs are append-only (immutable) — written to [Loki](https://grafana.com/oss/loki/) (open-source, by Grafana Labs).
        - Each log entry includes a SHA-256 hash chain linking it to the previous entry, making tampering detectable.
        - Logs are shipped in near real-time to a separate, restricted log aggregation server.
        - Only Super Admin has access to the log infrastructure; no role can delete logs.

## 7. Implementation Roadmap

### Phase 1: Foundation
- [ ] Deploy Keycloak for User Auth (OIDC/OAuth2, MFA).
- [ ] Implement Super Admin and Sensor Manager roles in Keycloak.
- [ ] Implement session management (Redis-backed, timeouts).
- [ ] Implement brute-force protection (fail2ban + application-level lockout).
- [ ] Implement basic Sensor Auth (single-use API Keys over TLS for enrollment).
- [ ] Setup SOPS + age for secrets management.
- [ ] Restrict Phase 1 sensors to a trusted network segment (no public exposure until mTLS is active).

### Phase 2: Enhanced Security
- [ ] Deploy step-ca as the private CA.
- [ ] Replace Sensor API Keys with mTLS (step-ca issued certs).
- [ ] Implement certificate revocation (CRL via step-ca).
- [ ] Implement full RBAC (Analyst, Auditor roles) with data masking.
- [ ] Implement JWT access/refresh token lifecycle with revocation (Redis).
- [ ] Deploy Loki for append-only, hash-chained audit logging.
- [ ] Implement environment-aware CORS allowlist.

### Phase 3: Advanced
- [ ] Deploy Linkerd service mesh for internal mTLS.
- [ ] Anomaly Detection on Auth Logs (AI-driven detection of compromised accounts).
- [ ] Zero Trust Network Access (ZTNA) principles integration.
- [ ] Deploy Infisical for centralized runtime secrets management.
- [ ] Automated certificate and secret rotation health checks with alerting.
