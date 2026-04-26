# Zero Trust Architecture — CSCI-641 Term Project

A containerized Zero Trust Architecture (ZTA) implementation demonstrating continuous, per-request authentication and behavioral trust scoring. Every request is evaluated against a multi-factor trust model regardless of network location. No implicit trust is granted after initial login.

---

## Table of Contents

1. [Architecture Overview](#architecture-overview)
2. [Services](#services)
3. [Trust Scoring Model](#trust-scoring-model)
4. [Certificate Infrastructure](#certificate-infrastructure)
5. [Getting Started](#getting-started)
6. [Running the Tests](#running-the-tests)
7. [Attack Scenarios](#attack-scenarios)
8. [SIEM & Security Dashboard](#siem--security-dashboard)
9. [Project Structure](#project-structure)
10. [Dependencies](#dependencies)
11. [AI Assistance Disclosure](#ai-assistance-disclosure)

---

## Architecture Overview

```
 Client (mTLS cert required)
        |
        v
 ┌─────────────────┐
 │  nginx (PEP)    │  Port 443 — enforces mTLS, routes all traffic
 │  web-server-pep │  Calls /_authz on every protected request
 └────────┬────────┘
          |  HTTPS + mTLS (internal CA)
          v
 ┌─────────────────┐       ┌──────────────┐
 │ Policy Engine   │──────>│   IDP/OIDC   │  Validates credentials & JWTs
 │ (PDP)           │       │   idp-oidc   │  Issues/revokes tokens
 └────────┬────────┘       └──────────────┘
          |  trust score >= threshold?
          v
 ┌─────────────────┐       ┌──────────────┐
 │  App Service    │──────>│  secure-db   │  PostgreSQL (mTLS only)
 │  (resource)     │       │              │  Not routable from host
 └─────────────────┘       └──────────────┘
          |
          v
 ┌─────────────────┐
 │     Splunk      │  All services ship security events via HEC
 │  (SIEM)         │  Dashboard at http://localhost:8001
 └─────────────────┘
```

All inter-service traffic uses mutual TLS authenticated with an internal CA (`internal-certs/ca.pem`). The external-facing nginx uses a separate Client-CA (`web-server-pep/certs/ca.pem`) to verify user client certificates, keeping the two trust domains isolated.

---

## Services

| Service | Container | Port | Description |
|---|---|---|---|
| nginx PEP | `web-server-pep` | 443 | Policy Enforcement Point. mTLS gateway, auth_request on every API call |
| Policy Engine | `policy-engine` | 8080 (internal) | Scores each request, enforces trust threshold, revokes JWTs on anomalies |
| IDP / OIDC | `idp-oidc` | 8081 (internal) | Validates credentials, issues RS256 JWTs, maintains revocation blocklist |
| App Service | `app-service` | 8000 | Protected resource server. Requires a valid, non-revoked JWT |
| Asset DB | `asset-db` | 5432 | Stores credentials and behavioral user profiles |
| Secure DB | `secure-db` | (internal only) | Stores sensitive application data. Only reachable by app-service |
| Splunk | `splunk` | 8001 (UI), 8088 (HEC) | SIEM. Receives structured security events from all Python services |

---

## Trust Scoring Model

Every request is scored before access is granted. The trust threshold is **105 points**.

| Factor | Points | Description |
|---|---|---|
| Known device ID | 30 | `X-Device-ID` header matches a registered device in the user's profile |
| Known client IP | 25 | Source IP matches a previously seen IP for this user |
| Known target URL | 25 | Requested URL is in the user's known URL profile |
| Known time of day | 25 | Request hour matches the user's historical access hours |
| Valid mTLS cert | 25 | nginx confirms `$ssl_client_verify = SUCCESS` |
| **Maximum** | **130** | All factors matched |

A legitimate user with a known device hitting a **new URL** scores 105 (30+25+0+25+25), which just meets the threshold. An attacker with stolen credentials but an unknown device scores 100 (0+25+25+25+25), which is blocked.

### Behavioral Profile Updates

- **New user**: Profile is created on first login and returns 100 points. Combined with mTLS the first request scores 125, passing the threshold.
- **Returning user (score ≥ 50)**: IPs and URLs are added to the profile automatically. Device IDs are **never** auto-enrolled after first login to prevent attacker devices from silently joining a profile.
- **Access denied**: The JWT is immediately revoked via the IDP's `/revoke` endpoint, invalidating any further use of that token across all devices.

---

## Certificate Infrastructure

Two separate CAs are used to enforce trust boundaries:

### Client-CA (`web-server-pep/certs/`)
- Issues the **nginx server certificate** (`cert.pem`) — presented to browsers and clients
- Issues **user client certificates** (`client.crt`) — required for mTLS at the nginx boundary
- Used only between external clients and nginx

### TermProject-CA (`internal-certs/`)
- Issues certificates for all internal services (policy-engine, idp-oidc, app-service, secure-db, nginx-client)
- Used for all service-to-service mTLS
- User-facing `client.crt` is **rejected** by internal services — a stolen user cert cannot bypass nginx and talk directly to app-service

To regenerate the external certs (Client-CA only):
```bash
python gen_certs.py
```
Internal certs are not touched by this script.

---

## Getting Started

### Prerequisites

- Docker Desktop (Windows/Mac) or Docker Engine + Compose (Linux)
- Python 3.9+ with `requests` and `cryptography` packages installed
- ~4 GB free RAM

### First Run

```bash
# 1. Start all services
docker compose up -d --build

# Wait ~60 seconds for all services to initialize

# 2. Seed the behavioral profile with a legitimate login
python tester.py

# 3. Open the Splunk dashboard
# http://localhost:8001  (admin / Admin1234!)
# Navigate to: Apps > ZTA Security Monitor
```

### Stopping

```bash
docker compose down        # keep database volumes
docker compose down -v     # wipe all volumes for a completely fresh start
```

> **Note:** After a full `down -v` restart, run `python tester.py` once before `python attacker.py`. The behavioral profile must exist for attack scenarios 3 and 4 to demonstrate the correct blocking behavior.

---

## Running the Tests

### tester.py — Legitimate User

Simulates a normal login from a registered device and retrieves protected data. Should always succeed with HTTP 200.

```bash
python tester.py
```

What it does:
- Presents `client.crt` for mTLS at the nginx boundary
- POSTs credentials to `/api/login` through the policy engine
- Uses the returned JWT to GET `/api/app/data`

### attacker.py — User-Perspective Attack Scenarios

```bash
python attacker.py
```

| Attack | Method | Expected Result |
|---|---|---|
| 1 — Credential Stuffing | Wrong passwords against known `client_id` | 401 from IDP |
| 2 — Compromised Device + Cert | Real cert, real creds, registered device | **200 — succeeds** (demonstrates physical security gap) |
| 3 — Stolen Credentials, Unknown Device | Real creds, valid cert, unregistered device ID | 403 from policy engine (score 100 < 105) |
| 4 — JWT URL Scanning | Valid JWT used from unknown device on unknown URLs | First probe 403 + JWT revoked, remaining probes 401 |

### attacker_backend.py — Direct Backend Attack Scenarios

```bash
python attacker_backend.py
```

Targets `app-service:8000` and the database directly, bypassing nginx and the policy engine. Demonstrates that the two-CA design prevents user-facing certificates from being accepted by internal services.

---

## Attack Scenarios — Detail

### Attack 1: Credential Stuffing
The attacker knows the `client_id` from network recon and tries a list of common passwords. Every attempt is rejected at the IDP with a 401 because none match the stored HMAC-compared secret.

### Attack 2: Compromised Device and Certificate
The attacker physically compromised the victim's device and extracted the client certificate, private key, and credentials. All five trust factors match — the system cannot distinguish a stolen device from the real user. This is an acknowledged limitation that requires out-of-band controls such as hardware-backed device attestation.

### Attack 3: Stolen Credentials, Unregistered Device
The attacker obtained credentials via phishing or a data breach and has a valid CA-signed client certificate, but is connecting from their own machine with an unrecognized device ID. Missing the device factor drops the score to 100, which falls below the 105 threshold. The policy engine returns 403.

### Attack 4: JWT URL Scanning
The attacker uses valid credentials and a valid device to obtain a JWT, then pivots into web scanning to enumerate common internal API paths that a normal user would not reach. The probe list includes:

- `/api/admin`
- `/api/users`
- `/api/config`
- `/api/internal`
- `/api/debug`

The PEP records each suspicious URL attempt for that client, lowers the URL trust component on repeated probes, and eventually revokes the JWT once the total score falls below threshold. After revocation, later probes return 401 even if the attacker keeps using the same valid device.

---

## SIEM & Security Dashboard

All Python services send structured JSON events to Splunk via HTTP Event Collector (HEC) on port 8088.

**Splunk UI:** `http://localhost:8001`  
**Credentials:** `admin / Admin1234!`  
**Dashboard path:** Apps → ZTA Security Monitor

### Logged Events

| Event | Service | Key Fields |
|---|---|---|
| `auth_success` | idp-oidc | `client_id` |
| `auth_failure` | idp-oidc, policy-engine | `client_id`, `reason` |
| `token_issued` | idp-oidc | `client_id` |
| `token_verified` | idp-oidc | `client_id` |
| `token_revoked` | idp-oidc | `client_id`, `reason` |
| `trust_scored` | policy-engine | `client_id`, `score`, `threshold`, `mtls` |
| `access_granted` | policy-engine | `client_id`, `score`, `device_id`, `client_ip` |
| `access_denied` | policy-engine | `client_id`, `score`, `device_id`, `client_ip` |
| `data_access` | app-service | `client_ip`, `client_dn`, `records` |

### Dashboard Panels

- **KPI row** — Access Denied, Auth Failures, Access Granted, Tokens Revoked, Credential Stuffing attempts (24h)
- **Event timeline** — All event types over the last hour in 1-minute buckets
- **Event type breakdown** — Pie chart of all logged event types
- **Trust score histogram** — Distribution of scores on denied requests
- **Denied by device** — Which device IDs triggered policy denials
- **Recent alerts table** — Color-coded by severity (HIGH / MEDIUM / LOW) for all security events
- **Live event table** — All events with a 10-second auto-refresh

---

## Project Structure

```
TermProject/
├── docker-compose.yml          # Full stack definition
├── tester.py                   # Legitimate user flow test
├── attacker.py                 # User-perspective attack scenarios
├── attacker_backend.py         # Direct backend and database attack scenarios
├── gen_certs.py                # Regenerates external Client-CA and user certs
│
├── web-server-pep/
│   ├── nginx.conf              # PEP — mTLS enforcement, auth_request, proxy rules
│   ├── certs/                  # Client-CA, nginx server cert, user client cert
│   └── html/                   # Static login and home pages
│
├── policy-engine/
│   ├── main.py                 # Trust scoring, JWT revocation, access decisions
│   └── siem.py                 # Splunk HEC event shipper
│
├── idp-oidc/
│   ├── main.py                 # Credential validation, JWT issuance, revocation
│   └── siem.py                 # Splunk HEC event shipper
│
├── app-service/
│   ├── main.py                 # Protected resource endpoint (/api/app/data)
│   └── siem.py                 # Splunk HEC event shipper
│
├── asset-db/
│   └── init.sql                # Schema: auth_clients, users (behavioral profiles)
│
├── secure-db/
│   └── init.sql                # Schema: sensitive_data
│
├── internal-certs/             # TermProject-CA and all internal service certificates
│
└── splunk/
    └── zta_security/           # Pre-built Splunk app mounted into the container
        └── default/
            ├── app.conf
            └── data/ui/views/security_dashboard.xml
```

---

## Dependencies

### Python (host machine)
```
requests
cryptography
```

### Per-service (installed inside Docker images)
- **policy-engine / app-service**: `fastapi`, `uvicorn`, `httpx`, `sqlalchemy`, `asyncpg`
- **idp-oidc**: `fastapi`, `uvicorn`, `httpx`, `psycopg2`, `pyjwt`, `cryptography`

---

## AI Assistance Disclosure

The following were created with the assistance of **Claude** (Anthropic, model `claude-sonnet-4-6`), an AI assistant, as part of an academic project for **CSCI-641, Spring 2026**:

- `README.md` — document drafting
- `gen_certs.py` — certificate generation script using the `cryptography` library
- `splunk/zta_security/` — Splunk app and SPL dashboard queries

All architectural decisions, implementation choices, and testing were performed by the project author.
