# CSCI-641 Term Project — Zero Trust Architecture

## Overview

A containerized Zero Trust Architecture (ZTA) demonstrating policy-based access control, identity verification, and continuous monitoring across segmented network zones.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                       control_net (internal)                │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ policy-engine│  │   idp-oidc   │  │   asset-db   │      │
│  │   :8080      │  │   :8081      │  │   :5432      │      │
│  └──────┬───────┘  └──────────────┘  └──────────────┘      │
├─────────┼───────────────────────────────────────────────────┤
│         │           frontend_net                            │
│  ┌──────┴───────┐              ┌──────────────┐             │
│  │web-server-pep│──────────────│  app-service  │            │
│  │  (nginx) :443│              │   :8000       │            │
│  └──────────────┘              └──────┬───────┘             │
├───────────────────────────────────────┼─────────────────────┤
│                       backend_net (internal)                │
│                                ┌──────────────┐             │
│                                │  secure-db   │             │
│                                │   :5432      │             │
│                                └──────────────┘             │
├─────────────────────────────────────────────────────────────┤
│  siem_net + all nets                                        │
│  ┌──────────────┐                                           │
│  │     SIEM     │                                           │
│  │   :9000      │                                           │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

## TODO

### Policy Engine (`policy-engine/`)
- [ ] Implement `/evaluate` endpoint — accept access requests, return permit/deny decisions
- [ ] Integrate with IdP to validate JWT tokens on each request
- [ ] Connect to `asset-db` to load and query access policies
- [ ] Implement policy CRUD endpoints (`GET /policies`, `POST /policies`, etc.)
- [ ] Define policy schema/model (subject, resource, action, effect, conditions)
- [ ] Add environment variable configuration (DB host, IdP URL, etc.)
- [ ] Add `requirements.txt` dependencies (Flask, psycopg2, PyJWT, requests)
- [ ] Write unit tests

### Identity Provider (`idp-oidc/`)
- [ ] Implement `/token` endpoint — issue JWT access tokens
- [ ] Implement `/introspect` endpoint — validate tokens for the policy engine
- [ ] Expose OIDC discovery (`/.well-known/openid-configuration`)
- [ ] Expose JWKS endpoint (`/.well-known/jwks.json`)
- [ ] Generate and manage RSA/EC signing keys (replace hardcoded secret)
- [ ] Implement user/client authentication (currently a stub)
- [ ] Add `requirements.txt` dependencies (Flask, PyJWT, cryptography)
- [ ] Write unit tests

### Asset Database (`asset-db/`)
- [ ] Design schema — policies, assets, subjects tables
- [ ] Write `init.sql` to create tables and seed default data
- [ ] Add environment variables to `docker-compose.yml` (POSTGRES_DB, user, password)
- [ ] Mount `init.sql` into `/docker-entrypoint-initdb.d/`
- [ ] Add a persistent volume for data

### Web Server / PEP (`web-server-pep/`)
- [ ] Configure Nginx as a reverse proxy to `app-service`
- [ ] Add `auth_request` subrequest to policy engine for every protected route
- [ ] Generate self-signed TLS certificates for HTTPS (port 443)
- [ ] Mount `nginx.conf` and certs into the container
- [ ] Set up `depends_on` for policy-engine and app-service

### App Service (`app-service/`)
- [ ] Implement `/api/data` GET/POST endpoints (business logic)
- [ ] Connect to `secure-db` for persistent storage
- [ ] Add environment variable configuration (DB host, credentials)
- [ ] Add `requirements.txt` dependencies (Flask, psycopg2, requests)
- [ ] Write unit tests

### Secure Database (`secure-db/`)
- [ ] Design schema — application data and audit log tables
- [ ] Write `init.sql` to create tables
- [ ] Add environment variables to `docker-compose.yml`
- [ ] Mount `init.sql` into `/docker-entrypoint-initdb.d/`
- [ ] Add a persistent volume for data

### SIEM (`siem/`)
- [ ] Configure Elasticsearch (single-node, port 9000)
- [ ] Write `elasticsearch.yml` with cluster settings
- [ ] Mount config into container
- [ ] Add persistent volume for data
- [ ] Set up log ingestion from other services (Filebeat / Fluentd / direct HTTP)
- [ ] Create index templates for security events

### Docker Compose (`docker-compose.yml`)
- [ ] Add `environment:` blocks with credentials and config for each service
- [ ] Add `volumes:` for database persistence and config mounts
- [ ] Pin Elasticsearch to a specific image version
- [ ] Add `.env` file for secrets

### Cross-Cutting
- [ ] End-to-end test: client → PEP → policy engine → IdP → permit/deny → app-service
- [ ] Logging: structured logs from all services forwarded to SIEM
- [ ] Documentation: architecture diagram, setup instructions, API reference
- [ ] CI pipeline (optional): lint, test, build images