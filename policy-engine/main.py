import os
import ssl
from time import time
import httpx
from fastapi import Depends, FastAPI, Request, HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text
from siem import send_log_async

_raw = os.getenv("TRUST_THRESHOLD", "75")
_val = float(_raw)
TRUST_THRESHOLD = int(_val * 100) if _val <= 1.0 else int(_val)

IDP_URL = os.getenv("IDP_URL", "http://idp-oidc:8081")
DB_URL = "postgresql+asyncpg://postgres:postgres@asset-db:5432/postgres"
URL_PENALTY_STEP = 5
URL_BASE_SCORE = 25
URL_SUSPICIOUS_PENALTY = 35

engine = create_async_engine(DB_URL)
SessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
app = FastAPI()

async def get_db():
    async with SessionLocal() as session:
        yield session


async def score_request(client_ip, target_url, device_id, client_id, db):
    if db is None:
        return 0

    res = await db.execute(
        text("SELECT * FROM users WHERE client_id = :cid"),
        {"cid": client_id}
    )
    user = res.mappings().first()
    hour = int(time()) // 3600 % 24
    now = int(time())
    suspicious_attempts = int(user["suspicious_url_attempts"] or 0) if user is not None else 0

    if user is None:
        await db.execute(text("""
            INSERT INTO users (client_id, device_ids, client_ips, common_urls, common_time_of_access, last_seen, suspicious_url_attempts, suspicious_urls)
            VALUES (:client_id, :device_ids, :client_ips, :common_urls, :common_time_of_access, :now, 0, ARRAY[]::TEXT[])
            ON CONFLICT (client_id) DO UPDATE
            SET
                device_ids = ARRAY(SELECT DISTINCT unnest(array_append(users.device_ids, :dev))),
                client_ips = ARRAY(SELECT DISTINCT unnest(array_append(users.client_ips, :ip))),
                common_urls = ARRAY(SELECT DISTINCT unnest(array_append(users.common_urls, :url))),
                common_time_of_access = ARRAY(SELECT DISTINCT unnest(array_append(users.common_time_of_access, :hour))),
                last_seen = :now
        """), {
            "client_id": client_id,
            "device_ids": [device_id],
            "client_ips": [client_ip],
            "common_urls": [target_url],
            "common_time_of_access": [hour],
            "dev": device_id, "ip": client_ip, "url": target_url, "hour": hour, "now": now,
        })
        await db.commit()
        return 100, 0, False

    devices = user["device_ids"] or []
    ips = user["client_ips"] or []
    urls = user["common_urls"] or []
    hours = user["common_time_of_access"] or []
    suspicious_urls = user["suspicious_urls"] or []

    if not (devices or ips or urls or hours):
        await db.execute(text("""
            UPDATE users SET
                device_ids = ARRAY(SELECT DISTINCT unnest(array_append(device_ids, :dev))),
                client_ips = ARRAY(SELECT DISTINCT unnest(array_append(client_ips, :ip))),
                common_urls = ARRAY(SELECT DISTINCT unnest(array_append(common_urls, :url))),
                common_time_of_access = ARRAY(SELECT DISTINCT unnest(array_append(common_time_of_access, :hour))),
                last_seen = :now
            WHERE client_id = :client_id
        """), {"dev": device_id, "ip": client_ip, "url": target_url, "hour": hour, "now": now, "client_id": client_id})
        await db.commit()
        return 100, 0, False

    score = 0
    if device_id in devices:
        score += 30
    if client_ip in ips:
        score += 25
    if hour in hours:
        score += 25

    is_suspicious_url = target_url not in urls

    if not is_suspicious_url:
        url_score = URL_BASE_SCORE
        if suspicious_attempts:
            await db.execute(text("""
                UPDATE users SET
                    suspicious_url_attempts = 0,
                    last_seen = :now
                WHERE client_id = :client_id
            """), {"now": now, "client_id": client_id})
            await db.commit()
    else:
        suspicious_attempts += 1
        if suspicious_attempts == 1:
            url_score = 0
        else:
            url_score = -min(URL_SUSPICIOUS_PENALTY + max(suspicious_attempts - 2, 0) * URL_PENALTY_STEP, 100)
        await db.execute(text("""
            UPDATE users SET
                suspicious_url_attempts = :attempts,
                suspicious_urls = ARRAY(SELECT DISTINCT unnest(array_append(suspicious_urls, :url))),
                last_seen = :now
            WHERE client_id = :client_id
        """), {
            "attempts": suspicious_attempts,
            "url": target_url,
            "now": now,
            "client_id": client_id,
        })
        await db.commit()

    score += url_score

    if score >= 50:
        await db.execute(text("""
            UPDATE users SET
                client_ips = ARRAY(SELECT DISTINCT unnest(array_append(client_ips, :ip))),
                last_seen = :now
            WHERE client_id = :client_id
        """), {"ip": client_ip, "now": now, "client_id": client_id})
        await db.commit()

    return score, suspicious_attempts, is_suspicious_url

@app.post("/authenticate")
async def authenticate(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.body()
    auth_header = request.headers.get("Authorization", "")
    client_ip = request.headers.get("X-Real-IP", "unknown")
    target_url = request.headers.get("X-Target-URL", "unknown")
    device_id = request.headers.get("X-Device-ID", "unknown")
    client_verify = request.headers.get("X-Client-Verify", "")

    async with httpx.AsyncClient() as c:
        idp_resp = await c.post(
            f"{IDP_URL}/authenticate",
            headers=dict(request.headers),
            content=body,
        )

    if idp_resp.status_code != 200:
        await send_log_async("auth_failure", {
            "reason": "idp_rejected",
            "client_ip": client_ip,
            "device_id": device_id,
            "idp_status": idp_resp.status_code,
        })
        raise HTTPException(idp_resp.status_code, idp_resp.json().get("detail", "Authentication failed"))

    client_id = idp_resp.json()["client_id"]
    trust, suspicious_attempts, is_suspicious_url = await score_request(client_ip, target_url, device_id, client_id, db)

    if client_verify == "SUCCESS":
        trust += 25

    await send_log_async("trust_scored", {
        "client_id": client_id,
        "client_ip": client_ip,
        "device_id": device_id,
        "score": trust,
        "threshold": TRUST_THRESHOLD,
        "mtls": client_verify,
    })

    if auth_header.startswith("Bearer ") and is_suspicious_url and suspicious_attempts == 1:
        await send_log_async("access_granted", {
            "client_id": client_id,
            "client_ip": client_ip,
            "device_id": device_id,
            "score": trust,
        })
        return {"status": "authenticated", "client_id": client_id}

    if trust < TRUST_THRESHOLD:
        await send_log_async("access_denied", {
            "client_id": client_id,
            "client_ip": client_ip,
            "device_id": device_id,
            "score": trust,
        })
        if auth_header.startswith("Bearer "):
            tok = auth_header[7:]
            async with httpx.AsyncClient() as c:
                await c.post(f"{IDP_URL}/revoke", json={
                    "token": tok,
                    "client_id": client_id,
                    "reason": "trust_score_too_low",
                })
        raise HTTPException(403, "Access denied by policy engine")

    await send_log_async("access_granted", {
        "client_id": client_id,
        "client_ip": client_ip,
        "device_id": device_id,
        "score": trust,
    })

    if auth_header.startswith("Bearer "):
        return {"status": "authenticated", "client_id": client_id}

    now = int(time())
    await db.execute(text("""
        UPDATE users SET
            suspicious_url_attempts = 0,
            last_seen = :now
        WHERE client_id = :client_id
    """), {"now": now, "client_id": client_id})
    await db.commit()

    async with httpx.AsyncClient() as c:
        req_body = await request.json() if body else {}
        token_resp = await c.post(
            f"{IDP_URL}/token",
            data={
                "grant_type": "client_credentials",
                "client_id": client_id,
                "client_secret": req_body.get("client_secret", ""),
            },
        )

    if token_resp.status_code != 200:
        raise HTTPException(500, "Failed to issue token")

    return token_resp.json()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8080,
        ssl_keyfile=os.getenv("POLICY_TLS_KEYFILE", "/etc/service-certs/policy-engine.key"),
        ssl_certfile=os.getenv("POLICY_TLS_CERTFILE", "/etc/service-certs/policy-engine.crt"),
        ssl_ca_certs=os.getenv("POLICY_TLS_CA_CERTS", "/etc/service-certs/ca.pem"),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
