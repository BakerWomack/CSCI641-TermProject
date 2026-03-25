# Policy Engine
import os
import ssl
from time import time
import httpx
from fastapi import Depends, FastAPI, Request, HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

def parse_trust_threshold(raw: str) -> int:
    value = float(raw)
    if value <= 1.0:
        return int(value * 100)
    return int(value)


TRUST_THRESHOLD = parse_trust_threshold(os.getenv("TRUST_THRESHOLD", "75"))
IDP_URL = os.getenv("IDP_URL", "http://idp-oidc:8081")

DATABASE_URL = "postgresql+asyncpg://postgres:postgres@asset-db:5432/postgres"
engine = create_async_engine(DATABASE_URL)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

async def get_db():
    async with AsyncSessionLocal() as session:
        yield session

async def calculate_trust_score(client_ip: str, target_url: str, device_id: str, client_id: str, db: AsyncSession) -> int:

    score = 0
    if db is None:
        return 0
    
    result = await db.execute(
        text("SELECT * FROM users WHERE client_id = :client_id"), 
        {"client_id": client_id}
    )

    user_info = result.mappings().first()
    current_hour = int(time()) // 3600 % 24
    now = int(time())

    if user_info is None:
        insert_stmt = text("""
            INSERT INTO users (client_id, device_ids, client_ips, common_urls, common_time_of_access, last_seen)
            VALUES (:client_id, :device_ids, :client_ips, :common_urls, :common_time_of_access, :now)
            ON CONFLICT (client_id) DO UPDATE
            SET
                device_ids = ARRAY(SELECT DISTINCT unnest(array_append(users.device_ids, :dev))),
                client_ips = ARRAY(SELECT DISTINCT unnest(array_append(users.client_ips, :ip))),
                common_urls = ARRAY(SELECT DISTINCT unnest(array_append(users.common_urls, :url))),
                common_time_of_access = ARRAY(SELECT DISTINCT unnest(array_append(users.common_time_of_access, :hour))),
                last_seen = :now
        """)
        await db.execute(insert_stmt, {
            "client_id": client_id,
            "device_ids": [device_id],
            "client_ips": [client_ip],
            "common_urls": [target_url],
            "common_time_of_access": [current_hour],
            "dev": device_id,
            "ip": client_ip,
            "url": target_url,
            "hour": current_hour,
            "now": now,
        })
        await db.commit()
        return 100

    stored_device_ids = user_info["device_ids"] or []
    stored_client_ips = user_info["client_ips"] or []
    stored_common_urls = user_info["common_urls"] or []
    common_time_of_access = user_info["common_time_of_access"] or []

    has_behavioral_baseline = any([
        len(stored_device_ids) > 0,
        len(stored_client_ips) > 0,
        len(stored_common_urls) > 0,
        len(common_time_of_access) > 0,
    ])

    if not has_behavioral_baseline:
        update_stmt = text("""
            UPDATE users
            SET
                device_ids = ARRAY(SELECT DISTINCT unnest(array_append(device_ids, :dev))),
                client_ips = ARRAY(SELECT DISTINCT unnest(array_append(client_ips, :ip))),
                common_urls = ARRAY(SELECT DISTINCT unnest(array_append(common_urls, :url))),
                common_time_of_access = ARRAY(SELECT DISTINCT unnest(array_append(common_time_of_access, :hour))),
                last_seen = :now
            WHERE client_id = :client_id
        """)
        await db.execute(update_stmt, {
            "dev": device_id,
            "ip": client_ip,
            "url": target_url,
            "hour": current_hour,
            "now": now,
            "client_id": client_id,
        })
        await db.commit()
        return 100

    if device_id in stored_device_ids:
        score += 25

    if client_ip in stored_client_ips:
        score += 25

    if target_url in stored_common_urls:
        score += 25

    if current_hour in common_time_of_access:
        score += 25
    
    if score >= 50: 
        update_stmt = text("""
            UPDATE users 
            SET 
                device_ids = ARRAY(SELECT DISTINCT unnest(array_append(device_ids, :dev))),
                client_ips = ARRAY(SELECT DISTINCT unnest(array_append(client_ips, :ip))),
                common_urls = ARRAY(SELECT DISTINCT unnest(array_append(common_urls, :url))),
                last_seen = :now
            WHERE client_id = :client_id
        """)
        await db.execute(update_stmt, {
            "dev": device_id,
            "ip": client_ip,
            "url": target_url,
            "now": now,
            "client_id": client_id
        })
        await db.commit()

    return score


app = FastAPI(title="Policy Engine")

@app.post("/authenticate")
async def authenticate(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.body()
    auth_header = request.headers.get("Authorization", "")
    async with httpx.AsyncClient() as client:
        idp_resp = await client.post(
            f"{IDP_URL}/authenticate",
            headers=dict(request.headers),
            content=body,
        )

    if idp_resp.status_code != 200:
        raise HTTPException(idp_resp.status_code, idp_resp.json().get("detail", "Authentication failed"))

    idp_data = idp_resp.json()
    client_id = idp_data["client_id"]

    client_ip = request.headers.get("X-Real-IP", "unknown")
    target_url = request.headers.get("X-Target-URL", "unknown")
    device_id = request.headers.get("X-Device-ID", "unknown")
    client_verify = request.headers.get("X-Client-Verify", "")

    trust_score = await calculate_trust_score(client_ip, target_url, device_id, client_id, db)
    if client_verify == "SUCCESS":
        trust_score += 25

    if trust_score < TRUST_THRESHOLD:
        raise HTTPException(403, "Access denied by policy engine")

    if auth_header.startswith("Bearer "):
        return {"status": "authenticated", "client_id": client_id}

    async with httpx.AsyncClient() as client:
        req_body = await request.json() if body else {}
        token_resp = await client.post(
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