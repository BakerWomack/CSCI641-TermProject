# Policy Engine
import os
from time import time
import httpx
from fastapi import Depends, FastAPI, Request, HTTPException
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from sqlalchemy.orm import sessionmaker
from sqlalchemy import text

TRUST_THRESHOLD = int(os.getenv("TRUST_THRESHOLD", "75"))
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

    user_info = result.fetchone()

    if user_info is None:
        return 0
    
    stored_device_ids = user_info["device_ids"]
    if device_id in stored_device_ids:
        score += 25
    
    stored_client_ips = user_info["client_ips"]
    if client_ip in stored_client_ips:
        score += 25
    
    stored_common_urls = user_info["common_urls"]
    if target_url in stored_common_urls:
        score += 25
    current_hour = int(time()) // 3600 % 24
    common_time_of_access = user_info["common_time_of_access"]
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
            "now": int(time()),
            "client_id": client_id
        })
        await db.commit()

    return score


app = FastAPI(title="Policy Engine")

@app.post("/authenticate")
async def authenticate(request: Request, db: AsyncSession = Depends(get_db)):
    body = await request.body()
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

    trust_score = await calculate_trust_score(client_ip, target_url, device_id, client_id, db)
    if trust_score < TRUST_THRESHOLD:
        raise HTTPException(403, "Access denied by policy engine")

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
    uvicorn.run(app, host="0.0.0.0", port=8080)