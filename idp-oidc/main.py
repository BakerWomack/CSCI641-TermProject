import os, time, hmac, json
import psycopg2
from fastapi import FastAPI, HTTPException, Form, Request
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt
from siem import send_log

app = FastAPI()

ISSUER = os.getenv("ISSUER", "http://idp-oidc:8081")
ASSET_DB_HOST = os.getenv("ASSET_DB_HOST", "asset-db")
ASSET_DB_PORT = int(os.getenv("ASSET_DB_PORT", "5432"))
ASSET_DB_USER = os.getenv("ASSET_DB_USER", "postgres")
ASSET_DB_PASSWORD = os.getenv("ASSET_DB_PASSWORD", "postgres")
ASSET_DB_NAME = os.getenv("ASSET_DB_NAME", "postgres")

_key = rsa.generate_private_key(65537, 2048)
_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_key.public_key()))
_jwk.update(kid="1", use="sig", alg="RS256")

revoked = set()


def get_db_connection():
    return psycopg2.connect(
        host=ASSET_DB_HOST,
        port=ASSET_DB_PORT,
        user=ASSET_DB_USER,
        password=ASSET_DB_PASSWORD,
        dbname=ASSET_DB_NAME,
    )


def get_client_secret(client_id):
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT client_secret FROM auth_clients WHERE client_id = %s AND active = TRUE",
            (client_id,),
        )
        row = cur.fetchone()
        cur.close()
        return row[0] if row else None
    finally:
        conn.close()


@app.post("/authenticate")
async def authenticate(request: Request):
    auth_header = request.headers.get("Authorization", "")

    if auth_header.startswith("Bearer "):
        tok = auth_header[7:]
        if tok in revoked:
            send_log("auth_failure", {"reason": "token_revoked"})
            raise HTTPException(401, "Token revoked")
        try:
            claims = jwt.decode(tok, _key.public_key(), algorithms=["RS256"], issuer=ISSUER,
                                options={"verify_aud": False})
            send_log("token_verified", {"client_id": claims["sub"]})
            return {"status": "authenticated", "client_id": claims["sub"]}
        except jwt.ExpiredSignatureError:
            send_log("auth_failure", {"reason": "token_expired"})
            raise HTTPException(401, "Token expired")
        except jwt.InvalidTokenError as e:
            send_log("auth_failure", {"reason": str(e)})
            raise HTTPException(401, f"Invalid token: {e}")

    body = await request.json()
    client_id = body.get("client_id", "")
    client_secret = body.get("client_secret", "")
    secret = get_client_secret(client_id)

    if secret is None or not hmac.compare_digest(secret, client_secret):
        send_log("auth_failure", {"client_id": client_id, "reason": "bad_secret"})
        raise HTTPException(401, "invalid_client")

    send_log("auth_success", {"client_id": client_id})
    return {"status": "authenticated", "client_id": client_id}


@app.post("/revoke")
async def revoke(request: Request):
    body = await request.json()
    tok = body.get("token", "")
    client_id = body.get("client_id", "unknown")
    revoked.add(tok)
    send_log("token_revoked", {"client_id": client_id, "reason": body.get("reason", "")})
    return {"status": "revoked"}


@app.post("/token")
async def token(grant_type: str = Form(...), client_id: str = Form(...), client_secret: str = Form(...)):
    if grant_type != "client_credentials":
        raise HTTPException(400, "unsupported_grant_type")

    secret = get_client_secret(client_id)
    if secret is None or not hmac.compare_digest(secret, client_secret):
        send_log("token_denied", {"client_id": client_id})
        raise HTTPException(401, "invalid_client")

    now = int(time.time())
    claims = {
        "iss": ISSUER,
        "sub": client_id,
        "iat": now,
        "exp": now + 3600,
        "scope": "api.read",
    }
    access_token = jwt.encode(claims, _key, algorithm="RS256", headers={"kid": "1"})
    send_log("token_issued", {"client_id": client_id})

    return {"access_token": access_token, "token_type": "Bearer", "expires_in": 3600}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)
