# IDP OIDC Service
import os, time, hmac, json
import psycopg2
from fastapi import FastAPI, HTTPException, Form, Request
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

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


def get_db_connection():
    return psycopg2.connect(
        host=ASSET_DB_HOST,
        port=ASSET_DB_PORT,
        user=ASSET_DB_USER,
        password=ASSET_DB_PASSWORD,
        dbname=ASSET_DB_NAME,
    )


def get_client_secret(client_id: str):
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT client_secret FROM auth_clients WHERE client_id = %s AND active = TRUE",
            (client_id,),
        )
        row = cursor.fetchone()
        cursor.close()
        return row[0] if row else None
    finally:
        conn.close()

@app.post("/authenticate")
async def authenticate(request: Request):
    auth_header = request.headers.get("Authorization", "")

    if auth_header.startswith("Bearer "):
        tok = auth_header[7:]
        try:
            pub_key = _key.public_key()
            claims = jwt.decode(tok, pub_key, algorithms=["RS256"], issuer=ISSUER,
                                options={"verify_aud": False})
            return {"status": "authenticated", "client_id": claims["sub"]}
        except jwt.ExpiredSignatureError:
            raise HTTPException(401, "Token expired")
        except jwt.InvalidTokenError as e:
            raise HTTPException(401, f"Invalid token: {e}")

    body = await request.json()
    client_id = body.get("client_id", "")
    client_secret = body.get("client_secret", "")
    secret = get_client_secret(client_id)
    if secret is None or not hmac.compare_digest(secret, client_secret):
        raise HTTPException(401, "invalid_client")

    return {"status": "authenticated", "client_id": client_id}


@app.post("/token")
async def token(grant_type: str = Form(...), client_id: str = Form(...), client_secret: str = Form(...)):
    if grant_type != "client_credentials":
        raise HTTPException(400, "unsupported_grant_type")

    secret = get_client_secret(client_id)
    if secret is None or not hmac.compare_digest(secret, client_secret):
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

    return {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": 3600,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)