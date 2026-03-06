# IDP OIDC Service
import os, time, hmac, json
from fastapi import FastAPI, HTTPException, Form, Request
from cryptography.hazmat.primitives.asymmetric import rsa
import jwt

app = FastAPI()
ISSUER = os.getenv("ISSUER", "http://idp-oidc:8081")
CLIENTS = {"test-user-001": "secret001"}

_key = rsa.generate_private_key(65537, 2048)
_jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(_key.public_key()))
_jwk.update(kid="1", use="sig", alg="RS256")

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
    secret = CLIENTS.get(client_id)
    if secret is None or not hmac.compare_digest(secret, client_secret):
        raise HTTPException(401, "invalid_client")

    return {"status": "authenticated", "client_id": client_id}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8081)