import os
import ssl
from fastapi import FastAPI, Request
from db import get_db_connection
from auth import POLICY_URL
from siem import send_log_async

app = FastAPI()

@app.get("/")
def home():
    return {
        "service": "app-service",
        "auth_backend": POLICY_URL,
        "message": "Use /app/data for protected data"
    }

@app.get("/app/data")
@app.get("/api/app/data")
async def get_data(request: Request):
    client_ip = request.headers.get("X-Real-IP", request.client.host)
    client_dn = request.headers.get("X-Client-DN", "unknown")

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM sensitive_data;")
    data = cur.fetchall()
    cur.close()
    conn.close()

    await send_log_async("data_access", {
        "client_ip": client_ip,
        "client_dn": client_dn,
        "records": len(data),
    })

    return {"data": data}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        ssl_keyfile=os.getenv("APP_TLS_KEYFILE", "/etc/service-certs/app-service.key"),
        ssl_certfile=os.getenv("APP_TLS_CERTFILE", "/etc/service-certs/app-service.crt"),
        ssl_ca_certs=os.getenv("APP_TLS_CA_CERTS", "/etc/service-certs/ca.pem"),
        ssl_cert_reqs=ssl.CERT_REQUIRED,
    )
