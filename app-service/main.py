# App Service
import os
import ssl
from fastapi import FastAPI
from db import get_db_connection
from auth import POLICY_URL

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
def get_data():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM sensitive_data;")
    data = cursor.fetchall()
    cursor.close()
    conn.close()
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