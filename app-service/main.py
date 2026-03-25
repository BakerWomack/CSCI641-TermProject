# App Service
from fastapi import FastAPI, Depends
from db import get_db_connection
from auth import verify_token

app = FastAPI()

@app.get("/app/data")
def get_data(user=Depends(verify_token)):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM sensitive_data;")
    data = cursor.fetchall()

    cursor.close()
    conn.close()

    return {"user": user, "data": data}