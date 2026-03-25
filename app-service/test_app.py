from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_no_token():
    response = client.get("/app/data")
    assert response.status_code == 401

def test_invalid_token():
    response = client.get("/app/data", headers={"Authorization": "Bearer invalid_token"})
    assert response.status_code == 403
