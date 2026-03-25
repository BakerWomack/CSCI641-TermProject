import os
import httpx
from fastapi import Depends, HTTPException


POLICY_URL = os.getenv("POLICY_URL", "http://policy-engine:8080/authenticate")

async def verify_token(request: Request):
    async with httpx.AsyncClient() as client:
        resp = await client.post(POLICY_URL, headers=request.headers)
    if resp.status_code != 200:
        raise HTTPException(resp.status_code, resp.text)
    return resp.json()