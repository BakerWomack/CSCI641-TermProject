import os, time, httpx

SIEM = os.getenv("SIEM_URL", "http://splunk:8088")
SVC = os.getenv("SERVICE_NAME", "app-service")
HEC_TOKEN = os.getenv("HEC_TOKEN", "security-hec-token")
HEADERS = {"Authorization": f"Splunk {HEC_TOKEN}"}


def send_log(event, data):
    doc = {"@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "service": SVC, "event": event, **data}
    try:
        with httpx.Client(timeout=2.0) as c:
            c.post(f"{SIEM}/services/collector/event", json={"event": doc, "sourcetype": "_json"}, headers=HEADERS)
    except:
        pass


async def send_log_async(event, data):
    doc = {"@timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "service": SVC, "event": event, **data}
    try:
        async with httpx.AsyncClient(timeout=2.0) as c:
            await c.post(f"{SIEM}/services/collector/event", json={"event": doc, "sourcetype": "_json"}, headers=HEADERS)
    except:
        pass
