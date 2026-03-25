import json
from pathlib import Path

import requests

BASE_URL = "https://localhost"
CLIENT_ID = "test-user-001"
CLIENT_SECRET = "secret000"
DEVICE_ID = "dev-alice-laptop-001"
CLIENT_CERT = "web-server-pep/certs/client.crt"
CLIENT_KEY = "web-server-pep/certs/client.key"
CA_CERT = "web-server-pep/certs/ca.pem"
VERIFY_TLS = True


def ensure_file(path_str: str, label: str):
    path = Path(path_str)
    if not path.exists():
        raise FileNotFoundError(f"{label} not found: {path}")
    return str(path)


def pretty_print(title: str, response: requests.Response):
    print(f"\n=== {title} ===")
    print(f"Status: {response.status_code}")
    try:
        print(json.dumps(response.json(), indent=2))
    except ValueError:
        print(response.text)


def main():
    cert_path = ensure_file(CLIENT_CERT, "Client cert")
    key_path = ensure_file(CLIENT_KEY, "Client key")
    verify = ensure_file(CA_CERT, "CA bundle") if VERIFY_TLS else False

    session = requests.Session()
    session.cert = (cert_path, key_path)
    session.verify = verify
    session.headers.update({"X-Device-ID": DEVICE_ID})

    login_url = f"{BASE_URL.rstrip('/')}/api/login"
    data_url = f"{BASE_URL.rstrip('/')}/api/app/data"

    login_payload = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }

    try:
        login_resp = session.post(login_url, json=login_payload, timeout=20)
    except requests.RequestException as exc:
        print(f"Login request failed: {exc}")
        return 1

    pretty_print("Login Response", login_resp)

    if login_resp.status_code != 200:
        print("Login failed")
        return 1

    token = login_resp.json().get("access_token")
    if not token:
        print("No access_token returned by login endpoint.")
        return 1

    session.headers.update({"Authorization": f"Bearer {token}"})

    try:
        data_resp = session.get(data_url, timeout=20)
    except requests.RequestException as exc:
        print(f"Protected data request failed: {exc}")
        return 1

    pretty_print("Protected Data Response", data_resp)

    if data_resp.status_code != 200:
        print("Protected data call failed.")
        return 1

    print("\nSuccess: mTLS login and protected data retrieval both succeeded.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except FileNotFoundError as exc:
        print(str(exc))
        raise SystemExit(1)
