import json
import requests

BASE_URL = "https://localhost"
CA_CERT = "web-server-pep/certs/ca.pem"
CERT = ("web-server-pep/certs/client.crt", "web-server-pep/certs/client.key")

KNOWN_DEVICE = "dev-alice-laptop-001"
CLIENT_ID = "test-user-001"
REAL_SECRET = "secret001"


def show(label, resp):
    print(f"\n-- {label} --")
    print(f"status: {resp.status_code}")
    try:
        print(json.dumps(resp.json(), indent=2))
    except:
        print(resp.text[:200])


def credential_stuffing():
    print("Credential stuffing attack")
    s = requests.Session()
    s.cert = CERT
    s.verify = CA_CERT
    s.headers.update({"X-Device-ID": KNOWN_DEVICE})

    guesses = ["password", "secret", "admin123", "letmein", "test123"]

    for guess in guesses:
        try:
            r = s.post(
                f"{BASE_URL}/api/login",
                json={"client_id": CLIENT_ID, "client_secret": guess},
                timeout=10,
            )
            print(f"'{guess}' -> {r.status_code}")
            if r.status_code == 200:
                return r.json().get("access_token")
        except requests.exceptions.RequestException as e:
            print(f"  error: {e}")
    return None


def compromised_device_and_cert():
    print("Compromised device + cert")

    s = requests.Session()
    s.cert = CERT
    s.verify = CA_CERT
    s.headers.update({"X-Device-ID": KNOWN_DEVICE})

    try:
        login = s.post(
            f"{BASE_URL}/api/login",
            json={"client_id": CLIENT_ID, "client_secret": REAL_SECRET},
            timeout=10,
        )
        show("login", login)
    except requests.exceptions.RequestException as e:
        print(f"  error: {e}")
        return None

    if login.status_code != 200:
        print("  login failed")
        return None

    token = login.json().get("access_token")
    s.headers.update({"Authorization": f"Bearer {token}"})

    try:
        data = s.get(f"{BASE_URL}/api/app/data", timeout=10)
        show("data", data)
    except requests.exceptions.RequestException as e:
        print(f"  error: {e}")

    return token


def compromised_credentials_unknown_device():
    print("Compromised credentials, unknown device")

    s = requests.Session()
    s.cert = CERT
    s.verify = CA_CERT
    s.headers.update({"X-Device-ID": "attacker-laptop-kali"})

    try:
        r = s.post(
            f"{BASE_URL}/api/login",
            json={"client_id": CLIENT_ID, "client_secret": REAL_SECRET},
            timeout=10,
        )
        show("result", r)
    except requests.exceptions.RequestException as e:
        print(f"  error: {e}")


def jwt_url_scanning():
    print("URL scanning")

    s = requests.Session()
    s.cert = CERT
    s.verify = CA_CERT
    s.headers.update({"X-Device-ID": KNOWN_DEVICE})

    try:
        login = s.post(
            f"{BASE_URL}/api/login",
            json={"client_id": CLIENT_ID, "client_secret": REAL_SECRET},
            timeout=10,
        )
    except requests.exceptions.RequestException as e:
        print(f"  login error: {e}")
        return

    if login.status_code != 200:
        print(f"  login failed: {login.status_code}")
        return

    token = login.json().get("access_token")

    scan_session = requests.Session()
    scan_session.cert = CERT
    scan_session.verify = CA_CERT
    scan_session.headers.update({
        "Authorization": f"Bearer {token}",
        "X-Device-ID": "attacker-laptop-kali",
    })

    scan_targets = [
        "/api/admin",
        "/api/users",
        "/api/config",
        "/api/internal",
        "/api/debug",
    ]

    for url in scan_targets:
        try:
            r = scan_session.get(f"{BASE_URL}{url}", timeout=10)
            print(f"  probe {url} -> {r.status_code}", end="")
        except requests.exceptions.RequestException as e:
            print(f"  probe {url} -> error: {e}")


print(f"target: {BASE_URL}")

credential_stuffing()
compromised_device_and_cert()
compromised_credentials_unknown_device()
jwt_url_scanning()
