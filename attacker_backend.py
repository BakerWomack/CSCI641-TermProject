import socket
import requests
import psycopg2
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# app-service cert is issued for hostname "app-service" not "localhost",
# so we use verify=False to skip the server cert hostname check and get
# to the actual mTLS layer behavior.
#
# NOTE: web-server-pep/certs/ca.pem and internal-certs/ca.pem are the same CA.
# this means any cert signed by the shared CA (including the user-facing client.crt)
# will pass the app-service mTLS check. attacks 2 and 3 exploit this.
#
# secure-db has no host port mapping and is on backend_net (internal: true).
# port 5432 on the host is a local postgres instance, not secure-db.

INTERNAL_CA = "internal-certs/ca.pem"
USER_CERT = ("web-server-pep/certs/client.crt", "web-server-pep/certs/client.key")
NGINX_CERT = ("internal-certs/nginx-client.crt", "internal-certs/nginx-client.key")


def show(label, resp):
    print(f"\n-- {label} --")
    print(f"status: {resp.status_code}")
    try:
        import json
        print(json.dumps(resp.json(), indent=2))
    except:
        print(resp.text[:200])


# no client cert - app-service runs with ssl_cert_reqs=CERT_REQUIRED
# uvicorn drops the connection immediately, no response
def attack_api_no_cert():
    print("\n[attack 1] hit app-service:8000 directly, no client cert")

    try:
        r = requests.get("https://localhost:8000/api/app/data", verify=False, timeout=10)
        show("result", r)
    except requests.exceptions.ConnectionError as e:
        print(f"  connection dropped (expected - no cert, mtls required): {type(e).__name__}")


# the user-facing client cert and internal certs share the same CA.
# so the app-service mTLS check accepts this cert, bypassing nginx entirely.
# this is a real design gap - separate CAs for internal vs external would block this.
def attack_api_user_cert():
    print("\n[attack 2] hit app-service:8000 with user-facing client cert")
    print("  finding: both certs share the same CA so app-service accepts it")
    print("  this bypasses nginx + policy engine entirely")

    try:
        r = requests.get(
            "https://localhost:8000/api/app/data",
            cert=USER_CERT,
            verify=False,
            timeout=10,
        )
        show("result", r)
        if r.status_code == 200:
            print("  [bypass] got data without going through nginx or the policy engine")
    except requests.exceptions.SSLError as e:
        print(f"  ssl error: {e}")
    except requests.exceptions.ConnectionError as e:
        print(f"  connection error: {e}")


# with the internal nginx-client cert an attacker also gets straight through.
# if someone got a hold of this cert (e.g. from a compromised nginx container)
# they can hit the backend with no trust checks at all.
def attack_api_internal_cert():
    print("\n[attack 3] hit app-service:8000 with stolen nginx-client cert")
    print("  if this cert leaks, policy engine is fully bypassed")

    try:
        r = requests.get(
            "https://localhost:8000/api/app/data",
            cert=NGINX_CERT,
            verify=False,
            timeout=10,
        )
        show("result", r)
        if r.status_code == 200:
            print("  [bypass] got data without any auth checks")
    except requests.exceptions.SSLError as e:
        print(f"  ssl error: {e}")
    except requests.exceptions.ConnectionError as e:
        print(f"  connection error: {e}")


# secure-db has no host port mapping - you cannot reach it from outside docker.
# port 5432 on the host resolves to a local postgres with no sensitive tables.
# the actual secure-db is only reachable from within the backend_net docker network.
def attack_secure_db():
    print("\n[attack 4] try to reach secure-db on localhost:5432")
    print("  secure-db has no exposed port - only app-service can reach it via docker network")

    try:
        s = socket.create_connection(("localhost", 5432), timeout=5)
        s.close()
        print("  port 5432 is open but this is a local postgres, NOT secure-db")

        conn = psycopg2.connect(
            host="localhost", port=5432,
            user="postgres", password="postgres", dbname="postgres",
            connect_timeout=5,
        )
        cur = conn.cursor()
        cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema='public';")
        tables = [r[0] for r in cur.fetchall()]
        print(f"  tables found here: {tables if tables else '(none)'}")
        print("  sensitive_data is in secure-db which is not routable from the host")
        conn.close()

    except (ConnectionRefusedError, socket.timeout, OSError) as e:
        print(f"  port not reachable: {e}")
    except Exception as e:
        print(f"  db error: {e}")


# even if secure-db were somehow reachable, it requires a valid mTLS client cert
# (app-db-client.crt) signed by the internal CA. connecting without it gets dropped.
def attack_secure_db_ssl():
    print("\n[attack 5] try to connect with ssl required but no client cert")
    print("  secure-db pg_hba.conf: hostssl all all all cert")

    try:
        conn = psycopg2.connect(
            host="localhost", port=5432,
            user="postgres", password="postgres", dbname="postgres",
            sslmode="require",
            sslrootcert=INTERNAL_CA,
            connect_timeout=5,
        )
        cur = conn.cursor()
        cur.execute("SELECT * FROM sensitive_data;")
        print(f"  got data: {cur.fetchall()}")
        conn.close()
    except psycopg2.OperationalError as e:
        msg = str(e).strip().split("\n")[0]
        print(f"  db rejected (expected): {msg}")
    except Exception as e:
        print(f"  error: {e}")


if __name__ == "__main__":
    print("target: app-service backend (port 8000) and databases")
    print("note: attacks 2+3 reveal a real single-CA misconfiguration\n")

    attack_api_no_cert()
    attack_api_user_cert()
    attack_api_internal_cert()
    attack_secure_db()
    attack_secure_db_ssl()
