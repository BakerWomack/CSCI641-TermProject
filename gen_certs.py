"""
Regenerates the external-facing certs under web-server-pep/certs/ using a
brand new Client-CA that is completely separate from internal-certs/ca.pem.

internal-certs/ is not touched.

After running this:
  - nginx presents cert.pem to browsers (signed by Client-CA)
  - nginx verifies client certs against Client-CA
  - app-service trusts only internal-certs/ca.pem (TermProject-CA)
  => user-facing client.crt will be rejected by app-service directly
"""

import datetime
import ipaddress
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa


def gen_key():
    return rsa.generate_private_key(65537, 2048)


def save_key(key, path):
    Path(path).write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )


def save_cert(cert, path):
    Path(path).write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def make_ca(key, cn):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, key_cert_sign=True, crl_sign=True,
            content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )


def make_server_cert(key, ca_key, ca_cert, cn, dns_names, ips=None):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    sans = [x509.DNSName(d) for d in dns_names]
    if ips:
        sans += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in ips]
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


def make_client_cert(key, ca_key, ca_cert, cn):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime.utcnow()
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .sign(ca_key, hashes.SHA256())
    )


out = Path("web-server-pep/certs")

client_ca_key = gen_key()
client_ca = make_ca(client_ca_key, "Client-CA")
save_key(client_ca_key, out / "ca.key")
save_cert(client_ca, out / "ca.pem")
print("generated: Client-CA  (web-server-pep/certs/ca.pem)")

nginx_key = gen_key()
nginx_cert = make_server_cert(
    nginx_key, client_ca_key, client_ca,
    cn="localhost",
    dns_names=["localhost"],
    ips=["127.0.0.1"],
)
save_key(nginx_key, out / "key.pem")
save_cert(nginx_cert, out / "cert.pem")
print("generated: nginx server cert  (web-server-pep/certs/cert.pem)")

client_key = gen_key()
client_cert = make_client_cert(client_key, client_ca_key, client_ca, "test-user-001")
save_key(client_key, out / "client.key")
save_cert(client_cert, out / "client.crt")
print("generated: client cert  (web-server-pep/certs/client.crt)")

print()
print("internal-certs/ not touched - TermProject-CA unchanged")
print("done. restart docker to pick up new certs.")
