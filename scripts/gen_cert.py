# scripts/gen_cert.py
import sys
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

CA_DIR = Path("certs/ca")
OUT_PUBLIC = Path("certs/public")
OUT_PRIVATE = Path("certs/private")
OUT_PUBLIC.mkdir(parents=True, exist_ok=True)
OUT_PRIVATE.mkdir(parents=True, exist_ok=True)

def gen_entity_cert(common_name: str, san_dns=None):
    # Load CA key and certificate
    ca_key = serialization.load_pem_private_key((CA_DIR / "ca.key.pem").read_bytes(), password=None)
    ca_cert = x509.load_pem_x509_certificate((CA_DIR / "ca.cert.pem").read_bytes())

    # Generate entity private key (RSA 2048)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])

    builder = x509.CertificateBuilder(
    ).subject_name(
        subject
    ).issuer_name(
        ca_cert.subject
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow() - datetime.timedelta(minutes=1)
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(san) for san in (san_dns or [common_name])]),
        critical=False
    ).add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    ).add_extension(
        x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH, ExtendedKeyUsageOID.SERVER_AUTH]),
        critical=False
    )

    cert = builder.sign(private_key=ca_key, algorithm=hashes.SHA256())

    # Write key & cert
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    fname = common_name.replace(" ", "_").lower()
    (OUT_PRIVATE / f"{fname}.key.pem").write_bytes(key_pem)
    (OUT_PUBLIC / f"{fname}.cert.pem").write_bytes(cert_pem)

    print("Wrote:", OUT_PRIVATE / f"{fname}.key.pem", OUT_PUBLIC / f"{fname}.cert.pem")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python gen_cert.py <common_name> [san_dns...]")
        sys.exit(1)
    cn = sys.argv[1]
    san = sys.argv[2:] if len(sys.argv) > 2 else None
    gen_entity_cert(cn, san_dns=san)
"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 
