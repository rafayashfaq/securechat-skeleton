import sys
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from pathlib import Path

# Paths
CA_DIR = Path("certs/ca")
PRIVATE_DIR = Path("certs/private")
PUBLIC_DIR = Path("certs/public")
PRIVATE_DIR.mkdir(parents=True, exist_ok=True)
PUBLIC_DIR.mkdir(parents=True, exist_ok=True)

def generate_cert(name, hosts):
    # Load CA key and cert
    ca_key = serialization.load_pem_private_key(
        (CA_DIR / "ca.key.pem").read_bytes(), password=None
    )
    ca_cert = x509.load_pem_x509_certificate((CA_DIR / "ca.cert.pem").read_bytes())

    # Generate entity private key
    key = rsa.generate_private_key(public_exponent=65537, key_size=4096)

    # Build subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"MyState"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"MyCity"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, name),
    ])

    # Subject Alternative Names for hostnames/IPs
    alt_names = [x509.DNSName(h) if not h.replace(".", "").isdigit() else x509.IPAddress(ip_address(h)) for h in hosts]

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(alt_names), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    # Write private key and cert
    key_file = PRIVATE_DIR / f"{name.replace(' ','_')}.key.pem"
    cert_file = PUBLIC_DIR / f"{name.replace(' ','_')}.cert.pem"

    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    key_file.write_bytes(key_pem)
    cert_file.write_bytes(cert_pem)

    print(f"Wrote: {key_file} {cert_file}")

# Utility to parse IPs
from ipaddress import ip_address

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python gen_cert.py <name> <host1> [host2 ...]")
        sys.exit(1)

    name = sys.argv[1]
    hosts = sys.argv[2:]
    generate_cert(name, hosts)

