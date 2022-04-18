"""
    CLIENT script:
        1) Load CA, server cert and CA revocation list
            and verify server cert validity
        2) Verify that the signed-msg is from the server

    @author: Marco Guidi
"""

# =============================================================================
# PACKAGES
# =============================================================================

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID

import sys
import datetime

# =============================================================================
# GLOBAL CONST
# =============================================================================

NEW_LINE = "\r\n"

CA_CERT = "fake_CA_cert.pem" # invalid CA: wrong_CA_cert.pem
SERVER_CERT = "fake_server_cert.pem" # invalid server cert: wrong_server_cert.pem

NOW = datetime.datetime.now() # invalid time: datetime.datetime(2030, 5, 17)

CA_CRL = "fake_CA_crl.pem"
CHECK_REVOCATION_LIST = False # set True if you want to check CA crl

ENC_FILE = "msg.enc"
SIGN_FILE = "msg.sgn"

# =============================================================================
# SCRIPT 1
# =============================================================================

# Load CA certificate
with open( CA_CERT, "rb" ) as f:
    pem_ca_cert = f.read()
    ca_cert = x509.load_pem_x509_certificate( pem_ca_cert, default_backend() )

ca_name = ca_cert.subject.get_attributes_for_oid( NameOID.COMMON_NAME )[0].value
ca_pub_key = ca_cert.public_key()

print( f"{NEW_LINE}Loaded CA cert. Name: {ca_name}." )

# Load server certificate
with open( SERVER_CERT, "rb" ) as f:
    pem_server_cert = f.read()
    server_cert = x509.load_pem_x509_certificate( pem_server_cert, default_backend() )

server_name = server_cert.subject.get_attributes_for_oid( NameOID.COMMON_NAME )[0].value
server_issuer_name = server_cert.issuer.get_attributes_for_oid( NameOID.COMMON_NAME )[0].value
server_pub_key = server_cert.public_key()

print( f"{NEW_LINE}Loaded server cert. Name: {server_name}." )

# Load CA crl
with open( CA_CRL, "rb" ) as f:
    pem_ca_crl = f.read()
    ca_crl = x509.load_pem_x509_crl( pem_ca_crl, default_backend() )

print( f"{NEW_LINE}Loaded CA crl. There are {len(ca_crl)} revoked cert." )

revoked_cert = ca_crl.get_revoked_certificate_by_serial_number( int(server_cert.serial_number) )

# Validation and verify
if not server_issuer_name == ca_name:
    print( f"{NEW_LINE}ERROR: Server certificate is not valid!" )
    sys.exit()
elif not server_cert.not_valid_before <= NOW <= server_cert.not_valid_after:
    print( f"{NEW_LINE}ERROR: Server certificate is expired!" )
    sys.exit()
elif CHECK_REVOCATION_LIST and not revoked_cert == None:
    print( f"{NEW_LINE}ERROR: Server certificate has been revoked!" )
    sys.exit()

ca_pub_key.verify(
    server_cert.signature,
    server_cert.tbs_certificate_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)

print( f"{NEW_LINE}The certificate of {server_name} is valid!" )

# =============================================================================
# SCRIPT 2
# =============================================================================

with open( ENC_FILE, "rb" ) as f:
    enc_msg = f.read()

with open( SIGN_FILE, "rb" ) as f:
    signature = f.read()

try:
    server_pub_key.verify(
        signature,
        enc_msg,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    print( f"{NEW_LINE}The message is verified!" )
except:
    print( f"{NEW_LINE}ERROR: The message is not verified!" )
