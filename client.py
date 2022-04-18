"""
    CLIENT script:
        1) Load CA, server cert and CA revocation list
            and verify server cert validity

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
CHECK_REVOCATION_LIST = True

# =============================================================================
# SCRIPT 1
# =============================================================================

# Load CA certificate
fileName = "fake_CA_cert.pem"
# fileName = "wrong_CA_cert.pem"
with open( fileName, "rb" ) as f:
    pem_text = f.read()
    ca_cert = x509.load_pem_x509_certificate( pem_text, default_backend() )

ca_name = ca_cert.subject.get_attributes_for_oid( NameOID.COMMON_NAME )[0].value
ca_pub_key = ca_cert.public_key()

# Load server certificate
fileName = "fake_server_cert.pem"
# fileName = "wrong_server_cert.pem"
with open( fileName, "rb" ) as f:
    pem_text = f.read()
    server_cert = x509.load_pem_x509_certificate( pem_text, default_backend() )

server_issuer_name = server_cert.issuer.get_attributes_for_oid( NameOID.COMMON_NAME )[0].value
server_pub_key = server_cert.public_key()

now = datetime.datetime.now()
# now = datetime.datetime(2030, 5, 17)

# Load CA crl
with open( "fake_CA_crl.pem", "rb" ) as f:
    pem_text = f.read()
    ca_crl = x509.load_pem_x509_crl( pem_text, default_backend() )

revoked_cert = ca_crl.get_revoked_certificate_by_serial_number( int(server_cert.serial_number) )

# Validation and verify
if not server_issuer_name == ca_name:
    print( f"{NEW_LINE}ERROR: Server certificate is not valid!" )
    sys.exit()
elif not server_cert.not_valid_before <= now <= server_cert.not_valid_after:
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