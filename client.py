"""
    CLIENT script:
        1) Load CA, server cert and CA revocation list
            and verify server cert validity
        2) Verify that the signed-msg is from the server
        3) Decrypt message

    @author: Marco Guidi
"""

# =============================================================================
# PACKAGES
# =============================================================================

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as padding_asym

from cryptography import x509
from cryptography.x509.oid import NameOID

import sys
import datetime
import binascii

# =============================================================================
# GLOBAL CONST
# =============================================================================

NEW_LINE = "\r\n"

CA_CERT = "fake_CA_cert.pem" # invalid CA: wrong_CA_cert.pem
SERVER_CERT = "fake_server_cert.pem" # invalid server cert: wrong_server_cert.pem

NOW = datetime.datetime.now() # invalid time: datetime.datetime(2030, 5, 17)

CA_CRL = "fake_CA_crl.pem"
CHECK_REVOCATION_LIST = False # set True if you want to check CA crl

ENC_FILE = "msg.txt"
SIGN_FILE = "msg.sgn"

AES_KEY = binascii.unhexlify("506C616E74207472506C616E74207472")

BLOCK_SIZE_BITS = algorithms.AES.block_size

# =============================================================================
# SCRIPT 1
# =============================================================================

# Load CA certificate
with open( CA_CERT, "rb" ) as f:
    pem_text = f.read()
    ca_cert = x509.load_pem_x509_certificate( pem_text, default_backend() )

ca_name = ca_cert.subject.get_attributes_for_oid( NameOID.COMMON_NAME )[0].value
ca_pub_key = ca_cert.public_key()

print( f"{NEW_LINE}Loaded CA cert. Name: {ca_name}." )

# Load server certificate
with open( SERVER_CERT, "rb" ) as f:
    pem_text = f.read()
    server_cert = x509.load_pem_x509_certificate( pem_text, default_backend() )

server_name = server_cert.subject.get_attributes_for_oid( NameOID.COMMON_NAME )[0].value
server_issuer_name = server_cert.issuer.get_attributes_for_oid( NameOID.COMMON_NAME )[0].value

server_pub_key = server_cert.public_key()

print( f"{NEW_LINE}Loaded server cert. Name: {server_name}." )

# Load CA crl
with open( CA_CRL, "rb" ) as f:
    pem_text = f.read()
    ca_crl = x509.load_pem_x509_crl( pem_text, default_backend() )

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
    padding_asym.PKCS1v15(),
    hashes.SHA256()
)

print( f"{NEW_LINE}The certificate of {server_name} is valid!" )

# =============================================================================
# SCRIPT 2
# =============================================================================

with open( ENC_FILE, "rb" ) as f:
    iv = f.read( int( BLOCK_SIZE_BITS / 8 ) )
    padded_cipher_text = f.read()

with open( SIGN_FILE, "rb" ) as f:
    signature = f.read()

try:
    server_pub_key.verify(
        signature,
        iv + padded_cipher_text,
        padding_asym.PSS(
            mgf=padding_asym.MGF1(hashes.SHA256()),
            salt_length=padding_asym.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print( f"{NEW_LINE}The message is verified!" )
except:
    print( f"{NEW_LINE}ERROR: The message is not verified!" )

# =============================================================================
# SCRIPT 3
# =============================================================================

cipher = Cipher( algorithms.AES( AES_KEY ), modes.CBC( iv ), default_backend() )

# Decrypt message
ctx = cipher.decryptor()
padded_plain_text = ctx.update( padded_cipher_text ) + ctx.finalize()

# Remove padding
unpadder = padding.PKCS7( BLOCK_SIZE_BITS ).unpadder()
plain_text = unpadder.update( padded_plain_text ) + unpadder.finalize()

print( f"{NEW_LINE}-----{NEW_LINE*2}Here's the message:{NEW_LINE*2}", plain_text.decode() )