"""
    SERVER script:
        1) Get the msg and encrypt with AES-128-CBC
        2) Load PK and sign the  ( IV + cyphertext )
        3) Save the signature in a new file

    @author: Marco Guidi
"""

# =============================================================================
# PACKAGES
# =============================================================================

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding as padding_asym

import binascii
import os

# =============================================================================
# GLOBAL CONST
# =============================================================================

NEW_LINE = "\r\n"
BLOCK_SIZE_BITS = algorithms.AES.block_size

SERVER_PK = "fake_server_key.pem"
SIGN_FILE = "message.txt.sign"

# =============================================================================
# SCRIPT 1
# =============================================================================

AES_KEY = binascii.unhexlify("506C616E74207472506C616E74207472")
AES_IV = os.urandom( int( BLOCK_SIZE_BITS / 8 ) )

print( f"{NEW_LINE}Loaded AES key and generated AES IV." )

plain_text = input( "Write the message to send to the client: " ).encode()

cipher = Cipher( algorithms.AES( AES_KEY ), modes.CBC( AES_IV ), default_backend() )

# Add padding
padder = padding.PKCS7( BLOCK_SIZE_BITS ).padder()
padded_plain_text = padder.update( plain_text ) + padder.finalize()

# Cypher the padded text
ctx = cipher.encryptor()
ciphertext = ctx.update( padded_plain_text ) + ctx.finalize()

print( f"{NEW_LINE}Message encrypted. Message: {plain_text}, cypher text: {ciphertext}." )

# =============================================================================
# SCRIPT 2
# =============================================================================

with open( SERVER_PK, "rb" ) as f:
    pem_text = f.read()

prvkey = serialization.load_pem_private_key(
    pem_text,
    None,
    default_backend()
)

print( f"{NEW_LINE}Loaded server private key." )

signature = prvkey.sign(
    AES_IV + ciphertext,
    padding_asym.PSS(
        mgf=padding_asym.MGF1(hashes.SHA256()),
        salt_length=padding_asym.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# =============================================================================
# SCRIPT 3
# =============================================================================

with open( SIGN_FILE, "wb" ) as f:
    f.write( signature )

print( f"{NEW_LINE}Message signed. File name: {SIGN_FILE}." )