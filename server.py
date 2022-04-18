"""
    SERVER script:
        1) Get the msg and encrypt with AES-128-CBC

    @author: Marco Guidi
"""

# =============================================================================
# PACKAGES
# =============================================================================

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

import binascii
import os
import sys

# =============================================================================
# GLOBAL CONST
# =============================================================================

NEW_LINE = "\r\n"
BLOCK_SIZE = int( algorithms.AES.block_size / 8 )

# =============================================================================
# SCRIPT 1
# =============================================================================

AES_KEY = binascii.unhexlify("506C616E74207472506C616E74207472")
AES_IV = os.urandom( BLOCK_SIZE )

print( f"{NEW_LINE}Loaded AES key and generated AES IV." )

plain_text = input( "Write the message to send to the client: " ).encode()

cipher = Cipher( algorithms.AES( AES_KEY ), modes.CBC( AES_IV ), default_backend() )
ctx = cipher.encryptor()
ctx = padding.PKCS7( BLOCK_SIZE ).padder()
ciphertext = ctx.update( plain_text ) + ctx.finalize()

print( f"{NEW_LINE}Message encrypted. Message: {plain_text}, cypher text: {ciphertext}." )
