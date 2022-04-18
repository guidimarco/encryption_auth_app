# Encryption and authentication app

Master in cybersecurity 2022/2023.

Final project for Applied cryptography.

## Description

Client-server application.

The server can send authenticated and secret messages to the client. The server has a private key and a certificate, created with SimpleAuthority.

## Server

- Takes from keyboard a message to encrypt
- Encrypts the message with `AES-128-CBC` with a key hardcoded in the script
- Loads the private key `fake_server_key.pem`
- Signs the ciphertext (and the IV) with such a private key
- Saves the signature, the IV, and the ciphertexton in `msg.txt` and `msg.sgn`

## Client

- Loads the server's and the CA's certificates: `fake_server_cert.pem` and `fake_CA_crl.pem`
- Verifies the validity of the server certificate with examples for triggering errors. Signature ( `wrong_server_cert.pem`, `wrong_CA_cert.pem` ), date ( `datetime.datetime(2030, 5, 17)` ), and revoked list ( set `CHECK_REVOCATION_LIST` on True )
- Loads the signature, the IV, and the ciphertext from the `msg.txt` and `msg.sgn`
- Verifies the signature with the public key embedded in the certificate
- Decrypts the message
- Prints the message on screen
