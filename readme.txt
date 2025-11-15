secure_storage_cli.py

CLI tool for a Secure Data Storage System:
 - init-keys    : generate RSA keypair and store protected private key
 - encrypt FILE : encrypt arbitrary file -> outputs FILE.enc.json
 - decrypt FILE : decrypt FILE (container) -> outputs FILE.decrypted.<origext>

Requirements:
  pip install cryptography
Python 3.8+
