#!/usr/bin/env python3
"""
secure_storage_cli.py

CLI tool for a Secure Data Storage System:
 - init-keys    : generate RSA keypair and store protected private key
 - encrypt FILE : encrypt arbitrary file -> outputs FILE.enc.json
 - decrypt FILE : decrypt FILE (container) -> outputs FILE.decrypted.<origext>

Requirements:
  pip install cryptography
Python 3.8+
"""
import argparse
import json
import base64
import os
import secrets
import getpass
import sys
import time
from typing import Optional, Tuple

# cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.backends import default_backend
    CRYPTO_OK = True
except Exception as e:
    CRYPTO_OK = False
    _IMPORT_ERR = e

# ---------- helpers ----------
def b64(b: bytes) -> str:
    return base64.b64encode(b).decode('ascii')

def ub64(s: str) -> bytes:
    return base64.b64decode(s.encode('ascii'))

def safe_save_bytes(path: str, data: bytes) -> None:
    with open(path, 'wb') as f:
        f.write(data)

def safe_load_bytes(path: str) -> bytes:
    with open(path, 'rb') as f:
        return f.read()

# ---------- key management ----------
def generate_rsa_keypair(key_size: int = 3072):
    if not CRYPTO_OK:
        raise RuntimeError(f"cryptography not available: {_IMPORT_ERR}")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

def serialize_public_key_pem(pub) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)

def serialize_private_key_encrypted(private_key, password: bytes, iterations: int = 200_000) -> bytes:
    """Return a JSON wrapper (utf-8) containing salt, iterations, nonce, ciphertext."""
    raw_pem = private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                        format=serialization.PrivateFormat.PKCS8,
                                        encryption_algorithm=serialization.NoEncryption())
    salt = secrets.token_bytes(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    key = kdf.derive(password)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aesgcm.encrypt(nonce, raw_pem, None)
    wrapper = {
        'kdf': 'pbkdf2',
        'kdf_params': {'salt': b64(salt), 'iterations': iterations, 'hash': 'sha256'},
        'cipher': 'aes-gcm',
        'nonce': b64(nonce),
        'ciphertext': b64(ct)
    }
    return json.dumps(wrapper).encode('utf-8')

def load_private_key_encrypted(blob: bytes, password: bytes):
    wrapper = json.loads(blob.decode('utf-8'))
    if wrapper.get('kdf') != 'pbkdf2':
        raise ValueError("Unsupported KDF")
    params = wrapper['kdf_params']
    salt = ub64(params['salt'])
    iterations = params['iterations']
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    key = kdf.derive(password)
    nonce = ub64(wrapper['nonce'])
    ct = ub64(wrapper['ciphertext'])
    aesgcm = AESGCM(key)
    raw_pem = aesgcm.decrypt(nonce, ct, None)
    private_key = serialization.load_pem_private_key(raw_pem, password=None, backend=default_backend())
    return private_key

# ---------- crypto ops ----------
def wrap_symmetric_key_with_rsa(sym_key: bytes, public_key) -> bytes:
    return public_key.encrypt(sym_key, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                    algorithm=hashes.SHA256(), label=None))

def unwrap_symmetric_key_with_rsa(wrapped: bytes, private_key) -> bytes:
    return private_key.decrypt(wrapped, padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                                      algorithm=hashes.SHA256(), label=None))

def encrypt_bytes(plaintext: bytes, recipient_public_key, metadata: Optional[dict] = None) -> bytes:
    sym_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(sym_key)
    ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
    tag = ct_with_tag[-16:]
    ciphertext_only = ct_with_tag[:-16]
    wrapped_key = wrap_symmetric_key_with_rsa(sym_key, recipient_public_key)
    container = {
        'version': 1,
        'wrap': 'rsa-oaep-sha256',
        'cipher': 'aes-256-gcm',
        'wrapped_key': b64(wrapped_key),
        'nonce': b64(nonce),
        'ciphertext': b64(ciphertext_only),
        'tag': b64(tag),
        'metadata': metadata or {}
    }
    return json.dumps(container).encode('utf-8')

def decrypt_container(container_bytes: bytes, recipient_private_key) -> Tuple[bytes, dict]:
    cont = json.loads(container_bytes.decode('utf-8'))
    wrapped_key = ub64(cont['wrapped_key'])
    sym_key = unwrap_symmetric_key_with_rsa(wrapped_key, recipient_private_key)
    nonce = ub64(cont['nonce'])
    ciphertext = ub64(cont['ciphertext'])
    tag = ub64(cont['tag'])
    aesgcm = AESGCM(sym_key)
    combined = ciphertext + tag
    plaintext = aesgcm.decrypt(nonce, combined, None)
    return plaintext, cont.get('metadata', {})

# ---------- CLI actions ----------
def action_init_keys(pub_out: str, priv_out: str, keysize: int = 3072):
    priv, pub = generate_rsa_keypair(keysize)
    pem_pub = serialize_public_key_pem(pub)
    safe_save_bytes(pub_out, pem_pub)
    # password
    print("Protecting private key with a password.")
    pw = getpass.getpass("Enter password to protect private key: ").encode('utf-8')
    pw2 = getpass.getpass("Confirm password: ").encode('utf-8')
    if pw != pw2:
        print("Passwords do not match. Aborting.")
        return
    wrapped_priv = serialize_private_key_encrypted(priv, pw)
    safe_save_bytes(priv_out, wrapped_priv)
    print(f"Saved public key -> {pub_out}")
    print(f"Saved encrypted private key -> {priv_out}")

def action_encrypt_file(filepath: str, pubpath: str, outpath: Optional[str] = None):
    if not os.path.exists(filepath):
        print("Input file not found:", filepath); return
    if not os.path.exists(pubpath):
        print("Public key not found:", pubpath); return
    pub_pem = safe_load_bytes(pubpath)
    public_key = serialization.load_pem_public_key(pub_pem, backend=default_backend())
    data = safe_load_bytes(filepath)
    metadata = {'orig_name': os.path.basename(filepath), 'timestamp': int(time.time())}
    container = encrypt_bytes(data, public_key, metadata=metadata)
    if outpath is None:
        outpath = filepath + '.enc.json'
    safe_save_bytes(outpath, container)
    print(f"Encrypted -> {outpath}")

def action_decrypt_file(container_path: str, privpath: str, outpath: Optional[str] = None):
    if not os.path.exists(container_path):
        print("Container not found:", container_path); return
    if not os.path.exists(privpath):
        print("Private key file not found:", privpath); return
    pw = getpass.getpass("Enter password to decrypt private key: ").encode('utf-8')
    wrapped_priv_blob = safe_load_bytes(privpath)
    try:
        priv = load_private_key_encrypted(wrapped_priv_blob, pw)
    except Exception as e:
        print("Failed to load private key (bad password or corrupted key):", e); return
    cont = safe_load_bytes(container_path)
    try:
        plaintext, metadata = decrypt_container(cont, priv)
    except Exception as e:
        print("Failed to decrypt container (corrupted or wrong key):", e); return
    orig = metadata.get('orig_name', None)
    if outpath is None:
        if orig:
            name, ext = os.path.splitext(orig)
            outpath = f"{name}.decrypted{ext or '.bin'}"
        else:
            outpath = os.path.splitext(container_path)[0] + '.decrypted'
    safe_save_bytes(outpath, plaintext)
    print(f"Decrypted -> {outpath}")

def action_test(pubpath: str, privpath: str):
    # simple self-test using small random blob
    print("Running self-test...")
    # ensure keys present
    if not (os.path.exists(pubpath) and os.path.exists(privpath)):
        print("Public/private key missing. Please run init-keys first.")
        return
    print("Loading public key...")
    pub = serialization.load_pem_public_key(safe_load_bytes(pubpath), backend=default_backend())
    pw = getpass.getpass("Enter password to decrypt private key for the test: ").encode('utf-8')
    priv = load_private_key_encrypted(safe_load_bytes(privpath), pw)
    data = b"The quick brown fox\n" * 1000
    container = encrypt_bytes(data, pub, metadata={'note': 'selftest'})
    pt, md = decrypt_container(container, priv)
    if pt == data:
        print("SELF-TEST OK: decrypted data matches original.")
    else:
        print("SELF-TEST FAIL: mismatch.")

# ---------- main ----------
def main():
    if not CRYPTO_OK:
        print("cryptography library missing. Install with: pip install cryptography")
        sys.exit(1)

    parser = argparse.ArgumentParser(prog="secure_storage_cli.py", description="Secure Storage CLI")
    sub = parser.add_subparsers(dest='cmd', required=True)

    p_init = sub.add_parser('init-keys', help='Generate RSA keypair and protect private key with a password')
    p_init.add_argument('--pub', default='demo_public_key.pem')
    p_init.add_argument('--priv', default='demo_private_key.json')
    p_init.add_argument('--keysize', type=int, default=3072)

    p_enc = sub.add_parser('encrypt', help='Encrypt a file')
    p_enc.add_argument('file')
    p_enc.add_argument('--pub', default='demo_public_key.pem')
    p_enc.add_argument('--out', default=None)

    p_dec = sub.add_parser('decrypt', help='Decrypt a container')
    p_dec.add_argument('file')
    p_dec.add_argument('--priv', default='demo_private_key.json')
    p_dec.add_argument('--out', default=None)

    p_test = sub.add_parser('test', help='Run a quick self-test that encrypts & decrypts a blob')
    p_test.add_argument('--pub', default='demo_public_key.pem')
    p_test.add_argument('--priv', default='demo_private_key.json')

    args = parser.parse_args()

    if args.cmd == 'init-keys':
        action_init_keys(args.pub, args.priv, args.keysize)
    elif args.cmd == 'encrypt':
        action_encrypt_file(args.file, args.pub, args.out)
    elif args.cmd == 'decrypt':
        action_decrypt_file(args.file, args.priv, args.out)
    elif args.cmd == 'test':
        action_test(args.pub, args.priv)

if __name__ == '__main__':
    main()
