#!/usr/bin/env python3
"""
File Protection Utility
Command line tool to encrypt / decrypt local files using AES-256-GCM
with a key derived from a password using PBKDF2-HMAC-SHA256.

Usage:
    python file_protect.py encrypt secret.txt          -> secret.txt.enc
    python file_protect.py decrypt secret.txt.enc      -> secret.txt.dec

File format (.enc):
    MAGIC (4) | SALT (16) | NONCE (12) | CIPHERTEXT + GCM TAG (16)
The header (MAGIC + SALT + NONCE) is authenticated as AAD, so any change to
the header, ciphertext or tag makes decryption fail (integrity check).
"""

import argparse
import getpass
import os
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"FPU1"
SALT_SIZE = 16          # 128-bit random salt
NONCE_SIZE = 12         # 96-bit nonce (recommended for GCM)
KEY_SIZE = 32           # 32 bytes = 256-bit AES key
ITERATIONS = 600_000    # PBKDF2 iterations (OWASP recommendation for SHA-256)


def derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from the password using PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def encrypt_file(in_path: str, out_path: str, password: str) -> None:
    with open(in_path, "rb") as f:
        plaintext = f.read()

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    header = MAGIC + salt + nonce
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, header)  # ciphertext + tag

    with open(out_path, "wb") as f:
        f.write(header + ciphertext)


def decrypt_file(in_path: str, out_path: str, password: str) -> None:
    with open(in_path, "rb") as f:
        data = f.read()

    header_len = len(MAGIC) + SALT_SIZE + NONCE_SIZE
    if len(data) < header_len + 16 or data[:4] != MAGIC:
        raise ValueError("Not a valid encrypted file (bad header).")

    header = data[:header_len]
    salt = data[4:4 + SALT_SIZE]
    nonce = data[4 + SALT_SIZE:header_len]
    ciphertext = data[header_len:]

    key = derive_key(password, salt)
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, header)
    except InvalidTag:
        raise ValueError(
            "Integrity check FAILED: wrong password or file was modified/corrupted."
        )

    with open(out_path, "wb") as f:
        f.write(plaintext)


def get_password(confirm: bool) -> str:
    pw = getpass.getpass("Enter password: ")
    if not pw:
        sys.exit("Error: password cannot be empty.")
    if confirm and getpass.getpass("Confirm password: ") != pw:
        sys.exit("Error: passwords do not match.")
    return pw


def main() -> None:
    parser = argparse.ArgumentParser(
        description="AES-256-GCM file encryption utility (PBKDF2 key derivation)"
    )
    parser.add_argument("mode", choices=["encrypt", "decrypt"])
    parser.add_argument("file", help="path of the file to process")
    parser.add_argument("-o", "--output", help="output path (optional)")
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        sys.exit(f"Error: file not found: {args.file}")

    if args.mode == "encrypt":
        out = args.output or args.file + ".enc"
    else:
        out = args.output or (
            args.file[:-4] + ".dec" if args.file.endswith(".enc") else args.file + ".dec"
        )

    if os.path.exists(out):
        sys.exit(f"Error: output file already exists: {out}")

    try:
        if args.mode == "encrypt":
            encrypt_file(args.file, out, get_password(confirm=True))
            print(f"[+] Encrypted  -> {out}")
        else:
            decrypt_file(args.file, out, get_password(confirm=False))
            print(f"[+] Decrypted  -> {out}  (integrity verified)")
    except ValueError as e:
        sys.exit(f"[-] {e}")


if __name__ == "__main__":
    main()
