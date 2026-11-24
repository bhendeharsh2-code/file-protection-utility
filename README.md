# File Protection Utility

A command line tool that encrypts and decrypts sensitive local files using **AES-256-GCM** with a password-based key derived using **PBKDF2-HMAC-SHA256**.

## Features
- AES-256 symmetric encryption (Python `cryptography` library)
- PBKDF2-HMAC-SHA256 key derivation, 600,000 iterations, random 16-byte salt
- Random 12-byte nonce for every encryption
- GCM authentication tag = built-in MAC integrity check (wrong password or tampered file is detected and rejected)
- Password typed securely (hidden) using `getpass`
- Never overwrites an existing output file

## Install
```
pip install cryptography
```

## Usage
```
python file_protect.py encrypt secret.txt        # creates secret.txt.enc
python file_protect.py decrypt secret.txt.enc    # creates secret.txt.dec
python file_protect.py decrypt secret.txt.enc -o restored.txt
```

## File format
`MAGIC "FPU1" (4) | SALT (16) | NONCE (12) | CIPHERTEXT + TAG (16)`

The header is authenticated as AAD, so changing any byte of the file makes decryption fail.

## Security notes
- Use a strong password; the key is only as strong as the password.
- Whole file is read into memory, so it suits small/medium files.
- Educational project; for production use vetted tools.
