"""Optional local-only decryption for explicitly user-owned AEAD envelopes.

This utility is deliberately disconnected from Telegram, SQLite, logging and any
LLM/API path. It never supports wallets or Ethereum keystores.
"""
from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def decrypt_owned_envelope(path: Path, password: str) -> bytes:
    data = json.loads(path.read_text(encoding="utf-8"))
    if data.get("format") != "BASE_AI_OWNED_AES256_GCM_V1":
        raise ValueError("Unsupported envelope; wallet/keystore decryption is prohibited")
    salt = base64.b64decode(data["salt"], validate=True)
    nonce = base64.b64decode(data["nonce"], validate=True)
    ciphertext = base64.b64decode(data["ciphertext"], validate=True)
    if len(salt) < 16 or len(nonce) != 12:
        raise ValueError("Invalid envelope parameters")
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1,
                         dklen=32)
    return AESGCM(key).decrypt(nonce, ciphertext, b"BASE_AI_OWNED_DATA")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Locally decrypt an explicitly user-owned Base AI data envelope"
    )
    parser.add_argument("input", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--i-own-this-data", action="store_true", required=True)
    args = parser.parse_args()
    if args.input.resolve() == args.output.resolve():
        raise SystemExit("Input and output paths must differ")
    password = getpass.getpass("Local decryption password (never stored/transmitted): ")
    if not password:
        raise SystemExit("A local password is required")
    plaintext = decrypt_owned_envelope(args.input, password)
    args.output.write_bytes(plaintext)
    print(f"Decrypted locally to {args.output}; no credentials were stored or transmitted.")


if __name__ == "__main__":
    main()
