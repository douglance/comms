#!/usr/bin/env python3
"""Encrypted external vault bridge for the Comms stdin credential contract."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def main():
    request = json.loads(sys.stdin.buffer.read(262145))
    identity = {key: request[key] for key in ("service", "account", "kind")}
    if any(not isinstance(value, str) or not value or len(value) > 8192 for value in identity.values()):
        raise ValueError("invalid identity")
    operation = request.get("op")
    if operation not in ("load", "save", "delete"):
        raise ValueError("invalid operation")
    key = base64.urlsafe_b64decode(os.environ["COMMS_VAULT_KEY"])
    if len(key) != 32:
        raise ValueError("invalid vault key")
    aad = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
    root = Path(os.environ.get("COMMS_VAULT_DIR", str(Path.home() / ".local/share/comms/vault")))
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(root, 0o700)
    path = root / (hashlib.sha256(aad).hexdigest() + ".sealed")
    cipher = AESGCM(key)
    if operation == "load":
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            print("null")
            return
        secret = cipher.decrypt(data[:12], data[12:], aad).decode()
        print(json.dumps({"secret": secret}))
    elif operation == "delete":
        path.unlink(missing_ok=True)
        print("null")
    else:
        secret = request.get("secret")
        if not isinstance(secret, str) or len(secret) > 131072:
            raise ValueError("invalid secret")
        nonce = os.urandom(12)
        data = nonce + cipher.encrypt(nonce, secret.encode(), aad)
        temporary = root / (".pending-" + secrets.token_hex(16))
        try:
            with os.fdopen(os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
        finally:
            temporary.unlink(missing_ok=True)
        print("null")


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Comms vault operation failed", file=sys.stderr)
        raise SystemExit(1)
