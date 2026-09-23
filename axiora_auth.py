"""Local developer account. Salted password hash, no plaintext persisted."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import threading


class Credentials:
    def __init__(self, path):
        self.path = Path(path)
        self.lock = threading.Lock()
        if self.path.exists():
            self.record = json.loads(self.path.read_text(encoding="utf-8"))
            if self.record.get("username") != "admin" or not self.record.get("salt") or not self.record.get("hash"):
                raise ValueError("Повреждён файл учётной записи")
        else:
            self.change("admin")

    def change(self, password):
        salt = secrets.token_hex(16)
        record = {"username": "admin", "salt": salt,
                  "hash": hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=16384, r=8, p=1).hex()}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(".tmp")
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as out:
            json.dump(record, out)
        os.chmod(temp, 0o600)
        temp.replace(self.path)
        with self.lock:
            self.record = record

    def verify(self, username, password):
        with self.lock:
            record = dict(self.record)
        digest = hashlib.scrypt(password.encode(), salt=bytes.fromhex(record["salt"]), n=16384, r=8, p=1).hex()
        return hmac.compare_digest(username.encode(), record["username"].encode()) and hmac.compare_digest(digest, record["hash"])
