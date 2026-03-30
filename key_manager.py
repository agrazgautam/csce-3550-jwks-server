# key_manager.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import sqlite3
import time

# Database name
DB_FILE = "totally_not_my_privateKeys.db"


class KeyManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE, check_same_thread=False)
        self._create_table()

        # ensure at least one expired key and one active key
        self.get_or_create_key(expired=True)
        self.get_or_create_key(expired=False)

    def _create_table(self):
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
            """)

    def generate_key(self):
        """Generate RSA private key and return PEM bytes."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )

        return private_key, pem

    def save_key_to_db(self, pem, exp):
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (sqlite3.Binary(pem), int(exp))
            )
            return cursor.lastrowid

    def get_or_create_key(self, expired=False):
        now = int(time.time())

        if expired:
            row = self.conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                (now,)
            ).fetchone()
            exp_time = now - 3600
        else:
            row = self.conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                (now,)
            ).fetchone()
            exp_time = now + 3600

        if row:
            kid, key_pem, exp_db = row
            private_key = serialization.load_pem_private_key(key_pem, password=None)
            return {
                "private_key": private_key,
                "pem": key_pem,
                "kid": kid,
                "exp": exp_db
            }

        private_key, pem = self.generate_key()
        kid = self.save_key_to_db(pem, exp_time)

        return {
            "private_key": private_key,
            "pem": pem,
            "kid": kid,
            "exp": exp_time
        }

    @staticmethod
    def int_to_base64(value):
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")