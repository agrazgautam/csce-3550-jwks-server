# key_manager.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64
import sqlite3

DB_FILE = "totally_not_my_privateKeys.db"


class KeyManager:
    def __init__(self):
        self.conn = sqlite3.connect(DB_FILE)
        self._create_table()
        self.active_key = self.generate_key()
        self.expired_key = self.generate_key()
        

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
        """Generate RSA key pair and return dict with private/public key and kid."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        numbers = private_key.private_numbers()
        return {
            "private_key": private_key,
            "public_key": private_key.public_key(),
            "numbers": numbers,
            "kid": "goodKID"  # will overwrite for expired if needed
        }

    @staticmethod
    def int_to_base64(value):
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, 'big')
        return base64.urlsafe_b64encode(value_bytes).rstrip(b'=').decode('utf-8')