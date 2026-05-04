# key_manager.py
import os
import base64
import sqlite3
import time

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file

# Database name
DB_FILE = "totally_not_my_privateKeys.db"

# AES helpers 

def _get_aes_key() -> bytes:
    """
    Load the 256-bit AES key from the environment variable NOT_MY_KEY.
    The env-var value is treated as raw UTF-8; we SHA-256 it so any
    string length becomes a valid 32-byte key.
    """
    raw = os.environ.get("NOT_MY_KEY")
    if not raw:
        raise EnvironmentError(
            "Environment variable NOT_MY_KEY is not set. "
            "Export it before starting the server."
        )
    import hashlib
    return hashlib.sha256(raw.encode()).digest()   # always 32 bytes


def encrypt_pem(pem: bytes) -> bytes:
    """
    Encrypt PEM bytes with AES-CBC.
    Format stored in DB:  IV (16 bytes) || ciphertext
    """
    key = _get_aes_key()
    iv = os.urandom(16)                            # fresh IV per encryption
    # PKCS7 padding
    pad_len = 16 - (len(pem) % 16)
    padded = pem + bytes([pad_len] * pad_len)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    enc = cipher.encryptor()
    ciphertext = enc.update(padded) + enc.finalize()
    return iv + ciphertext                         # prepend IV


def decrypt_pem(blob: bytes) -> bytes:
    """
    Decrypt a blob previously produced by encrypt_pem().
    """
    key = _get_aes_key()
    iv, ciphertext = blob[:16], blob[16:]

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()

    # Remove PKCS7 padding
    pad_len = padded[-1]
    return padded[:-pad_len]


# KeyManager class definition
# This class handles RSA key generation, encryption, storage, and retrieval,
# as well as user management and authentication logging.

class KeyManager:
    def __init__(self, db_file: str = DB_FILE):
        self.db_file = db_file
        self.conn = sqlite3.connect(db_file, check_same_thread=False)
        self._create_tables()

        # Ensure at least one expired key and one active key exist
        self.get_or_create_key(expired=True)
        self.get_or_create_key(expired=False)

    # Schema 

    def _create_tables(self):
        with self.conn:
            # RSA keys  – stored AES-encrypted
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS keys(
                    kid INTEGER PRIMARY KEY AUTOINCREMENT,
                    key BLOB NOT NULL,
                    exp INTEGER NOT NULL
                )
            """)

            # Users
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS users(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    date_registered TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP
                )
            """)

            # Auth request log
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS auth_logs(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_ip TEXT NOT NULL,
                    request_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    user_id INTEGER,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                )
            """)

    """Key generation & storage 
       generate_key() - creates a new RSA-2048 private key and returns it along with its PEM representation.
       save_key_to_db(pem, exp) - encrypts the PEM bytes and stores it
    """

    def generate_key(self):
        """Generate RSA-2048 private key and return (private_key, PEM bytes)."""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
        )
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return private_key, pem

    def save_key_to_db(self, pem: bytes, exp: int) -> int:
        """Encrypt *pem* then store it; return the new kid."""
        encrypted = encrypt_pem(pem)
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO keys (key, exp) VALUES (?, ?)",
                (sqlite3.Binary(encrypted), int(exp)),
            )
        return cursor.lastrowid

    def get_or_create_key(self, expired: bool = False) -> dict:
        now = int(time.time())

        if expired:
            row = self.conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                (now,),
            ).fetchone()
            exp_time = now - 3600
        else:
            row = self.conn.execute(
                "SELECT kid, key, exp FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                (now,),
            ).fetchone()
            exp_time = now + 3600

        if row:
            kid, encrypted_pem, exp_db = row
            pem = decrypt_pem(bytes(encrypted_pem))
            private_key = serialization.load_pem_private_key(pem, password=None)
            return {"private_key": private_key, "pem": pem, "kid": kid, "exp": exp_db}

        private_key, pem = self.generate_key()
        kid = self.save_key_to_db(pem, exp_time)
        return {"private_key": private_key, "pem": pem, "kid": kid, "exp": exp_time}


    #  User helpers
    """looks up a username and returns its integer ID, or None if not found.
    logs an authentication request with the client's IP"""
    def get_user_id(self, username: str):
        """Return the integer id of *username*, or None if not found."""
        row = self.conn.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        return row[0] if row else None

    #  Auth-log helper 

    def log_auth_request(self, request_ip: str, user_id=None):
        with self.conn:
            self.conn.execute(
                "INSERT INTO auth_logs (request_ip, user_id) VALUES (?, ?)",
                (request_ip, user_id),
            )



    # Utility
    """Utility functions for the KeyManager class.
        converts an integer to a URL-safe base64 string without padding.
    """

    @staticmethod
    def int_to_base64(value: int) -> str:
        value_bytes = value.to_bytes((value.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(value_bytes).rstrip(b"=").decode("utf-8")
