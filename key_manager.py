# app/key_manager.py
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import time
import uuid

class KeyManager:
    def __init__(self):
        self.keys = []

    def generate_key(self, expiry_seconds=3600):

        """Generate RSA key pair with kid and expiry."""

        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        kid = str(uuid.uuid4())
        expiry = int(time.time()) + expiry_seconds
        key_data = {
            "kid": kid,
            "private_key": private_key,
            "public_key": private_key.public_key(),
            "expiry": expiry
        }
        self.keys.append(key_data)
        return key_data

    def get_active_keys(self):

        """Return all unexpired keys."""

        now = int(time.time())
        return [k for k in self.keys if k["expiry"] > now]

    def get_key_by_kid(self, kid):
        for key in self.keys:
            if key["kid"] == kid:
                return key
        return None
