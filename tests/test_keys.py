# test_keys.py
import os
import sys

os.environ.setdefault("NOT_MY_KEY", "test_secret_key_for_ci")
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from key_manager import KeyManager, encrypt_pem, decrypt_pem

"""Tests for key_manager.py, covering key generation, database storage, encryption, and retrieval."""
def test_key_generation():
    km = KeyManager(":memory:")
    key_data = km.get_or_create_key(expired=False)
    assert key_data["kid"] is not None
    assert key_data["private_key"] is not None


def test_expired_key():
    km = KeyManager(":memory:")
    key_data = km.get_or_create_key(expired=True)
    import time
    assert key_data["exp"] <= int(time.time())


def test_base64_conversion():
    value = 65537
    encoded = KeyManager.int_to_base64(value)
    assert isinstance(encoded, str)


def test_generate_key():
    km = KeyManager(":memory:")
    private_key, pem = km.generate_key()
    assert private_key is not None
    assert isinstance(pem, bytes)
    assert b"BEGIN PRIVATE KEY" in pem

# Database storage
def test_save_key_to_db():
    km = KeyManager(":memory:")
    _, pem = km.generate_key()
    exp_time = 9999999999
    kid = km.save_key_to_db(pem, exp_time)
    assert isinstance(kid, int)

    row = km.conn.execute(
        "SELECT kid, key, exp FROM keys WHERE kid = ?", (kid,)
    ).fetchone()
    assert row is not None
    assert row[0] == kid
    assert row[2] == exp_time


# AES encryption round-trip

def test_encrypt_decrypt_roundtrip():
    sample = b"This is a test PEM string padded to block size."
    blob = encrypt_pem(sample)
    # Encrypted blob should not equal plaintext
    assert blob != sample
    # But decryption must restore original
    assert decrypt_pem(blob) == sample


def test_keys_stored_encrypted():
    """Keys in the DB must NOT be the raw PEM (i.e. they are encrypted)."""
    km = KeyManager(":memory:")
    _, pem = km.generate_key()
    kid = km.save_key_to_db(pem, 9999999999)
    row = km.conn.execute("SELECT key FROM keys WHERE kid = ?", (kid,)).fetchone()
    stored_blob = bytes(row[0])
    # Raw PEM starts with b"-----BEGIN"
    assert not stored_blob.startswith(b"-----BEGIN"), \
        "Private key PEM was stored in plaintext — encryption not applied!"


def test_get_or_create_key_decrypts_correctly():
    """get_or_create_key must return a usable private key object."""
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
    km = KeyManager(":memory:")
    key_data = km.get_or_create_key(expired=False)
    assert isinstance(key_data["private_key"], RSAPrivateKey)


# User helpers

def test_get_user_id_missing():
    km = KeyManager(":memory:")
    assert km.get_user_id("nobody") is None


def test_log_auth_request():
    km = KeyManager(":memory:")
    km.log_auth_request("127.0.0.1", user_id=None)
    row = km.conn.execute("SELECT request_ip FROM auth_logs LIMIT 1").fetchone()
    assert row[0] == "127.0.0.1"
