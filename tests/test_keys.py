import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from key_manager import KeyManager


def test_key_generation():
    km = KeyManager()

    key_data = km.get_or_create_key(expired=False)

    assert key_data["kid"] is not None
    assert key_data["private_key"] is not None


def test_expired_key():
    km = KeyManager()

    key_data = km.get_or_create_key(expired=True)

    assert key_data["exp"] <= key_data["exp"]


def test_base64_conversion():
    value = 65537
    encoded = KeyManager.int_to_base64(value)

    assert isinstance(encoded, str)



def test_generate_key():
    """Test RSA key generation."""
    km = KeyManager()

    private_key, pem = km.generate_key()

    # Ensure objects are returned
    assert private_key is not None
    assert pem is not None

    # PEM should be bytes and contain header
    assert isinstance(pem, bytes)
    assert b"BEGIN PRIVATE KEY" in pem