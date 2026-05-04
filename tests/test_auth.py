# test_auth.py
import os
import sys

os.environ.setdefault("NOT_MY_KEY", "test_secret_key_for_ci")
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import jwt
from auth import create_jwt
from cryptography.hazmat.primitives.asymmetric import rsa


def _gen_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

"""Tests for auth.py, covering JWT creation, expiration handling, and header contents."""
def test_create_valid_jwt():
    key = _gen_key()
    token = create_jwt(key, kid="1", expired=False)
    decoded = jwt.decode(token, key.public_key(), algorithms=["RS256"])
    assert decoded["user"] == "username"


def test_create_expired_jwt():
    key = _gen_key()
    token = create_jwt(key, kid="2", expired=True)
    try:
        jwt.decode(token, key.public_key(), algorithms=["RS256"])
        assert False, "Should have raised ExpiredSignatureError"
    except jwt.ExpiredSignatureError:
        assert True


def test_jwt_contains_kid_header():
    key = _gen_key()
    token = create_jwt(key, kid="42", expired=False)
    header = jwt.get_unverified_header(token)
    assert header["kid"] == "42"


def test_jwt_algorithm_is_rs256():
    key = _gen_key()
    token = create_jwt(key, kid="1", expired=False)
    header = jwt.get_unverified_header(token)
    assert header["alg"] == "RS256"
