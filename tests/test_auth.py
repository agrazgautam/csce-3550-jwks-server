import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
import jwt
from auth import create_jwt
from cryptography.hazmat.primitives.asymmetric import rsa


def generate_test_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def test_create_valid_jwt():
    key = generate_test_key()

    token = create_jwt(key, kid="1", expired=False)

    decoded = jwt.decode(token, key.public_key(), algorithms=["RS256"])

    assert decoded["user"] == "username"


def test_create_expired_jwt():
    key = generate_test_key()

    token = create_jwt(key, kid="2", expired=True)

    try:
        jwt.decode(token, key.public_key(), algorithms=["RS256"])
        assert False
    except jwt.ExpiredSignatureError:
        assert True