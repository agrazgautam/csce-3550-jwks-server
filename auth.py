# app/auth.py
import jwt
import time

def create_jwt(private_key, kid, payload=None, expired=False):
    payload = payload or {}
    now = int(time.time())
    payload.update({
        "iat": now,
        "exp": now + 3600 if not expired else now - 3600,
        "sub": "fake_user"
    })

    token = jwt.encode(
        payload,
        key=private_key,
        algorithm="RS256",
        headers={"kid": kid}
    )
    return token
