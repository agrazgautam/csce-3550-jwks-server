# auth.py
import jwt
import datetime

def create_jwt(private_key_pem, kid, expired=False):
    """Create JWT with optional expired claim."""
    now = datetime.datetime.utcnow()
    exp = now - datetime.timedelta(hours=1) if expired else now + datetime.timedelta(hours=1)

    payload = {
        "user": "username",
        "exp": exp
    }

    token = jwt.encode(payload, private_key_pem, algorithm="RS256", headers={"kid": kid})
    return token