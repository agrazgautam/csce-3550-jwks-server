# auth.py
import jwt
import datetime

"""
    Creates a JWT signed with private_key and a "kid" header set to kid.
    If expired is True, sets "exp" to 1 hour ago; otherwise 1 hour ahead.
    Includes a "user" claim (e.g., "username"). Returns the encoded JWT as a string.
"""
def create_jwt(private_key, kid, expired=False):
    """Create JWT with optional expired claim.
     - private_key: RSA private key for signing
     - kid: Key ID to include in JWT header
     - expired: If True, set "exp" to 1 hour ago; otherwise 1 hour ahead
     Returns the encoded JWT as a string.
    """
    now = datetime.datetime.now(datetime.UTC)
    exp = now - datetime.timedelta(hours=1) if expired else now + datetime.timedelta(hours=1)

    payload = {
        "user": "username",
        "exp": exp
    }

    """
        Create JWT with the given payload, signed with the provided RSA private key.
        The JWT header includes the "kid" to indicate which key was used for signing.
     """
    token = jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": str(kid)}
    )

    return token