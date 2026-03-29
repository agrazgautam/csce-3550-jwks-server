# app/main.py
from fastapi import FastAPI, Query
from fastapi.responses import JSONResponse
from key_manager import KeyManager, int_to_base64
from auth import create_jwt
from cryptography.hazmat.primitives import serialization

app = FastAPI()
key_manager = KeyManager()

# Generate a default key
key_manager.generate_key(expiry_seconds=60*60)  # 1 hour expiry

@app.get("/.well-known/jwks.json")
def get_jwks():
    keys = key_manager.get_active_keys()
    jwks = {
        "keys": [
            {
                "kty": "RSA",
                "kid": key["kid"],
                "use": "sig",
                "alg": "RS256",
                "n": int_to_base64(key["public_key"].public_numbers().n),
                "e": int_to_base64(key["public_key"].public_numbers().e)
            } for key in keys
        ]
    }
    return JSONResponse(content=jwks)

@app.post("/auth")
def auth(expired: bool = Query(False)):
    """Return a JWT, optionally signed with an expired key."""

    key_data = key_manager.get_latest_key(expired=expired)
    token = create_jwt(key_data["private_key"], key_data["kid"], expired=expired)
    
    return {"access_token": token, "token_type": "bearer"}