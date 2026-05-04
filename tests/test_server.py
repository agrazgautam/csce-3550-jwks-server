# test_server.py
"""
Integration tests for the JWKS server.
Covers: /auth, /.well-known/jwks.json, /register, rate limiting, method blocking.
"""

import os
import threading
import time
import json
import requests
import pytest

# Set the AES encryption key before any import touches KeyManager
os.environ.setdefault("NOT_MY_KEY", "test_secret_key_for_ci")

import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from http.server import HTTPServer
from main import MyServer, hostName, serverPort

BASE = f"http://{hostName}:{serverPort}"

"""Integration tests for the JWKS server, covering authentication, JWKS retrieval, user registration, rate limiting, and method blocking."""

# Server fixture

@pytest.fixture(scope="module", autouse=True)
def running_server():
    server = HTTPServer((hostName, serverPort), MyServer)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    time.sleep(0.5)
    yield
    server.shutdown()


# /auth endpoint

def test_auth_endpoint():
    r = requests.post(f"{BASE}/auth")
    assert r.status_code == 200
    assert len(r.text) > 20


def test_auth_expired():
    r = requests.post(f"{BASE}/auth?expired=true")
    assert r.status_code == 200


# /.well-known/jwks.json

def test_jwks_endpoint():
    r = requests.get(f"{BASE}/.well-known/jwks.json")
    assert r.status_code == 200
    data = r.json()
    assert "keys" in data
    assert len(data["keys"]) >= 1
    key = data["keys"][0]
    assert "kid" in key
    assert "n" in key
    assert "e" in key


# /register endpoint
# Tests for user registration, including password return, duplicate username handling, and optional email field.
def test_register_returns_password():
    payload = {"username": "testuser_reg", "email": "testuser@example.com"}
    r = requests.post(f"{BASE}/register", json=payload)
    assert r.status_code in (200, 201)
    body = r.json()
    assert "password" in body
    # UUIDv4: 36 characters with 4 hyphens
    pw = body["password"]
    assert len(pw) == 36
    assert pw.count("-") == 4


def test_register_duplicate_username():
    payload = {"username": "dup_user", "email": "dup@example.com"}
    requests.post(f"{BASE}/register", json=payload)
    r = requests.post(f"{BASE}/register", json=payload)
    assert r.status_code == 409


def test_register_missing_username():
    r = requests.post(f"{BASE}/register", json={"email": "nousername@example.com"})
    assert r.status_code == 400


def test_register_no_email():
    """email is optional per the schema."""
    payload = {"username": "no_email_user"}
    r = requests.post(f"{BASE}/register", json=payload)
    assert r.status_code in (200, 201)
    assert "password" in r.json()


# Method blocking
# Unsupported methods should return 405 Method Not Allowed.
def test_put_not_allowed():
    r = requests.put(f"{BASE}/auth")
    assert r.status_code == 405


def test_delete_not_allowed():
    r = requests.delete(f"{BASE}/auth")
    assert r.status_code == 405


def test_invalid_route_get():
    r = requests.get(f"{BASE}/invalid")
    assert r.status_code == 405


# Rate limiter
"""Fire 15 requests in quick succession; at least some should be 429."""

def test_rate_limiter():
    """
    Fire 15 requests in quick succession; at least some should be 429.
    """
    responses = [requests.post(f"{BASE}/auth") for _ in range(15)]
    codes = [r.status_code for r in responses]
    assert 429 in codes, f"Expected a 429 among: {codes}"
    assert 200 in codes, f"Expected some 200s among: {codes}"
