import threading
import time
import requests
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import MyServer, hostName, serverPort
from http.server import HTTPServer


def run_server():
    server = HTTPServer((hostName, serverPort), MyServer)
    server.serve_forever()


def setup_module():
    thread = threading.Thread(target=run_server, daemon=True)
    thread.start()
    time.sleep(1)


def test_auth_endpoint():
    r = requests.post("http://127.0.0.1:8080/auth")

    assert r.status_code == 200
    assert len(r.text) > 20


def test_auth_expired():
    r = requests.post("http://127.0.0.1:8080/auth?expired=true")

    assert r.status_code == 200


def test_jwks_endpoint():
    r = requests.get("http://127.0.0.1:8080/.well-known/jwks.json")

    assert r.status_code == 200

    data = r.json()

    assert "keys" in data
    assert len(data["keys"]) >= 1

    key = data["keys"][0]

    assert "kid" in key
    assert "n" in key
    assert "e" in key


def test_invalid_method():
    import requests

    # PUT request
    r = requests.put("http://127.0.0.1:8080/auth")

    assert r.status_code == 405


def test_invalid_route():
    import requests

    r = requests.get("http://127.0.0.1:8080/invalid")

    assert r.status_code == 405