# main.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from urllib.parse import urlparse, parse_qs
import json
import time

from auth import create_jwt
from key_manager import KeyManager

hostName = "127.0.0.1"
serverPort = 8080

km = KeyManager()


class MyServer(BaseHTTPRequestHandler):

    def _method_not_allowed(self):
        self.send_response(405)
        self.end_headers()

    def do_PUT(self): self._method_not_allowed()
    def do_PATCH(self): self._method_not_allowed()
    def do_DELETE(self): self._method_not_allowed()
    def do_HEAD(self): self._method_not_allowed()

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)

        if parsed_path.path == "/auth":
            now = int(time.time())

            try:
                if 'expired' in params:
                    row = km.conn.execute(
                        "SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                        (now,)
                    ).fetchone()
                else:
                    row = km.conn.execute(
                        "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                        (now,)
                    ).fetchone()

                if not row:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"No key found")
                    return

                kid, key_pem = row

                private_key = serialization.load_pem_private_key(
                    key_pem,
                    password=None
                )

                token = create_jwt(
                    private_key,
                    kid,
                    expired=('expired' in params)
                )

                self.send_response(200)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(token.encode())

            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Server error: {e}".encode())

            return

        self._method_not_allowed()


    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            now = int(time.time())

            try:
                rows = km.conn.execute(
                    "SELECT kid, key FROM keys WHERE exp > ?",
                    (now,)
                ).fetchall()

                keys = {"keys": []}

                for kid, key_pem in rows:
                    private_key = serialization.load_pem_private_key(
                        key_pem,
                        password=None
                    )

                    pub_numbers = private_key.public_key().public_numbers()

                    keys["keys"].append({
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": str(kid),
                        "n": KeyManager.int_to_base64(pub_numbers.n),
                        "e": KeyManager.int_to_base64(pub_numbers.e)
                    })

                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(keys).encode())


            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Server error: {e}".encode())

            return

        self._method_not_allowed()


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)

    print(f"Starting server at http://{hostName}:{serverPort}")

    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped")

    finally:
        webServer.server_close()