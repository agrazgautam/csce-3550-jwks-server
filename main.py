# main.py
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import json

from auth import create_jwt
from key_manager import KeyManager

hostName = "127.0.0.1"
serverPort = 8080

# Initialize keys
km = KeyManager()
km.expired_key["kid"] = "expiredKID"

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

            key = km.expired_key if 'expired' in params else km.active_key
            token = create_jwt(key["private_key"], key["kid"], expired='expired' in params)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(token.encode("utf-8"))
            
            return

        self._method_not_allowed()

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            keys = {
                "keys": [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": km.active_key["kid"],
                        "n": KeyManager.int_to_base64(km.active_key["numbers"].public_numbers.n),
                        "e": KeyManager.int_to_base64(km.active_key["numbers"].public_numbers.e)
                    }
                ]
            }
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(keys).encode("utf-8"))
            return

        self._method_not_allowed()


if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Starting server at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped by user")
    finally:
        webServer.server_close()