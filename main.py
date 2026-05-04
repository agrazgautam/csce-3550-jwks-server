# main.py
import json
import time
import uuid
import threading
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization

from auth import create_jwt
from key_manager import KeyManager

hostName = "127.0.0.1"
serverPort = 8080

km = KeyManager()
ph = PasswordHasher(time_cost=2, memory_cost=65536, parallelism=2, hash_len=32, salt_len=16)

# Rate limiter (time-window, 10 req/s)

RATE_LIMIT = 10          # max requests
RATE_WINDOW = 1.0        # seconds

_rate_lock = threading.Lock()
_request_times: deque = deque()   # timestamps of recent /auth requests


def _is_rate_limited() -> bool:
    """Return True if the caller should be throttled."""
    now = time.monotonic()
    with _rate_lock:
        # Discard entries outside the current window
        while _request_times and now - _request_times[0] > RATE_WINDOW:
            _request_times.popleft()

        if len(_request_times) >= RATE_LIMIT:
            return True

        _request_times.append(now)
        return False


#  HTTP handler
"""handles incoming HTTP requests, implements the /auth and /register endpoints, and serves the JWKS at /.well-known/jwks.json."""

class MyServer(BaseHTTPRequestHandler):

    # Helpers
    # Helper methods for sending JSON responses, reading request bodies, extracting client IPs, and handling unsupported HTTP methods.

    def _send_json(self, status: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _method_not_allowed(self):
        self.send_response(405)
        self.end_headers()

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", 0))
        return self.rfile.read(length) if length else b""

    def _client_ip(self) -> str:
        # Honour X-Forwarded-For when behind a proxy, else use remote address.
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]

    def log_message(self, fmt, *args):
        # Suppress default per-request console noise (optional; remove to restore)
        pass

    #  Blocked methods
    """do_PUT(), do_PATCH(), do_DELETE(), and do_HEAD() all respond with 405 Method Not Allowed."""

    def do_PUT(self):    self._method_not_allowed()
    def do_PATCH(self):  self._method_not_allowed()
    def do_DELETE(self): self._method_not_allowed()
    def do_HEAD(self):   self._method_not_allowed()

    # POST

    def do_POST(self):
        parsed_path = urlparse(self.path)
        params      = parse_qs(parsed_path.query)

        #  POST /auth
        # If the path is /auth, check the rate limiter. If the client has made too many requests in the last second, respond with 429 Too Many Requests and a JSON error message. Otherwise, look up the appropriate RSA key (expired or valid based on the "expired" query parameter), create a JWT, log the authentication request, and respond with the token.
        if parsed_path.path == "/auth":

            # Rate limiter check
            # If the client has made too many requests in the last second, respond with 429 Too Many Requests and a JSON error message.
            if _is_rate_limited():
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error": "Too Many Requests"}')
                return

            now = int(time.time())
            use_expired = "expired" in params

            try:
                if use_expired:
                    row = km.conn.execute(
                        "SELECT kid, key FROM keys WHERE exp <= ? ORDER BY exp DESC LIMIT 1",
                        (now,),
                    ).fetchone()
                else:
                    row = km.conn.execute(
                        "SELECT kid, key FROM keys WHERE exp > ? ORDER BY exp DESC LIMIT 1",
                        (now,),
                    ).fetchone()

                if not row:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(b"No key found")
                    return

                kid, encrypted_pem = row

                from key_manager import decrypt_pem
                pem = decrypt_pem(bytes(encrypted_pem))
                private_key = serialization.load_pem_private_key(pem, password=None)

                token = create_jwt(private_key, kid, expired=use_expired)

                # Log this auth request
                # Try to extract username from request body (best-effort)
                request_ip = self._client_ip()
                user_id    = None
                try:
                    body = self._read_body()
                    if body:
                        data = json.loads(body)
                        username = data.get("username")
                        if username:
                            user_id = km.get_user_id(username)
                except Exception:
                    pass

                km.log_auth_request(request_ip, user_id)

                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(token.encode())

            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Server error: {e}".encode())

            return

        # POST /register
        if parsed_path.path == "/register":
            try:
                body = self._read_body()
                data = json.loads(body)
            except (ValueError, KeyError):
                self._send_json(400, {"error": "Invalid JSON body"})
                return

            username = data.get("username", "").strip()
            email    = data.get("email", "").strip() or None

            if not username:
                self._send_json(400, {"error": "username is required"})
                return

            # Generate a secure UUIDv4 password
            password = str(uuid.uuid4())

            # Hash with Argon2
            password_hash = ph.hash(password)

            try:
                with km.conn:
                    km.conn.execute(
                        "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                        (username, password_hash, email),
                    )
            except Exception as e:
                # UNIQUE constraint failure -> conflict
                if "UNIQUE" in str(e):
                    self._send_json(409, {"error": "Username or email already exists"})
                else:
                    self._send_json(500, {"error": f"Database error: {e}"})
                return

            self._send_json(201, {"password": password})
            return

        # Any other POST path
        self._method_not_allowed()

    # GET
    """handles GET requests, serves the JWKS at /.well-known/jwks.json, and responds with 405 Method Not Allowed for unsupported paths."""

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            now = int(time.time())
            try:
                rows = km.conn.execute(
                    "SELECT kid, key FROM keys WHERE exp > ?",
                    (now,),
                ).fetchall()

                from key_manager import decrypt_pem
                keys_list = []
                for kid, encrypted_pem in rows:
                    pem = decrypt_pem(bytes(encrypted_pem))
                    private_key = serialization.load_pem_private_key(pem, password=None)
                    pub_numbers = private_key.public_key().public_numbers()
                    keys_list.append({
                        "kty": "RSA",
                        "use": "sig",
                        "alg": "RS256",
                        "kid": str(kid),
                        "n": KeyManager.int_to_base64(pub_numbers.n),
                        "e": KeyManager.int_to_base64(pub_numbers.e),
                    })

                self._send_json(200, {"keys": keys_list})

            except Exception as e:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(f"Server error: {e}".encode())

            return

        self._method_not_allowed()


# Entry point
# When run directly, start the HTTP server on the specified host and port, and handle requests with MyServer. Gracefully shut down on keyboard interrupt.

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    print(f"Starting server at http://{hostName}:{serverPort}")
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        print("Server stopped")
    finally:
        webServer.server_close()
