#!/usr/bin/env python3
"""Server statis + proteksi password sederhana untuk Q-EKH Protocol."""
import base64
import hmac
import http.server
import os
import socketserver

PORT = int(os.environ.get("QEKH_PORT", "8000"))
BIND = os.environ.get("QEKH_BIND", "127.0.0.1")  # ganti "0.0.0.0" untuk akses dari HP/laptop lain di WiFi sama
USERNAME = os.environ.get("QEKH_USER", "admin")
PASSWORD = os.environ.get("QEKH_PASS", "")

if not PASSWORD:
    raise SystemExit('PASSWORD belum diset. Jalankan: QEKH_PASS="passwordAnda" python serve.py')

EXPECTED_AUTH = "Basic " + base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()

class AuthHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        header = self.headers.get("Authorization", "")
        if not hmac.compare_digest(header, EXPECTED_AUTH):
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="Q-EKH Protocol"')
            self.end_headers()
            self.wfile.write(b"401 - Autentikasi diperlukan.")
            return
        super().do_GET()

with socketserver.TCPServer((BIND, PORT), AuthHandler) as httpd:
    print(f"Q-EKH Protocol jalan di http://{BIND}:{PORT}  (user: {USERNAME})")
    print("Ctrl+C untuk berhenti.")
    httpd.serve_forever()
