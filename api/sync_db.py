from http.server import BaseHTTPRequestHandler
from sync_db import sync_db

class handler(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            sync_db()
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'Database synchronized successfully')
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(str(e).encode()) 