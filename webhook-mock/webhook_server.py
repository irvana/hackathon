from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"OK")
            return
        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode()
        print("=== WEBHOOK RECEIVED ===", flush=True)
        print(body, flush=True)
        print("========================", flush=True)
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *_):
        pass


if __name__ == "__main__":
    port = 9000
    print(f"Webhook listener ready on http://0.0.0.0:{port}/webhook", flush=True)
    HTTPServer(("0.0.0.0", port), Handler).serve_forever()
