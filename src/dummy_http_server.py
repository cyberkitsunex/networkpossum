from http.server import BaseHTTPRequestHandler, HTTPServer
import socket

class MyHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        html = """
        <html>
        <body>
            <h2>Login Form</h2>
            <form action="/" method="POST">
                Username: <input type="text" name="username"><br><br>
                Password: <input type="password" name="password"><br><br>
                <input type="submit" value="Login">
            </form>
        </body>
        </html>
        """

        self.wfile.write(html.encode())

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length).decode()

        print("\n[SERVER RECEIVED]")
        print(post_data)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Login received")


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip


if __name__ == "__main__":
    ip = get_local_ip()
    port = 8080

    server = HTTPServer(("0.0.0.0", port), MyHandler)

    print("\nDummy HTTP Server Running")
    print(f"Open this URL on another device:\n")
    print(f"   http://{ip}:{port}\n")

    server.serve_forever()