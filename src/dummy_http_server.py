from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse

class SimpleLoginHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        html = """
        <html>
            <body>
                <h2>Dummy Login Page (HTTP - Insecure)</h2>
                <form method="POST">
                    Username: <input type="text" name="username"><br><br>
                    Password: <input type="password" name="password"><br><br>
                    <input type="submit" value="Login">
                </form>
            </body>
        </html>
        """
        self.wfile.write(html.encode())

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode()

        parsed = urllib.parse.parse_qs(post_data)
        username = parsed.get("username", [""])[0]
        password = parsed.get("password", [""])[0]

        print("\n[SERVER RECEIVED]")
        print("Username:", username)
        print("Password:", password)

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Login received (insecure HTTP).")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8080), SimpleLoginHandler)
    print("Serving insecure HTTP login on http://192.168.1.18:8080")
    server.serve_forever()