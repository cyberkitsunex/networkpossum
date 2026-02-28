from http.server import BaseHTTPRequestHandler, HTTPServer
import urllib.parse
import socket

class SimpleLoginHandler(BaseHTTPRequestHandler):

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        html = """
<html>
<head>
    <title>Secure Account Portal</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f2f4f7;
            display: flex;
            justify-content: center;
            align-items: center;
            height: 100vh;
        }
        .login-box {
            background: white;
            padding: 30px;
            width: 350px;
            box-shadow: 0 4px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
        }
        .login-box h2 {
            margin-bottom: 20px;
            text-align: center;
        }
        .login-box input {
            width: 100%;
            padding: 10px;
            margin: 8px 0;
            border: 1px solid #ccc;
            border-radius: 4px;
        }
        .login-box button {
            width: 100%;
            padding: 10px;
            background-color: #0078d4;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .login-box button:hover {
            background-color: #005ea6;
        }
        .notice {
            margin-top: 15px;
            font-size: 12px;
            color: red;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>Account Sign In</h2>
        <form method="POST">
            <input type="text" name="username" placeholder="Email or Username" required>
            <input type="password" name="password" placeholder="Password" required>
            <button type="submit">Sign In</button>
        </form>
    </div>
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

def get_local_ip():
    """Get the LAN IP address of the machine."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # The IP doesn't have to be reachable; just used to get local IP
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    finally:
        s.close()
    return ip

if __name__ == "__main__":
    ip = get_local_ip()
    server = HTTPServer(("0.0.0.0", 8080), SimpleLoginHandler)
    print(f"Serving insecure HTTP login on http://{ip}:8080")
    server.serve_forever()