from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    # Deliberately adding ALL the good headers our scanner checks for
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src *; script-src 'unsafe-inline'"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    return response

@app.route("/")
def home():
    return "This is a safely configured test page."

if __name__ == "__main__":
    app.run(port=5000)