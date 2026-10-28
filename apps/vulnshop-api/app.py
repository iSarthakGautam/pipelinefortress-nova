"""Main application entry point for vulnshop-api (Python/Flask backend).
Wires up search, user, payment routes, and health monitoring.
"""
from flask import Flask, jsonify, render_template, request
from config import DEBUG, APP_PORT
from routes.search import search_bp, init_items_table
from routes.user import user_bp, init_users_table
from routes.pay import pay_bp


def create_app():
    app = Flask(__name__, template_folder="views")
    app.config["DEBUG"] = DEBUG

    # Register blueprints
    app.register_blueprint(search_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(pay_bp)

    @app.route("/", methods=["GET"])
    def index():
        return """<!DOCTYPE html>
<html>
<head><title>VulnShop Staging Target</title></head>
<body>
    <h1>VulnShop Staging Target</h1>
    <ul>
        <li><a href="/healthz">Health Check</a></li>
        <li><a href="/profile?username=Guest">Profile (Reflected XSS Target)</a></li>
        <li><a href="/api/search?q=phone">Search (SQLi Target)</a></li>
        <li><a href="/api/user/1">User Info (Negative Control)</a></li>
    </ul>
</body>
</html>"""

    @app.route("/healthz", methods=["GET"])
    def health():
        return jsonify({"status": "HEALTHY", "service": "vulnshop-api"})

    @app.route("/profile", methods=["GET"])
    def profile():
        username = request.args.get("username", "Guest")
        email = request.args.get("email", "guest@vulnshop.local")
        return render_template("profile.html", username=username, email=email)

    @app.route("/api/version", methods=["GET"])
    def version():
        return jsonify({"version": "1.0.0", "name": "vulnshop-api"})

    @app.after_request
    def set_security_headers(response):
        # [PLANTED VULN CONTROL: PLANT-009] Frameguard protection against clickjacking
        response.headers["X-Frame-Options"] = "DENY"
        return response

    with app.app_context():
        init_items_table()
        init_users_table()

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=APP_PORT, debug=DEBUG)

