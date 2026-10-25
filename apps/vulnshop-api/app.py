"""Main application entry point for vulnshop-api (Python/Flask backend).
Wires up search, user, payment routes, and health monitoring.
"""
from flask import Flask, jsonify
from config import DEBUG, APP_PORT
from routes.search import search_bp, init_items_table
from routes.user import user_bp
from routes.pay import pay_bp


def create_app():
    app = Flask(__name__)
    app.config["DEBUG"] = DEBUG

    # Register blueprints
    app.register_blueprint(search_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(pay_bp)

    @app.route("/healthz", methods=["GET"])
    def health():
        return jsonify({"status": "HEALTHY", "service": "vulnshop-api"})

    @app.route("/api/version", methods=["GET"])
    def version():
        return jsonify({"version": "1.0.0", "name": "vulnshop-api"})

    with app.app_context():
        init_items_table()

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=APP_PORT, debug=DEBUG)

