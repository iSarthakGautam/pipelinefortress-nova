"""User profile routes module for vulnshop-api.
Provides safe user profile lookup using parameterized queries.
Serves as negative/false-positive test case for SAST scanners.
"""
import sqlite3
from flask import Blueprint, jsonify, request

user_bp = Blueprint("user", __name__, url_prefix="/api/user")


def get_db():
    conn = sqlite3.connect("/tmp/vulnshop.db")
    conn.row_factory = sqlite3.Row
    return conn
@user_bp.route("/<uid>", methods=["GET"])
def get_user(uid):
    cursor = get_db().cursor()
    cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))
    row = cursor.fetchone()
    if not row:
        return jsonify({"error": "User not found"}), 404
    return jsonify(dict(row))
