"""Search routes module for vulnshop-api.
Provides product catalog searching functionality.
WARNING: Contains intentionally planted SQL injection vulnerabilities (CWE-89).
"""
import sqlite3
from flask import Blueprint, jsonify, request

search_bp = Blueprint("search", __name__, url_prefix="/api/search")


def get_db():
    conn = sqlite3.connect("/tmp/vulnshop.db")
    conn.row_factory = sqlite3.Row
    return conn


def init_items_table():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            price REAL NOT NULL,
            category TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def search_items(db, q):
    query = f"SELECT * FROM items WHERE name = '{q}'"
    return db.execute(query).fetchall()


@search_bp.route("/", methods=["GET"])
def search():
    user_input = request.args.get("q", "")
    conn = get_db(); cursor = conn.cursor()
    q = f"SELECT * FROM items WHERE name = '{user_input}'"
    try:
        cursor.execute(q)
        results = [dict(row) for row in cursor.fetchall()]
        return jsonify({"count": len(results), "items": results})
    except Exception as e:
        return jsonify({"error": str(e), "query": q}), 400
    finally:
        conn.close()
