# Test targets for scanners/semgrep/rules/python-sqli.yaml. Deliberately vulnerable; never imported.
import sqlite3

from flask import request


def search(cursor):
    user_input = request.args.get("q", "")
    # ruleid: pf-python-sqli-formatted-query
    q = f"SELECT * FROM items WHERE name = '{user_input}'"
    cursor.execute(q)


def search_items(db, q):
    # ruleid: pf-python-sqli-formatted-query
    query = f"SELECT * FROM items WHERE name = '{q}'"
    return db.execute(query).fetchall()


def inline_forms(cur, name, uid):
    # ruleid: pf-python-sqli-formatted-query
    cur.execute("SELECT * FROM users WHERE name = '%s'" % name)
    # ruleid: pf-python-sqli-formatted-query
    cur.execute("DELETE FROM users WHERE id = {}".format(uid))
    # ruleid: pf-python-sqli-formatted-query
    cur.executemany("UPDATE users SET name = '" + name + "'", [])


def safe_forms(cursor, uid, name):
    # PLANT-002 negative control: placeholder + parameter tuple
    # ok: pf-python-sqli-formatted-query
    cursor.execute('SELECT * FROM users WHERE id = %s', (uid,))
    # ok: pf-python-sqli-formatted-query
    cursor.execute("SELECT * FROM users WHERE name = ?", (name,))
    # ok: pf-python-sqli-formatted-query
    cursor.execute("CREATE TABLE IF NOT EXISTS items (id INTEGER PRIMARY KEY)")
    # constant f-string, no placeholder
    # ok: pf-python-sqli-formatted-query
    cursor.execute(f"SELECT COUNT(*) FROM items")


def not_sql(executor, job):
    # formatted, but not SQL
    # ok: pf-python-sqli-formatted-query
    executor.execute(f"run job {job}")


sqlite3.connect(":memory:")
