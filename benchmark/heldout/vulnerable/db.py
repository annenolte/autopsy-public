"""Order database access (held-out generality fixture — vulnerable)."""
import sqlite3

_conn = None


def connect():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect("orders.db")
    return _conn


def run_sql(query):
    """Execute a raw SQL string — a thin wrapper sink."""
    return connect().execute(query).fetchall()
