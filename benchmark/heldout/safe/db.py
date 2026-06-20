"""Order database access (held-out generality fixture — safe)."""
import sqlite3

_conn = None


def connect():
    global _conn
    if _conn is None:
        _conn = sqlite3.connect("orders.db")
    return _conn


def run_sql(query, params=None):
    """Execute SQL with bound parameters."""
    return connect().execute(query, params or []).fetchall()
