"""Database connection and query execution layer.

RECONSTRUCTED CLEAN BASELINE — safe, non-vulnerable reconstruction of
demo_project/database.py. Same module layout and public function signatures
(an optional `params` argument is added so callers can bind parameters).
Used only as the "before" commit for benchmark/make_diff.py. NOT recovered
original source; see benchmark README.
"""
import sqlite3
import os

DB_PATH = os.getenv("USER_DB_PATH", "users.db")

_connection = None


def get_connection():
    """Get or create the database connection."""
    global _connection
    if _connection is None:
        _connection = sqlite3.connect(DB_PATH)
    return _connection


def execute_query(sql, params=None):
    """Execute a write query (INSERT, UPDATE, DELETE) with bound parameters."""
    conn = get_connection()
    conn.execute(sql, params or [])
    conn.commit()


def execute_read(sql, params=None):
    """Execute a read query with bound parameters and return all rows."""
    conn = get_connection()
    cursor = conn.execute(sql, params or [])
    return cursor.fetchall()


def init_db():
    """Initialize the database schema."""
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            bio TEXT,
            website TEXT,
            location TEXT,
            password_hash TEXT
        )
    """)
    conn.commit()
