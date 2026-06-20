"""Database connection and query execution layer."""
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


def execute_query(sql):
    """Execute a write query (INSERT, UPDATE, DELETE)."""
    conn = get_connection()
    # BUG: executes raw SQL string — no parameterized queries
    conn.execute(sql)
    conn.commit()


def execute_read(sql):
    """Execute a read query and return all rows."""
    conn = get_connection()
    # BUG: executes raw SQL string — this is where injection payload lands
    cursor = conn.execute(sql)
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
