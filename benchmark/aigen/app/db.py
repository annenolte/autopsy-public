import sqlite3
import os
from werkzeug.security import generate_password_hash

DATABASE = 'app.db'

def get_db():
    db = sqlite3.connect(DATABASE)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    if os.path.exists(DATABASE):
        os.remove(DATABASE)
    
    db = get_db()
    
    db.execute('''
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            is_admin INTEGER DEFAULT 0,
            profile_photo TEXT
        )
    ''')
    
    admin_password = generate_password_hash('admin123')
    db.execute(
        'INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
        ('admin', admin_password, 1)
    )
    
    db.commit()
    db.close()

def create_user(username, password):
    db = get_db()
    password_hash = generate_password_hash(password)
    try:
        db.execute(
            'INSERT INTO users (username, password) VALUES (?, ?)',
            (username, password_hash)
        )
        db.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        db.close()

def get_user_by_username(username):
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ?',
        (username,)
    ).fetchone()
    db.close()
    return user

def get_user_by_id(user_id):
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE id = ?',
        (user_id,)
    ).fetchone()
    db.close()
    return user

def update_profile_photo(user_id, filename):
    db = get_db()
    db.execute(
        'UPDATE users SET profile_photo = ? WHERE id = ?',
        (filename, user_id)
    )
    db.commit()
    db.close()

def search_users(query):
    db = get_db()
    users = db.execute(
        'SELECT id, username, profile_photo FROM users WHERE username LIKE ?',
        ('%' + query + '%',)
    ).fetchall()
    db.close()
    return users

