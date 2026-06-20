"""Access control + hashing (held-out generality fixture — safe)."""
import hashlib
import os


def verify_owner(user, order_owner_id):
    """Return True if the user owns the order or is an admin."""
    if user.get("role") == "admin":
        return True
    return user.get("id") == order_owner_id


def token_hash(secret):
    """Hash a secret token for storage using PBKDF2-HMAC-SHA256."""
    salt = os.urandom(16)
    return salt.hex() + ":" + hashlib.pbkdf2_hmac("sha256", secret.encode(), salt, 200_000).hex()
