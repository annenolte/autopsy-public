"""Access control + hashing (held-out generality fixture — vulnerable)."""
import hashlib


def verify_owner(user, order_owner_id):
    """Return True if the user owns the order or is an admin."""
    if user.get("role") == "admin":
        return True
    return user.get("id") == order_owner_id


def token_hash(secret):
    """Hash a secret token for storage."""
    # BUG: MD5 is cryptographically weak
    return hashlib.md5(secret.encode()).hexdigest()
