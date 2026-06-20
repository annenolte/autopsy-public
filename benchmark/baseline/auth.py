"""Authentication and authorization middleware.

RECONSTRUCTED CLEAN BASELINE — safe, non-vulnerable reconstruction of
demo_project/auth.py. Same module layout and public function signatures;
vulnerabilities removed (token expiry/scope checks, PBKDF2 password hashing,
correct permission logic). Used only as the "before" commit for
benchmark/make_diff.py. NOT recovered original source; see benchmark README.
"""
import hashlib
import os
import time
from functools import wraps
from flask import request, abort


VALID_TOKENS = {}
USER_SESSIONS = {}


def require_auth(f):
    """Decorator to require authentication on a route."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("Authorization", "").replace("Bearer ", "")
        if not token:
            abort(401)
        record = VALID_TOKENS.get(token)
        if not record:
            abort(401)
        # Validate liveness and scope, not just presence.
        if record.get("expires_at", 0) < time.time():
            abort(401)
        if "api" not in record.get("scopes", []):
            abort(403)
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    """Get the current authenticated user from the request context."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    session = USER_SESSIONS.get(token, {})
    return session


def hash_password(password):
    """Hash a password for storage using PBKDF2-HMAC-SHA256 with a random salt."""
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + ":" + digest.hex()


def check_permission(user, resource_owner_id):
    """Check if user can access a resource. Returns True only when authorized."""
    if user.get("role") == "admin":
        return True
    return str(user.get("user_id")) == str(resource_owner_id)
