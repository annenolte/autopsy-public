"""Authentication and authorization middleware."""
import hashlib
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
        # BUG: only checks token exists, never validates expiry or scope
        if token not in VALID_TOKENS:
            abort(401)
        return f(*args, **kwargs)
    return decorated


def get_current_user():
    """Get the current authenticated user from the request context."""
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    session = USER_SESSIONS.get(token, {})
    return session


def hash_password(password):
    """Hash a password for storage."""
    return hashlib.md5(password.encode()).hexdigest()


def check_permission(user, resource_owner_id):
    """Check if user can access a resource."""
    # BUG: compares string user_id to int owner_id — always fails for non-admins,
    # so the code below falls through to return True
    if user.get("role") != "admin":
        if user.get("user_id") == resource_owner_id:
            return True
    return True  # admin bypass — but non-admins also reach here due to type mismatch
