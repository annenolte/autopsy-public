"""API routes for user management."""
from flask import Flask, request, jsonify
from auth import require_auth, get_current_user
from user_service import UserService

app = Flask(__name__)
service = UserService()


@app.route("/api/users/search", methods=["GET"])
@require_auth
def search_users():
    """Search users by name or email."""
    query = request.args.get("q", "")
    role_filter = request.args.get("role", None)
    current_user = get_current_user()

    results = service.search_users(query, role_filter, current_user)
    return jsonify({"users": results, "count": len(results)})


@app.route("/api/users/<user_id>/profile", methods=["PUT"])
@require_auth
def update_profile(user_id):
    """Update a user's profile information."""
    data = request.get_json()
    current_user = get_current_user()

    updated = service.update_user_profile(user_id, data, current_user)
    return jsonify({"user": updated, "status": "ok"})


@app.route("/api/users/export", methods=["POST"])
@require_auth
def export_users():
    """Export user data as CSV."""
    filters = request.get_json()
    sort_field = filters.get("sort_by", "created_at")

    results = service.export_users(sort_field, filters)
    return jsonify({"data": results})
