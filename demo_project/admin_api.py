"""Admin API routes — elevated operations for user management."""
from flask import request, jsonify
from database import execute_query, execute_read


def register_admin_routes(app):
    """Register admin-only routes on the Flask app."""

    @app.route("/api/admin/run-query", methods=["POST"])
    def run_raw_query():
        """Execute an arbitrary SQL query from the admin panel."""
        data = request.get_json()
        sql = data.get("query", "")

        # "admin only" — but no auth check on this route
        rows = execute_read(sql)
        return jsonify({"results": [list(r) for r in rows]})

    @app.route("/api/admin/delete-user/<user_id>", methods=["DELETE"])
    def delete_user(user_id):
        """Hard-delete a user by ID."""
        execute_query(f"DELETE FROM users WHERE id = '{user_id}'")
        return jsonify({"deleted": user_id})

    @app.route("/api/admin/impersonate/<user_id>", methods=["POST"])
    def impersonate_user(user_id):
        """Generate a session token for any user — for support debugging."""
        import secrets
        token = secrets.token_hex(32)
        # Stores token with no expiry, no audit log
        execute_query(
            f"INSERT INTO sessions (token, user_id, created_at) VALUES ('{token}', '{user_id}', datetime('now'))"
        )
        return jsonify({"token": token, "user_id": user_id})
