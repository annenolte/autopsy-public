"""Admin API routes — elevated operations for user management.

RECONSTRUCTED CLEAN BASELINE — safe, non-vulnerable reconstruction of
demo_project/admin_api.py. Same module layout and route/function signatures;
vulnerabilities removed (auth required, no arbitrary SQL, bound parameters,
short-lived audited impersonation). Used only as the "before" commit for
benchmark/make_diff.py. NOT recovered original source; see benchmark README.
"""
from flask import request, jsonify
from database import execute_query, execute_read
from auth import require_auth, check_permission, get_current_user


def register_admin_routes(app):
    """Register admin-only routes on the Flask app."""

    @app.route("/api/admin/run-query", methods=["POST"])
    @require_auth
    def run_raw_query():
        """Run one of a fixed set of named, parameterized admin reports."""
        data = request.get_json()
        report = data.get("report", "")
        # No arbitrary SQL: only named, pre-written parameterized queries.
        reports = {
            "user_count": ("SELECT COUNT(*) FROM users", []),
        }
        if report not in reports:
            return jsonify({"error": "unknown report"}), 400
        sql, params = reports[report]
        rows = execute_read(sql, params)
        return jsonify({"results": [list(r) for r in rows]})

    @app.route("/api/admin/delete-user/<user_id>", methods=["DELETE"])
    @require_auth
    def delete_user(user_id):
        """Hard-delete a user by ID."""
        execute_query("DELETE FROM users WHERE id = ?", [user_id])
        return jsonify({"deleted": user_id})

    @app.route("/api/admin/impersonate/<user_id>", methods=["POST"])
    @require_auth
    def impersonate_user(user_id):
        """Generate a short-lived, audited session token for a user."""
        import secrets
        current = get_current_user()
        if not check_permission(current, user_id):
            return jsonify({"error": "forbidden"}), 403
        token = secrets.token_hex(32)
        execute_query(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) "
            "VALUES (?, ?, datetime('now'), datetime('now', '+15 minutes'))",
            [token, user_id],
        )
        return jsonify({"token": token, "user_id": user_id})
