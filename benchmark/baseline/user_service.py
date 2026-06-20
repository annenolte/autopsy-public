"""User service layer — business logic for user operations.

RECONSTRUCTED CLEAN BASELINE — safe, non-vulnerable reconstruction of
demo_project/user_service.py. Same class/method signatures; vulnerabilities
removed (permission return value enforced, parameterized queries, field
whitelist). Used only as the "before" commit for benchmark/make_diff.py.
NOT recovered original source; see benchmark README.
"""
from auth import check_permission
from query_builder import build_search_query, build_update_query, build_export_query
from database import execute_query, execute_read


class UserService:
    """Handles user-related business logic."""

    def search_users(self, query, role_filter, current_user):
        """Search for users matching a query string."""
        sql, params = build_search_query(query, role_filter)
        rows = execute_read(sql, params)
        return [self._format_user(row) for row in rows]

    def update_user_profile(self, user_id, data, current_user):
        """Update a user's profile. Enforces permission first."""
        if not check_permission(current_user, user_id):
            raise PermissionError("not authorized to update this profile")

        allowed_fields = ["name", "email", "bio", "website", "location"]
        clean_data = {k: v for k, v in data.items() if k in allowed_fields}

        sql, params = build_update_query(user_id, clean_data)
        execute_query(sql, params)
        return {"id": user_id, **clean_data}

    def export_users(self, sort_field, filters):
        """Export users with sorting and filtering."""
        sql, params = build_export_query(sort_field, filters)
        rows = execute_read(sql, params)
        return [self._format_user(row) for row in rows]

    def _format_user(self, row):
        """Format a database row into a user dict."""
        return {
            "id": row[0],
            "name": row[1],
            "email": row[2],
            "role": row[3],
            "created_at": str(row[4]),
        }
