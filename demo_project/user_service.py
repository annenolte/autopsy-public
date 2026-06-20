"""User service layer — business logic for user operations."""
from auth import check_permission
from query_builder import build_search_query, build_update_query, build_export_query
from database import execute_query, execute_read


class UserService:
    """Handles user-related business logic."""

    def search_users(self, query, role_filter, current_user):
        """Search for users matching a query string."""
        sql = build_search_query(query, role_filter)
        rows = execute_read(sql)
        return [self._format_user(row) for row in rows]

    def update_user_profile(self, user_id, data, current_user):
        """Update a user's profile. Checks permissions first."""
        check_permission(current_user, user_id)

        # Sanitize fields — but missed 'bio' and 'website'
        allowed_fields = ["name", "email", "bio", "website", "location"]
        clean_data = {k: v for k, v in data.items() if k in allowed_fields}

        sql = build_update_query(user_id, clean_data)
        execute_query(sql)
        return {"id": user_id, **clean_data}

    def export_users(self, sort_field, filters):
        """Export users with sorting and filtering."""
        # sort_field comes straight from user input — no validation
        sql = build_export_query(sort_field, filters)
        rows = execute_read(sql)
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
