"""SQL query construction for user operations.

RECONSTRUCTED CLEAN BASELINE — safe, non-vulnerable reconstruction of
demo_project/query_builder.py. Same module layout and public function
signatures, vulnerabilities removed (bound parameters; whitelisted ORDER BY).
Used only as the "before" commit when generating the evaluation diff
(benchmark/make_diff.py). This is NOT recovered original source — no
pre-vulnerability version was ever committed; see benchmark README.
"""

ALLOWED_SORT_FIELDS = {"id", "name", "email", "role", "created_at"}


def build_search_query(search_term, role_filter=None):
    """Build a parameterized query to search users by name or email."""
    sql = (
        "SELECT id, name, email, role, created_at FROM users "
        "WHERE (name LIKE ? OR email LIKE ?)"
    )
    like = f"%{search_term}%"
    params = [like, like]

    if role_filter:
        sql += " AND role = ?"
        params.append(role_filter)

    sql += " ORDER BY name ASC LIMIT 50"
    return sql, params


def build_update_query(user_id, data):
    """Build a parameterized UPDATE statement for user profile fields."""
    set_clauses = []
    params = []
    for key, value in data.items():
        # Column names come from a server-side whitelist (see UserService).
        set_clauses.append(f"{key} = ?")
        params.append(value)

    clause_str = ", ".join(set_clauses)
    params.append(user_id)
    return f"UPDATE users SET {clause_str} WHERE id = ?", params


def build_export_query(sort_field, filters):
    """Build a parameterized query for exporting user data."""
    sql = "SELECT id, name, email, role, created_at FROM users"

    conditions = []
    params = []
    if filters.get("role"):
        conditions.append("role = ?")
        params.append(filters["role"])
    if filters.get("created_after"):
        conditions.append("created_at > ?")
        params.append(filters["created_after"])

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    # Whitelist the sort column — never interpolate user input into ORDER BY.
    if sort_field not in ALLOWED_SORT_FIELDS:
        sort_field = "name"
    sql += f" ORDER BY {sort_field}"
    return sql, params
