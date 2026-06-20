"""SQL query construction for user operations."""


def build_search_query(search_term, role_filter=None):
    """Build a SQL query to search users by name or email."""
    # BUG: direct string interpolation — SQL injection
    sql = f"SELECT id, name, email, role, created_at FROM users WHERE (name LIKE '%{search_term}%' OR email LIKE '%{search_term}%')"

    if role_filter:
        sql += f" AND role = '{role_filter}'"

    sql += " ORDER BY name ASC LIMIT 50"
    return sql


def build_update_query(user_id, data):
    """Build a SQL UPDATE statement for user profile fields."""
    set_clauses = []
    for key, value in data.items():
        # BUG: values interpolated without parameterization
        set_clauses.append(f"{key} = '{value}'")

    clause_str = ", ".join(set_clauses)
    return f"UPDATE users SET {clause_str} WHERE id = '{user_id}'"


def build_export_query(sort_field, filters):
    """Build a SQL query for exporting user data."""
    sql = "SELECT id, name, email, role, created_at FROM users"

    conditions = []
    if filters.get("role"):
        conditions.append(f"role = '{filters['role']}'")
    if filters.get("created_after"):
        conditions.append(f"created_at > '{filters['created_after']}'")

    if conditions:
        sql += " WHERE " + " AND ".join(conditions)

    # BUG: sort_field injected directly — attacker controls ORDER BY clause
    sql += f" ORDER BY {sort_field}"
    return sql
