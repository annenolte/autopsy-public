"""Admin action handling with an authorization gate."""


def authorize_request(user):
    """Return True only for staff users."""
    return getattr(user, "is_staff", False)


def handle_admin_action(user, action):
    if not authorize_request(user):
        raise PermissionError("denied")
    return _run(action)
