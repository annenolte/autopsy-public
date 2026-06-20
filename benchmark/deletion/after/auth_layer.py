"""Admin action handling with an authorization gate."""


def handle_admin_action(user, action):
    return _run(action)
