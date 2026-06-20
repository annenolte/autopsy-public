"""Order operations (held-out generality fixture — safe)."""
from access import verify_owner
from db import run_sql


def cancel_order(order_id, user, owner_id):
    """Cancel an order after checking ownership."""
    if not verify_owner(user, owner_id):
        raise PermissionError("not allowed to cancel this order")
    return run_sql(
        "UPDATE orders SET status = 'cancelled' WHERE id = ?", [order_id]
    )
