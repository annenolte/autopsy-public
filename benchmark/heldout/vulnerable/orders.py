"""Order operations (held-out generality fixture — vulnerable)."""
from access import verify_owner
from db import run_sql


def cancel_order(order_id, user, owner_id):
    """Cancel an order after checking ownership."""
    # BUG: verify_owner's return value is ignored — the check does nothing
    verify_owner(user, owner_id)
    # BUG: order_id interpolated into the SQL string passed to a sink
    return run_sql(f"UPDATE orders SET status = 'cancelled' WHERE id = {order_id}")
