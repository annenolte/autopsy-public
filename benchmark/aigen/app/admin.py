from flask import Blueprint, render_template, request, session, redirect, url_for
import db

admin_bp = Blueprint('admin', __name__)

@admin_bp.route('/admin')
def admin_page():
    if 'user_id' not in session or not session.get('is_admin'):
        return redirect(url_for('auth.login'))
    
    query = request.args.get('search', '')
    users = []
    
    if query:
        users = db.search_users(query)
    
    return render_template('admin.html', users=users, query=query)

