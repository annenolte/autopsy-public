from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.utils import secure_filename
import os
import db
from auth import auth_bp
from admin import admin_bp

app = Flask(__name__)
app.secret_key = 'dev_secret_key_change_in_production'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('profile'))
    return redirect(url_for('auth.login'))

@app.route('/profile', methods=['GET', 'POST'])
def profile():
    if 'user_id' not in session:
        return redirect(url_for('auth.login'))
    
    if request.method == 'POST':
        if 'photo' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['photo']
        
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filename = f"{session['user_id']}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            db.update_profile_photo(session['user_id'], filename)
            flash('Profile photo updated successfully')
            return redirect(url_for('profile'))
        else:
            flash('Invalid file type')
    
    user = db.get_user_by_id(session['user_id'])
    return render_template('profile.html', user=user)

if __name__ == '__main__':
    if not os.path.exists(db.DATABASE):
        db.init_db()
    app.run(debug=True)

