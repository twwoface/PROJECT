from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required

app = Flask(__name__)

# Database Configuration
app.config['SECRET_KEY'] = 'your_secret_key'

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# List of Colleges for Dropdown
COLLEGES = ["KMCT COLLEGE OF ENG", "KMCT COLLEGE OF ARCH"]

# Create Database and Table
def init_db():
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            college TEXT NOT NULL,
                            admission_number TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            is_hosteller INTEGER NOT NULL,
                            hostel_name TEXT)''')
        conn.commit()

init_db()

class User(UserMixin):
    def __init__(self, id, email, password):
        self.id = id
        self.email = email
        self.password = password

@login_manager.user_loader
def load_user(user_id):
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT id, email, password FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        if user:
            return User(id=user[0], email=user[1], password=user[2])
    return None

@app.route('/', methods=['POST', 'GET'])
def home():
    return render_template('home.html')

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            
            if user and bcrypt.check_password_hash(user[1], password):
                user_obj = User(id=user[0], email=email, password=user[1])
                login_user(user_obj)
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid email or password.", "danger")
    
    return render_template('login.html')

@app.route('/signup', methods=['POST', 'GET'])
def signup():
    if request.method == 'POST':
        college = request.form.get('college')
        admission_number = request.form.get('admission_no')  # ✅ Fixed
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        is_hosteller = request.form.get('hosteller') == 'yes'  # ✅ Fixed
        hostel_name = request.form.get('hostel_name') if is_hosteller else None  # ✅ Fixed

        print("Received signup data:", college, admission_number, email, is_hosteller, hostel_name)  # Debugging

        if college not in COLLEGES:
            flash("Invalid college selection.", "danger")
            return redirect(url_for('signup'))

        if not admission_number:
            flash("Admission number is required.", "danger")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (college, admission_number, email, password, is_hosteller, hostel_name) VALUES (?, ?, ?, ?, ?, ?)",
                           (college, admission_number, email, hashed_password, is_hosteller, hostel_name))
            conn.commit()

        print("User inserted into database!")  # Debugging
        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html', colleges=COLLEGES)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/settings')
def settings():
    return render_template('setting.html')

@app.route('/payments')
def payments():
    return render_template('payments.html')

@app.route('/history')
def history():
    return render_template('history.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
