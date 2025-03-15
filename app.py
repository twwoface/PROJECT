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
        
        # Create the new users table with student_id
        cursor.execute('''CREATE TABLE IF NOT EXISTS users_new (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            college TEXT NOT NULL,
                            student_id TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            is_hosteller INTEGER NOT NULL,
                            hostel_name TEXT)''')
        
        # Check if the old users table exists and contains data
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
        if cursor.fetchone():
            # Attempt to copy data from the old table if it exists
            try:
                cursor.execute('''INSERT INTO users_new (id, college, student_id, email, password, is_hosteller, hostel_name)
                                   SELECT id, college, student_id, email, password, is_hosteller, hostel_name FROM users''')
            except sqlite3.OperationalError:
                # Handle cases where the old table does not have the expected columns
                print("Skipping data migration: old table does not have the expected columns.")
        
        # Drop the old table and rename the new table
        cursor.execute('DROP TABLE IF EXISTS users')
        cursor.execute('ALTER TABLE users_new RENAME TO users')
        
        # Create the payments table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS payments (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id TEXT NOT NULL,
                            amount REAL NOT NULL,
                            category TEXT NOT NULL,
                            description TEXT,
                            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                            FOREIGN KEY (student_id) REFERENCES users (student_id))''')
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
        student_id = request.form.get('student_id')  # Updated field name
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        is_hosteller = request.form.get('hosteller') == 'yes'
        hostel_name = request.form.get('hostel_name') if is_hosteller else None

        if college not in COLLEGES:
            flash("Invalid college selection.", "danger")
            return redirect(url_for('signup'))

        if not student_id:
            flash("Student ID is required.", "danger")
            return redirect(url_for('signup'))

        if password != confirm_password:
            flash("Passwords do not match.", "danger")
            return redirect(url_for('signup'))

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (college, student_id, email, password, is_hosteller, hostel_name) VALUES (?, ?, ?, ?, ?, ?)",
                           (college, student_id, email, hashed_password, is_hosteller, hostel_name))
            conn.commit()

        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html', colleges=COLLEGES)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

@app.route('/admin-payments', methods=['GET', 'POST'])
@login_required
def admin_payments():
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        amount = request.form.get('amount')
        category = request.form.get('category')
        description = request.form.get('description')
        
        if not student_id or not amount or not category:
            flash("All fields are required.", "danger")
            return redirect(url_for('admin_payments'))
        
        try:
            with sqlite3.connect("users.db") as conn:
                cursor = conn.cursor()
                cursor.execute('''INSERT INTO payments (student_id, amount, category, description)
                                  VALUES (?, ?, ?, ?)''', (student_id, amount, category, description))
                conn.commit()
                flash("Payment recorded successfully!", "success")
        except sqlite3.Error as e:
            flash(f"Error recording payment: {e}", "danger")
        
        return redirect(url_for('admin_payments'))
    
    recent_payments = []
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT student_id, amount, category, description, timestamp
                          FROM payments ORDER BY timestamp DESC LIMIT 10''')
        recent_payments = cursor.fetchall()
    
    return render_template('admin_payments.html', recent_payments=recent_payments)

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
