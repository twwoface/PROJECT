from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

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
        
        # Create the users table if it doesn't exist
        cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            college TEXT NOT NULL,
                            student_id TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            is_hosteller INTEGER NOT NULL,
                            hostel_name TEXT)''')
        
        # Create the purchases table with a category column
        cursor.execute('''CREATE TABLE IF NOT EXISTS purchases (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id TEXT NOT NULL,
                            item_name TEXT NOT NULL,
                            quantity INTEGER NOT NULL,
                            price REAL NOT NULL,
                            total REAL NOT NULL,
                            category TEXT NOT NULL,  -- New column for category
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
    # For admin user
    if user_id == "0":
        return User(id=0, email='admin', password='123')
    
    # For regular users
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

        # Special case for admin login
        if email == 'admin' and password == '123':
            admin_user = User(id=0, email='admin', password='123')  # Create a mock admin user
            login_user(admin_user)
            flash("Logged in as admin.", "success")
            return redirect(url_for('admin_panel'))

        # Regular user login
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, password FROM users WHERE email = ?", (email,))
            user = cursor.fetchone()
            
            if user and bcrypt.check_password_hash(user[1], password):
                user_obj = User(id=user[0], email=email, password=user[1])
                login_user(user_obj)
                flash("Login successful.", "success")
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
@login_required
def dashboard():
    if current_user.email == 'admin':
        return redirect(url_for('admin_panel'))
    return render_template('dashboard.html')

@app.route('/admin_panel', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if current_user.email != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        item_name = request.form.get('item_name')
        quantity = request.form.get('quantity')
        price = request.form.get('price')
        category = request.form.get('category')  # New field for category

        # Validate inputs
        try:
            quantity = int(quantity)
            price = float(price)
            total = quantity * price
        except ValueError:
            flash("Invalid quantity or price.", "danger")
            return redirect(url_for('admin_panel'))

        if not student_id or not item_name or not category or quantity <= 0 or price <= 0:
            flash("All fields are required and must be valid.", "danger")
            return redirect(url_for('admin_panel'))

        try:
            # Insert purchase details into the database
            with sqlite3.connect("users.db") as conn:
                cursor = conn.cursor()
                cursor.execute('''INSERT INTO purchases (student_id, item_name, quantity, price, total, category)
                                  VALUES (?, ?, ?, ?, ?, ?)''', (student_id, item_name, quantity, price, total, category))
                conn.commit()
                flash("Purchase recorded successfully!", "success")
        except sqlite3.Error as e:
            flash(f"Error recording purchase: {e}", "danger")

        return redirect(url_for('admin_panel'))

    # Fetch recent purchases to display in the table
    recent_purchases = []
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT student_id, item_name, quantity, price, total, category, timestamp
                          FROM purchases ORDER BY timestamp DESC LIMIT 10''')
        recent_purchases = cursor.fetchall()

    return render_template('admin_panel.html', recent_purchases=recent_purchases)

@app.route('/recent_purchases')
@login_required
def recent_purchases():
    if current_user.email != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    # Fetch recent purchases from the database
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT student_id, item_name, quantity, price, total, category, timestamp 
                          FROM purchases ORDER BY timestamp DESC LIMIT 20''')
        purchases = cursor.fetchall()

    return render_template('recent_purchases.html', purchases=purchases)

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
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
