from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from datetime import datetime

app = Flask(__name__)
#123
# Database Configuration
app.config['SECRET_KEY'] = 'your_secret_key'

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# List of Colleges for Dropdown
COLLEGES = [
    "KMCT COLLEGE OF ENGINEERING",
    "KMCT COLLEGE OF ARCHITECTURE",
    "KMCT COLLEGE OF POLYTECHNIC",
    "KMCT SCHOOL OF BUSSINESS"
]

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

@app.template_filter('datetimeformat')
def datetimeformat(value):
    try:
        # Adjust the format to match your database timestamp format
        dt = datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
        # Windows-compatible format (remove leading zeros without using minus flag)
        day = str(int(dt.strftime('%d')))  # Remove leading zero from day
        hour = str(int(dt.strftime('%I')))  # Remove leading zero from hour
        return f"{day} {dt.strftime('%B %Y')} {hour}:{dt.strftime('%M %p')}"
    except (ValueError, TypeError):
        # Handle cases where the value is None or not in the expected format
        return value

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
        student_id = request.form.get('student_id')
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

    # Fetch the logged-in user's student_id
    student_id = None
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT student_id FROM users WHERE id = ?", (current_user.id,))
        result = cursor.fetchone()
        if result:
            student_id = result[0]

    if not student_id:
        flash("Unable to fetch student ID.", "danger")
        return redirect(url_for('logout'))

    # Fetch user-specific purchases (last 3 transactions)
    purchases = []
    recent_total_spent = 0
    category_totals = {"food": 0, "stationery": 0}
    total_spent = 0  # Total amount spent by the student
    total_food = 0  # Total spent on food
    total_stationery = 0  # Total spent on stationery

    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        
        # Fetch last 3 purchases
        cursor.execute('''SELECT item_name, quantity, price, total, category, timestamp 
                          FROM purchases WHERE student_id = ? ORDER BY timestamp DESC LIMIT 3''', 
                       (student_id,))
        purchases = cursor.fetchall()

        # Fetch total amount spent by the student
        cursor.execute("SELECT SUM(total) FROM purchases WHERE student_id = ?", (student_id,))
        total_result = cursor.fetchone()
        if total_result and total_result[0]:
            total_spent = total_result[0]
        
        # Fetch total spent on food category
        cursor.execute("SELECT SUM(total) FROM purchases WHERE student_id = ? AND category = 'food'", (student_id,))
        food_result = cursor.fetchone()
        if food_result and food_result[0]:
            total_food = food_result[0]
        
        # Fetch total spent on stationery category
        cursor.execute("SELECT SUM(total) FROM purchases WHERE student_id = ? AND category = 'stationery'", (student_id,))
        stationery_result = cursor.fetchone()
        if stationery_result and stationery_result[0]:
            total_stationery = stationery_result[0]
        
        # Calculate recent total spent and category-wise totals
        for purchase in purchases:
            recent_total_spent += purchase[3]
            if purchase[4] in category_totals:
                category_totals[purchase[4]] += purchase[3]

    return render_template('dashboard.html', 
                           purchases=purchases, 
                           recent_total_spent=recent_total_spent,
                           total_spent=total_spent,
                           total_food=total_food,
                           total_stationery=total_stationery,
                           category_totals=category_totals)



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
        category = request.form.get('category')

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

        # Check if student_id exists in the users table
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE student_id = ?", (student_id,))
            if not cursor.fetchone():
                flash("Invalid student ID. No user found with this ID.", "danger")
                return redirect(url_for('admin_panel'))

            # Insert purchase details into the database
            try:
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

@app.route('/recent_purchases', methods=['GET', 'POST'])
@login_required
def recent_purchases():
    if current_user.email != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()

        # Handle edit form submission
        if request.method == 'POST':
            purchase_id = request.form.get('purchase_id')
            item_name = request.form.get('item_name')
            quantity = int(request.form.get('quantity'))
            price = float(request.form.get('price'))
            category = request.form.get('category')
            total = quantity * price

            cursor.execute('''UPDATE purchases 
                            SET item_name = ?, quantity = ?, price = ?, total = ?, category = ? 
                            WHERE id = ?''', 
                            (item_name, quantity, price, total, category, purchase_id))
            conn.commit()
            flash("Purchase updated successfully!", "success")
            return redirect(url_for('recent_purchases'))

        # Fetch recent purchases
        cursor.execute('''SELECT * FROM purchases ORDER BY timestamp DESC LIMIT 20''')
        purchases = cursor.fetchall()

        # If editing, fetch the specific purchase details
        edit_id = request.args.get('edit_id')
        edit_purchase = None
        if edit_id:
            cursor.execute('SELECT * FROM purchases WHERE id = ?', (edit_id,))
            edit_purchase = cursor.fetchone()

    return render_template('recent_purchases.html', 
                         purchases=purchases, 
                         edit_purchase=edit_purchase)



@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/settings')
def settings():
    return render_template('setting.html')



@app.route('/payments')
def payments():
    conn = sqlite3.connect('users.db')  # Connect to your database
    cursor = conn.cursor()
    
    # Fetch transactions from the 'purchases' table
    cursor.execute("SELECT item_name, quantity, price, total, category, timestamp FROM purchases")
    transactions = cursor.fetchall()
    
    conn.close()

    # Calculate total spent
    total_spent = sum(float(transaction[3]) for transaction in transactions)  # 'total' is at index 3

    return render_template('payments.html', transactions=transactions, total_spent=total_spent)


@app.route('/history')
@login_required
def history():
    # Fetch the logged-in user's student_id
    student_id = None
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT student_id FROM users WHERE id = ?", (current_user.id,))
        result = cursor.fetchone()
        if result:
            student_id = result[0]

    if not student_id:
        flash("Unable to fetch student ID.", "danger")
        return redirect(url_for('logout'))

    # Fetch all transactions of the logged-in user
    transactions = []
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute('''SELECT item_name, quantity, price, total, category, timestamp 
                          FROM purchases WHERE student_id = ? ORDER BY timestamp DESC''', 
                       (student_id,))
        transactions = cursor.fetchall()

    return render_template('history.html', transactions=transactions)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash("Logged out successfully.", "success")
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
