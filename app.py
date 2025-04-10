from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
from flask_bcrypt import Bcrypt
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user

from datetime import datetime

app = Flask(__name__)

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
                            name TEXT NOT NULL,
                            college TEXT NOT NULL,
                            student_id TEXT UNIQUE NOT NULL,
                            email TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            status TEXT NOT NULL DEFAULT 'pending')''')
        
        # Add status column if it doesn't exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'status' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
        
        # Add budget columns to the users table if they don't exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [col[1] for col in cursor.fetchall()]
        if 'total_budget' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN total_budget REAL DEFAULT 2000")
        if 'food_budget' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN food_budget REAL DEFAULT 1000")
        if 'stationery_budget' not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN stationery_budget REAL DEFAULT 1000")
        
        # Create the purchases table with the correct schema
        cursor.execute('''CREATE TABLE IF NOT EXISTS purchases (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            student_id TEXT NOT NULL,
                            item_name TEXT NOT NULL,
                            quantity INTEGER NOT NULL,
                            price REAL NOT NULL,
                            total REAL NOT NULL,
                            category TEXT NOT NULL,
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
        name = request.form.get('name')
        college = request.form.get('college')
        student_id = request.form.get('student_id')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

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
            cursor.execute("INSERT INTO users (name, college, student_id, email, password, status) VALUES (?, ?, ?, ?, ?, ?)",
                           (name, college, student_id, email, hashed_password, 'pending'))
            conn.commit()

        flash("Account created successfully! Please login.", "success")
        return redirect(url_for('login'))

    return render_template('signup.html', colleges=COLLEGES)


@app.route('/dashboard')
@login_required
def dashboard():
    # Fetch the logged-in user's budget and spending data
    student_id = None
    user_name = None
    total_budget = 2000
    food_budget = 1000
    stationery_budget = 1000
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT student_id, name, total_budget, food_budget, stationery_budget FROM users WHERE id = ?", (current_user.id,))
        result = cursor.fetchone()
        if result:
            student_id, user_name, total_budget, food_budget, stationery_budget = result

    if not student_id:
        flash("Unable to fetch student ID.", "danger")
        return redirect(url_for('logout'))

    # Fetch user-specific purchases
    total_spent = 0
    total_food = 0
    total_stationery = 0
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT SUM(total) FROM purchases WHERE student_id = ?", (student_id,))
        total_spent = cursor.fetchone()[0] or 0
        cursor.execute("SELECT SUM(total) FROM purchases WHERE student_id = ? AND category = 'food'", (student_id,))
        total_food = cursor.fetchone()[0] or 0
        cursor.execute("SELECT SUM(total) FROM purchases WHERE student_id = ? AND category = 'stationery'", (student_id,))
        total_stationery = cursor.fetchone()[0] or 0

    # Fetch last 3 purchases for this user
    purchases = []
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT item_name, quantity, price, total, category, timestamp 
            FROM purchases 
            WHERE student_id = ? 
            ORDER BY timestamp DESC 
            LIMIT 3""", (student_id,))
        purchases = cursor.fetchall()

    return render_template('dashboard.html', 
                           total_spent=total_spent, 
                           total_food=total_food, 
                           total_stationery=total_stationery, 
                           total_budget=total_budget, 
                           food_budget=food_budget, 
                           stationery_budget=stationery_budget, 
                           user_name=user_name,
                           purchases=purchases)

@app.route('/admin_panel', methods=['GET', 'POST'])
@login_required
def admin_panel():
    if current_user.email != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    if request.method == 'POST':
        student_id = request.form.get('student_id')
        
        # Check if student_id exists
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE student_id = ?", (student_id,))
            if not cursor.fetchone():
                flash("Invalid student ID. No user found with this ID.", "danger")
                return redirect(url_for('admin_panel'))

            # Process multiple items
            items = []
            i = 0
            while f'items[{i}][item_name]' in request.form:
                item = {
                    'item_name': request.form[f'items[{i}][item_name]'],
                    'quantity': request.form[f'items[{i}][quantity]'],
                    'price': request.form[f'items[{i}][price]'],
                    'category': request.form[f'items[{i}][category]']
                }
                items.append(item)
                i += 1

            try:
                # Insert all items for the student
                for item in items:
                    quantity = int(item['quantity'])
                    price = float(item['price'])
                    total = quantity * price
                    
                    cursor.execute('''INSERT INTO purchases 
                                    (student_id, item_name, quantity, price, total, category)
                                    VALUES (?, ?, ?, ?, ?, ?)''', 
                                    (student_id, item['item_name'], quantity, 
                                     price, total, item['category']))
                
                conn.commit()
                flash(f"Successfully recorded {len(items)} items for student {student_id}!", "success")
            except (ValueError, sqlite3.Error) as e:
                flash(f"Error recording purchases: {e}", "danger")
                return redirect(url_for('admin_panel'))

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

        # Fetch recent purchases with student names
        cursor.execute('''
            SELECT p.*, u.name 
            FROM purchases p 
            JOIN users u ON p.student_id = u.student_id 
            ORDER BY p.timestamp DESC LIMIT 20
        ''')
        purchases = cursor.fetchall()

        # If editing, fetch the specific purchase details
        edit_id = request.args.get('edit_id')
        edit_purchase = None
        if edit_id:
            cursor.execute('''
                SELECT p.*, u.name 
                FROM purchases p 
                JOIN users u ON p.student_id = u.student_id 
                WHERE p.id = ?
            ''', (edit_id,))
            edit_purchase = cursor.fetchone()

    return render_template('recent_purchases.html', 
                         purchases=purchases, 
                         edit_purchase=edit_purchase)

@app.route('/delete_purchase/<int:purchase_id>')
@login_required
def delete_purchase(purchase_id):
    if current_user.email != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM purchases WHERE id = ?", (purchase_id,))
        conn.commit()
        flash("Purchase deleted successfully!", "success")
    
    return redirect(url_for('recent_purchases'))

@app.route('/student_details', methods=['GET', 'POST'])
@login_required
def student_details():
    if current_user.email != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('login'))

    student_data = None
    if request.method == 'POST':
        student_id = request.form.get('student_id')
        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            
            # Get student details
            cursor.execute("""
                SELECT name, college, student_id, total_budget, food_budget, stationery_budget
                FROM users WHERE student_id = ?
            """, (student_id,))
            student_info = cursor.fetchone()

            if student_info:
                # Get purchase history
                cursor.execute("""
                    SELECT item_name, quantity, price, total, category, timestamp
                    FROM purchases 
                    WHERE student_id = ?
                    ORDER BY timestamp DESC
                """, (student_id,))
                purchases = cursor.fetchall()

                # Calculate totals
                cursor.execute("SELECT SUM(total) FROM purchases WHERE student_id = ?", (student_id,))
                total_spent = cursor.fetchone()[0] or 0

                cursor.execute("SELECT SUM(total) FROM purchases WHERE student_id = ? AND category = 'food'", (student_id,))
                food_spent = cursor.fetchone()[0] or 0

                cursor.execute("SELECT SUM(total) FROM purchases WHERE student_id = ? AND category = 'stationery'", (student_id,))
                stationery_spent = cursor.fetchone()[0] or 0

                student_data = {
                    'info': student_info,
                    'purchases': purchases,
                    'total_spent': total_spent,
                    'food_spent': food_spent,
                    'stationery_spent': stationery_spent
                }
            else:
                flash('Student not found.', 'error')

    return render_template('student_details.html', student_data=student_data)

@app.route('/profile')
def profile():
    return render_template('profile.html')

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    if request.method == 'POST':
        total_budget = request.form.get('limit', 2000)
        food_budget = request.form.get('food_limit', 1000)
        stationery_budget = request.form.get('stationery_limit', 1000)

        with sqlite3.connect("users.db") as conn:
            cursor = conn.cursor()
            cursor.execute('''UPDATE users 
                              SET total_budget = ?, food_budget = ?, stationery_budget = ? 
                              WHERE id = ?''', 
                           (total_budget, food_budget, stationery_budget, current_user.id))
            conn.commit()
        
        flash("Budget settings updated successfully!", "success")
        return redirect(url_for('settings'))

    # Fetch current budget settings
    total_budget = 2000
    food_budget = 1000
    stationery_budget = 1000
    with sqlite3.connect("users.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT total_budget, food_budget, stationery_budget FROM users WHERE id = ?", (current_user.id,))
        result = cursor.fetchone()
        if result:
            total_budget, food_budget, stationery_budget = result

    return render_template('setting.html', 
                           total_budget=total_budget, 
                           food_budget=food_budget, 
                           stationery_budget=stationery_budget)

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
