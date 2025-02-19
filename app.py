from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Dummy user credentials (for testing)
users = {
    "test@gmail.com": "password123"
}

@app.route('/', methods=['POST', 'GET'])
def home():
    if request.method == 'GET':
        return render_template('home.html')
    else:
        return redirect(url_for('login'))

@app.route('/login', methods=['POST', 'GET'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        if email in users and users[email] == password:
            return redirect(url_for('dashboard'))
        else:
            return render_template('login.html', error="Invalid Credentials. Try again.")
    
    # If it's a GET request, just show the login page
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')  # Renders the dashboard page

@app.route('/payments')
def payments():
    return render_template('payments.html')  # Renders the payments page

@app.route('/history')
def history():
    return render_template('history.html')  # Renders the history page

@app.route('/settings')
def settings():
    return render_template('settings.html')  # Renders the settings page

if __name__ == '__main__':
    app.run(debug=True)
