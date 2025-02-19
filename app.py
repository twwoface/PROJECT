from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Dummy user credentials (for testing)
users = {
    "test@gmail.com": "password123"
}

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    if email in users and users[email] == password:
        return redirect(url_for('dashboard'))
    else:
        return "Invalid Credentials. Try again."

@app.route('/dashboard')
def dashboard():
    return "<h1>Welcome to CanTech Dashboard</h1>"

if __name__ == '__main__':
    app.run(debug=True)
