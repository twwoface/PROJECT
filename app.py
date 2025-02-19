from flask import Flask, render_template, request, redirect, url_for

app = Flask(__name__)

# Dummy user credentials (for testing)
users = {
    "test@gmail.com": "password123"
}

@app.route('/',methods=['POST', 'GET'])
def home():
    if request.method == 'GET':
        return render_template('home.html')
    else:
         return render_template('login.html')


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

if __name__ == '__main__':
    app.run(debug=True)
