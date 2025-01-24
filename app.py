from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3

app = Flask(__name__)
app.secret_key = 'devsite_secret_key'  # Secure secret key for sessions

# Initialize database
def init_db():
    with sqlite3.connect('users.db') as conn:
        conn.execute('''CREATE TABLE IF NOT EXISTS users (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            username TEXT UNIQUE NOT NULL,
                            password TEXT NOT NULL,
                            is_admin BOOLEAN NOT NULL DEFAULT 0
                        )''')
        conn.commit()

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        is_admin = request.form.get('is_admin', '0') == '1'
        try:
            with sqlite3.connect('users.db') as conn:
                conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                             (username, password, is_admin))
                conn.commit()
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            return "Username already exists. Try another."
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect('users.db') as conn:
            user = conn.execute('SELECT * FROM users WHERE username=? AND password=?', (username, password)).fetchone()
            if user:
                session['user_id'] = user[0]
                session['is_admin'] = user[3]
                if user[3]:  # If the user is an admin
                    return redirect(url_for('admin'))
                return redirect(url_for('form'))
        return "Invalid credentials. Please try again."
    return render_template('login.html')

@app.route('/admin')
def admin():
    if session.get('is_admin'):
        return render_template('admin.html')
    return redirect(url_for('home'))

@app.route('/form', methods=['GET', 'POST'])
def form():
    if 'user_id' in session:
        if request.method == 'POST':
            # Handle form submission and save user-specific data if needed
            return "Form submitted successfully!"
        return render_template('form.html')
    return redirect(url_for('home'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)

