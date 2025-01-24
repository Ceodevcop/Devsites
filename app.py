from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import DataRequired, Length, EqualTo

app = Flask(__name__)
app.secret_key = 'devcxxp_secret_key'  # Secure secret key for sessions

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

# Flask-WTF form for registration
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    is_admin = BooleanField('Admin')

# Flask-WTF form for login
class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        is_admin = form.is_admin.data
        hashed_password = generate_password_hash(password)
        try:
            with sqlite3.connect('users.db') as conn:
                conn.execute('INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)',
                             (username, hashed_password, is_admin))
                conn.commit()
            return redirect(url_for('home'))
        except sqlite3.IntegrityError:
            return "Username already exists. Try another."
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        with sqlite3.connect('users.db') as conn:
            user = conn.execute('SELECT * FROM users WHERE username=?', (username,)).fetchone()
            if user and check_password_hash(user[2], password):
                session['user_id'] = user[0]
                session['is_admin'] = user[3]
                if user[3]:  # If the user is an admin
                    return redirect(url_for('admin'))
                return redirect(url_for('form'))
        return "Invalid credentials. Please try again."
    return render_template('login.html', form=form)

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
