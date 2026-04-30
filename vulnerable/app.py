from flask import Flask, request, jsonify, session, render_template, redirect, url_for
import sqlite3
import hashlib
import os
import datetime

app = Flask(__name__)
app.secret_key = "secret123"  # VULNERABILITATE: secret key slaba si hardcodata

DATABASE = "authx_vulnerable.db"

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'USER',
            created_at TEXT,
            locked INTEGER DEFAULT 0
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL,
            used INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            desciption TEXT,
            severity TEXT DEFAULT 'LOW',
            status TEXT DEFAULT 'OPEN',
            owner_id INTEGER,
            created_at TEXT,
            updated_at TEXT,
            FOREIGN KEY (owner_id) REFERENCES users(id)
        )
""")
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            resource TEXT,
            timestamp TEXT,
            ip_address TEXT
        )
    """)
    conn.commit()
    conn.close()

# -------------------------------------------------------
# REGISTER
# -------------------------------------------------------
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')

    data = request.form
    email = data.get('email', '')
    password = data.get('password', '')

    # VULNERABILITATE 4.1: Nu exista validare a parolei (poate fi "1" sau "abc")
    if not email or not password:
        return render_template('register.html', error="Completati toate campurile.")

    # VULNERABILITATE 4.2: Parola stocata cu MD5 (hash slab, fara salt)
    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (email, password, role, created_at) VALUES (?, ?, 'USER', ?)",
            (email, password_hash, datetime.datetime.now().isoformat())
        )
        conn.commit()
    except sqlite3.IntegrityError:
        # VULNERABILITATE 4.4: Mesaj diferit pentru user existent (user enumeration)
        return render_template('register.html', error="Email-ul este deja folosit.")
    finally:
        conn.close()

    return redirect(url_for('login'))

# -------------------------------------------------------
# LOGIN
# -------------------------------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')

    email = request.form.get('email', '')
    password = request.form.get('password', '')

    # VULNERABILITATE 4.2: Acelasi hash MD5 slab
    password_hash = hashlib.md5(password.encode()).hexdigest()

    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ?", (email,)
    ).fetchone()
    conn.close()

    # VULNERABILITATE 4.4: Mesaje diferite pentru user inexistent vs parola gresita
    if not user:
        return render_template('login.html', error="Utilizatorul nu exista.")

    if user['password'] != password_hash:
        return render_template('login.html', error="Parola incorecta.")

    # VULNERABILITATE 4.3: Nu exista rate limiting, poti incerca la infinit
    # VULNERABILITATE 4.5: Sesiune fara expirare, fara flags de securitate
    session['user_id'] = user['id']
    session['email'] = user['email']
    session['role'] = user['role']

    return redirect(url_for('dashboard'))

# -------------------------------------------------------
# DASHBOARD
# -------------------------------------------------------
@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', email=session['email'], role=session['role'])

# -------------------------------------------------------
# LOGOUT
# -------------------------------------------------------
@app.route('/logout')
def logout():
    # VULNERABILITATE 4.5: Session nu e invalidata complet pe server
    session.clear()
    return redirect(url_for('login'))

# -------------------------------------------------------
# FORGOT PASSWORD
# -------------------------------------------------------
@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'GET':
        return render_template('forgottenpassword.html')

    email = request.form.get('email', '')

    # VULNERABILITATE 4.4: Mesaj diferit daca emailul nu exista
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user:
        conn.close()
        return render_template('forgottenpassword.html', error="Email-ul nu este inregistrat.")

    # VULNERABILITATE 4.6: Token predictibil bazat pe timestamp
    token = str(int(datetime.datetime.now().timestamp()))

    conn.execute(
        "INSERT INTO reset_tokens (email, token, used, created_at) VALUES (?, ?, 0, ?)",
        (email, token, datetime.datetime.now().isoformat())
    )
    conn.commit()
    conn.close()

    # In productie s-ar trimite pe email; aici afisam direct (pentru lab)
    reset_link = f"http://localhost:5000/reset-password?token={token}&email={email}"
    return render_template('forgottenpassword.html', success=f"Link resetare: {reset_link}")

# -------------------------------------------------------
# RESET PASSWORD
# -------------------------------------------------------
@app.route('/reset-password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token', '')
    email = request.args.get('email', '')

    if request.method == 'GET':
        return render_template('reset_password.html', token=token, email=email)

    new_password = request.form.get('password', '')
    token = request.form.get('token', '')
    email = request.form.get('email', '')

    conn = get_db()
    # VULNERABILITATE 4.6: Token reutilizabil (nu se verifica used=0), fara expirare
    reset = conn.execute(
        "SELECT * FROM reset_tokens WHERE token = ? AND email = ?",
        (token, email)
    ).fetchone()

    if not reset:
        conn.close()
        return render_template('reset_password.html', error="Token invalid.", token=token, email=email)

    # VULNERABILITATE 4.2: Din nou MD5
    new_hash = hashlib.md5(new_password.encode()).hexdigest()
    conn.execute("UPDATE users SET password = ? WHERE email = ?", (new_hash, email))
    # VULNERABILITATE 4.6: Token-ul NU este marcat ca used si NU este sters
    conn.commit()
    conn.close()

    return redirect(url_for('login'))

if __name__ == '__main__':
    init_db()
    # VULNERABILITATE: debug=True in productie expune stack traces
    app.run(debug=True, port=5000)
