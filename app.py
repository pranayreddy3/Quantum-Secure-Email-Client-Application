from flask import Flask, render_template, request, redirect, url_for, session, send_file
from cryptography.fernet import Fernet
import os
import sqlite3
import io

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # Replace with a strong secret key

# ------------------------------
# Persistent Encryption Key Setup
# ------------------------------
KEY_FILE = 'secret.key'

def load_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

key = load_key()
cipher_suite = Fernet(key)

# ------------------------------
# Database Setup (SQLite)
# ------------------------------
db_file = 'messages.db'
if not os.path.exists(db_file):
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute('''CREATE TABLE users (
                    id INTEGER PRIMARY KEY,
                    email TEXT UNIQUE,
                    password TEXT)''')
    c.execute('''CREATE TABLE messages (
                    id INTEGER PRIMARY KEY,
                    sender TEXT,
                    receiver TEXT,
                    message TEXT,
                    file BLOB,
                    filename TEXT)''')
    conn.commit()
    conn.close()

# ------------------------------
# Route: Registration (Default Page)
# ------------------------------
@app.route('/', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        
        # Check if the email already exists
        c.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = c.fetchone()
        
        if existing_user:
            conn.close()
            return "Registration failed. Email is already registered. Please log in instead."
        
        try:
            c.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, password))
            conn.commit()
            session['email'] = email
            return redirect(url_for('inbox'))
        except Exception as e:
            return "Registration failed. Error: " + str(e)
        finally:
            conn.close()
    
    return render_template('register.html')

# ------------------------------
# Route: Login
# ------------------------------
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, password))
        user = c.fetchone()
        conn.close()
        if user:
            session['email'] = email
            return redirect(url_for('inbox'))
        else:
            return "Login failed. Check your credentials."
    return render_template('login.html')

# ------------------------------
# Route: Logout
# ------------------------------
@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))

# ------------------------------
# Route: Send Message (with File Attachment)
# ------------------------------
@app.route('/send', methods=['GET', 'POST'])
def send_message():
    if 'email' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        sender = session['email']
        receiver = request.form['receiver']
        message = request.form['message'].encode()
        encrypted_message = cipher_suite.encrypt(message)
        
        file = request.files.get('file')
        encrypted_file = None
        filename = None
        if file:
            filename = file.filename
            encrypted_file = cipher_suite.encrypt(file.read())
        
        conn = sqlite3.connect(db_file)
        c = conn.cursor()
        c.execute("INSERT INTO messages (sender, receiver, message, file, filename) VALUES (?, ?, ?, ?, ?)",
                  (sender, receiver, encrypted_message, encrypted_file, filename))
        conn.commit()
        conn.close()
        return redirect(url_for('inbox'))
    return render_template('send_email.html')

# ------------------------------
# Route: Inbox
# ------------------------------
@app.route('/inbox')
def inbox():
    if 'email' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("SELECT id, sender, message, file, filename FROM messages WHERE receiver = ?", (session['email'],))
    messages = c.fetchall()
    conn.close()
    return render_template('inbox.html', messages=messages)

# ------------------------------
# Route: Decrypt a Message
# ------------------------------
@app.route('/decrypt/<int:message_id>')
def decrypt_message(message_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("SELECT sender, message, file, filename FROM messages WHERE id = ?", (message_id,))
    message_data = c.fetchone()
    conn.close()
    if message_data:
        sender, encrypted_message, encrypted_file, filename = message_data
        try:
            decrypted_message = cipher_suite.decrypt(encrypted_message).decode()
        except Exception as e:
            decrypted_message = "Error decrypting message: " + str(e)
        return render_template('decrypt.html', sender=sender, message=decrypted_message, filename=filename, message_id=message_id, file_exists=(encrypted_file is not None))
    return "Message not found", 404

# ------------------------------
# Route: Download Decrypted File
# ------------------------------
@app.route('/download_decrypted_file/<int:message_id>')
def download_decrypted_file(message_id):
    if 'email' not in session:
        return redirect(url_for('login'))
    
    conn = sqlite3.connect(db_file)
    c = conn.cursor()
    c.execute("SELECT file, filename FROM messages WHERE id = ?", (message_id,))
    message_data = c.fetchone()
    conn.close()
    
    if message_data and message_data[0]:
        decrypted_file = cipher_suite.decrypt(message_data[0])
        return send_file(
            io.BytesIO(decrypted_file),
            as_attachment=True,
            download_name=message_data[1] if message_data[1] else "decrypted_file"
        )
    return "File not found", 404

if __name__ == '__main__':
    app.run(debug=True)
