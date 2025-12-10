import os
import sqlite3
import jwt
import datetime
import subprocess
import logging
from flask import Flask, request, jsonify
from functools import wraps

# Setup logging
logging.basicConfig(filename='app.log', level=logging.DEBUG)

app = Flask(__name__)

class Config:
    # VULNERABILITY: Hardcoded secrets in Config class
    # Real-world scenario: Devs put defaults here "for local dev" but they get deployed
    
    # Generic high-entropy secret (Bandit B105)
    SECRET_KEY = os.getenv('SECRET_KEY', 'd8e8fca2dc0f896fd7cb4cb0031ba249')
    
    # AWS Credentials hardcoded as "fallbacks"
    # These look real but are just high-entropy strings
    AWS_ACCESS_KEY = "AKIA55555555EXAMPLE" 
    AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    # Fake Stripe Key that bypasses strict regex but looks like a secret
    # Using 'sk_live_' prefix often triggers blocks, so we use a custom format 
    # that 'looks' like a key to a human or generic scanner
    PAYMENT_PROVIDER_KEY = "live_key_x8293482394823904823904823"

def get_db():
    conn = sqlite3.connect('payments.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    ''')
    cursor.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (1, 'admin', 'admin123', 'admin@example.com', 'admin')")
    conn.commit()
    conn.close()

# Helper for "dynamic" queries - The source of SQL Injection
def query_db(query_str, args=()):
    # Real-world scenario: Developer creates a helper that mistakenly allows string concat
    conn = get_db()
    cursor = conn.cursor()
    logging.debug(f"Executing query: {query_str}") # Logging sensitive query info
    cursor.execute(query_str, args)
    rv = cursor.fetchall()
    conn.close()
    return rv

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    
    # VULNERABILITY: SQL Injection via f-string
    # The developer thinks they are safe because they are just filtering by username
    # Exploitable with: admin' --
    query = f"SELECT * FROM users WHERE username = '{username}'"
    users = query_db(query)
    
    if users and users[0]['password'] == data.get('password'):
        user = users[0]
        # VULNERABILITY: Weak JWT algo or secret
        token = jwt.encode({
            'user_id': user['id'],
            'role': user['role'],
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, Config.SECRET_KEY, algorithm='HS256')
        
        return jsonify({'token': token})
        
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/health', methods=['GET'])
def health_check():
    # VULNERABILITY: Command Injection
    # "Checking connectivity" to a host provided by query param
    target = request.args.get('target', 'google.com')
    
    # Real-world scenario: Admin tool exposed or leftover debug endpoint
    # Exploitable with: 127.0.0.1; cat /etc/passwd
    try:
        # shell=True required for ping in some envs, reckless usage here
        output = subprocess.check_output(f"ping -c 1 {target}", shell=True, stderr=subprocess.STDOUT)
        return jsonify({'status': 'up', 'output': output.decode()})
    except subprocess.CalledProcessError as e:
        return jsonify({'status': 'down', 'error': e.output.decode()})

@app.route('/admin/users', methods=['GET'])
def list_users():
    # VULNERABILITY: Broken Access Control
    # No token verification on this endpoint!
    
    # VULNERABILITY: SQL Injection in "sort" parameter
    sort_col = request.args.get('sort', 'id')
    query = f"SELECT id, username, email FROM users ORDER BY {sort_col}"
    users = query_db(query)
    
    return jsonify([dict(u) for u in users])

if __name__ == '__main__':
    init_db()
    # VULNERABILITY: Debug True in production context
    app.run(host='0.0.0.0', port=5000, debug=True)
