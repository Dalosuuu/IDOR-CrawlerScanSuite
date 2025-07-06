#!/usr/bin/env python3
"""
Simple test server with intentional IDOR vulnerabilities for testing the scanner
⚠️  FOR TESTING PURPOSES ONLY - DO NOT USE IN PRODUCTION
"""
from flask import Flask, request, jsonify, render_template_string
import random

app = Flask(__name__)

# Fake user data for testing
USERS = {
    1: {"name": "John Doe", "email": "john@example.com", "role": "user", "secret": "john_secret_data"},
    2: {"name": "Jane Smith", "email": "jane@example.com", "role": "admin", "secret": "jane_admin_data"},
    3: {"name": "Bob Wilson", "email": "bob@example.com", "role": "user", "secret": "bob_private_info"},
    4: {"name": "Alice Brown", "email": "alice@example.com", "role": "user", "secret": "alice_confidential"},
    5: {"name": "Admin User", "email": "admin@example.com", "role": "admin", "secret": "super_secret_admin_data"},
}

DOCUMENTS = {
    1: {"title": "Public Document", "content": "This is public", "owner": 1, "access": "public"},
    2: {"title": "Private Document", "content": "This is private to user 2", "owner": 2, "access": "private"},
    3: {"title": "Confidential Report", "content": "CONFIDENTIAL: Admin only", "owner": 5, "access": "admin"},
    4: {"title": "User Document", "content": "Personal notes", "owner": 3, "access": "private"},
}

HTML_TEMPLATE = '''
<!DOCTYPE html>
<html>
<head>
    <title>IDOR Test Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .container { max-width: 800px; margin: 0 auto; }
        .warning { background: #ffebcd; padding: 20px; border-left: 5px solid #ffa500; margin-bottom: 30px; }
        .endpoint { background: #f5f5f5; padding: 15px; margin: 10px 0; border-left: 3px solid #007acc; }
        a { color: #007acc; text-decoration: none; }
        a:hover { text-decoration: underline; }
    </style>
</head>
<body>
    <div class="container">
        <h1>IDOR Vulnerability Test Server</h1>
        
        <div class="warning">
            <strong>WARNING:</strong> This server contains intentional vulnerabilities for testing purposes only.
            Never deploy this in a production environment!
        </div>
        
        <h2>Available Endpoints:</h2>
        
        <div class="endpoint">
            <h3>User Profile (Vulnerable)</h3>
            <p><strong>GET</strong> <a href="/api/user?id=1">/api/user?id=1</a></p>
            <p>Try changing the ID parameter to access other users' data!</p>
        </div>
        
        <div class="endpoint">
            <h3>Document Access (Vulnerable)</h3>
            <p><strong>GET</strong> <a href="/document/1">/document/1</a></p>
            <p>Try different document IDs to access private documents!</p>
        </div>
        
        <div class="endpoint">
            <h3>Admin Panel (Vulnerable)</h3>
            <p><strong>GET</strong> <a href="/admin?user_id=2">/admin?user_id=2</a></p>
            <p>Try different user_id values to access admin functions for other users!</p>
        </div>
        
        <div class="endpoint">
            <h3>File Download (Vulnerable)</h3>
            <p><strong>GET</strong> <a href="/download?file=report_1.pdf">/download?file=report_1.pdf</a></p>
            <p>Try different filenames to access unauthorized files!</p>
        </div>
        
        <div class="endpoint">
            <h3>Search Form (Vulnerable)</h3>
            <form action="/search" method="POST">
                <input type="hidden" name="user_id" value="1">
                <input type="text" name="query" placeholder="Search query" value="test">
                <button type="submit">Search</button>
            </form>
            <p>Form contains hidden user_id field that can be manipulated!</p>
        </div>
    </div>
</body>
</html>
'''

@app.route('/')
def index():
    return HTML_TEMPLATE

@app.route('/api/user')
def get_user():
    user_id = request.args.get('id', type=int)
    if not user_id or user_id not in USERS:
        return jsonify({"error": "User not found"}), 404
    
    user = USERS[user_id].copy()
    return jsonify(user)

@app.route('/document/<int:doc_id>')
def get_document(doc_id):
    if doc_id not in DOCUMENTS:
        return jsonify({"error": "Document not found"}), 404
    
    doc = DOCUMENTS[doc_id]
    return jsonify(doc)

@app.route('/admin')
def admin_panel():
    user_id = request.args.get('user_id', type=int)
    if not user_id or user_id not in USERS:
        return jsonify({"error": "Access denied"}), 403
    
    user = USERS[user_id]
    if user['role'] != 'admin':
        return jsonify({"error": "Admin access required"}), 403
    
    return jsonify({
        "message": f"Admin panel for {user['name']}",
        "all_users": USERS,
        "sensitive_data": "This should only be visible to admins!"
    })

@app.route('/download')
def download_file():
    filename = request.args.get('file', '')
    
    # Simulate file access based on filename
    files = {
        'report_1.pdf': {'content': 'Public report content', 'access': 'public'},
        'report_2.pdf': {'content': 'Private report content', 'access': 'private'},
        'admin_report.pdf': {'content': 'CONFIDENTIAL: Admin report', 'access': 'admin'},
        'user_private.pdf': {'content': 'Personal user document', 'access': 'user'},
    }
    
    if filename not in files:
        return jsonify({"error": "File not found"}), 404
    
    file_data = files[filename]
    return jsonify({
        "filename": filename,
        "content": file_data['content'],
        "access_level": file_data['access']
    })

@app.route('/search', methods=['POST'])
def search():
    user_id = request.form.get('user_id', type=int)
    query = request.form.get('query', '')
    
    if not user_id or user_id not in USERS:
        return jsonify({"error": "Invalid user"}), 400
    
    user = USERS[user_id]
    
    # Simulate search results with user-specific data
    results = [
        f"Result 1 for {user['name']}: {query}",
        f"Result 2 for {user['name']}: {query} data",
        f"Private result for {user['name']}: {user['secret']}"
    ]
    
    return jsonify({
        "user": user['name'],
        "query": query,
        "results": results
    })

if __name__ == '__main__':
    print("Starting IDOR Test Server...")
    print("Server will be available at: http://localhost:5000")
    print("WARNING: This server contains intentional vulnerabilities for testing!")
    print("Use this to test your IDOR scanner")
    print("-" * 50)
    app.run(debug=True, host='0.0.0.0', port=5000)
