from flask import Flask, request, jsonify, render_template
import sqlite3
import bcrypt
import re

app = Flask(__name__)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"

def login_user(email, password):
    conn = sqlite3.connect('register_base_cookie.db')
    cursor = conn.cursor()

    cursor.execute("SELECT hashed_password, salt FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()

    if result is None:
        return jsonify({"status": "fail", "message": "User with email {} not found.".format(email)}), 404

    hashed_password, salt = result

    if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        return jsonify({"status": "success", "message": "Successfully logged in"}), 200
    else:
        return jsonify({"status": "fail", "message": "Incorrect password."}), 401

def validate_email(email):
    pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return pattern.match(email) is not None  # Return True if the email matches the pattern, else return False

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/input', methods=['POST'])
def input_data():
    email = request.json['email']
    password = request.json['password']

    if validate_email(email):  # Call the function and check the result
        return login_user(email, password)
    else:
        return jsonify({"status": "fail", "message": "Invalid email"}), 400

if __name__ == '__main__':
    app.run(debug=True)
