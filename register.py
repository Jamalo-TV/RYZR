from flask import Flask, request, jsonify, render_template
import sqlite3
import bcrypt
import secrets
import re
from flask_talisman import Talisman
from flask import Flask, render_template, redirect, request, session
from flask_session import Session

app = Flask(__name__)
talisman = Talisman(app, content_security_policy=None)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)


# generate session Key

def key_generator(length=256):
    return secrets.token_hex(length // 2)


# Database
def create_database():
    conn = sqlite3.connect('register_base_cookie.db')
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        hashed_password TEXT NOT NULL,
        salt TEXT NOT NULL,
        generated_key NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP

    )
    """)

    conn.commit()
    conn.close()


def insert_user(email, hashed_password, salt, generated_key):
    conn = sqlite3.connect('register_base_cookie.db')
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO users (email, hashed_password, salt, generated_key) VALUES (?, ?, ?, ?)
    """, (email, hashed_password, salt, generated_key))

    conn.commit()
    conn.close()


def register_user(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
    return hashed_password, salt


# Input validation
def validate_email(email):
    pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return pattern.match(email)


#def validate_username(username):
#    pattern = re.compile(r'^[\w]{3,30}$')
#    return pattern.match(username)


def validate_password(password):
    pattern = re.compile(r'^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{8,}$')
    return pattern.match(password)

def compare_password(password, validate_password):
    if password == validate_password:
        return True
    else:
        return False


# Flask routes
@app.route('/')
def index():
    return render_template('register.html')


@app.route('/input', methods=['POST'])
def input_data():
    email = request.json['email']
    repeated_password = request.json['validate_password']
    password = request.json['password']

    if not validate_email(email):
        return jsonify(error="Invalid email format.")

    if not compare_password(password, repeated_password):
        return jsonify(
            error="Passwords do not match.")

    if not validate_password(password):
        return jsonify(error="Invalid password format. Does not meet requirements.")

    conn = sqlite3.connect('register_base_cookie.db')
    cursor = conn.cursor()

    hashed_password, salt = register_user(password)

    generated_key = key_generator()

    validation_for_user = "registered successfully!"

    found_email = "You already have an account."

    cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()
    if result:
        print("Email has been found in the database")

        return jsonify(found_email=found_email)

    else:
            insert_user(email, hashed_password.decode('utf-8'), salt.decode('utf-8'), generated_key)
            print("User registered successfully!")

            return jsonify(validation_for_user=validation_for_user, generated_key=generated_key)

    conn.close()


if __name__ == '__main__':
    create_database()
    app.run(debug=True)