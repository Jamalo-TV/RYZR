from flask import Flask, request, jsonify, render_template
import sqlite3
import bcrypt
import re

def login_user(email, password):
    conn = sqlite3.connect('register_base_cookie.db')
    cursor = conn.cursor()

    cursor.execute("SELECT hashed_password, salt FROM users WHERE email = ?", (email,))
    result = cursor.fetchone()

    if result is None:
        print("User with email {} not found.".format(email))
        return False

    hashed_password, salt = result

    if bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8')):
        print("Successfully logged in!")
        return True
    else:
        print("Incorrect password.")
        return False


def validate_email(email):
    pattern = re.compile(r'^[\w\.-]+@[\w\.-]+\.\w+$')
    return pattern.match(email) is not None  # Return True if the email matches the pattern, else return False

email = input("Enter your email: ")
password = input("Enter your password: ")

if validate_email(email):  # Call the function and check the result
    print("Email valid")
    login_user(email, password)

else:
    print("Email not valid")
