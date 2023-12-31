# Python Flask Email Storage Web Application

This repository contains a Python Flask web application designed to securely store email usernames and passwords. The application allows users to input their email credentials through a web interface, which are then encrypted with a salt and stored in a SQLite database. Additionally, the application generates a unique key, sends it to the user's browser, and creates a cookie.

## Features

 - User-friendly web interface for inputting email credentials
 - Encrypted storage of email credentials with bcrypt
 - Salted hashing for added security
 - Generation of unique keys using the secrets module
 - Cookie creation for user sessions
 - Data validation with regular expressions
 - The Username, Email, and Password are validated to ensure that the username and email are not already in use, and to verify that the password is strong enough. An error message is sent back if something is not right.
 
 ## Dependencies
 
 - Flask
 - SQLite3
 - bcrypt
 - secrets
 - re
 - flask_talisman
 
 ## Usage
 
 1. Run the Flask application:
 2. Open a web browser and navigate to the URL displayed in the terminal (usually http://127.0.0.1:5000/).
 3. Input your email username and password in the provided form and click "Sing Up".
 4. Your email credentials will be encrypted and stored securely in the database.
 5. A unique key will be generated, sent to your browser, and a cookie will be created.
 
 ## Modules Used
 
  - `flask`: Flask web framework for building the web application
	 - `Flask`: main class for creating a Flask application
	 - `request`: provides access to incoming request data
	 - `jsonify`: utility to create JSON responses
	 - `render_template`: function to render HTML templates
- `sqlite3`: library for working with SQLite databases
- `crypt`: library for hashing and verifying passwords
- `secrets`: module for generating cryptographically secure random numbers and strings
- `re`: regular expressions module for data validation
- `lask_talisman`: security headers library for Flask applications
- `Talisman`: main class for configuring security headers#   R Y Z R 
 
 
