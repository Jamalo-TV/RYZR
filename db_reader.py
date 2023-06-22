import sqlite3

# Replace the database filename with the name of your own database file
db_filename = 'register_base_cookie.db'

# Connect to the database file
conn = sqlite3.connect(db_filename)

# Create a cursor object to execute SQL queries
cursor = conn.cursor()

# Example: Select all records from a table named "users"
cursor.execute("SELECT * FROM users")
rows = cursor.fetchall()

# Print the results
for row in rows:
    print(row)

# Close the cursor and database connection
cursor.close()
conn.close()