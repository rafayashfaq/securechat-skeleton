import mysql.connector
import hashlib
import os
import base64

# Step 1: Connect to MySQL
db = mysql.connector.connect(
    host="localhost",
    user="securechat",       # your MySQL user
    password="securepass",   # user's password
    database="securechat"    # your database
)
cursor = db.cursor()

# Step 2: Registration
print("=== SecureChat Registration ===")
username = input("Enter username: ")
email = input("Enter email: ")
password = input("Enter password: ")
confirm = input("Confirm password: ")

if password != confirm:
    print("❌ Passwords do not match!")
    exit()

# Step 3: Generate salt and hash password
salt = os.urandom(16)  # 16 bytes random salt
pwd_hash = hashlib.sha256(salt + password.encode()).hexdigest()

# Step 4: Insert into database
try:
    cursor.execute(
        "INSERT INTO users (username, email, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
        (username, email, salt, pwd_hash)
    )
    db.commit()
    print("✅ Registration successful!")
except mysql.connector.Error as err:
    print(f"❌ Registration failed: {err}")

