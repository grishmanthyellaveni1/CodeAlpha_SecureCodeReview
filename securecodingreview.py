import sqlite3
import bcrypt
import re
import logging
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
conn = sqlite3.connect("users.db")
cursor = conn.cursor()
cursor.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
""")
conn.commit()
def validate_username(username):
    pattern = r"^[a-zA-Z0-9_]{3,20}$"
    return bool(re.match(pattern, username))
def register():
    print("\n===== User Registration =====")
    username = input("Enter Username: ")
    if not validate_username(username):
        print(
            "Username must contain only letters, numbers,"
            " and underscore (3-20 chars)"
        )
        return
    password = input("Enter Password: ")
    if len(password) < 8:
        print("Password must be at least 8 characters")
        return
    hashed_password = bcrypt.hashpw(
        password.encode(),
        bcrypt.gensalt()
    )
    try:
        cursor.execute(
            "INSERT INTO users(username,password) VALUES (?,?)",
            (
                username,
                hashed_password.decode()
            )
        )
        conn.commit()
        logging.info(
            f"New user registered: {username}"
        )
        print("Registration Successful")
    except sqlite3.IntegrityError:
        print("Username already exists")
def login():
    print("\n===== User Login =====")
    username = input("Username: ")
    password = input("Password: ")
    try:
        cursor.execute(
            "SELECT password FROM users WHERE username=?",
            (username,)
        )
        result = cursor.fetchone()
        if result:
            stored_hash = result[0]
            if bcrypt.checkpw(
                password.encode(),
                stored_hash.encode()
            ):
                print("Login Successful")
                logging.info(
                    f"Successful login: {username}"
                )
            else:
                print("Invalid Credentials")
                logging.warning(
                    f"Failed login attempt: {username}"
                )
        else:
            print("Invalid Credentials")
            logging.warning(
                f"Unknown user login attempt: {username}"
            )
    except Exception:
        logging.error(
            "Unexpected error during login"
        )
        print("An error occurred")
def view_users():
    print("\n===== Registered Users =====")
    cursor.execute(
        "SELECT id, username FROM users"
    )
    users = cursor.fetchall()
    for user in users:
        print(user)
while True:
    print("\n")
    print("=" * 40)
    print(" Secure Login System ")
    print("=" * 40)
    print("1. Register")
    print("2. Login")
    print("3. View Users")
    print("4. Exit")
    choice = input("Enter Choice: ")
    if choice == "1":
        register()
    elif choice == "2":
        login()
    elif choice == "3":
        view_users()
    elif choice == "4":
        conn.close()
        print("Goodbye!")
        break
    else:
        print("Invalid Choice")