from flask import Flask, request
import sqlite3

app = Flask(__name__)

# ❌ Hardcoded secret (volontairement vulnérable)
SECRET_KEY = "supersecret123"

def get_db():
    return sqlite3.connect("users.db")

@app.route("/")
def home():
    return "DevSecOps Lab - Vulnerable App"

# ❌ SQL Injection
@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username")
    password = request.form.get("password")

    conn = get_db()
    cursor = conn.cursor()

    query = """SELECT * FROM users WHERE username = (?) AND password = (?)"""
    value = (username, password,)
    cursor.execute(query,value)

    user = cursor.fetchone()
    conn.close()

    if user:
        return "Login successful"
    else:
        return "Login failed"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)