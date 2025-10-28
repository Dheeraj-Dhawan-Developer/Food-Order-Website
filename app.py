from flask import Flask, render_template, request, redirect, url_for, session, flash
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = "supersecretkey"
bcrypt = Bcrypt(app)

# --- Database Setup ---
def init_db():
    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()
    # Customers Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS customers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    # Restaurants Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS restaurants (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()

init_db()

# --- Routes ---

@app.route('/')
def home():
    return render_template("login.html")


# ----- SIGNUP -----
@app.route('/signup', methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        user_type = request.form["user_type"]  # "customer" or "restaurant"
        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]
        password_hash = bcrypt.generate_password_hash(password).decode('utf-8')

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        try:
            if user_type == "customer":
                cursor.execute("INSERT INTO customers (name, email, password_hash) VALUES (?, ?, ?)", (name, email, password_hash))
            else:
                cursor.execute("INSERT INTO restaurants (name, email, password_hash) VALUES (?, ?, ?)", (name, email, password_hash))
            conn.commit()
            flash("Account created successfully!", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Email already exists!", "danger")
            return redirect(url_for("signup"))
        finally:
            conn.close()
    return render_template("signup.html")


# ----- LOGIN -----
@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user_type = request.form["user_type"]
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        if user_type == "customer":
            cursor.execute("SELECT * FROM customers WHERE email=?", (email,))
        else:
            cursor.execute("SELECT * FROM restaurants WHERE email=?", (email,))

        user = cursor.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[3], password):
            session["user_id"] = user[0]
            session["user_name"] = user[1]
            session["user_type"] = user_type
            flash("Login successful!", "success")
            if user_type == "customer":
                return redirect(url_for("customer_dashboard"))
            else:
                return redirect(url_for("restaurant_dashboard"))
        else:
            flash("Invalid credentials!", "danger")
            return redirect(url_for("login"))

    return render_template("login.html")


# ----- DASHBOARDS -----
@app.route('/customer')
def customer_dashboard():
    if "user_id" in session and session["user_type"] == "customer":
        return render_template("customer_dashboard.html", name=session["user_name"])
    return redirect(url_for("login"))

@app.route('/restaurant')
def restaurant_dashboard():
    if "user_id" in session and session["user_type"] == "restaurant":
        return render_template("restaurant_dashboard.html", name=session["user_name"])
    return redirect(url_for("login"))

# ----- LOGOUT -----
@app.route('/logout')
def logout():
    session.clear()
    flash("Logged out successfully!", "info")
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)
