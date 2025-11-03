import os
import sqlite3
from flask import Flask, render_template, flash, redirect, url_for, session
from flask_wtf import FlaskForm, CSRFProtect
from flask_login import (
    LoginManager, UserMixin, login_required, current_user,
    login_user, logout_user
)
from wtforms import StringField, SubmitField, PasswordField, DateField, TelField
from wtforms.validators import DataRequired, Email, Length
from werkzeug.security import generate_password_hash, check_password_hash

# --------------------- App & Auth setup ---------------------
app = Flask(__name__)
app.secret_key = "xoLBbyGovMe0Z1CiCKqWODomAtpeRSLj"  # TODO: put in env var for production
csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "index"

# --------------------- Forms ---------------------
class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Sign in")

class SignupForm(FlaskForm):
    first_name = StringField("First Name", validators=[DataRequired()])
    last_name  = StringField("Last Name", validators=[DataRequired()])
    DoB        = DateField("Date of Birth", validators=[DataRequired()])
    email      = StringField("Email", validators=[DataRequired(), Email()])
    phone      = TelField("Mobile Number", validators=[DataRequired(), Length(min=10, max=10)])
    password   = PasswordField("Create Password", validators=[DataRequired(), Length(min=6)])
    submit     = SubmitField("Sign up")

# --------------------- Database helpers ---------------------
DB_PATH = "instance/database.db"

def init_db():
    os.makedirs("instance", exist_ok=True)
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                first_name TEXT,
                last_name  TEXT,
                DoB        TEXT,
                email      TEXT NOT NULL UNIQUE,
                phone      TEXT,
                password   TEXT
            )
        """)
        conn.commit()

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# --------------------- User model & loader ---------------------
class User(UserMixin):
    def __init__(self, row):
        self.id         = row["email"]      
        self.first_name = row["first_name"]
        self.last_name  = row["last_name"]
        self.DoB        = row["DoB"]
        self.email      = row["email"]
        self.phone      = row["phone"]
        self.password   = row["password"]

@login_manager.user_loader
def load_user(user_id: str):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM users WHERE email = ?", (user_id,)).fetchone()
    conn.close()
    return User(row) if row else None

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect(url_for("index"))

# --------------------- Routes ---------------------
@app.route("/")
def home():
    return redirect(url_for("index"))

@app.route("/index", methods=["GET", "POST"])
def index():
   
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data

        conn = get_db_connection()
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        conn.close()

        if row and check_password_hash(row["password"], password):
            login_user(User(row))                
            return redirect(url_for("dashboard")) 
        flash("Invalid email or password.", "wrong")
    return render_template("index.html", form=form)

@app.route("/Signup", methods=["GET", "POST"])
def Signup():
    form = SignupForm()
    if form.validate_on_submit():
        first_name = form.first_name.data
        last_name  = form.last_name.data
        DoB        = form.DoB.data
        email      = form.email.data
        phone      = form.phone.data
        password   = form.password.data
        hashed_password = generate_password_hash(password)

        with sqlite3.connect(DB_PATH) as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM users WHERE email = ?", (email,))
            if cur.fetchone():
                flash("Email already registered. Please use another email.", "wrong")
                return render_template("Signup.html", form=form)

            cur.execute("""
                INSERT INTO users (first_name, last_name, DoB, email, phone, password)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (first_name, last_name, DoB.isoformat(), email, phone, hashed_password))
            conn.commit()

        flash("Sign up successful! Please sign in.", "success")
        return redirect(url_for("index"))
    return render_template("Signup.html", form=form)

@app.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html", user=current_user)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    logout_user()
    session.clear()
    flash("Logout successful!", "success")
    return redirect(url_for("index"))

# --------------------- Cache control ---------------------
@app.after_request
def no_cache(response):
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# --------------------- Main ---------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
