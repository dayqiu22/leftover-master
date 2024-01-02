import datetime
import json
import os
import sqlite3
import requests

from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from oauthlib.oauth2 import WebApplicationClient
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

from db import init_db_command, get_db, close_db

# Google Configuration (boiler plate code from https://realpython.com/flask-google-login/#creating-your-own-web-application)
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = (
    "https://accounts.google.com/.well-known/openid-configuration"
)

# Configure application
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY") or os.urandom(24)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Naive database setup
try:
    init_db_command()
except sqlite3.OperationalError:
    # Already been created
    pass

# OAuth2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Ensure responses are not cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Decorate routes to require login
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function

FREEZER_MULTIPLIER = 7

# Get general fridge storage times for food groups
def expiry(group):
    storage_duration = 0

    if group == "Cooked foods/meats" or group == "Baked goods":
        storage_duration = 4
    elif group == "Fruits/vegetables":
        storage_duration = 7
    elif group == "Whole eggs":
        storage_duration = 21
    elif group == "Raw meat":
        storage_duration = 3
    elif group == "Milk/soft cheeses":
        storage_duration = 14
    elif group == "Hard cheeses":
        storage_duration = 30
    elif group == "Preserved":
        storage_duration = 30

    return storage_duration



@app.route("/")
@login_required
def index():
    db = get_db()
    # Display foods, their location, and best before
    try:
        user = db.execute("SELECT * FROM users WHERE id = ?", (session["user_id"],)).fetchall()[0]
    except IndexError:
        return redirect("/login")

    db.execute("DELETE FROM foods WHERE (user_id, portions) = (?, ?)", (session["user_id"], 0,))
    db.commit()

    foods = db.execute("SELECT * FROM foods WHERE user_id =?", (session["user_id"],)).fetchall()
    close_db()

    return render_template("index.html", user=user, foods=foods)


@app.route("/track", methods=["POST"])
@login_required
def track():
    db = get_db()
    # Tracks new leftovers/groceries

    name = request.form.get("name").upper()
    group = request.form.get("group")
    location = request.form.get("location")
    try:
        portions = int(request.form.get("portions"))
    except ValueError:
        flash("Invalid number of portions!")
        return redirect("/")

    date_time = datetime.datetime.now()
    start_date = date_time.date()

    # Calculate best before date
    storage_duration = expiry(group)

    if storage_duration == 0:
        flash("Invalid food group!")
        return redirect("/")
    elif location == "Fridge":
        storage_duration = storage_duration
    elif location == "Freezer":
        storage_duration = storage_duration * FREEZER_MULTIPLIER
    else:
        flash("Invalid storage location!")
        return redirect("/")

    time_delta = datetime.timedelta(days = storage_duration)
    best_before = start_date + time_delta

    # Add leftovers to database
    db.execute("INSERT INTO foods (user_id, name, food_group, location, start_date, best_before, portions) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (session["user_id"], name, group, location, start_date, best_before, portions,))
    db.commit()
    close_db()

    flash("Tracking new leftovers!")
    return redirect("/")


@app.route("/consume", methods=["POST"])
@login_required
def consume():
    db = get_db()
    # Consumes 1 or all portions of a food item

    name = request.form.get("name")
    try:
        id = int(request.form.get("id"))
    except ValueError:
        flash("Invalid food item!")
        return redirect("/")
    try:
        consumed = int(request.form.get("consumed"))
    except ValueError:
        flash("Invalid number of portions consumed!")
        return redirect("/")

    if name is None:
        flash("Invalid food item!")
        return redirect("/")

    # Update database
    foods = db.execute("SELECT * FROM foods WHERE (id, user_id, name) = (?, ?, ?)", (id, session["user_id"], name,)).fetchall()
    if len(foods) != 1:
        flash("Invalid food item!")
        return redirect("/")

    leftovers = foods[0]["portions"] - consumed
    db.execute("UPDATE foods SET portions = ? WHERE (id, user_id, name) = (?, ?, ?)", (leftovers, id, session["user_id"], name,))
    db.commit()
    close_db()

    flash("Ate some leftovers!")
    return redirect("/")



@app.route("/calendar")
@login_required
def calendar():
    db = get_db()
    # Display a calendar with food expiry timelines

    db.execute("DELETE FROM foods WHERE (user_id, portions) = (?, ?)", (session["user_id"], 0,))
    db.commit()

    foods = db.execute("SELECT * FROM foods WHERE user_id =?", (session["user_id"],)).fetchall()
    close_db()

    return render_template("calendar.html", foods=foods)


@app.route("/login", methods=["GET", "POST"])
def login():
    db = get_db()
    # User reached route via POST
    if request.method == "POST":
        session.clear()

        # Ensure username and password was submitted
        if not request.form.get("username"):
            flash("Invalid username")
            return redirect("/login")
        elif not request.form.get("password"):
            flash("Password not provided")
            return redirect("/login")

        # Query database for username of regular users
        rows = db.execute("SELECT * FROM users WHERE (username, user_type) = (?, ?)", (request.form.get("username"), "regular",)).fetchall()

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid username or password")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]
        close_db()

        return redirect("/")

    # User reached route via GET
    else:
        close_db()
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    db = get_db()
    # User reached route via POST
    if request.method == "POST":

        # Ensure username given and is at least 4 characters in length
        if not request.form.get("username") or len(request.form.get("username")) < 4:
            flash("Invalid username")
            return redirect("/register")

        # Ensure username is unique (for non-google users)
        rows = db.execute("SELECT * FROM users WHERE username = ?", (request.form.get("username"),)).fetchall()
        if len(rows) >= 1:
            flash("Username has been taken")
            return redirect("/register")

        # Ensure password given and is at least 6 characters in length
        if not request.form.get("password") or len(request.form.get("password")) < 6:
            flash("Password must be at least 6 characters long")
            return redirect("/register")

        # Ensure passwords match
        if request.form.get("password") != request.form.get("confirmation"):
            flash("Passwords do not match")
            return redirect("/register")

        # Encrypt password and insert user information into database
        password = generate_password_hash(request.form.get("password"))
        db.execute("INSERT INTO users (username, hash, user_type) VALUES (?, ?, ?)", (request.form.get("username"), password, "regular",))
        db.commit()

        # Redirect user to login
        flash('Successfully registered!')
        return redirect("/login")

    # User reached route via GET
    else:
        return render_template("register.html")
    

@app.route("/googlelogin")
def googlelogin():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for login and provide
    # scopes that for retrieving user's profile from Google
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri=request.base_url + "/callback",
        scope=["openid", "email", "profile"],
    )
    return redirect(request_uri)


@app.route("/googlelogin/callback")
def callback():
    db = get_db()
    # Get authorization code Google sent back
    code = request.args.get("code")

    # Find out what URL to hit to get tokens to ask for
    # things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]

    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=request.base_url,
        code=code,
    )
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )

    # Parse the tokens
    client.parse_request_body_response(json.dumps(token_response.json()))

    # Find and hit URL from Google that gives user information
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)

    # Verify Google email
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        users_name = userinfo_response.json()["given_name"]
    else:
        flash("User email not available or not verified by Google.")
        return redirect("/")

    # Add user to db if new
    rows = db.execute("SELECT * FROM users WHERE google_id = ?", (unique_id,)).fetchall()
    if len(rows) < 1:
        db.execute("INSERT INTO users (google_id, username, email, user_type) VALUES (?, ?, ?, ?)",
                   (unique_id, users_name, users_email, "google"),)
        db.commit()

    # Remember which user has logged in
    rows = db.execute("SELECT * FROM users WHERE google_id = ?", (unique_id,)).fetchall()
    session["user_id"] = rows[0]["id"]

    close_db()

    return redirect("/")


@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()
    return redirect("/")

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

if __name__ == "__main__":
    app.run(ssl_context="adhoc")
