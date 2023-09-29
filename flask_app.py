import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps

# Configure application
app = Flask(__name__)

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure SQLite database
db = SQL("sqlite:////home/dayqiu19/leftover-master/leftover.db")

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
    # Display foods, their location, and best before
    try:
        user = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]
    except IndexError:
        return redirect("/login")

    db.execute("DELETE FROM foods WHERE (user_id, portions) = (?, ?)", session["user_id"], 0)

    foods = db.execute("SELECT * FROM foods WHERE user_id =?", session["user_id"])

    return render_template("index.html", user=user, foods=foods)


@app.route("/track", methods=["POST"])
@login_required
def track():
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
                session["user_id"], name, group, location, start_date, best_before, portions)

    flash("Tracking new leftovers!")
    return redirect("/")


@app.route("/consume", methods=["POST"])
@login_required
def consume():
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
    foods = db.execute("SELECT * FROM foods WHERE (id, user_id, name) = (?, ?, ?)", id, session["user_id"], name)
    if len(foods) != 1:
        flash("Invalid food item!")
        return redirect("/")

    leftovers = foods[0]["portions"] - consumed
    db.execute("UPDATE foods SET portions = ? WHERE (id, user_id, name) = (?, ?, ?)", leftovers, id, session["user_id"], name)

    #if leftovers == 0:
        #db.execute("UPDATE foods SET portions = ? WHERE (id, user_id, name) = (?, ?, ?)", 0, id, session["user_id"], name)
    #else:


    flash("Ate some leftovers!")
    return redirect("/")



@app.route("/calendar")
@login_required
def calendar():
    # Display a calendar with food expiry timelines

    db.execute("DELETE FROM foods WHERE (user_id, portions) = (?, ?)", session["user_id"], 0)

    foods = db.execute("SELECT * FROM foods WHERE user_id =?", session["user_id"])
    #foods_json = json.dumps(foods)

    return render_template("calendar.html", foods=foods)


@app.route("/login", methods=["GET", "POST"])
def login():
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

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            flash("Invalid username or password")
            return redirect("/login")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        return redirect("/")

    # User reached route via GET
    else:
        return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    # User reached route via POST
    if request.method == "POST":

        # Ensure username given and is at least 4 characters in length
        if not request.form.get("username") or len(request.form.get("username")) < 4:
            flash("Invalid username")
            return redirect("/register")

        # Ensure username is unique
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))
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
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), password)

        # Redirect user to login
        flash('Successfully registered!')
        return redirect("/login")

    # User reached route via GET
    else:
        return render_template("register.html")


@app.route("/logout")
def logout():
    # Forget any user_id
    session.clear()
    return redirect("/")
