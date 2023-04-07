import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Lookup stock data and store in variable
        stock_data = lookup(request.form.get("symbol"))

        # Get shares from form input and cast to int
        shares_tobuy = int(request.form.get("shares"))

        # Check if lookup was unsuccessful
        # and render apology
        if stock_data == None:
            return apology("ERROR!\nPlease try again, and make sure you enter a valid symbol (e.g. NFLX for Netflix)")

        # Check if number of shares is NOT positive integer
        # and render apology
        if not shares_tobuy > 0:
            return apology("ERROR!\nInvalid number of shares\nMinimum shares you can buy: 1")

        # If shares is 1 or more, then try to buy
        # We need to make sure user's got enough money        
        user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
        if user_cash < stock_data["price"] * shares_tobuy:
            return apology("Insufficient funds")
        
        # If user got enough funds
        # then make purchase and update db
        db.execute("INSERT INTO purchases (user_id, stock_symbol, stock_price, shares) VALUES (?, ?, ?, ?)",
                    session["user_id"],
                    stock_data["symbol"],
                    stock_data["price"],
                    shares_tobuy)
        
        # Update user's funds after purchase
        user_cash -= stock_data["price"] * shares_tobuy
        db.execute("UPDATE users SET cash = ? WHERE id = ?", user_cash, session["user_id"])

        # Redirect user to home page
        return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    return apology("TODO")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":
        
        # Lookup stock data and store in variable
        stock_data = lookup(request.form.get("symbol"))

        # Check if lookup was unsuccessful
        if stock_data == None:
            return apology("ERROR!\nPlease try again, and make sure you enter a valid symbol (e.g. NFLX for Netflix)")
        
        # If lookup was successful, display useful information about stock
        return render_template("quoted.html", 
                               name=stock_data["name"], 
                               price=stock_data["price"],
                               symbol=stock_data["symbol"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)
        
        # Ensure password and confirmation password are the same
        elif not request.form.get("password") == request.form.get("confirmation"):
            return apology("passwords don't match", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username doesn't exist already
        if len(rows) > 0:
            return apology("username already exists", 403)
        
        # Add new user to database
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)",
                   request.form.get("username"),
                   generate_password_hash(request.form.get("password")))
        
        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    return apology("TODO")
