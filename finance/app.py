import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, get_flashed_messages
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd
from datetime import datetime

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
    cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    stocks = db.execute("SELECT stock, amount FROM shares WHERE id = ?", session["user_id"])
    total = 0
    for item in stocks:
        price = lookup(item["stock"])
        total = total + (float(price["price"] * float(item["amount"])))
        item["price"] = price["price"]
        item["total"] = float(price["price"] * float(item["amount"]))

    print(stocks)

    total = total + db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])[0]["cash"]
    get_flashed_messages()
    return render_template("index.html", cash=cash, total=total, stocks=stocks)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Symbol Not Found", 403)

        amount = request.form.get("shares")
        try:
            if not amount or int(amount) < 1 or int(amount) % 1 != 0:
                return apology("Invalid Amount", 400)
        except ValueError:
            return apology("Invalid Amount")
        amount = int(amount)

        val = lookup(symbol.upper())
        if not val:
            return apology("Symbol Does Not Exist")
        balance = db.execute("SELECT cash FROM users WHERE ID = ?", session["user_id"])[0]

        if val["price"] * amount > int(balance['cash']):
            return apology("Not Enough Money", 403)
        else:
            db.execute("UPDATE users SET cash = (?) WHERE id = ?", float(
                balance['cash'] - (amount * val["price"])), session["user_id"])
            if len(db.execute("SELECT id FROM shares WHERE id = ? AND stock = ?", session["user_id"], symbol.upper())) == 0:
                db.execute("INSERT INTO shares(id, stock, amount) VALUES(?, ?, ?)",
                           session["user_id"], symbol.upper(), amount)
                db.execute("INSERT INTO history (date, id, stock, amount) VALUES (?, ?, ?, ?)",
                           datetime.now(), session["user_id"], symbol.upper(), amount)
                flash("Bought")
                return redirect("/")
            else:
                stockAmount = db.execute(
                    "SELECT amount FROM shares WHERE id = ? AND stock = ?", session["user_id"], symbol.upper())[0]
                db.execute("UPDATE shares SET amount = ? where stock = ? AND id = ?",
                           stockAmount["amount"] + int(amount), symbol.upper(), session["user_id"])
                db.execute("INSERT INTO history (date, id, stock, amount) VALUES (?, ?, ?, ?)",
                           datetime.now(), session["user_id"], symbol.upper(), amount)
                flash("Bought!")
                return redirect("/")

    return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    data = db.execute("SELECT * FROM history WHERE id = ?", session["user_id"])
    for item in data:
        item["price"] = lookup(item["stock"])["price"]

    return render_template("history.html", data=data)


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
        rows = db.execute(
            "SELECT * FROM users WHERE username = ?", request.form.get("username")
        )

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], request.form.get("password")
        ):
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
    show = False
    if request.method == "POST":
        show = True
        symbol = request.form.get("symbol")
        quote = lookup(symbol.upper())
        print(lookup("X"))
        if not quote:
            return apology("Stock not found")

    if show:
        return render_template("quote.html", symbol=symbol, price=quote["price"], show=show)
    else:
        return render_template("quote.html", show=show)


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        password = request.form.get("password")
        if not password == request.form.get("confirmation"):
            return apology("passwords do not match", 400)
        # Checking if password was inputted
        if password:
            password = generate_password_hash(password)
        else:
            return apology("Must provide Password", 400)

        # Checking name Exists
        name = request.form.get("username")
        if not name:
            return apology("Must provide Username", 400)

        # Registering user if the name is not taken
        if name and password:
            try:
                db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", name, password)
            except ValueError:
                return apology("Username Taken")
            else:
                rows = db.execute(
                    "SELECT * FROM users WHERE username = ?", request.form.get("username")
                )
                session["user_id"] = rows[0]["id"]
                flash("Registered!")
                return redirect("/")

    return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "POST":
        symbol = request.form.get("symbol")
        if not symbol:
            return apology("Symbol Not Found", 403)
        print("symbol: ", symbol)

        amount = request.form.get("shares")
        if not int(amount) or int(amount) < 1:
            return apology("Invalid Amount", 403)
        amount = int(amount)

        val = lookup(symbol.upper())
        balance = db.execute("SELECT cash FROM users WHERE ID = ?", session["user_id"])[0]["cash"]

        if amount > db.execute("SELECT amount FROM shares WHERE id = ? AND stock = ?", session["user_id"], symbol)[0]["amount"]:
            return apology("not enough stock")
        else:
            stockAmount = db.execute(
                "SELECT amount FROM shares WHERE id = ? AND stock = ?", session["user_id"], symbol.upper())[0]
            print(stockAmount)
            print("Stock left = ", stockAmount["amount"] - amount)
            # setting the correct amount of shares
            db.execute("UPDATE shares SET amount = ? where stock = ? AND id = ?",
                       stockAmount["amount"] - amount, symbol.upper(), session["user_id"])
            db.execute("INSERT INTO history(date, id, stock, amount) VALUES (?, ?, ?, ?)",
                       datetime.now(), session["user_id"], symbol.upper(), -amount)
            if stockAmount["amount"] - amount <= 0:
                db.execute("DELETE FROM shares WHERE id = ? AND stock = ?",
                           session["user_id"], symbol.upper())
            # setting users balance
            db.execute("UPDATE users SET cash = ? WHERE id = ?", balance +
                       (val["price"] * amount), session["user_id"])
            flash("Sold!")
            return redirect("/")
    else:
        symbols = []
        for symbol in db.execute("SELECT stock FROM shares WHERE id = ?", session["user_id"]):
            symbols.append(symbol["stock"])

        return render_template("sell.html", symbols=symbols)


@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    message = ""
    if request.method == "POST":
        if request.form.get("password") and request.form.get("new"):
            if check_password_hash(db.execute("SELECT hash FROM users WHERE id = ?", session["user_id"])[0]["hash"], request.form.get("password")):
                db.execute("UPDATE users SET hash = ? WHERE id = ?",
                           generate_password_hash(request.form.get("new")), session["user_id"])
                flash("Password Changed!")
                return redirect("/")
            else:
                message = "Incorrect Password"
        else:
            message = "Please fill in all fields"
    return render_template("password.html", message=message)
