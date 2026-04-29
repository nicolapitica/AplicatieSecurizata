from flask import Flask, request, render_template, redirect, make_response
import sqlite3
from datetime import datetime

app = Flask(__name__)
DB_NAME = "authx_vulnerable.db"


def get_db():
    return sqlite3.connect(DB_NAME)


def init_db():
    conn = get_db()
    c = conn.cursor()

#nu folosesc UNIQUE la email => duplicate
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT , 
            password_hash TEXT,
            role TEXT DEFAULT 'USER',
            created_at TEXT,
            locked INTEGER DEFAULT 0
        )
    """)
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS tickets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT,
            description TEXT,
            severity TEXT,
            status TEXT,
            owner_id INTEGER,
            created_at TEXT,
            updated_at TEXT
        )
    """)
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            action TEXT,
            resource TEXT,
            resource_id TEXT,
            timestamp TEXT,
            ip_address TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            token TEXT,
            used INTEGER DEFAULT 0,
            created_at TEXT
        )
    """)

    conn.commit()
    conn.close()


def log_action(user_id, action, resource, resource_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("""
        INSERT INTO audit_logs (user_id, action, resource, resource_id, timestamp, ip_address)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        action,
        resource,
        resource_id,
        datetime.now().isoformat(),
        request.remote_addr
    ))
    conn.commit()
    conn.close()


def get_current_user():
    email = request.cookies.get("session")

    if not email:
        return None

    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, email, role FROM users WHERE email = ?", (email,))
    user = c.fetchone()
    conn.close()

    return user


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db()
        c = conn.cursor()

        # VULNERABIL:
        # - nu exista validare reala a parolei
        # - accepta parole foarte scurte
        # - parola este salvata in clar in coloana password_hash
        try:
            c.execute("""
                INSERT INTO users (email, password_hash, role, created_at, locked)
                VALUES (?, ?, ?, ?, ?)
            """, (
                email,
                password,
                "USER",
                datetime.now().isoformat(),
                0
            ))

            conn.commit()
            user_id = c.lastrowid
            log_action(user_id, "REGISTER", "auth", str(user_id))

            conn.close()
            return "Cont creat cu succes. Parola a fost salvata vulnerabil in baza de date."

        except sqlite3.IntegrityError:
            conn.close()
            return "User already exists"

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        conn = get_db()
        c = conn.cursor()

        c.execute("SELECT id, email, password_hash, role, locked FROM users WHERE email = ?", (email,))
        user = c.fetchone()
        conn.close()

        # VULNERABIL:
        # - mesaj diferit pentru user inexistent
        # - permite user enumeration
        if not user:
            return "User does not exist"

        if user[4] == 1:
            return "Account locked"

        # VULNERABIL:
        # - compara parola introdusa cu parola salvata in clar
        if user[2] != password:
            log_action(user[0], "FAILED_LOGIN", "auth", str(user[0]))
            return "Wrong password"

        log_action(user[0], "LOGIN", "auth", str(user[0]))

        response = make_response(redirect("/dashboard"))

        # VULNERABIL:
        # - cookie fara HttpOnly
        # - fara Secure
        # - fara SameSite
        # - contine direct email-ul utilizatorului
        response.set_cookie("session", user[1], max_age=60 * 60 * 24 * 30)

        return response

    return render_template("login.html")


@app.route("/dashboard")
def dashboard():
    user = get_current_user()

    if not user:
        return redirect("/login")

    return render_template("dashboard.html", user=user)


@app.route("/logout")
def logout():
    user = get_current_user()

    if user:
        log_action(user[0], "LOGOUT", "auth", str(user[0]))

    response = make_response("Logout realizat. Cookie-ul a fost sters.")
    response.set_cookie("session", "", expires=0)
    return response


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        email = request.form.get("email")

        # VULNERABIL:
        # - token predictibil
        # - acelasi token pentru toti userii
        # - token reutilizabil
        # - fara expirare reala
        token = "1234"

        conn = get_db()
        c = conn.cursor()
        c.execute("""
            INSERT INTO reset_tokens (email, token, used, created_at)
            VALUES (?, ?, ?, ?)
        """, (
            email,
            token,
            0,
            datetime.now().isoformat()
        ))
        conn.commit()
        conn.close()

        return f"Token de resetare generat: {token}"

    return render_template("forgot.html")


@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        email = request.form.get("email")
        token = request.form.get("token")
        new_password = request.form.get("password")

        conn = get_db()
        c = conn.cursor()

        # VULNERABIL:
        # - nu verifica expirarea
        # - nu invalideaza token-ul dupa folosire
        # - token-ul poate fi refolosit
        c.execute("""
            SELECT id FROM reset_tokens
            WHERE email = ? AND token = ?
        """, (email, token))

        valid_token = c.fetchone()

        if not valid_token:
            conn.close()
            return "Invalid reset token"

        c.execute("""
            UPDATE users
            SET password_hash = ?
            WHERE email = ?
        """, (new_password, email))

        conn.commit()
        conn.close()

        return "Parola a fost resetata. Token-ul ramane reutilizabil in versiunea vulnerabila."

    return render_template("reset.html")


@app.route("/debug/users")
def debug_users():
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, email, password_hash, role, created_at, locked FROM users")
    users = c.fetchall()
    conn.close()

    return render_template("dashboard.html", user=("DEBUG", "debug", "ADMIN"), users=users)

@app.route("/tickets")
def tickets():
    user = get_current_user()

    if not user:
        return redirect("/login")

    conn = get_db()
    c = conn.cursor()

    # VULNERABIL:
    # afiseaza toate ticketele, nu doar ale utilizatorului logat
    c.execute("""
        SELECT id, title, description, severity, status, owner_id, created_at, updated_at
        FROM tickets
    """)
    tickets_list = c.fetchall()

    conn.close()

    return render_template("tickets.html", tickets=tickets_list, user=user)


@app.route("/tickets/create", methods=["GET", "POST"])
def create_ticket():
    user = get_current_user()

    if not user:
        return redirect("/login")

    if request.method == "POST":
        title = request.form.get("title")
        description = request.form.get("description")
        severity = request.form.get("severity")

        conn = get_db()
        c = conn.cursor()

        c.execute("""
            INSERT INTO tickets (title, description, severity, status, owner_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            title,
            description,
            severity,
            "OPEN",
            user[0],
            datetime.now().isoformat(),
            datetime.now().isoformat()
        ))

        conn.commit()
        ticket_id = c.lastrowid
        conn.close()

        log_action(user[0], "CREATE_TICKET", "ticket", str(ticket_id))

        return redirect("/tickets")

    return render_template("create_ticket.html")


@app.route("/tickets/<int:ticket_id>")
def view_ticket(ticket_id):
    user = get_current_user()

    if not user:
        return redirect("/login")

    conn = get_db()
    c = conn.cursor()
    # VULNERABIL:
    # putem vedea detaiile tuturor ticketelor, nu doar ale utilizatorului logat
    c.execute("""
        SELECT id, title, description, severity, status, owner_id, created_at, updated_at
        FROM tickets
        WHERE id = ?
    """, (ticket_id,))
    ticket = c.fetchone()

    conn.close()

    if not ticket:
        return "Ticket not found"

    return render_template("view_ticket.html", ticket=ticket)


@app.route("/search")
def search():
    user = get_current_user()

    if not user:
        return redirect("/login")

    q = request.args.get("q", "")

    conn = get_db()
    c = conn.cursor()

    # VULNERABIL:
    # cautare simpla, fara limitare pe owner
    c.execute("""
        SELECT id, title, description, severity, status, owner_id
        FROM tickets
        WHERE title LIKE ? OR description LIKE ?
    """, (f"%{q}%", f"%{q}%"))

    results = c.fetchall()
    conn.close()

    return render_template("search.html", results=results, q=q)

@app.route("/tickets/<int:ticket_id>/status", methods=["POST"])
def update_ticket_status(ticket_id):
    user = get_current_user()

    if not user:
        return redirect("/login")

    new_status = request.form.get("status")

    conn = get_db()
    c = conn.cursor()

    # VULNERABIL:
    # orice utilizator logat poate modifica statusul oricarui ticket
    # nu se verifica owner_id si nici rolul utilizatorului
    c.execute("""
        UPDATE tickets
        SET status = ?, updated_at = ?
        WHERE id = ?
    """, (
        new_status,
        datetime.now().isoformat(),
        ticket_id
    ))

    conn.commit()
    conn.close()

    log_action(user[0], "UPDATE_TICKET_STATUS", "ticket", str(ticket_id))

    return redirect(f"/tickets/{ticket_id}")
    
if __name__ == "__main__":
    init_db()
    app.run(debug=True)
