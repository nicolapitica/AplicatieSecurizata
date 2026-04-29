from flask import Flask, request, render_template, redirect, make_response
import sqlite3
from datetime import datetime, timedelta
import bcrypt
import re
import secrets

app = Flask(__name__)
DB_NAME = "authx_fixed.db"
MAX_LOGIN_ATTEMPTS = 5
LOCK_MINUTES = 5
SESSION_MINUTES = 30
RESET_TOKEN_MINUTES = 10

# Pentru localhost HTTP ramane False ca sa functioneze in browser.
# In productie trebuie True.
COOKIE_SECURE = False

def get_db():
    return sqlite3.connect(DB_NAME)
    
    
#3.1 Input-ul trebuie validat în backend
def is_valid_email(email):
    if not email:
        return False
    if len(email) > 120:
        return False
        
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(pattern, email) is not None

#3.1 Input-ul trebuie validat în backend

def is_strong_password(password):
    errors = []

    if not password:
        errors.append("Parola este obligatorie.")
        return errors

    if len(password) < 8:
        errors.append("Parola trebuie sa aiba minimum 8 caractere.")

    if len(password) > 72:
        errors.append("Parola trebuie sa aiba maximum 72 caractere.")

    if not re.search(r"[a-z]", password):
        errors.append("Parola trebuie sa contina cel putin o litera mica.")

    if not re.search(r"[A-Z]", password):
        errors.append("Parola trebuie sa contina cel putin o litera mare.")

    if not re.search(r"[0-9]", password):
        errors.append("Parola trebuie sa contina cel putin o cifra.")

    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-+=]", password):
        errors.append("Parola trebuie sa contina cel putin un caracter special.")

    return errors

def is_valid_login_input(email, password):
    if not email or not password:
        return False

    if len(email) > 120:
        return False

    if len(password) > 72:
        return False

    if not is_valid_email(email):
        return False

    return True
    
def hash_password(password):
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")

def create_reset_token(user_id, email):
    # Etapa 17 + FIX 4.6:
    # token random, greu de ghicit, cu expirare scurta
    token = secrets.token_urlsafe(32)
    now = datetime.now()
    expires_at = now + timedelta(minutes=RESET_TOKEN_MINUTES)

    conn = get_db()
    c = conn.cursor()

    # Invalidam tokenurile vechi ale aceluiasi utilizator
    # ca sa ramana activ doar cel mai recent token
    c.execute("""
        UPDATE reset_tokens
        SET used = 1
        WHERE user_id = ? AND used = 0
    """, (user_id,))

    c.execute("""
        INSERT INTO reset_tokens (user_id, email, token, used, created_at, expires_at)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        user_id,
        email,
        token,
        0,
        now.isoformat(),
        expires_at.isoformat()
    ))

    conn.commit()
    conn.close()

    return token
    
def init_db():
    conn = get_db()
    c = conn.cursor()
    
    c.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE,
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
        user_id INTEGER,
        email TEXT,
        token TEXT UNIQUE,
        used INTEGER DEFAULT 0,
        created_at TEXT,
        expires_at TEXT
    )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT,
            ip_address TEXT,
            success INTEGER,
            timestamp TEXT
        )
    """)

    c.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            token TEXT UNIQUE,
            created_at TEXT,
            expires_at TEXT,
            valid INTEGER DEFAULT 1
        )
    """)
    
    conn.commit()
    conn.close()


def log_action(user_id, action, resource, resource_id):
    # Audit general
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
    # Etapa 12: dupa login, fiecare request verifica sesiunea/token-ul
    # Etapa 13: identificare utilizator curent
    # Etapa 15: verificare sesiune/token la fiecare request
    token = request.cookies.get("session_token")

    if not token:
        return None

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT users.id, users.email, users.role
        FROM sessions
        JOIN users ON sessions.user_id = users.id
        WHERE sessions.token = ?
          AND sessions.valid = 1
          AND sessions.expires_at > ?
    """, (
        token,
        datetime.now().isoformat()
    ))

    user = c.fetchone()
    conn.close()

    return user

def user_owns_ticket(user_id, ticket_id):
    # Etapa 14: autorizare
    # Verifica daca ticket-ul apartine utilizatorului curent
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT id
        FROM tickets
        WHERE id = ? AND owner_id = ?
    """, (ticket_id, user_id))

    ticket = c.fetchone()
    conn.close()

    return ticket is not None

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        # FIX 4.1:
        # Validare backend pentru email si parola.
        # Nu se mai accepta parole triviale precum "1", "1234", "test".
        if not is_valid_email(email):
            return "Adresa de email este invalida."

        password_errors = is_strong_password(password)

        if password_errors:
            return "<br>".join(password_errors)
        conn = get_db()
        c = conn.cursor()

        # 4. Register –existență user: Verifică dacă userul există deja
        c.execute("SELECT id FROM users WHERE email = ?", (email,))
        existing_user = c.fetchone()

        if existing_user:
            conn.close()
            return "Date invalide. Verifica email-ul si parola."

        # FIX 4.2:
        # Parola nu mai este salvata in clar.
        # Se foloseste bcrypt, care include salt implicit.
        #5. Register – parola: Hash-uiește parola
        password_hash = hash_password(password)
        
        #6Register–persistare: Salvează utilizatorul în baza de date
        c.execute("""
            INSERT INTO users (email, password_hash, role, created_at, locked)
            VALUES (?, ?, ?, ?, ?)
        """, (
            email,
            password_hash,
            "USER",
            datetime.now().isoformat(),
            0
        ))

        conn.commit()
        user_id = c.lastrowid
        conn.close()

        log_action(user_id, "REGISTER", "auth", str(user_id))

        return "Cont creat cu succes. Parola a fost salvata securizat cu bcrypt."

    return render_template("register.html")

def verify_password(password, password_hash):
    # FIX 4.2 / Login: parola introdusa este comparata cu hash-ul bcrypt
    try:
        return bcrypt.checkpw(
            password.encode("utf-8"),
            password_hash.encode("utf-8")
        )
    except Exception:
        return False


def is_login_blocked(email, ip_address):
    # FIX 4.3: blocare temporara dupa prea multe incercari esuate
    since = (datetime.now() - timedelta(minutes=LOCK_MINUTES)).isoformat()

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT COUNT(*)
        FROM login_attempts
        WHERE email = ?
          AND ip_address = ?
          AND success = 0
          AND timestamp > ?
    """, (email, ip_address, since))

    failed_count = c.fetchone()[0]
    conn.close()

    return failed_count >= MAX_LOGIN_ATTEMPTS


def save_login_attempt(email, ip_address, success):
    # FIX 4.3: logarea tentativelor de login
    conn = get_db()
    c = conn.cursor()

    c.execute("""
        INSERT INTO login_attempts (email, ip_address, success, timestamp)
        VALUES (?, ?, ?, ?)
    """, (
        email,
        ip_address,
        1 if success else 0,
        datetime.now().isoformat()
    ))

    conn.commit()
    conn.close()


def create_session(user_id):
    # FIX 4.5: token random nou la fiecare login
    token = secrets.token_urlsafe(32)
    now = datetime.now()
    expires_at = now + timedelta(minutes=SESSION_MINUTES)

    conn = get_db()
    c = conn.cursor()

    # invalidare sesiuni vechi ale userului
    c.execute("""
        UPDATE sessions
        SET valid = 0
        WHERE user_id = ?
    """, (user_id,))

    c.execute("""
        INSERT INTO sessions (user_id, token, created_at, expires_at, valid)
        VALUES (?, ?, ?, ?, ?)
    """, (
        user_id,
        token,
        now.isoformat(),
        expires_at.isoformat(),
        1
    ))

    conn.commit()
    conn.close()

    return token
    
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Etapa 7: login - trimitere date
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        ip_address = request.remote_addr
        
        # respinge input invalid inainte de verificarea in DB
        if not is_valid_login_input(email, password):
            save_login_attempt(email, ip_address, False)
            return "Credentiale invalide!"
            
        # FIX 4.3: rate limiting / blocare temporara
        if is_login_blocked(email, ip_address):
            save_login_attempt(email, ip_address, False)
            return "Credentiale invalide!"

        conn = get_db()
        c = conn.cursor()

        # Etapa 8: cautare user in DB
        c.execute("""
            SELECT id, email, password_hash, role, locked
            FROM users
            WHERE email = ?
        """, (email,))

        user = c.fetchone()
        conn.close()

        # FIX 4.4: mesaj unic pentru user inexistent si parola gresita
        if not user:
            save_login_attempt(email, ip_address, False)
            return "Credentiale invalide!"

        if user[4] == 1:
            save_login_attempt(email, ip_address, False)
            return "Credentiale invalide!"

        # Etapa 9: verificare parola cu bcrypt
        if not verify_password(password, user[2]):
            save_login_attempt(email, ip_address, False)
            log_action(user[0], "FAILED_LOGIN", "auth", str(user[0]))
            return "Credentiale invalide!"

        save_login_attempt(email, ip_address, True)
        log_action(user[0], "LOGIN", "auth", str(user[0]))

        # Etapa 10: creare sesiune/token
        session_token = create_session(user[0])

        response = make_response(redirect("/dashboard"))

        # Etapa 11 + FIX 4.5: cookie cu token random, HttpOnly, SameSite, expirare
        response.set_cookie(
            "session_token",
            session_token,
            max_age=SESSION_MINUTES * 60,
            httponly=True,
            secure=COOKIE_SECURE,
            samesite="Strict"
        )

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
    token = request.cookies.get("session_token")

    if token:
        conn = get_db()
        c = conn.cursor()

        # Etapa 16: logout
        # Invalidam token-ul server-side
        c.execute("""
            UPDATE sessions
            SET valid = 0
            WHERE token = ?
        """, (token,))

        conn.commit()
        conn.close()

    if user:
        log_action(user[0], "LOGOUT", "auth", str(user[0]))

    response = make_response("Logout realizat. Sesiunea a fost invalidata.")

    # Stergem cookieul din browser
    response.set_cookie(
        "session_token",
        "",
        expires=0,
        httponly=True,
        secure=COOKIE_SECURE,
        samesite="Strict"
    )

    return response

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if request.method == "POST":
        # Etapa 17: utilizatorul cere resetarea parolei
        email = request.form.get("email", "").strip().lower()

        conn = get_db()
        c = conn.cursor()

        c.execute("""
            SELECT id, email
            FROM users
            WHERE email = ?
        """, (email,))

        user = c.fetchone()
        conn.close()

        # FIX 4.4 + 4.6:
        # mesaj generic, ca sa nu confirmam daca emailul exista sau nu
        if not user:
            log_action(None, "PASSWORD_RESET_REQUEST_UNKNOWN_EMAIL", "auth", email)
            return "Daca emailul exista, a fost generat un token de resetare."

        reset_token = create_reset_token(user[0], user[1])

        log_action(user[0], "PASSWORD_RESET_REQUEST", "auth", str(user[0]))

        # afisam tokenul pe ecran.
        # Intr-o aplicatie reala, tokenul s-ar trimite pe email.
        return f"""
            Daca emailul exista, a fost generat un token de resetare.<br>
            Token demo pentru laborator: {reset_token}<br>
            Tokenul expira in {RESET_TOKEN_MINUTES} minute.
        """

    return render_template("forgot.html")

@app.route("/reset", methods=["GET", "POST"])
def reset():
    if request.method == "POST":
        # Etapa 18: utilizatorul trimite email, token si parola noua
        email = request.form.get("email", "").strip().lower()
        token = request.form.get("token", "").strip()
        new_password = request.form.get("password", "")

        # Validare input pentru parola noua
        # Refolosim aceeasi politica de parola ca la Register
        if not is_valid_email(email):
            return "Date invalide pentru resetarea parolei."

        password_errors = is_strong_password(new_password)

        if password_errors:
            return "<br>".join(password_errors)

        conn = get_db()
        c = conn.cursor()

        # Etapa 18 + FIX 4.6:
        # tokenul trebuie sa existe, sa nu fie folosit si sa nu fie expirat
        c.execute("""
            SELECT id, user_id
            FROM reset_tokens
            WHERE email = ?
              AND token = ?
              AND used = 0
              AND expires_at > ?
        """, (
            email,
            token,
            datetime.now().isoformat()
        ))

        reset_record = c.fetchone()

        if not reset_record:
            conn.close()
            log_action(None, "PASSWORD_RESET_FAILED", "auth", email)
            return "Token invalid sau expirat."

        reset_token_id = reset_record[0]
        user_id = reset_record[1]

        # Parola noua este salvata securizat, cu bcrypt
        new_password_hash = hash_password(new_password)

        c.execute("""
            UPDATE users
            SET password_hash = ?
            WHERE id = ?
        """, (
            new_password_hash,
            user_id
        ))

        # Etapa 19 + FIX 4.6:
        # tokenul devine one-time si nu mai poate fi reutilizat
        c.execute("""
            UPDATE reset_tokens
            SET used = 1
            WHERE id = ?
        """, (reset_token_id,))

        conn.commit()
        conn.close()

        log_action(user_id, "PASSWORD_RESET_SUCCESS", "auth", str(user_id))

        return "Parola a fost resetata cu succes. Tokenul a fost invalidat."

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

    # Etapa 14: autorizare
    # Userul vede doar ticketele proprii, nu toate ticketele din sistem
    c.execute("""
        SELECT id, title, description, severity, status, owner_id, created_at, updated_at
        FROM tickets
        WHERE owner_id = ?
    """, (user[0],))

    tickets_list = c.fetchall()
    conn.close()

    log_action(user[0], "VIEW_TICKETS", "ticket", "own_tickets")

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

    # Etapa 14: autorizare
    # Previne IDOR: userul nu poate vedea ticket-ul altui user
    if not user_owns_ticket(user[0], ticket_id):
        log_action(user[0], "UNAUTHORIZED_VIEW_TICKET", "ticket", str(ticket_id))
        return "Access denied", 403

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        SELECT id, title, description, severity, status, owner_id, created_at, updated_at
        FROM tickets
        WHERE id = ?
    """, (ticket_id,))

    ticket = c.fetchone()
    conn.close()

    log_action(user[0], "VIEW_TICKET", "ticket", str(ticket_id))

    return render_template("view_ticket.html", ticket=ticket)
    
@app.route("/tickets/<int:ticket_id>/status", methods=["POST"])
def update_ticket_status(ticket_id):
    user = get_current_user()

    if not user:
        return redirect("/login")

    # Etapa 14: autorizare
    # Previne modificarea ticketelor altui user
    if not user_owns_ticket(user[0], ticket_id):
        log_action(user[0], "UNAUTHORIZED_UPDATE_TICKET", "ticket", str(ticket_id))
        return "Access denied", 403

    new_status = request.form.get("status")

    if new_status not in ["OPEN", "IN_PROGRESS", "RESOLVED"]:
        return "Invalid status", 400

    conn = get_db()
    c = conn.cursor()

    c.execute("""
        UPDATE tickets
        SET status = ?, updated_at = ?
        WHERE id = ? AND owner_id = ?
    """, (
        new_status,
        datetime.now().isoformat(),
        ticket_id,
        user[0]
    ))

    conn.commit()
    conn.close()

    log_action(user[0], "UPDATE_TICKET_STATUS", "ticket", str(ticket_id))

    return redirect(f"/tickets/{ticket_id}")
    
@app.route("/search")
def search():
    user = get_current_user()

    if not user:
        return redirect("/login")

    q = request.args.get("q", "")

    conn = get_db()
    c = conn.cursor()

    # Search securizat:
    # - query parametrizat
    # - cauta doar in ticketele userului curent
    c.execute("""
        SELECT id, title, description, severity, status, owner_id
        FROM tickets
        WHERE owner_id = ?
          AND (title LIKE ? OR description LIKE ?)
    """, (user[0], f"%{q}%", f"%{q}%"))

    results = c.fetchall()
    conn.close()

    log_action(user[0], "SEARCH_TICKETS", "ticket", q)

    return render_template("search.html", results=results, q=q)   

if __name__ == "__main__":
    init_db()
    app.run(debug=True)
