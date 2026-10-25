import os
import sys
import sqlite3
import logging
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, session, g
from werkzeug.security import generate_password_hash, check_password_hash

# Base directory paths
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "database.db")
LOG_DIR = os.path.join(BASE_DIR, "logs")
LOG_FILE = os.path.join(LOG_DIR, "requests.log")


def setup_request_logger(log_file_path: str = LOG_FILE) -> logging.Logger:
    """Configures and returns the dedicated HTTP request logger."""
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)
    logger_name = f"for_test.requests.{os.path.abspath(log_file_path)}"
    req_logger = logging.getLogger(logger_name)
    req_logger.setLevel(logging.INFO)
    req_logger.propagate = False

    # Avoid duplicate handlers on hot reloads
    if not req_logger.handlers:
        handler = logging.FileHandler(log_file_path, encoding="utf-8")
        handler.setFormatter(logging.Formatter("%(message)s"))
        req_logger.addHandler(handler)

    return req_logger


def get_db_connection(db_path: str = DB_PATH) -> sqlite3.Connection:
    """Creates a database connection with dictionary-like row access."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str = DB_PATH) -> None:
    """Initializes the database schema and seeds default demo accounts if missing."""
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)

        # Demo accounts for isolated security testing
        demo_accounts = [
            ("admin", "admin123", "admin"),
            ("user", "user123", "user"),
        ]

        for username, password, role in demo_accounts:
            cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
            if cursor.fetchone() is None:
                pwd_hash = generate_password_hash(password)
                cursor.execute(
                    "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                    (username, pwd_hash, role),
                )
        conn.commit()
    finally:
        conn.close()


def get_secret_key() -> str:
    """Retrieves secret key from environment or halts startup if unconfigured."""
    key = os.environ.get("FLASK_SECRET_KEY") or os.environ.get("SECRET_KEY")
    if not key:
        error_msg = (
            "\n"
            "======================================================================\n"
            "CRITICAL SECURITY CONFIGURATION ERROR:\n"
            "FLASK_SECRET_KEY environment variable is not configured!\n\n"
            "To prevent insecure defaults, this application requires a secret key.\n"
            "Before launching, please set FLASK_SECRET_KEY in your shell:\n\n"
            "  export FLASK_SECRET_KEY=\"$(python3 -c 'import secrets; print(secrets.token_hex(32))')\"\n"
            "======================================================================\n"
        )
        sys.stderr.write(error_msg)
        raise RuntimeError("FLASK_SECRET_KEY is not set.")
    return key


def create_app(test_config=None) -> Flask:
    """Application factory for FOR-TEST."""
    app = Flask(__name__)

    if test_config is not None:
        app.config.update(test_config)
    else:
        app.secret_key = get_secret_key()

    target_db_path = app.config.get("DATABASE_PATH", DB_PATH)
    target_log_path = app.config.get("LOG_FILE_PATH", LOG_FILE)

    # Initialize storage and logging
    init_db(target_db_path)
    req_logger = setup_request_logger(target_log_path)

    @app.before_request
    def determine_default_event():
        # Default event tag based on route classification
        if request.path.startswith("/static/"):
            g.auth_event = "STATIC_REQUEST"
        elif request.method == "GET":
            g.auth_event = "PAGE_REQUEST"
        else:
            g.auth_event = "HTTP_REQUEST"

    @app.after_request
    def log_http_request(response):
        """Records HTTP request telemetry without logging credentials or session tokens."""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            # Directly use remote_addr; do not trust arbitrary forwarded headers
            source_ip = request.remote_addr or "-"
            method = request.method
            path = request.path
            status = response.status_code
            event = getattr(g, "auth_event", "HTTP_REQUEST")
            user_agent = request.headers.get("User-Agent") or "-"

            log_entry = (
                f"{timestamp} | {source_ip:<15} | {method:<4} | "
                f"{path:<15} | {status:<3} | {event:<15} | {user_agent}"
            )
            req_logger.info(log_entry)
        except Exception as ex:
            app.logger.error(f"Failed to record request log: {ex}")

        return response

    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            if "user_id" in session:
                return redirect(url_for("dashboard"))
            return render_template("login.html")

        # POST /login
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            g.auth_event = "LOGIN_FAILURE"
            return render_template("login.html", error="Invalid username or password."), 401

        conn = get_db_connection(target_db_path)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, password_hash, role FROM users WHERE username = ?",
                (username,),
            )
            user = cursor.fetchone()

            if user and check_password_hash(user["password_hash"], password):
                # Valid credentials
                session.clear()
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                g.auth_event = "LOGIN_SUCCESS"
                return redirect(url_for("dashboard"))
            else:
                # Invalid credentials
                g.auth_event = "LOGIN_FAILURE"
                return render_template("login.html", error="Invalid username or password."), 401
        finally:
            conn.close()

    @app.route("/dashboard", methods=["GET"])
    def dashboard():
        if "user_id" not in session:
            g.auth_event = "PAGE_REQUEST"
            return redirect(url_for("login"))

        g.auth_event = "PAGE_REQUEST"
        return render_template(
            "dashboard.html",
            username=session.get("username"),
            role=session.get("role"),
        )

    @app.route("/logout", methods=["POST"])
    def logout():
        session.clear()
        g.auth_event = "LOGOUT"
        return redirect(url_for("login"))

    return app


if __name__ == "__main__":
    # In direct execution, instantiate and run on 0.0.0.0:5000
    try:
        application = create_app()
        # Bind to 0.0.0.0:5000 for isolated laboratory LAN accessibility
        application.run(host="0.0.0.0", port=5000, debug=False)
    except RuntimeError:
        sys.exit(1)
