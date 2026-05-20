from functools import wraps
from pathlib import Path
import os
import re
import secrets
import sqlite3

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, abort, flash, redirect, render_template, request, session, url_for


BASE_DIR = Path(__file__).resolve().parent
DATABASE = BASE_DIR / "grades.db"
KEY_FILE = BASE_DIR / "encryption.key"
SECRET_FILE = BASE_DIR / ".flask_secret"
ADMIN_BOOTSTRAP_FILE = BASE_DIR / "admin_initial_password.txt"
INSTRUCTOR_LOGIN = "instructor"

USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
COURSE_RE = re.compile(r"^[A-Za-z0-9ÇĞİÖŞÜçğıöşü ._-]{2,80}$")
GRADE_OPTIONS = ("AA", "AB", "BB", "CB", "CC", "DC", "DD", "FF")
ALLOWED_ROLES = {"student", "admin"}


def load_or_create_bytes(path: Path, generator) -> bytes:
    if path.exists():
        return path.read_bytes().strip()
    value = generator()
    path.write_bytes(value)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return value


def create_app() -> Flask:
    app = Flask(__name__)
    app.secret_key = os.environ.get("FLASK_SECRET_KEY") or load_or_create_bytes(
        SECRET_FILE, lambda: secrets.token_urlsafe(48).encode()
    ).decode()
    app.config.update(
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
        PERMANENT_SESSION_LIFETIME=1800,
    )

    init_crypto()
    init_db()
    register_routes(app)
    return app


def init_crypto() -> None:
    global fernet
    key = load_or_create_bytes(KEY_FILE, Fernet.generate_key)
    fernet = Fernet(key)


def get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))
    except ValueError:
        return False


def validate_password(password: str) -> str | None:
    if len(password) < 8:
        return "Password must be at least 8 characters."
    checks = [
        (r"[a-z]", "one lowercase letter"),
        (r"[A-Z]", "one uppercase letter"),
        (r"\d", "one number"),
        (r"[^A-Za-z0-9]", "one special character"),
    ]
    missing = [label for pattern, label in checks if not re.search(pattern, password)]
    if missing:
        return "Password must include " + ", ".join(missing) + "."
    return None


def validate_username(username: str) -> str | None:
    if username.lower() == INSTRUCTOR_LOGIN:
        return "This username is reserved for instructor access."
    if not USERNAME_RE.fullmatch(username):
        return "Username must be 3-32 characters and use letters, numbers, dots, dashes or underscores."
    return None


def normalize_login_username(username: str) -> str:
    if username.strip().lower() == INSTRUCTOR_LOGIN:
        return "admin"
    return username.strip()


def validate_course(course: str) -> str | None:
    if not COURSE_RE.fullmatch(course):
        return "Course name must be 2-80 characters and contain only safe characters."
    return None


def validate_grade(grade: str) -> str | None:
    if grade not in GRADE_OPTIONS:
        return "Grade must be one of: " + ", ".join(GRADE_OPTIONS) + "."
    return None


def init_db() -> None:
    with get_db() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role     TEXT NOT NULL DEFAULT 'student'
                         CHECK(role IN ('student', 'admin'))
            )
            """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS grades (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                student_id      INTEGER NOT NULL,
                course          TEXT NOT NULL,
                grade_encrypted TEXT NOT NULL,
                created_at      TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(student_id) REFERENCES users(id) ON DELETE CASCADE
            )
            """
        )
        ensure_column(conn, "grades", "created_at", "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")
        ensure_admin(conn)
        conn.commit()


def ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})")}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


def ensure_admin(conn: sqlite3.Connection) -> None:
    admin = conn.execute("SELECT id, password FROM users WHERE username=?", ("admin",)).fetchone()
    if admin:
        bootstrap_password = os.environ.get("ADMIN_PASSWORD") or generate_bootstrap_password()
        if verify_password("admin123", admin["password"]) or not verify_password(bootstrap_password, admin["password"]):
            password = os.environ.get("ADMIN_PASSWORD") or generate_bootstrap_password()
            conn.execute("UPDATE users SET password=?, role='admin' WHERE id=?", (hash_password(password), admin["id"]))
        return

    password = os.environ.get("ADMIN_PASSWORD") or generate_bootstrap_password()
    conn.execute(
        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
        ("admin", hash_password(password), "admin"),
    )


def generate_bootstrap_password() -> str:
    if ADMIN_BOOTSTRAP_FILE.exists():
        for line in ADMIN_BOOTSTRAP_FILE.read_text().splitlines():
            if line.startswith("Password: "):
                return line.removeprefix("Password: ").strip()
    password = "Isu-" + secrets.token_urlsafe(12) + "9!"
    ADMIN_BOOTSTRAP_FILE.write_text(
        "Initial instructor credentials\nUsername: instructor\nPassword: " + password + "\n"
    )
    try:
        os.chmod(ADMIN_BOOTSTRAP_FILE, 0o600)
    except OSError:
        pass
    return password


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please log in first.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return view(*args, **kwargs)

    return wrapper


def csrf_token() -> str:
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf() -> None:
    if request.form.get("_csrf_token") != session.get("_csrf_token"):
        abort(400)


def current_user() -> sqlite3.Row | None:
    user_id = session.get("user_id")
    if not user_id:
        return None
    with get_db() as conn:
        return conn.execute("SELECT id, username, role FROM users WHERE id=?", (user_id,)).fetchone()


def display_identity(user: sqlite3.Row | None) -> str:
    if not user:
        return ""
    if user["role"] == "admin":
        return "Academic Staff · Instructor"
    return user["username"] + " · Student"


def decrypt_grade(value: str) -> str:
    try:
        return fernet.decrypt(value.encode("utf-8")).decode("utf-8")
    except InvalidToken:
        return "[decryption failed]"


def students_for_select(conn: sqlite3.Connection) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT id, username FROM users WHERE role='student' ORDER BY username COLLATE NOCASE"
    ).fetchall()


def register_routes(app: Flask) -> None:
    app.jinja_env.globals["csrf_token"] = csrf_token

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "same-origin"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'self'; "
            "base-uri 'self'; frame-ancestors 'none'"
        )
        return response

    @app.context_processor
    def inject_user():
        user = current_user()
        return {
            "current_user": user,
            "current_identity": display_identity(user),
            "grade_options": GRADE_OPTIONS,
        }

    @app.errorhandler(403)
    def forbidden(_error):
        return render_template("error.html", code=403, message="You are not allowed to access this area."), 403

    @app.errorhandler(400)
    def bad_request(_error):
        return render_template("error.html", code=400, message="The submitted form could not be verified."), 400

    @app.route("/")
    def index():
        if "user_id" in session:
            return redirect(url_for("dashboard"))
        return redirect(url_for("login"))

    @app.route("/register", methods=["GET", "POST"])
    def register():
        if request.method == "POST":
            validate_csrf()
            username = normalize_login_username(request.form.get("username", ""))
            password = request.form.get("password", "")
            confirm = request.form.get("confirm_password", "")
            errors = [validate_username(username), validate_password(password)]
            if password != confirm:
                errors.append("Password confirmation does not match.")
            errors = [error for error in errors if error]
            if errors:
                for error in errors:
                    flash(error, "danger")
                return render_template("register.html", username=username), 422
            try:
                with get_db() as conn:
                    conn.execute(
                        "INSERT INTO users (username, password, role) VALUES (?, ?, ?)",
                        (username, hash_password(password), "student"),
                    )
                    conn.commit()
                flash("Registration successful. Please log in.", "success")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Username already exists.", "danger")
        return render_template("register.html")

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            validate_csrf()
            username = normalize_login_username(request.form.get("username", ""))
            password = request.form.get("password", "")
            with get_db() as conn:
                user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
            if user and verify_password(password, user["password"]):
                session.clear()
                session.permanent = True
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                flash("Welcome back, instructor." if user["role"] == "admin" else "Welcome back, " + user["username"] + ".", "success")
                return redirect(url_for("dashboard"))
            flash("Invalid username or password.", "danger")
        return render_template("login.html")

    @app.route("/logout", methods=["POST"])
    @login_required
    def logout():
        validate_csrf()
        session.clear()
        flash("Logged out successfully.", "info")
        return redirect(url_for("login"))

    @app.route("/dashboard")
    @login_required
    def dashboard():
        if session.get("role") == "admin":
            return redirect(url_for("admin"))
        with get_db() as conn:
            rows = conn.execute(
                """
                SELECT id, course, grade_encrypted, created_at
                FROM grades
                WHERE student_id=?
                ORDER BY created_at DESC, id DESC
                """,
                (session["user_id"],),
            ).fetchall()
        grades = [
            {
                "id": row["id"],
                "course": row["course"],
                "grade": decrypt_grade(row["grade_encrypted"]),
                "created_at": row["created_at"],
            }
            for row in rows
        ]
        return render_template("dashboard.html", grades=grades)

    @app.route("/admin")
    @login_required
    @admin_required
    def admin():
        with get_db() as conn:
            users = conn.execute("SELECT id, username, role FROM users ORDER BY role, username").fetchall()
            all_grades = conn.execute(
                """
                SELECT g.id, g.student_id, u.username, g.course, g.grade_encrypted, g.created_at
                FROM grades g
                JOIN users u ON g.student_id = u.id
                ORDER BY g.created_at DESC, g.id DESC
                """
            ).fetchall()
            students = students_for_select(conn)
        grades = [
            {
                "id": row["id"],
                "student_id": row["student_id"],
                "username": row["username"],
                "course": row["course"],
                "grade": decrypt_grade(row["grade_encrypted"]),
                "encrypted": row["grade_encrypted"],
                "created_at": row["created_at"],
            }
            for row in all_grades
        ]
        return render_template("admin.html", users=users, students=students, grades=grades)

    @app.route("/admin/grades", methods=["POST"])
    @login_required
    @admin_required
    def create_grade():
        validate_csrf()
        student_id = request.form.get("student_id", type=int)
        course = request.form.get("course", "").strip()
        grade = request.form.get("grade", "").strip().upper()
        errors = [validate_course(course), validate_grade(grade)]
        with get_db() as conn:
            student = conn.execute(
                "SELECT id FROM users WHERE id=? AND role='student'", (student_id,)
            ).fetchone()
            if not student:
                errors.append("Select a valid student.")
            errors = [error for error in errors if error]
            if errors:
                for error in errors:
                    flash(error, "danger")
                return redirect(url_for("admin"))
            conn.execute(
                "INSERT INTO grades (student_id, course, grade_encrypted) VALUES (?, ?, ?)",
                (student_id, course, fernet.encrypt(grade.encode("utf-8")).decode("utf-8")),
            )
            conn.commit()
        flash("Grade was encrypted and saved.", "success")
        return redirect(url_for("admin"))

    @app.route("/admin/grades/<int:grade_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def delete_grade(grade_id: int):
        validate_csrf()
        with get_db() as conn:
            conn.execute("DELETE FROM grades WHERE id=?", (grade_id,))
            conn.commit()
        flash("Grade deleted.", "info")
        return redirect(url_for("admin"))

    @app.route("/admin/users/<int:user_id>/role", methods=["POST"])
    @login_required
    @admin_required
    def update_role(user_id: int):
        validate_csrf()
        role = request.form.get("role", "")
        if role not in ALLOWED_ROLES:
            abort(400)
        if user_id == session["user_id"] and role != "admin":
            flash("You cannot remove your own instructor access.", "danger")
            return redirect(url_for("admin"))
        with get_db() as conn:
            conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
            conn.commit()
        flash("User role updated.", "success")
        return redirect(url_for("admin"))

    @app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
    @login_required
    @admin_required
    def delete_user(user_id: int):
        validate_csrf()
        if user_id == session["user_id"]:
            flash("You cannot delete your own account.", "danger")
            return redirect(url_for("admin"))
        with get_db() as conn:
            conn.execute("DELETE FROM users WHERE id=?", (user_id,))
            conn.commit()
        flash("User and their grades were deleted.", "info")
        return redirect(url_for("admin"))


app = create_app()

# ─── VERİTABANI EXPORT ───────────────────────────────────────────
def export_db_to_file(output_path: str = "db_export.txt") -> None:
    """users ve grades tablolarını okunabilir formatta dosyaya yazar."""
    key = KEY_FILE.read_bytes().strip()
    from cryptography.fernet import Fernet, InvalidToken
    f = Fernet(key)

    lines = []
    lines.append("=" * 60)
    lines.append("KULLANICI BİLGİLERİ (users tablosu)")
    lines.append("=" * 60)

    with get_db() as conn:
        users = conn.execute(
            "SELECT id, username, password, role FROM users ORDER BY role, username"
        ).fetchall()
        for u in users:
            lines.append(f"  ID       : {u['id']}")
            lines.append(f"  Kullanıcı: {u['username']}")
            lines.append(f"  Rol      : {u['role']}")
            lines.append(f"  Şifre (bcrypt hash): {u['password']}")
            lines.append("")

        lines.append("=" * 60)
        lines.append("NOT BİLGİLERİ (grades tablosu)")
        lines.append("=" * 60)

        rows = conn.execute(
            """
            SELECT g.id, u.username, g.course, g.grade_encrypted, g.created_at
            FROM grades g JOIN users u ON g.student_id = u.id
            ORDER BY u.username, g.course
            """
        ).fetchall()
        for r in rows:
            try:
                grade = f.decrypt(r["grade_encrypted"].encode()).decode()
            except InvalidToken:
                grade = "[çözülemedi]"
            lines.append(f"  Not ID   : {r['id']}")
            lines.append(f"  Öğrenci  : {r['username']}")
            lines.append(f"  Ders     : {r['course']}")
            lines.append(f"  Not      : {grade}")
            lines.append(f"  Şifreli  : {r['grade_encrypted'][:40]}...")
            lines.append(f"  Tarih    : {r['created_at']}")
            lines.append("")

    if ADMIN_BOOTSTRAP_FILE.exists():
        lines.append("=" * 60)
        lines.append("ADMIN BOOTSTRAP (admin_initial_password.txt)")
        lines.append("=" * 60)
        lines.append(ADMIN_BOOTSTRAP_FILE.read_text().strip())

    Path(output_path).write_text("\n".join(lines), encoding="utf-8")
    print(f"[export] Kaydedildi → {output_path}")


def jls_extract_def():
    # uygulama her başladığında çalışır
    return 


export_db_to_file("db_export.txt")   # uygulama her başladığında çalışır = jls_extract_def()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "5001")), debug=False)
