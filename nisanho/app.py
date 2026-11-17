import os
import re
import secrets
import sys
from datetime import datetime, timedelta
from functools import wraps
from getpass import getpass
from urllib.parse import urlsplit

import pyodbc
from dotenv import load_dotenv
from flask import (
    Flask,
    abort,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_socketio import SocketIO, emit, join_room, leave_room, disconnect
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET_KEY") or secrets.token_hex(32)
if not os.getenv("FLASK_SECRET_KEY"):
    app.logger.warning("FLASK_SECRET_KEY is not set; sessions will not survive an application restart.")
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.getenv("SESSION_COOKIE_SECURE", "false").lower() == "true",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    SESSION_REFRESH_EACH_REQUEST=True,
    MAX_CONTENT_LENGTH=64 * 1024,
)

socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading", manage_session=False)

ORDER_STATUSES = {"pending", "approved", "rejected"}
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^[0-9+\-()\s]{7,30}$")


def odbc_value(value):
    return "{" + str(value).replace("}", "}}") + "}"


def get_db_connection():
    conn_str = os.getenv("SQL_SERVER_CONNECTION_STRING")
    if conn_str:
        return pyodbc.connect(conn_str, autocommit=False, timeout=int(os.getenv("SQL_CONNECTION_TIMEOUT", "10")))

    driver = os.getenv("SQL_DRIVER", "ODBC Driver 17 for SQL Server").strip("{}")
    server = os.getenv("SQL_SERVER", r"localhost\SQLEXPRESS")
    database = os.getenv("SQL_DATABASE", "NisanhoAdmin")
    username = os.getenv("SQL_USERNAME")
    password = os.getenv("SQL_PASSWORD")
    parts = [
        f"DRIVER={odbc_value(driver)}",
        f"SERVER={odbc_value(server)}",
        f"DATABASE={odbc_value(database)}",
        "TrustServerCertificate=yes",
    ]
    if username is not None or password is not None:
        if not username or not password:
            raise RuntimeError("Set both SQL_USERNAME and SQL_PASSWORD for SQL Server authentication.")
        parts.extend([f"UID={odbc_value(username)}", f"PWD={odbc_value(password)}"])
    else:
        parts.append("Trusted_Connection=yes")
    return pyodbc.connect(
        ";".join(parts),
        autocommit=False,
        timeout=int(os.getenv("SQL_CONNECTION_TIMEOUT", "10")),
    )


def rows_to_dicts(cursor):
    if not cursor.description:
        return []
    cols = [c[0] for c in cursor.description]
    return [dict(zip(cols, row)) for row in cursor.fetchall()]


def fetch_all(query, params=()):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(query, params)
        return rows_to_dicts(cur)
    finally:
        if conn:
            conn.close()


def fetch_one(query, params=()):
    rows = fetch_all(query, params)
    return rows[0] if rows else None


def execute(query, params=(), commit=False):
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(query, params)
        if commit:
            conn.commit()
        return cur
    except Exception:
        if conn:
            conn.rollback()
        raise
    finally:
        if conn:
            conn.close()


def table_has_column(table, column):
    row = fetch_one(
        """
        SELECT 1 AS ok
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = 'dbo' AND TABLE_NAME = ? AND COLUMN_NAME = ?
        """,
        (table, column),
    )
    return bool(row)


def table_exists(table):
    row = fetch_one(
        "SELECT 1 AS ok FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA='dbo' AND TABLE_NAME=?",
        (table,),
    )
    return bool(row)


def require_admin_users_table():
    if not table_exists("admin_users"):
        raise RuntimeError("dbo.admin_users is missing. Apply database/migrations.sql first.")


def get_admin_user(email):
    require_admin_users_table()
    return fetch_one(
        "SELECT TOP 1 id, email, password_hash, is_active FROM dbo.admin_users WHERE LOWER(email)=LOWER(?)",
        (email,),
    )


def create_admin_account(email):
    email = clean_text(email, 200).lower()
    if not EMAIL_RE.fullmatch(email):
        raise ValueError("Enter a valid administrator email address.")
    require_admin_users_table()
    if get_admin_user(email):
        raise ValueError("An administrator with that email already exists.")

    password = getpass("New administrator password (at least 12 characters): ")
    confirmation = getpass("Confirm administrator password: ")
    if len(password) < 12:
        raise ValueError("The password must contain at least 12 characters.")
    if password != confirmation:
        raise ValueError("The passwords do not match.")

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO dbo.admin_users (email, password_hash, full_name, is_active, created_at, updated_at)
            VALUES (?, ?, ?, 1, GETDATE(), GETDATE())
            """,
            (email, generate_password_hash(password), "Administrator"),
        )
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin_id"):
            return redirect(url_for("admin_login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def get_csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_globals():
    return {
        "csrf_token": get_csrf_token,
        "current_year": datetime.now().year,
        "admin_email": session.get("admin_email"),
    }


@app.before_request
def csrf_protect():
    if request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        if request.path in {"/api/orders", "/api/contact"}:
            return
        token = session.get("csrf_token")
        sent = request.headers.get("X-CSRFToken") or request.form.get("csrf_token")
        if request.is_json:
            payload = request.get_json(silent=True) or {}
            sent = sent or payload.get("csrf_token")
        if not token or not sent or not secrets.compare_digest(str(token), str(sent)):
            if request.path.startswith("/api/"):
                return jsonify({"ok": False, "error": "Invalid or missing CSRF token."}), 400
            abort(400, description="Invalid or missing CSRF token.")


@app.template_filter("datetimeformat")
def datetimeformat(value, fmt="%b %d, %Y %I:%M %p"):
    if value is None:
        return "-"
    if hasattr(value, "strftime"):
        return value.strftime(fmt)
    return str(value)


def clean_text(value, max_len=200):
    text = value.strip() if isinstance(value, str) else ""
    return text[:max_len] if len(text) > max_len else text


def validate_order_payload(data):
    errors = {}
    full_name = clean_text(data.get("fullName"), 200)
    company_name = clean_text(data.get("companyName"), 200)
    email = clean_text(data.get("email"), 200).lower()
    phone = clean_text(data.get("phone"), 50)
    service = clean_text(data.get("service"), 100)
    shipping_method = clean_text(data.get("shippingMethod"), 50) or "Not Sure"
    origin = clean_text(data.get("origin"), 200)
    destination = clean_text(data.get("destination"), 200)
    cargo_type = clean_text(data.get("cargoType"), 200)
    weight = clean_text(data.get("weight"), 100)
    message = clean_text(data.get("message"), 4000)

    if not full_name:
        errors["fullName"] = "Full name is required."
    if not email or not EMAIL_RE.fullmatch(email):
        errors["email"] = "A valid email address is required."
    if not phone or not PHONE_RE.fullmatch(phone):
        errors["phone"] = "A valid phone number is required."
    if not service:
        errors["service"] = "Service required is required."

    cleaned = {
        "full_name": full_name,
        "company_name": company_name or None,
        "email": email or None,
        "phone": phone or None,
        "service_required": service or None,
        "shipping_method": shipping_method,
        "origin": origin or None,
        "destination": destination or None,
        "cargo_type": cargo_type or None,
        "weight": weight or None,
        "message": message or None,
    }
    return cleaned, errors


def validate_contact_payload(data):
    full_name = clean_text(data.get("fullName"), 200)
    email = clean_text(data.get("email"), 200).lower()
    subject = clean_text(data.get("subject"), 200)
    message = clean_text(data.get("message"), 4000)
    errors = {}
    if not full_name:
        errors["fullName"] = "Full name is required."
    if not email or not EMAIL_RE.fullmatch(email):
        errors["email"] = "A valid email address is required."
    if not message:
        errors["message"] = "A message is required."
    return {"full_name": full_name, "email": email, "subject": subject or None, "message": message}, errors


def generate_tracking_number(order_id):
    return f"NIS-{datetime.now().strftime('%Y')}-{int(order_id):04d}"


# ----------------------------------------------------------------------
# Public customer site
# ----------------------------------------------------------------------
@app.route("/")
def customer_home():
    return render_template("customer/index.html")


# ----------------------------------------------------------------------
# Customer authentication and dashboard
# ----------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def customer_login():
    if session.get("customer_id"):
        return redirect(url_for("customer_dashboard"))

    if request.method == "POST":
        email = clean_text(request.form.get("email"), 200).lower()
        password = request.form.get("password") or ""
        if not EMAIL_RE.fullmatch(email):
            flash("Please enter a valid email address.", "error")
            return render_template("customer/login.html", next=request.args.get("next", "")), 400

        customer = fetch_one(
            "SELECT id, email, password_hash, is_active FROM dbo.customers WHERE LOWER(email) = LOWER(?)",
            (email,),
        )
        valid = bool(customer and customer.get("is_active", 1) and customer.get("password_hash") and check_password_hash(customer["password_hash"], password))
        if valid:
            for k in ("customer_id", "customer_email", "customer_role"):
                session.pop(k, None)
            session["customer_id"] = customer["id"]
            session["customer_email"] = customer["email"]
            session["customer_role"] = "customer"
            session.permanent = True
            get_csrf_token()
            next_url = request.args.get("next") or request.form.get("next")
            target = urlsplit(next_url) if next_url else None
            if (
                target
                and target.scheme == ""
                and target.netloc == ""
                and target.path.startswith("/customer")
                and not target.path.startswith("//")
                and "\\" not in target.path
            ):
                return redirect(next_url)
            return redirect(url_for("customer_dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("customer/login.html", next=request.args.get("next", ""))


@app.route("/customer/logout", methods=["POST"])
def customer_logout():
    for k in ("customer_id", "customer_email", "customer_role"):
        session.pop(k, None)
    if not session.get("admin_id"):
        session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("customer_home"))


def customer_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("customer_id"):
            return redirect(url_for("customer_login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@app.route("/customer")
@customer_required
def customer_dashboard():
    customer_id = session.get("customer_id")
    customer = fetch_one(
        "SELECT id, full_name, company_name, email, phone, created_at, updated_at FROM dbo.customers WHERE id = ?",
        (customer_id,),
    )
    if not customer:
        session.pop("customer_id", None)
        flash("Your account could not be found. Please log in again.", "error")
        return redirect(url_for("customer_login"))

    orders = fetch_all(
        """
        SELECT id, tracking_number, service_required, origin, destination, status,
               submission_date, approved_at, approved_by, rejected_at, rejected_by, rejection_reason
        FROM dbo.orders
        WHERE LOWER(email) = LOWER(?)
        ORDER BY submission_date DESC, id DESC
        """,
        (customer["email"],),
    )
    stats = {
        "total": len(orders),
        "pending": sum(1 for o in orders if str(o.get("status") or "").lower() == "pending"),
        "approved": sum(1 for o in orders if str(o.get("status") or "").lower() == "approved"),
        "rejected": sum(1 for o in orders if str(o.get("status") or "").lower() == "rejected"),
    }
    return render_template("customer/dashboard.html", customer=customer, orders=orders, stats=stats)


@app.route("/customer/orders/<int:order_id>")
@customer_required
def customer_order_details(order_id):
    customer_id = session.get("customer_id")
    customer_email = session.get("customer_email")
    order = fetch_one(
        """
        SELECT o.*, c.id AS linked_customer_id, c.full_name AS customer_full_name,
               c.company_name AS customer_company_name, c.email AS customer_email,
               c.phone AS customer_phone, c.created_at AS customer_created_at
        FROM dbo.orders o
        LEFT JOIN dbo.customers c ON o.customer_id = c.id
        WHERE o.id = ? AND (LOWER(o.email) = LOWER(?) OR o.customer_id = ?)
        """,
        (order_id, customer_email, customer_id),
    )
    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("customer_dashboard"))
    return render_template("customer/order_details.html", order=order)


@app.route("/customer/register", methods=["GET", "POST"])
def customer_register():
    if session.get("customer_id"):
        return redirect(url_for("customer_dashboard"))

    if request.method == "POST":
        full_name = clean_text(request.form.get("full_name"), 200)
        email = clean_text(request.form.get("email"), 200).lower()
        phone = clean_text(request.form.get("phone"), 50)
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm_password") or ""
        errors = {}
        if not full_name:
            errors["full_name"] = "Full name is required."
        if not email or not EMAIL_RE.fullmatch(email):
            errors["email"] = "A valid email address is required."
        if not phone or not PHONE_RE.fullmatch(phone):
            errors["phone"] = "A valid phone number is required."
        if len(password) < 8:
            errors["password"] = "Password must be at least 8 characters."
        if password != confirm:
            errors["confirm_password"] = "Passwords do not match."

        if errors:
            return render_template("customer/register.html", errors=errors), 400

        existing = fetch_one("SELECT id FROM dbo.customers WHERE LOWER(email) = LOWER(?)", (email,))
        if existing:
            flash("An account with that email already exists.", "error")
            return render_template("customer/register.html"), 400

        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(
                """
                INSERT INTO dbo.customers (full_name, company_name, email, phone, password_hash, is_active, created_at, updated_at)
                VALUES (?, NULL, ?, ?, ?, 1, GETDATE(), GETDATE())
                """,
                (full_name, email, phone, generate_password_hash(password)),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            app.logger.exception("Failed to register customer.")
            flash("Could not create your account. Please try again later.", "error")
            return render_template("customer/register.html"), 500
        finally:
            conn.close()

        flash("Account created. Please log in.", "success")
        return redirect(url_for("customer_login"))

    return render_template("customer/register.html", errors={})


@app.route("/api/orders", methods=["POST"])
def api_create_order():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = request.form.to_dict()
    payload, errors = validate_order_payload(data)
    if errors:
        return jsonify({"ok": False, "errors": errors, "error": "Validation failed."}), 400

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        temporary_tracking_number = f"TEMP-{secrets.token_hex(16).upper()}"
        cur.execute(
            """
            INSERT INTO dbo.orders
                (tracking_number, full_name, company_name, email, phone,
                 service_required, shipping_method, origin, destination,
                 cargo_type, weight, message, status, submission_date, created_at, updated_at)
            OUTPUT INSERTED.id
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', GETDATE(), GETDATE(), GETDATE())
            """,
            (
                temporary_tracking_number,
                payload["full_name"],
                payload["company_name"],
                payload["email"],
                payload["phone"],
                payload["service_required"],
                payload["shipping_method"],
                payload["origin"],
                payload["destination"],
                payload["cargo_type"],
                payload["weight"],
                payload["message"],
            ),
        )
        new_id = cur.fetchone()[0]
        tracking_number = generate_tracking_number(new_id)
        cur.execute("UPDATE dbo.orders SET tracking_number = ? WHERE id = ?", (tracking_number, new_id))
        conn.commit()
        try:
            socketio.emit("order_created", {
                "id": new_id,
                "tracking_number": tracking_number,
                "full_name": payload["full_name"],
                "email": payload["email"],
                "service_required": payload["service_required"],
                "origin": payload["origin"],
                "destination": payload["destination"],
                "status": "pending",
                "submission_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }, to="admins")
        except Exception:
            app.logger.exception("Failed to emit order_created event.")
        return jsonify({"ok": True, "tracking_number": tracking_number, "order_id": new_id}), 201
    except Exception:
        if conn:
            conn.rollback()
        app.logger.exception("Failed to save customer order.")
        return jsonify({"ok": False, "error": "The order could not be saved. Please try again later."}), 500
    finally:
        if conn:
            conn.close()


@app.route("/api/tracking/<string:tracking_number>")
def api_track_order(tracking_number):
    tracking_number = clean_text(tracking_number, 50)
    if not tracking_number:
        return jsonify({"ok": False, "error": "A tracking number is required."}), 400
    order = fetch_one(
        """
        SELECT tracking_number, status, submission_date, updated_at, approved_at, rejected_at
        FROM dbo.orders
        WHERE tracking_number = ?
        """,
        (tracking_number,),
    )
    if not order:
        return jsonify({"ok": False, "error": "No order was found for that tracking number."}), 404

    status = str(order["status"] or "").lower()
    if status not in ORDER_STATUSES:
        status = "pending"
    updated_at = order["updated_at"] or order["submission_date"]
    if status == "approved":
        latest_update = f"Order approved on {(order['approved_at'] or updated_at):%b %d, %Y %I:%M %p}."
    elif status == "rejected":
        latest_update = f"Order rejected on {(order['rejected_at'] or updated_at):%b %d, %Y %I:%M %p}."
    else:
        latest_update = "Your order has been received and is awaiting review."
    return jsonify(
        {
            "ok": True,
            "tracking_number": order["tracking_number"],
            "status": status,
            "submitted_at": order["submission_date"].strftime("%b %d, %Y %I:%M %p"),
            "latest_update": latest_update,
        }
    )


@app.route("/api/contact", methods=["POST"])
def api_create_contact_message():
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        data = request.form.to_dict()
    payload, errors = validate_contact_payload(data)
    if errors:
        return jsonify({"ok": False, "errors": errors, "error": "Validation failed."}), 400

    conn = None
    try:
        conn = get_db_connection()
        conn.cursor().execute(
            """
            INSERT INTO dbo.contact_messages (full_name, email, subject, message, created_at)
            VALUES (?, ?, ?, ?, GETDATE())
            """,
            (payload["full_name"], payload["email"], payload["subject"], payload["message"]),
        )
        conn.commit()
        return jsonify({"ok": True}), 201
    except Exception:
        if conn:
            conn.rollback()
        app.logger.exception("Failed to save customer contact message.")
        return jsonify({"ok": False, "error": "Your message could not be saved. Please try again later."}), 500
    finally:
        if conn:
            conn.close()


# ----------------------------------------------------------------------
# Admin auth
# ----------------------------------------------------------------------
@app.route("/admin/login", methods=["GET", "POST"])
def admin_login():
    if session.get("admin_id"):
        return redirect(url_for("admin_dashboard"))

    if request.method == "POST":
        email = clean_text(request.form.get("email"), 200).lower()
        password = request.form.get("password") or ""
        try:
            user = get_admin_user(email) if EMAIL_RE.fullmatch(email) else None
        except Exception:
            app.logger.exception("Admin login could not access the administrator table.")
            flash("Admin login is temporarily unavailable. Check the SQL Server configuration and database migration.", "error")
            return render_template("admin/login.html", next=request.args.get("next", "")), 503
        valid = bool(user and user.get("is_active", 0) and check_password_hash(user["password_hash"], password))
        if valid:
            for k in ("admin_id", "admin_email"):
                session.pop(k, None)
            session["admin_id"] = user["id"]
            session["admin_email"] = user["email"]
            session.permanent = True
            get_csrf_token()
            next_url = request.args.get("next") or request.form.get("next")
            target = urlsplit(next_url) if next_url else None
            if (
                target
                and target.scheme == ""
                and target.netloc == ""
                and target.path.startswith("/")
                and not target.path.startswith("//")
                and "\\" not in target.path
            ):
                return redirect(next_url)
            return redirect(url_for("admin_dashboard"))
        flash("Invalid email or password.", "error")
    return render_template("admin/login.html", next=request.args.get("next", ""))


@app.route("/admin/logout", methods=["POST"])
@login_required
def admin_logout():
    for k in ("admin_id", "admin_email"):
        session.pop(k, None)
    if not session.get("customer_id"):
        session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("admin_login"))


# ----------------------------------------------------------------------
# Admin dashboard
# ----------------------------------------------------------------------
@app.route("/admin")
@login_required
def admin_dashboard():
    stats = {
        "total": fetch_one("SELECT COUNT(*) AS c FROM dbo.orders")["c"],
        "pending": fetch_one("SELECT COUNT(*) AS c FROM dbo.orders WHERE status = 'pending'")["c"],
        "approved": fetch_one("SELECT COUNT(*) AS c FROM dbo.orders WHERE status = 'approved'")["c"],
        "rejected": fetch_one("SELECT COUNT(*) AS c FROM dbo.orders WHERE status = 'rejected'")["c"],
        "customers": fetch_one("SELECT COUNT(*) AS c FROM dbo.customers")["c"],
    }
    recent_orders = fetch_all(
        """
        SELECT TOP 10 o.id, o.tracking_number, o.full_name, o.email, o.service_required,
               o.status, o.submission_date
        FROM dbo.orders o
        ORDER BY o.submission_date DESC, o.id DESC
        """
    )
    return render_template("admin/dashboard.html", stats=stats, recent_orders=recent_orders)


# ----------------------------------------------------------------------
# Orders management
# ----------------------------------------------------------------------
@app.route("/admin/orders")
@login_required
def admin_orders():
    q = clean_text(request.args.get("q"), 200)
    status = clean_text(request.args.get("status"), 20).lower()
    sort = request.args.get("sort", "submission_date")
    direction = request.args.get("dir", "desc").lower()

    allowed_sorts = {
        "id": "o.id",
        "full_name": "o.full_name",
        "email": "o.email",
        "status": "o.status",
        "submission_date": "o.submission_date",
    }
    order_col = allowed_sorts.get(sort, "o.submission_date")
    order_dir = "ASC" if direction == "asc" else "DESC"

    where = ["1=1"]
    params = []
    if q:
        where.append("(o.tracking_number LIKE ? OR o.full_name LIKE ? OR o.email LIKE ? OR o.phone LIKE ?)")
        like = f"%{q}%"
        params.extend([like, like, like, like])
    if status in ORDER_STATUSES:
        where.append("o.status = ?")
        params.append(status)

    orders = fetch_all(
        f"""
        SELECT o.id, o.tracking_number, o.full_name, o.company_name, o.email, o.phone,
               o.service_required, o.shipping_method, o.origin, o.destination,
               o.cargo_type, o.weight, o.status, o.submission_date,
               o.approved_at, o.approved_by, o.rejected_at, o.rejected_by,
               o.rejection_reason,
               c.id AS customer_id, c.full_name AS customer_full_name
        FROM dbo.orders o
        LEFT JOIN dbo.customers c ON o.customer_id = c.id
        WHERE {' AND '.join(where)}
        ORDER BY {order_col} {order_dir}, o.id DESC
        """,
        tuple(params),
    )
    return render_template("admin/orders.html", orders=orders, q=q, status=status, sort=sort, direction=direction)


@app.route("/admin/orders/<int:order_id>")
@login_required
def admin_order_details(order_id):
    order = fetch_one(
        """
        SELECT o.*, c.id AS linked_customer_id, c.full_name AS customer_full_name,
               c.company_name AS customer_company_name, c.email AS customer_email,
               c.phone AS customer_phone, c.created_at AS customer_created_at
        FROM dbo.orders o
        LEFT JOIN dbo.customers c ON o.customer_id = c.id
        WHERE o.id = ?
        """,
        (order_id,),
    )
    if not order:
        flash("Order not found.", "error")
        return redirect(url_for("admin_orders"))
    return render_template("admin/order_details.html", order=order)


def audit(conn, admin_email, action, order_id, details):
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO dbo.admin_audit_log (admin_email, action, order_id, details, created_at) VALUES (?, ?, ?, ?, GETDATE())",
        (admin_email, action, order_id, details),
    )


@app.route("/admin/orders/<int:order_id>/approve", methods=["POST"])
@login_required
def approve_order(order_id):
    admin_email = session.get("admin_email")
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            SELECT status, email, full_name, company_name, phone
            FROM dbo.orders WITH (UPDLOCK, ROWLOCK)
            WHERE id = ?
            """,
            (order_id,),
        )
        row = cur.fetchone()
        if not row:
            flash("Order not found.", "error")
            conn.rollback()
            return redirect(url_for("admin_orders"))
        status, email, full_name, company_name, phone = row
        if status != "pending":
            flash("Only pending orders can be approved.", "error")
            conn.rollback()
            return redirect(url_for("admin_order_details", order_id=order_id))

        cur.execute(
            "SELECT id FROM dbo.customers WITH (UPDLOCK, HOLDLOCK) WHERE LOWER(email) = LOWER(?)",
            (email,),
        )
        crow = cur.fetchone()
        if crow:
            customer_id = crow[0]
            cur.execute(
                """
                UPDATE dbo.customers
                SET full_name=?, company_name=COALESCE(?, company_name),
                    phone=COALESCE(?, phone), updated_at=GETDATE()
                WHERE id=?
                """,
                (full_name, company_name, phone, customer_id),
            )
        else:
            cur.execute(
                """
                INSERT INTO dbo.customers (full_name, company_name, email, phone, created_at, updated_at)
                OUTPUT INSERTED.id
                VALUES (?, ?, ?, ?, GETDATE(), GETDATE())
                """,
                (full_name, company_name, email, phone),
            )
            customer_id = cur.fetchone()[0]

        cur.execute(
            """
            UPDATE dbo.orders
            SET customer_id=?, status='approved', approved_at=GETDATE(), approved_by=?, updated_at=GETDATE()
            WHERE id=? AND status='pending'
            """,
            (customer_id, admin_email, order_id),
        )
        if cur.rowcount != 1:
            conn.rollback()
            flash("This order was already processed by another administrator.", "error")
            return redirect(url_for("admin_order_details", order_id=order_id))
        audit(conn, admin_email, "approve", order_id, f"Order approved and linked to customer {customer_id}.")
        conn.commit()
        try:
            ord_row = fetch_one("SELECT tracking_number, status, full_name, email FROM dbo.orders WHERE id=?", (order_id,))
            socketio.emit("order_status", {"id": order_id, "status": "approved", "tracking_number": (ord_row or {}).get("tracking_number")}, to="admins")
            socketio.emit("order_status", {"id": order_id, "status": "approved", "tracking_number": (ord_row or {}).get("tracking_number")}, to=f"customer_{customer_id}")
        except Exception:
            app.logger.exception("Failed to emit approve event.")
        flash(f"Order #{order_id} approved.", "success")
    except Exception:
        if conn:
            conn.rollback()
        app.logger.exception("Failed to approve order %s.", order_id)
        flash("A database error prevented this order from being approved.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for("admin_order_details", order_id=order_id))


@app.route("/admin/orders/<int:order_id>/reject", methods=["POST"])
@login_required
def reject_order(order_id):
    admin_email = session.get("admin_email")
    reason = clean_text(request.form.get("rejection_reason"), 2000)
    if not reason:
        flash("A rejection reason is required.", "error")
        return redirect(url_for("admin_order_details", order_id=order_id))

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "SELECT status FROM dbo.orders WITH (UPDLOCK, ROWLOCK) WHERE id = ?",
            (order_id,),
        )
        row = cur.fetchone()
        if not row:
            flash("Order not found.", "error")
            conn.rollback()
            return redirect(url_for("admin_orders"))
        if row[0] != "pending":
            flash("Only pending orders can be rejected.", "error")
            conn.rollback()
            return redirect(url_for("admin_order_details", order_id=order_id))
        cur.execute(
            """
            UPDATE dbo.orders
            SET status='rejected', rejection_reason=?, rejected_at=GETDATE(), rejected_by=?, updated_at=GETDATE()
            WHERE id=? AND status='pending'
            """,
            (reason, admin_email, order_id),
        )
        if cur.rowcount != 1:
            conn.rollback()
            flash("This order was already processed by another administrator.", "error")
            return redirect(url_for("admin_order_details", order_id=order_id))
        audit(conn, admin_email, "reject", order_id, reason)
        conn.commit()
        try:
            ord_row = fetch_one("SELECT tracking_number, status, customer_id FROM dbo.orders WHERE id=?", (order_id,))
            socketio.emit("order_status", {"id": order_id, "status": "rejected", "tracking_number": (ord_row or {}).get("tracking_number")}, to="admins")
            cid = (ord_row or {}).get("customer_id")
            if cid:
                socketio.emit("order_status", {"id": order_id, "status": "rejected", "tracking_number": (ord_row or {}).get("tracking_number")}, to=f"customer_{cid}")
        except Exception:
            app.logger.exception("Failed to emit reject event.")
        flash(f"Order #{order_id} rejected.", "success")
    except Exception:
        if conn:
            conn.rollback()
        app.logger.exception("Failed to reject order %s.", order_id)
        flash("A database error prevented this order from being rejected.", "error")
    finally:
        if conn:
            conn.close()
    return redirect(url_for("admin_order_details", order_id=order_id))


# ----------------------------------------------------------------------
# Customers management
# ----------------------------------------------------------------------
@app.route("/admin/customers")
@login_required
def admin_customers():
    q = clean_text(request.args.get("q"), 200)
    params = []
    where = "1=1"
    if q:
        where = "(c.full_name LIKE ? OR c.company_name LIKE ? OR c.email LIKE ? OR c.phone LIKE ?)"
        like = f"%{q}%"
        params = [like, like, like, like]
    customers = fetch_all(
        f"""
        SELECT c.id, c.full_name, c.company_name, c.email, c.phone, c.created_at,
               COUNT(o.id) AS order_count,
               SUM(CASE WHEN o.status = 'approved' THEN 1 ELSE 0 END) AS approved_count,
               SUM(CASE WHEN o.status = 'rejected' THEN 1 ELSE 0 END) AS rejected_count,
               SUM(CASE WHEN o.status = 'pending' THEN 1 ELSE 0 END) AS pending_count
        FROM dbo.customers c
        LEFT JOIN dbo.orders o ON o.customer_id = c.id
        WHERE {where}
        GROUP BY c.id, c.full_name, c.company_name, c.email, c.phone, c.created_at
        ORDER BY c.created_at DESC, c.id DESC
        """,
        tuple(params),
    )
    return render_template("admin/customers.html", customers=customers, q=q)


@app.route("/admin/customers/<int:customer_id>")
@login_required
def admin_customer_details(customer_id):
    customer = fetch_one(
        "SELECT id, full_name, company_name, email, phone, created_at, updated_at FROM dbo.customers WHERE id = ?",
        (customer_id,),
    )
    if not customer:
        flash("Customer not found.", "error")
        return redirect(url_for("admin_customers"))
    orders = fetch_all(
        """
        SELECT id, tracking_number, service_required, origin, destination, status,
               submission_date, approved_at, approved_by, rejected_at, rejected_by, rejection_reason
        FROM dbo.orders
        WHERE customer_id = ? OR LOWER(email) = LOWER(?)
        ORDER BY submission_date DESC, id DESC
        """,
        (customer_id, customer["email"]),
    )
    return render_template("admin/customer_details.html", customer=customer, orders=orders)


@app.route("/admin/messages")
@login_required
def admin_messages():
    q = clean_text(request.args.get("q"), 200)
    if q:
        like = f"%{q}%"
        messages = fetch_all(
            """
            SELECT TOP 250 id, full_name, email, subject, message, created_at
            FROM dbo.contact_messages
            WHERE full_name LIKE ? OR email LIKE ? OR subject LIKE ? OR message LIKE ?
            ORDER BY created_at DESC, id DESC
            """,
            (like, like, like, like),
        )
    else:
        messages = fetch_all(
            """
            SELECT TOP 250 id, full_name, email, subject, message, created_at
            FROM dbo.contact_messages
            ORDER BY created_at DESC, id DESC
            """
        )
    return render_template("admin/messages.html", messages=messages, q=q)


@app.errorhandler(400)
def bad_request(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": getattr(e, "description", "Bad request")}), 400
    return render_template("shared/error.html", code=400, message=getattr(e, "description", "Bad request")), 400


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "Not found"}), 404
    return render_template("shared/error.html", code=404, message="Page not found."), 404


@app.errorhandler(500)
def server_error(e):
    if request.path.startswith("/api/"):
        return jsonify({"ok": False, "error": "Internal server error"}), 500
    return render_template("shared/error.html", code=500, message="Internal server error."), 500


# ----------------------------------------------------------------------
# Chat / messaging (persisted in SQL Server, real-time via Socket.IO)
# ----------------------------------------------------------------------

def ensure_conversation(customer_id: int):
    conv = fetch_one("SELECT id, customer_id, created_at, updated_at, last_message_at FROM dbo.conversations WHERE customer_id=?", (customer_id,))
    if conv:
        return conv
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("INSERT INTO dbo.conversations (customer_id, created_at, updated_at) OUTPUT INSERTED.id VALUES (?, GETDATE(), GETDATE())", (customer_id,))
        cid = cur.fetchone()[0]
        conn.commit()
    except Exception:
        conn.rollback()
        # race: maybe created concurrently
        cur2 = None
        try:
            conn.close()
        except Exception:
            pass
        conv = fetch_one("SELECT id, customer_id, created_at, updated_at, last_message_at FROM dbo.conversations WHERE customer_id=?", (customer_id,))
        if conv:
            return conv
        raise
    else:
        conn.close()
        return fetch_one("SELECT id, customer_id, created_at, updated_at, last_message_at FROM dbo.conversations WHERE id=?", (cid,))


def get_or_create_conversation_for_customer(customer_id: int):
    return ensure_conversation(customer_id)


def list_conversations_for_admin():
    return fetch_all(
        """
        SELECT c.id, c.customer_id, c.updated_at, c.last_message_at,
               cu.full_name, cu.email, cu.company_name,
               (SELECT COUNT(1) FROM dbo.chat_messages m WHERE m.conversation_id=c.id AND m.sender_role='customer' AND m.is_read=0) AS unread_for_admin,
               (SELECT TOP 1 body FROM dbo.chat_messages m WHERE m.conversation_id=c.id ORDER BY m.created_at DESC, m.id DESC) AS last_body
        FROM dbo.conversations c
        JOIN dbo.customers cu ON cu.id = c.customer_id
        ORDER BY ISNULL(c.last_message_at, c.updated_at) DESC, c.id DESC
        """
    )


def list_messages(conversation_id: int, limit: int = 200):
    return fetch_all(
        """
        SELECT TOP (?) id, conversation_id, sender_role, sender_id, sender_name, body, is_read, read_at, created_at
        FROM dbo.chat_messages
        WHERE conversation_id=?
        ORDER BY created_at ASC, id ASC
        """,
        (limit, conversation_id),
    )


def save_chat_message(conversation_id: int, sender_role: str, sender_id, sender_name: str, body: str):
    body = clean_text(body, 4000)
    if not body:
        raise ValueError("Message cannot be empty.")
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO dbo.chat_messages (conversation_id, sender_role, sender_id, sender_name, body, is_read, created_at)
            OUTPUT INSERTED.id, INSERTED.conversation_id, INSERTED.sender_role, INSERTED.sender_id, INSERTED.sender_name, INSERTED.body, INSERTED.is_read, INSERTED.created_at
            VALUES (?, ?, ?, ?, ?, 0, GETDATE())
            """,
            (conversation_id, sender_role, sender_id, sender_name, body),
        )
        row = cur.fetchone()
        cur.execute("UPDATE dbo.conversations SET updated_at=GETDATE(), last_message_at=GETDATE() WHERE id=?", (conversation_id,))
        conn.commit()
        cols = [d[0] for d in cur.description] if cur.description else ["id","conversation_id","sender_role","sender_id","sender_name","body","is_read","created_at"]
        # OUTPUT gives description for that statement in some drivers; safer to refetch
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()
    msg = fetch_one(
        "SELECT id, conversation_id, sender_role, sender_id, sender_name, body, is_read, read_at, created_at FROM dbo.chat_messages WHERE id=(SELECT MAX(id) FROM dbo.chat_messages WHERE conversation_id=? AND sender_role=? AND body=?)",
        (conversation_id, sender_role, body),
    )
    if not msg:
        msg = fetch_one("SELECT TOP 1 id, conversation_id, sender_role, sender_id, sender_name, body, is_read, read_at, created_at FROM dbo.chat_messages WHERE conversation_id=? ORDER BY id DESC", (conversation_id,))
    return msg


def mark_messages_read(conversation_id: int, reader_role: str):
    # reader_role 'admin' marks customer messages read; 'customer' marks admin messages read
    other = 'customer' if reader_role == 'admin' else 'admin'
    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "UPDATE dbo.chat_messages SET is_read=1, read_at=GETDATE() WHERE conversation_id=? AND sender_role=? AND is_read=0",
            (conversation_id, other),
        )
        conn.commit()
        return cur.rowcount
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def serialize_message(m):
    if not m:
        return None
    created = m.get('created_at')
    if hasattr(created, 'isoformat'):
        created = created.strftime('%Y-%m-%d %H:%M:%S')
    read_at = m.get('read_at')
    if hasattr(read_at, 'isoformat'):
        read_at = read_at.strftime('%Y-%m-%d %H:%M:%S')
    return {
        'id': m.get('id'),
        'conversation_id': m.get('conversation_id'),
        'sender_role': m.get('sender_role'),
        'sender_id': m.get('sender_id'),
        'sender_name': m.get('sender_name'),
        'body': m.get('body'),
        'is_read': bool(m.get('is_read')),
        'read_at': read_at,
        'created_at': created,
    }


@app.route('/customer/chat')
@customer_required
def customer_chat():
    customer_id = session['customer_id']
    conv = get_or_create_conversation_for_customer(customer_id)
    messages = list_messages(conv['id'])
    mark_messages_read(conv['id'], 'customer')
    return render_template('customer/chat.html', conversation=conv, messages=messages)


@app.route('/admin/chat')
@login_required
def admin_chat():
    conversations = list_conversations_for_admin() if table_exists('conversations') else []
    selected_id = request.args.get('conversation_id', type=int)
    selected = None
    messages = []
    if conversations:
        if selected_id:
            selected = next((c for c in conversations if c['id'] == selected_id), None)
        if not selected:
            selected = conversations[0]
        messages = list_messages(selected['id'])
        mark_messages_read(selected['id'], 'admin')
        conversations = list_conversations_for_admin()
    return render_template('admin/chat.html', conversations=conversations, selected=selected, messages=messages)


@app.route('/api/chat/customer/messages', methods=['GET', 'POST'])
@customer_required
def api_customer_chat_messages():
    customer_id = session['customer_id']
    conv = get_or_create_conversation_for_customer(customer_id)
    if request.method == 'GET':
        mark_messages_read(conv['id'], 'customer')
        msgs = list_messages(conv['id'])
        return jsonify({'ok': True, 'conversation_id': conv['id'], 'messages': [serialize_message(m) for m in msgs]})
    data = request.get_json(silent=True) or {}
    body = (data.get('body') or '').strip()
    if not body:
        return jsonify({'ok': False, 'error': 'Message cannot be empty.'}), 400
    cust = fetch_one('SELECT full_name FROM dbo.customers WHERE id=?', (customer_id,))
    msg = save_chat_message(conv['id'], 'customer', customer_id, (cust or {}).get('full_name') or session.get('customer_email'), body)
    payload = {'conversation_id': conv['id'], 'message': serialize_message(msg)}
    socketio.emit('chat_message', payload, to='admins')
    socketio.emit('chat_message', payload, to=f"customer_{customer_id}")
    return jsonify({'ok': True, **payload})


@app.route('/api/chat/admin/conversations/<int:conversation_id>/messages', methods=['GET', 'POST'])
@login_required
def api_admin_chat_messages(conversation_id):
    conv = fetch_one('SELECT c.id, c.customer_id, cu.full_name, cu.email FROM dbo.conversations c JOIN dbo.customers cu ON cu.id=c.customer_id WHERE c.id=?', (conversation_id,))
    if not conv:
        return jsonify({'ok': False, 'error': 'Conversation not found.'}), 404
    if request.method == 'GET':
        mark_messages_read(conversation_id, 'admin')
        msgs = list_messages(conversation_id)
        return jsonify({'ok': True, 'conversation': {'id': conv['id'], 'customer_id': conv['customer_id'], 'full_name': conv['full_name'], 'email': conv['email']}, 'messages': [serialize_message(m) for m in msgs]})
    data = request.get_json(silent=True) or {}
    body = (data.get('body') or '').strip()
    if not body:
        return jsonify({'ok': False, 'error': 'Message cannot be empty.'}), 400
    admin_email = session.get('admin_email') or 'Admin'
    msg = save_chat_message(conversation_id, 'admin', session.get('admin_id'), admin_email, body)
    payload = {'conversation_id': conversation_id, 'message': serialize_message(msg)}
    socketio.emit('chat_message', payload, to='admins')
    socketio.emit('chat_message', payload, to=f"customer_{conv['customer_id']}")
    return jsonify({'ok': True, **payload})


@app.route('/api/chat/admin/unread-count')
@login_required
def api_admin_chat_unread():
    row = fetch_one("SELECT COUNT(1) AS cnt FROM dbo.chat_messages WHERE sender_role='customer' AND is_read=0") if table_exists('chat_messages') else {'cnt': 0}
    return jsonify({'ok': True, 'count': int((row or {}).get('cnt') or 0)})


@app.route('/api/chat/customer/unread-count')
@customer_required
def api_customer_chat_unread():
    conv = fetch_one('SELECT id FROM dbo.conversations WHERE customer_id=?', (session['customer_id'],))
    if not conv or not table_exists('chat_messages'):
        return jsonify({'ok': True, 'count': 0})
    row = fetch_one("SELECT COUNT(1) AS cnt FROM dbo.chat_messages WHERE conversation_id=? AND sender_role='admin' AND is_read=0", (conv['id'],))
    return jsonify({'ok': True, 'count': int((row or {}).get('cnt') or 0)})


# Socket.IO
@socketio.on('connect')
def on_connect():
    if session.get('admin_id'):
        join_room('admins')
        emit('connected', {'role': 'admin'})
    elif session.get('customer_id'):
        join_room(f"customer_{session['customer_id']}")
        emit('connected', {'role': 'customer'})


@socketio.on('join_chat')
def on_join_chat(data=None):
    # customers join their conversation room; admins join specific conversation rooms
    data = data or {}
    conv_id = data.get('conversation_id')
    if session.get('admin_id') and conv_id:
        conv = fetch_one('SELECT id FROM dbo.conversations WHERE id=?', (conv_id,))
        if conv:
            join_room(f'chat_{conv_id}')
            emit('joined_chat', {'conversation_id': conv_id})
    elif session.get('customer_id'):
        conv = fetch_one('SELECT id FROM dbo.conversations WHERE customer_id=?', (session['customer_id'],))
        if conv:
            join_room(f'chat_{conv["id"]}')
            emit('joined_chat', {'conversation_id': conv['id']})


@socketio.on('chat_send')
def on_chat_send(data):
    data = data or {}
    body = (data.get('body') or '').strip()
    if not body:
        emit('chat_error', {'error': 'Message cannot be empty.'})
        return
    if session.get('admin_id'):
        conv_id = data.get('conversation_id')
        conv = fetch_one('SELECT c.id, c.customer_id FROM dbo.conversations c WHERE c.id=?', (conv_id,)) if conv_id else None
        if not conv:
            emit('chat_error', {'error': 'Conversation not found.'})
            return
        msg = save_chat_message(conv_id, 'admin', session.get('admin_id'), session.get('admin_email') or 'Admin', body)
        payload = {'conversation_id': conv_id, 'message': serialize_message(msg)}
        socketio.emit('chat_message', payload, to=f'chat_{conv_id}')
        socketio.emit('chat_message', payload, to=f"customer_{conv['customer_id']}")
        socketio.emit('chat_message', payload, to='admins')
        return
    if session.get('customer_id'):
        customer_id = session['customer_id']
        conv = get_or_create_conversation_for_customer(customer_id)
        cust = fetch_one('SELECT full_name FROM dbo.customers WHERE id=?', (customer_id,))
        msg = save_chat_message(conv['id'], 'customer', customer_id, (cust or {}).get('full_name') or session.get('customer_email'), body)
        payload = {'conversation_id': conv['id'], 'message': serialize_message(msg)}
        socketio.emit('chat_message', payload, to=f'chat_{conv["id"]}')
        socketio.emit('chat_message', payload, to='admins')
        socketio.emit('chat_message', payload, to=f"customer_{customer_id}")
        return
    emit('chat_error', {'error': 'Not authenticated.'})



def main():
    if len(sys.argv) > 1 and sys.argv[1] == "create-admin":
        email = sys.argv[2] if len(sys.argv) > 2 else input("Administrator email: ")
        try:
            create_admin_account(email)
        except (RuntimeError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            raise SystemExit(1) from exc
        except Exception:
            app.logger.exception("Could not create administrator account.")
            raise SystemExit(1)
        print("Administrator account created.")
        return

    host = os.getenv("FLASK_HOST", "127.0.0.1")
    port = int(os.getenv("PORT", "5000"))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    base_url = f"http://{host}:{port}"

    if os.getenv("AUTO_OPEN_BROWSER", "true").lower() == "true" and not debug:
        import threading
        import webbrowser

        def _open_browser():
            webbrowser.open(f"{base_url}/")

        threading.Timer(1.0, _open_browser).start()

    print(f"Customer site:   {base_url}/")
    print(f"Customer login:  {base_url}/login")
    print(f"Customer portal: {base_url}/customer")
    print(f"Admin login:     {base_url}/admin/login")
    print(f"Admin dashboard: {base_url}/admin")

    socketio.run(
        app,
        host=host,
        port=port,
        debug=debug,
        allow_unsafe_werkzeug=True,
    )


if __name__ == "__main__":
    main()
