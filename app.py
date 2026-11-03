import io
import base64
import hashlib
import html
import hmac
import os
import secrets
import smtplib
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from functools import wraps
from urllib.parse import quote

from flask import Flask, abort, flash, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE_PATH = os.environ.get('CAMPUSFIX_DATABASE_PATH', os.path.join(BASE_DIR, 'campusfix.db'))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'static', 'uploads')
BACKUP_FOLDER = os.environ.get('CAMPUSFIX_BACKUP_FOLDER', os.path.join(BASE_DIR, 'backups'))

app = Flask(__name__)
configured_secret = os.environ.get('CAMPUSFIX_SECRET_KEY')
if os.environ.get('CAMPUSFIX_ENV', '').lower() == 'production' and not configured_secret:
    raise RuntimeError('Set CAMPUSFIX_SECRET_KEY before starting CampusFix in production.')
app.secret_key = configured_secret or secrets.token_hex(32)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('CAMPUSFIX_COOKIE_SECURE', '').lower() == 'true'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(BACKUP_FOLDER, exist_ok=True)

ROLES = ['student', 'lecturer', 'technician', 'supervisor', 'admin']
REPORTER_ROLES = ['student', 'lecturer']


def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA foreign_keys = ON')
        db.execute('PRAGMA busy_timeout = 5000')
        g._database = db
    return db


@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        with open(os.path.join(BASE_DIR, 'schema.sql'), 'r', encoding='utf-8') as handle:
            db.executescript(handle.read())
        ensure_schema_columns(db)
        seed_data(db)
        db.commit()
        create_daily_backup(db)


def ensure_schema_columns(db):
    columns = {row['name'] for row in db.execute('PRAGMA table_info(users)').fetchall()}
    if 'two_factor_secret' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN two_factor_secret TEXT')
    if 'auth_version' not in columns:
        db.execute('ALTER TABLE users ADD COLUMN auth_version INTEGER NOT NULL DEFAULT 0')


def create_daily_backup(db):
    if DATABASE_PATH == ':memory:' or not os.path.isfile(DATABASE_PATH):
        return None
    backup_path = os.path.join(BACKUP_FOLDER, f"campusfix-{datetime.now().strftime('%Y-%m-%d')}.sqlite")
    if not os.path.exists(backup_path):
        backup_db = sqlite3.connect(backup_path)
        try:
            db.backup(backup_db)
            integrity = backup_db.execute('PRAGMA integrity_check').fetchone()[0]
            if integrity != 'ok':
                raise sqlite3.DatabaseError(f'Database backup integrity check failed: {integrity}')
        finally:
            backup_db.close()
    return backup_path


def create_manual_backup(db):
    db.commit()
    backup_path = os.path.join(
        BACKUP_FOLDER,
        f"campusfix-manual-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}.sqlite",
    )
    backup_db = sqlite3.connect(backup_path)
    try:
        db.backup(backup_db)
        integrity = backup_db.execute('PRAGMA integrity_check').fetchone()[0]
        if integrity != 'ok':
            raise sqlite3.DatabaseError(f'Database backup integrity check failed: {integrity}')
    finally:
        backup_db.close()
    return backup_path


def daily_backup_worker(stop_event):
    while not stop_event.wait(60):
        try:
            with app.app_context():
                create_daily_backup(get_db())
        except (OSError, sqlite3.Error):
            app.logger.exception('Scheduled CampusFix database backup failed.')


def csrf_token():
    token = session.get('_csrf_token')
    if not token:
        token = secrets.token_urlsafe(32)
        session['_csrf_token'] = token
    return token


@app.before_request
def protect_state_changes():
    if request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
        submitted = request.form.get('_csrf_token') or request.headers.get('X-CSRF-Token')
        expected = session.get('_csrf_token')
        if not submitted or not expected or not hmac.compare_digest(submitted, expected):
            abort(400, description='Your form session expired. Reload the page and try again.')


@app.context_processor
def inject_template_security_helpers():
    return {'csrf_token': csrf_token}


@app.after_request
def set_security_headers(response):
    response.headers.setdefault('X-Content-Type-Options', 'nosniff')
    response.headers.setdefault('X-Frame-Options', 'SAMEORIGIN')
    response.headers.setdefault('Referrer-Policy', 'strict-origin-when-cross-origin')
    response.headers.setdefault('Permissions-Policy', 'camera=(), microphone=(), geolocation=()')
    return response


def seed_data(db):
    if db.execute('SELECT COUNT(*) FROM users').fetchone()[0] == 0:
        default_users = [
            {
                'first_name': 'System',
                'last_name': 'Admin',
                'email': 'admin@campusfix.com',
                'password': 'admin123',
                'role': 'admin',
                'phone': '0700000000',
            },
            {
                'first_name': 'Amina',
                'last_name': 'Kiptoo',
                'email': 'supervisor@campusfix.com',
                'password': 'supervisor123',
                'role': 'supervisor',
                'phone': '0701234567',
            },
            {
                'first_name': 'Kevin',
                'last_name': 'Omondi',
                'email': 'tech@campusfix.com',
                'password': 'tech123',
                'role': 'technician',
                'phone': '0707654321',
            },
            {
                'first_name': 'Jane',
                'last_name': 'Mwangi',
                'email': 'student@campusfix.com',
                'password': 'student123',
                'role': 'student',
                'phone': '0711122233',
            },
        ]
        for user in default_users:
            db.execute(
                'INSERT INTO users (first_name, last_name, email, password_hash, role, phone) VALUES (?, ?, ?, ?, ?, ?)',
                (
                    user['first_name'],
                    user['last_name'],
                    user['email'],
                    generate_password_hash(user['password']),
                    user['role'],
                    user['phone'],
                ),
            )

    categories = [
        'Electrical', 'Plumbing', 'Furniture', 'Cleaning', 'ICT', 'Security',
        'Classroom Equipment', 'Grounds and Landscaping', 'General Facilities',
    ]
    for name in categories:
        db.execute('INSERT OR IGNORE INTO categories (name) VALUES (?)', (name,))

    building_names = [
        'Administration Block', 'Main Library', 'Student Center', 'Science Block',
        'Hostels', 'Lecture Theatre', 'Auditorium', 'Sports Complex',
        'Campus Cafeteria', 'Teaching Block',
    ]
    for name in building_names:
        db.execute('INSERT OR IGNORE INTO buildings (name) VALUES (?)', (name,))

    room_data = {
        'Administration Block': ['A101', 'A102', 'A201'],
        'Main Library': ['L201', 'L305', 'Study Room 1'],
        'Student Center': ['S12', 'Ground Floor'],
        'Science Block': ['LAB1', 'LAB2', 'S201'],
        'Hostels': ['H4-05', 'H4-06', 'Common Room'],
        'Lecture Theatre': ['LT1', 'LT2', 'LT3'],
        'Auditorium': ['AUD1', 'Control Room'],
        'Sports Complex': ['Reception', 'Changing Room'],
        'Campus Cafeteria': ['Kitchen', 'Dining Hall'],
        'Teaching Block': ['TB101', 'TB102', 'TB201'],
    }
    for building_name, room_numbers in room_data.items():
        building = db.execute('SELECT id FROM buildings WHERE name = ?', (building_name,)).fetchone()
        for room_number in room_numbers:
            db.execute(
                'INSERT OR IGNORE INTO rooms (building_id, room_number) VALUES (?, ?)',
                (building['id'], room_number),
            )

    if db.execute('SELECT COUNT(*) FROM issues').fetchone()[0] == 0:
        now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        student_id = db.execute('SELECT id FROM users WHERE email = ?', ('student@campusfix.com',)).fetchone()['id']
        tech_id = db.execute('SELECT id FROM users WHERE email = ?', ('tech@campusfix.com',)).fetchone()['id']
        supervisor_id = db.execute('SELECT id FROM users WHERE email = ?', ('supervisor@campusfix.com',)).fetchone()['id']
        category_id = db.execute('SELECT id FROM categories WHERE name = ?', ('Electrical',)).fetchone()['id']
        building_id = db.execute('SELECT id FROM buildings WHERE name = ?', ('Main Library',)).fetchone()['id']
        room_id = db.execute('SELECT id FROM rooms WHERE building_id = ? AND room_number = ?', (building_id, 'L201')).fetchone()['id']
        db.execute(
            'INSERT INTO issues (ticket_number, reporter_id, category_id, building_id, room_id, title, description, priority, status, created_at, due_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)',
            (
                'CF-20261101-0001',
                student_id,
                category_id,
                building_id,
                room_id,
                'Library projector not working',
                'The projector in the library conference room flickers and won’t display content during classes.',
                'High',
                'Assigned',
                now,
                '2026-11-04',
            ),
        )
        issue_id = db.execute('SELECT id FROM issues WHERE ticket_number = ?', ('CF-20261101-0001',)).fetchone()['id']
        db.execute(
            'INSERT INTO assignments (issue_id, technician_id, supervisor_id, status) VALUES (?, ?, ?, ?)',
            (issue_id, tech_id, supervisor_id, 'Assigned'),
        )
        db.execute(
            'INSERT INTO notifications (user_id, issue_id, message) VALUES (?, ?, ?)',
            (tech_id, issue_id, 'New maintenance task assigned: Library projector not working.'),
        )
        db.execute(
            'INSERT INTO work_logs (assignment_id, technician_id, note) VALUES (?, ?, ?)',
            (db.execute('SELECT id FROM assignments WHERE issue_id = ?', (issue_id,)).fetchone()['id'], tech_id, 'Initial inspection scheduled for today.'),
        )

    student = db.execute('SELECT id FROM users WHERE email = ?', ('student@campusfix.com',)).fetchone()
    if student:
        demo_issues = [
            ('CF-DEMO-0002', 'Plumbing', 'Student Center', 'Ground Floor', 'Leaking tap near the student centre', 'A tap is leaking and leaving water on the floor. Please inspect the area.', 'High'),
            ('CF-DEMO-0003', 'Furniture', 'Lecture Theatre', 'LT1', 'Broken desk in lecture theatre', 'One of the desks is unstable and needs repair before the next class.', 'Medium'),
        ]
        for ticket, category_name, building_name, room_number, title, description, priority in demo_issues:
            if db.execute('SELECT id FROM issues WHERE ticket_number = ?', (ticket,)).fetchone():
                continue
            category = db.execute('SELECT id FROM categories WHERE name = ?', (category_name,)).fetchone()
            building = db.execute('SELECT id FROM buildings WHERE name = ?', (building_name,)).fetchone()
            room = db.execute(
                'SELECT id FROM rooms WHERE building_id = ? AND room_number = ?',
                (building['id'], room_number),
            ).fetchone()
            db.execute(
                '''
                INSERT INTO issues
                    (ticket_number, reporter_id, category_id, building_id, room_id, title, description, priority, status)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending')
                ''',
                (ticket, student['id'], category['id'], building['id'], room['id'], title, description, priority),
            )

        demo_items = [
            ('LF-DEMO-0001', 'Lost', 'Blue notebook', 'Blue notebook with lecture notes inside. Demo notice.', 'Books and stationery', 'Main Library, study area', '2026-10-30'),
            ('LF-DEMO-0002', 'Found', 'Water bottle', 'Reusable silver bottle found after a lecture. Demo notice.', 'Personal items', 'Lecture Theatre, LT1', '2026-10-31'),
        ]
        for reference, item_type, item_name, description, category, location, date_occurred in demo_items:
            db.execute(
                '''
                INSERT OR IGNORE INTO lost_found_items
                    (reference_number, reporter_id, item_type, item_name, description, category, location, date_occurred)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''',
                (reference, student['id'], item_type, item_name, description, category, location, date_occurred),
            )

        db.execute(
            '''
            INSERT OR IGNORE INTO vehicle_registrations
                (owner_id, registration_number, make, model, colour, vehicle_type)
            VALUES (?, 'DEMO-001', 'Demo', 'Campus Car', 'Blue', 'Car')
            ''',
            (student['id'],),
        )


def is_reporter(role):
    return role in REPORTER_ROLES


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get('user_id'):
            flash('Please log in to continue.', 'warning')
            return redirect(url_for('login'))
        user = user_from_session()
        if (
            not user
            or not user['is_active']
            or session.get('auth_version') != user['auth_version']
        ):
            session.clear()
            flash('Your account is inactive or your session has expired. Sign in again or contact an administrator.', 'warning')
            return redirect(url_for('login'))
        session['role'] = user['role']
        return view_func(*args, **kwargs)
    return wrapped


def role_required(*allowed_roles):
    def decorator(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not session.get('user_id'):
                flash('Please log in to continue.', 'warning')
                return redirect(url_for('login'))
            user = user_from_session()
            if (
                not user
                or not user['is_active']
                or session.get('auth_version') != user['auth_version']
            ):
                session.clear()
                flash('Your account is inactive or your session has expired.', 'warning')
                return redirect(url_for('login'))
            role = user['role']
            session['role'] = role
            if role not in allowed_roles:
                flash('You do not have access to that page.', 'danger')
                return redirect(url_for('dashboard'))
            return view_func(*args, **kwargs)
        return wrapped
    return decorator


def user_from_session():
    user_id = session.get('user_id')
    if not user_id:
        return None
    db = get_db()
    return db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()


def user_full_name(user):
    return f"{user['first_name']} {user['last_name']}" if user else 'Unknown user'


def add_audit(user_id, action, details):
    db = get_db()
    db.execute(
        'INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)',
        (user_id, action, details),
    )
    db.commit()


def create_notification(user_id, issue_id, message):
    db = get_db()
    db.execute(
        'INSERT INTO notifications (user_id, issue_id, message) VALUES (?, ?, ?)',
        (user_id, issue_id, message),
    )
    db.commit()
    if os.environ.get('CAMPUSFIX_SMTP_HOST'):
        recipient = db.execute('SELECT email FROM users WHERE id = ?', (user_id,)).fetchone()
        if recipient:
            try:
                send_email(recipient['email'], 'CampusFix issue update', message)
            except (OSError, RuntimeError, smtplib.SMTPException):
                app.logger.exception('CampusFix issue notification email delivery failed.')

def create_service_notification(user_id, message, target_url=None):
    db = get_db()
    db.execute(
        'INSERT INTO service_notifications (user_id, message, target_url) VALUES (?, ?, ?)',
        (user_id, message, target_url),
    )
    if os.environ.get('CAMPUSFIX_SMTP_HOST'):
        recipient = db.execute('SELECT email FROM users WHERE id = ?', (user_id,)).fetchone()
        if recipient:
            try:
                send_email(recipient['email'], 'CampusFix service update', message)
            except (OSError, RuntimeError, smtplib.SMTPException):
                app.logger.exception('CampusFix service notification email delivery failed.')


def totp_code(secret, counter=None):
    if counter is None:
        counter = int(time.time() // 30)
    key = base64.b32decode(secret, casefold=True)
    digest = hmac.new(key, counter.to_bytes(8, 'big'), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = int.from_bytes(digest[offset:offset + 4], 'big') & 0x7FFFFFFF
    return f'{value % 1_000_000:06d}'


def verify_totp(secret, submitted_code):
    code = submitted_code.strip()
    if not code.isdigit() or len(code) != 6:
        return False
    current_counter = int(time.time() // 30)
    return any(
        hmac.compare_digest(totp_code(secret, current_counter + offset), code)
        for offset in (-1, 0, 1)
    )


def send_email(recipient, subject, body):
    host = os.environ.get('CAMPUSFIX_SMTP_HOST')
    if not host:
        raise RuntimeError('Email delivery is not configured. Set CAMPUSFIX_SMTP_HOST and related SMTP variables.')
    message = EmailMessage()
    message['Subject'] = subject
    message['From'] = os.environ.get('CAMPUSFIX_SMTP_FROM', os.environ.get('CAMPUSFIX_SMTP_USER', 'campusfix@localhost'))
    message['To'] = recipient
    message.set_content(body)
    port = int(os.environ.get('CAMPUSFIX_SMTP_PORT', '587'))
    with smtplib.SMTP(host, port, timeout=15) as server:
        server.starttls()
        username = os.environ.get('CAMPUSFIX_SMTP_USER')
        password = os.environ.get('CAMPUSFIX_SMTP_PASSWORD')
        if username and password:
            server.login(username, password)
        server.send_message(message)


def get_status_badge(status):
    mapping = {
        'Pending': 'secondary',
        'Assigned': 'primary',
        'In Progress': 'warning',
        'Resolved': 'success',
        'Cancelled': 'dark',
        'Closed': 'info',
    }
    return mapping.get(status, 'secondary')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        first_name = request.form.get('first_name', '').strip()
        last_name = request.form.get('last_name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        phone = request.form.get('phone', '').strip()
        role = request.form.get('role', 'student')

        if not first_name or not last_name or not email or len(password) < 10:
            flash('Enter your name, a valid email address, and a password of at least 10 characters.', 'danger')
            return render_template('register.html', roles=REPORTER_ROLES)

        if role not in REPORTER_ROLES:
            flash('Student and lecturer accounts can be self-registered. Admins create staff accounts.', 'warning')
            return render_template('register.html', roles=REPORTER_ROLES)

        db = get_db()
        if db.execute('SELECT id FROM users WHERE email = ?', (email,)).fetchone():
            flash('An account with that email already exists.', 'warning')
            return render_template('register.html')

        try:
            db.execute(
                'INSERT INTO users (first_name, last_name, email, password_hash, role, phone) VALUES (?, ?, ?, ?, ?, ?)',
                (first_name, last_name, email, generate_password_hash(password), role, phone),
            )
        except sqlite3.IntegrityError:
            flash('An account with that email already exists.', 'warning')
            return render_template('register.html', roles=REPORTER_ROLES)
        db.commit()
        add_audit(None, 'Register account', f'{email} created a {role} account.')
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html', roles=REPORTER_ROLES)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        user = get_db().execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()

        if user and user['is_active'] and check_password_hash(user['password_hash'], password):
            session.clear()
            if user['role'] in ['admin', 'supervisor'] and user['two_factor_enabled']:
                if not user['two_factor_secret']:
                    session['pending_2fa_setup_user_id'] = user['id']
                    session['pending_2fa_auth_version'] = user['auth_version']
                    session['pending_2fa_started_at'] = time.time()
                    flash('Set up your authenticator app to finish signing in.', 'info')
                    return redirect(url_for('two_factor_setup'))
                session['pending_2fa_user_id'] = user['id']
                session['pending_2fa_auth_version'] = user['auth_version']
                session['pending_2fa_started_at'] = time.time()
                return redirect(url_for('two_factor_verify'))
            session['user_id'] = user['id']
            session['role'] = user['role']
            session['auth_version'] = user['auth_version']
            add_audit(user['id'], 'Login', 'User logged in successfully.')
            flash('Welcome back to CampusFix.', 'success')
            return redirect(url_for('dashboard'))

        flash('Invalid email or password.', 'danger')
        return render_template('login.html')
    return render_template('login.html')


@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            db = get_db()
            user = db.execute('SELECT id, email FROM users WHERE email = ? AND is_active = 1', (email,)).fetchone()
            reset_link = None
            if user:
                raw_token = secrets.token_urlsafe(32)
                token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
                expires_at = (datetime.now(timezone.utc) + timedelta(minutes=30)).strftime('%Y-%m-%d %H:%M:%S')
                db.execute(
                    'INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
                    (user['id'], token_hash, expires_at),
                )
                db.commit()
                reset_link = url_for('reset_password', token=raw_token, _external=True)
                try:
                    send_email(user['email'], 'Reset your CampusFix password', f'Use this link within 30 minutes to reset your password:\n\n{reset_link}\n')
                except RuntimeError as error:
                    if app.debug or os.environ.get('CAMPUSFIX_SHOW_RESET_LINK', '').lower() == 'true':
                        app.logger.warning('Local password reset link for %s: %s (%s)', user['email'], reset_link, error)
                    else:
                        app.logger.error('Password reset email could not be sent: %s', error)
                        flash('Password reset email is not configured. Contact the system administrator.', 'warning')
                        return render_template('forgot_password.html')
                except (OSError, smtplib.SMTPException) as error:
                    app.logger.exception('Password reset email delivery failed')
                    flash('Password reset email could not be sent. Please try again later or contact the administrator.', 'warning')
                    return render_template('forgot_password.html')
            message = 'If an active account matches that email, password reset instructions have been sent.'
            if reset_link and (app.debug or os.environ.get('CAMPUSFIX_SHOW_RESET_LINK', '').lower() == 'true') and not os.environ.get('CAMPUSFIX_SMTP_HOST'):
                flash(f'Local demo reset link (valid for 30 minutes): {reset_link}', 'info')
            else:
                flash(message, 'info')
            return redirect(url_for('login'))
        return render_template('forgot_password.html')


@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
        token_hash = hashlib.sha256(token.encode('utf-8')).hexdigest()
        db = get_db()
        reset = db.execute(
            '''
            SELECT pr.id, pr.user_id FROM password_resets pr
            JOIN users u ON u.id = pr.user_id
            WHERE pr.token_hash = ? AND pr.used_at IS NULL
              AND datetime(pr.expires_at) > datetime('now') AND u.is_active = 1
            ''',
            (token_hash,),
        ).fetchone()
        if not reset:
            flash('That password reset link is invalid or expired. Request a new one.', 'warning')
            return redirect(url_for('forgot_password'))
        if request.method == 'POST':
            password = request.form.get('password', '')
            if len(password) < 10:
                flash('Choose a password with at least 10 characters.', 'danger')
                return render_template('reset_password.html')
            db.execute(
                'UPDATE users SET password_hash = ?, auth_version = auth_version + 1 WHERE id = ?',
                (generate_password_hash(password), reset['user_id']),
            )
            db.execute('UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE id = ?', (reset['id'],))
            db.execute(
                'UPDATE password_resets SET used_at = CURRENT_TIMESTAMP WHERE user_id = ? AND id != ? AND used_at IS NULL',
                (reset['user_id'], reset['id']),
            )
            db.execute('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)', (reset['user_id'], 'Reset password', 'Password reset completed.'))
            db.commit()
            flash('Password updated. You can now sign in.', 'success')
            return redirect(url_for('login'))
        return render_template('reset_password.html')


@app.route('/security/two-factor/setup', methods=['GET'])
def two_factor_setup():
        pending_setup = session.get('pending_2fa_setup_user_id')
        user_id = pending_setup or session.get('user_id')
        if not user_id:
            flash('Sign in before configuring two-factor authentication.', 'warning')
            return redirect(url_for('login'))
        user = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if (
            not user
            or not user['is_active']
            or user['role'] not in ['admin', 'supervisor']
            or (
                pending_setup
                and (
                    session.get('pending_2fa_auth_version') != user['auth_version']
                    or time.time() - session.get('pending_2fa_started_at', 0) > 300
                )
            )
            or (
                not pending_setup
                and session.get('auth_version') != user['auth_version']
            )
        ):
            session.clear()
            flash('Authenticator setup is available for administrators and supervisors.', 'warning')
            return redirect(url_for('login'))
        secret = session.get('pending_totp_secret')
        if not secret:
            secret = base64.b32encode(secrets.token_bytes(20)).decode('ascii').rstrip('=')
            session['pending_totp_secret'] = secret
        issuer = 'CampusFix'
        account = quote(f'{issuer}:{user["email"]}')
        provisioning_uri = f'otpauth://totp/{account}?secret={secret}&issuer={quote(issuer)}&period=30&digits=6'
        return render_template('two_factor_setup.html', secret=secret, provisioning_uri=provisioning_uri)


@app.route('/security/two-factor/confirm', methods=['POST'])
def two_factor_confirm():
        user_id = session.get('pending_2fa_setup_user_id') or session.get('user_id')
        secret = session.get('pending_totp_secret')
        if not user_id or not secret:
            flash('Authenticator setup expired. Start setup again.', 'warning')
            return redirect(url_for('login'))
        user = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        pending_setup = session.get('pending_2fa_setup_user_id')
        if (
            not user
            or not user['is_active']
            or user['role'] not in ['admin', 'supervisor']
            or (
                pending_setup
                and (
                    session.get('pending_2fa_auth_version') != user['auth_version']
                    or time.time() - session.get('pending_2fa_started_at', 0) > 300
                )
            )
            or (
                not pending_setup
                and session.get('auth_version') != user['auth_version']
            )
        ):
            session.clear()
            abort(403)
        if not verify_totp(secret, request.form.get('code', '')):
            flash('That code is not valid. Check your authenticator and try again.', 'danger')
            return redirect(url_for('two_factor_setup'))
        db = get_db()
        db.execute('UPDATE users SET two_factor_enabled = 1, two_factor_secret = ? WHERE id = ?', (secret, user_id))
        db.execute('INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)', (user_id, 'Enable two-factor authentication', 'Authenticator app enrolled.'))
        db.commit()
        session.pop('pending_totp_secret', None)
        session.pop('pending_2fa_setup_user_id', None)
        session.pop('pending_2fa_auth_version', None)
        session.pop('pending_2fa_started_at', None)
        session['user_id'] = user['id']
        session['role'] = user['role']
        session['auth_version'] = user['auth_version']
        flash('Two-factor authentication is enabled for your account.', 'success')
        return redirect(url_for('dashboard'))


@app.route('/security/two-factor/verify', methods=['GET', 'POST'])
def two_factor_verify():
        user_id = session.get('pending_2fa_user_id')
        if not user_id:
            flash('Sign in with your password before entering an authenticator code.', 'warning')
            return redirect(url_for('login'))
        user = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        if (
            not user
            or not user['is_active']
            or not user['two_factor_enabled']
            or not user['two_factor_secret']
            or session.get('pending_2fa_auth_version') != user['auth_version']
            or time.time() - session.get('pending_2fa_started_at', 0) > 300
        ):
            session.pop('pending_2fa_user_id', None)
            session.pop('pending_2fa_auth_version', None)
            session.pop('pending_2fa_started_at', None)
            session.pop('pending_2fa_attempts', None)
            flash('Two-factor setup is incomplete. Sign in again to set it up.', 'warning')
            return redirect(url_for('login'))
        if request.method == 'POST':
            if verify_totp(user['two_factor_secret'], request.form.get('code', '')):
                session.pop('pending_2fa_user_id', None)
                session.pop('pending_2fa_auth_version', None)
                session.pop('pending_2fa_started_at', None)
                session.pop('pending_2fa_attempts', None)
                session['user_id'] = user['id']
                session['role'] = user['role']
                session['auth_version'] = user['auth_version']
                add_audit(user['id'], 'Login', 'Two-factor authentication verified.')
                flash('Welcome back to CampusFix.', 'success')
                return redirect(url_for('dashboard'))
            attempts = session.get('pending_2fa_attempts', 0) + 1
            if attempts >= 5:
                session.pop('pending_2fa_user_id', None)
                session.pop('pending_2fa_auth_version', None)
                session.pop('pending_2fa_started_at', None)
                session.pop('pending_2fa_attempts', None)
                flash('Too many invalid authenticator codes. Sign in again to retry.', 'danger')
                return redirect(url_for('login'))
            session['pending_2fa_attempts'] = attempts
            flash('That authenticator code is not valid. Try again.', 'danger')
        return render_template('two_factor_verify.html')


@app.route('/security/two-factor/enable', methods=['POST'])
@login_required
def enable_two_factor():
        user = user_from_session()
        if user['role'] not in ['admin', 'supervisor']:
            flash('Two-factor authentication is available for administrators and supervisors.', 'warning')
            return redirect(url_for('dashboard'))
        get_db().execute('UPDATE users SET two_factor_enabled = 1 WHERE id = ?', (user['id'],))
        add_audit(user['id'], 'Require two-factor authentication', 'Authenticator enrollment required at next login.')
        flash('Two-factor authentication is now required. Sign out and back in to enroll an authenticator.', 'success')
        return redirect(url_for('dashboard'))


@app.route('/logout', methods=['POST'])
def logout():
    user_id = session.get('user_id')
    if user_id:
        add_audit(user_id, 'Logout', 'User logged out.')
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))


@app.route('/dashboard')
@login_required
def dashboard():
    user = user_from_session()
    db = get_db()
    categories = db.execute('SELECT * FROM categories ORDER BY name').fetchall()
    buildings = db.execute('SELECT * FROM buildings ORDER BY name').fetchall()
    rooms = db.execute('SELECT r.*, b.name AS building_name FROM rooms r JOIN buildings b ON b.id = r.building_id ORDER BY b.name, r.room_number').fetchall()
    technicians = db.execute('SELECT * FROM users WHERE role = ? AND is_active = 1', ('technician',)).fetchall()
    notifications = db.execute(
        '''
        SELECT id, issue_id, message, created_at, NULL AS target_url, is_read, 'issue' AS kind
        FROM notifications WHERE user_id = ?
        UNION ALL
        SELECT id, NULL AS issue_id, message, created_at, target_url, (read_at IS NOT NULL) AS is_read, 'service' AS kind
        FROM service_notifications WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 10
        ''',
        (user['id'], user['id']),
    ).fetchall()

    if user['role'] in REPORTER_ROLES:
        issues = db.execute(
            '''
            SELECT i.*, c.name AS category_name, b.name AS building_name, r.room_number,
                   (SELECT COUNT(*) FROM notifications n WHERE n.issue_id = i.id) AS notification_count
            FROM issues i
            JOIN categories c ON c.id = i.category_id
            JOIN buildings b ON b.id = i.building_id
            JOIN rooms r ON r.id = i.room_id
            WHERE i.reporter_id = ?
            ORDER BY i.created_at DESC
            ''',
            (user['id'],),
        ).fetchall()
        stats = {
            'total': len(issues),
            'open': sum(1 for item in issues if item['status'] in ['Pending', 'Assigned', 'In Progress']),
            'resolved': sum(1 for item in issues if item['status'] == 'Resolved'),
        }
        return render_template(
            'dashboard.html',
            user=user,
            categories=categories,
            buildings=buildings,
            rooms=rooms,
            issues=issues,
            stats=stats,
            notifications=notifications,
            technicians=technicians,
        )

    if user['role'] == 'technician':
        assigned = db.execute(
            '''
            SELECT a.id AS assignment_id, i.*, c.name AS category_name, b.name AS building_name, r.room_number,
                   u.first_name || ' ' || u.last_name AS reporter_name, a.status AS assignment_status
            FROM assignments a
            JOIN issues i ON i.id = a.issue_id
            JOIN categories c ON c.id = i.category_id
            JOIN buildings b ON b.id = i.building_id
            JOIN rooms r ON r.id = i.room_id
            JOIN users u ON u.id = i.reporter_id
            WHERE a.technician_id = ?
            ORDER BY i.created_at DESC
            ''',
            (user['id'],),
        ).fetchall()
        return render_template('dashboard.html', user=user, issues=assigned, notifications=notifications, technicians=technicians)

    if user['role'] == 'supervisor':
        pending = db.execute(
            '''
            SELECT i.*, c.name AS category_name, b.name AS building_name, r.room_number,
                   u.first_name || ' ' || u.last_name AS reporter_name
            FROM issues i
            JOIN categories c ON c.id = i.category_id
            JOIN buildings b ON b.id = i.building_id
            JOIN rooms r ON r.id = i.room_id
            JOIN users u ON u.id = i.reporter_id
            WHERE i.status IN ('Pending', 'Assigned')
            ORDER BY i.created_at DESC
            ''',
        ).fetchall()
        return render_template('dashboard.html', user=user, issues=pending, notifications=notifications, technicians=technicians)

    if user['role'] == 'admin':
        stats = {
            'issues_total': db.execute('SELECT COUNT(*) FROM issues').fetchone()[0],
            'users_total': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
            'pending_total': db.execute("SELECT COUNT(*) FROM issues WHERE status IN ('Pending', 'Assigned', 'In Progress')").fetchone()[0],
            'resolved_total': db.execute("SELECT COUNT(*) FROM issues WHERE status = 'Resolved'").fetchone()[0],
            'lost_found_total': db.execute("SELECT COUNT(*) FROM lost_found_items WHERE status IN ('Open', 'Matched')").fetchone()[0],
            'vehicle_pending_total': db.execute("SELECT COUNT(*) FROM vehicle_registrations WHERE status = 'Pending'").fetchone()[0],
        }
        audit_logs = db.execute('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 12').fetchall()
        all_users = db.execute('SELECT * FROM users ORDER BY role, last_name').fetchall()
        all_issues = db.execute(
            '''
            SELECT i.*, c.name AS category_name, b.name AS building_name, r.room_number, u.first_name || ' ' || u.last_name AS reporter_name
            FROM issues i
            JOIN categories c ON c.id = i.category_id
            JOIN buildings b ON b.id = i.building_id
            JOIN rooms r ON r.id = i.room_id
            JOIN users u ON u.id = i.reporter_id
            ORDER BY i.created_at DESC LIMIT 20
            '''
        ).fetchall()
        return render_template(
            'admin.html',
            user=user,
            stats=stats,
            audit_logs=audit_logs,
            categories=categories,
            buildings=buildings,
            rooms=rooms,
            users=all_users,
            issues=all_issues,
            notifications=notifications,
        )

    flash('Unsupported role detected.', 'warning')
    return redirect(url_for('index'))


@app.route('/services')
@login_required
def campus_services():
    user = user_from_session()
    db = get_db()
    is_staff = user['role'] in ['supervisor', 'admin']
    if is_staff:
        vehicle_query = '''
            SELECT v.*, u.first_name || ' ' || u.last_name AS owner_name, u.email AS owner_email
            FROM vehicle_registrations v JOIN users u ON u.id = v.owner_id
            ORDER BY CASE v.status WHEN 'Pending' THEN 0 ELSE 1 END, v.submitted_at DESC
        '''
        claims = db.execute(
            '''
            SELECT c.*, i.reference_number, i.item_name, i.item_type,
                   u.first_name || ' ' || u.last_name AS claimant_name
            FROM lost_found_claims c
            JOIN lost_found_items i ON i.id = c.item_id
            JOIN users u ON u.id = c.claimant_id
            ORDER BY CASE c.status WHEN 'Pending' THEN 0 ELSE 1 END, c.created_at DESC
            '''
        ).fetchall()
    else:
        vehicle_query = '''
            SELECT v.*, u.first_name || ' ' || u.last_name AS owner_name, u.email AS owner_email
            FROM vehicle_registrations v JOIN users u ON u.id = v.owner_id
            WHERE v.owner_id = ? ORDER BY v.submitted_at DESC
        '''
        claims = db.execute(
            '''
            SELECT c.*, i.reference_number, i.item_name, i.item_type,
                   u.first_name || ' ' || u.last_name AS claimant_name
            FROM lost_found_claims c
            JOIN lost_found_items i ON i.id = c.item_id
            JOIN users u ON u.id = c.claimant_id
            WHERE c.claimant_id = ? ORDER BY c.created_at DESC
            ''',
            (user['id'],),
        ).fetchall()
    vehicles = db.execute(vehicle_query, () if is_staff else (user['id'],)).fetchall()
    items = db.execute(
        '''
        SELECT i.*, u.first_name || ' ' || u.last_name AS reporter_name
        FROM lost_found_items i JOIN users u ON u.id = i.reporter_id
        WHERE (? = 1 OR i.status != 'Closed')
        ORDER BY CASE i.status WHEN 'Open' THEN 0 WHEN 'Matched' THEN 1 WHEN 'Returned' THEN 2 ELSE 3 END, i.created_at DESC
        ''',
        (int(is_staff),),
    ).fetchall()
    own_items = db.execute(
        'SELECT * FROM lost_found_items WHERE reporter_id = ? ORDER BY created_at DESC',
        (user['id'],),
    ).fetchall()
    return render_template(
        'campus_services.html',
        user=user,
        is_staff=is_staff,
        items=items,
        own_items=own_items,
        claims=claims,
        vehicles=vehicles,
    )


@app.route('/services/lost-found', methods=['POST'])
@login_required
def create_lost_found_item():
    user = user_from_session()
    if user['role'] not in REPORTER_ROLES:
        flash('Only students and lecturers can submit lost-and-found notices.', 'danger')
        return redirect(url_for('campus_services'))

    item_type = request.form.get('item_type', '')
    item_name = request.form.get('item_name', '').strip()
    description = request.form.get('description', '').strip()
    category = request.form.get('item_category', '').strip()
    location = request.form.get('location', '').strip()
    date_occurred = request.form.get('date_occurred', '').strip()
    try:
        datetime.strptime(date_occurred, '%Y-%m-%d')
    except ValueError:
        date_valid = False
    else:
        date_valid = True
    contact_phone = request.form.get('contact_phone', '').strip()
    if (
        item_type not in ['Lost', 'Found']
        or not all([item_name, description, category, location, date_occurred])
        or not date_valid
        or len(item_name) > 120
        or len(description) > 1000
        or len(category) > 80
        or len(location) > 160
        or len(contact_phone) > 30
    ):
        flash('Complete all required lost-and-found details.', 'danger')
        return redirect(url_for('campus_services'))

    reference = f"LF-{datetime.now().strftime('%Y%m%d')}-{uuid.uuid4().hex[:6].upper()}"
    db = get_db()
    db.execute(
        '''
        INSERT INTO lost_found_items
            (reference_number, reporter_id, item_type, item_name, description, category, location, date_occurred, contact_phone)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''',
        (reference, user['id'], item_type, item_name, description, category, location, date_occurred, contact_phone or user['phone']),
    )
    supervisors = db.execute("SELECT id FROM users WHERE role IN ('supervisor', 'admin') AND is_active = 1").fetchall()
    for recipient in supervisors:
        create_service_notification(
            recipient['id'],
            f'{item_type} item notice {reference} needs review.',
            url_for('campus_services'),
        )
    add_audit(user['id'], 'Create lost-and-found notice', f'{item_type} item {reference} submitted.')
    db.commit()
    flash(f'{item_type} notice submitted with reference {reference}.', 'success')
    return redirect(url_for('campus_services'))


@app.route('/services/lost-found/<int:item_id>/claim', methods=['POST'])
@login_required
def create_lost_found_claim(item_id):
    user = user_from_session()
    if user['role'] not in REPORTER_ROLES:
        flash('Only students and lecturers can submit a possible match.', 'danger')
        return redirect(url_for('campus_services'))
    message = request.form.get('message', '').strip()
    db = get_db()
    item = db.execute('SELECT * FROM lost_found_items WHERE id = ?', (item_id,)).fetchone()
    if not item or item['status'] != 'Open':
        flash('That notice is no longer open for possible matches.', 'warning')
    elif item['reporter_id'] == user['id']:
        flash('You cannot submit a possible match for your own notice.', 'warning')
    elif not message or len(message) > 1000:
        flash('Describe the possible match so staff can review it.', 'warning')
    else:
        try:
            db.execute(
                'INSERT INTO lost_found_claims (item_id, claimant_id, message) VALUES (?, ?, ?)',
                (item_id, user['id'], message),
            )
            create_service_notification(
                item['reporter_id'],
                f'A possible match was submitted for your item notice {item["reference_number"]}.',
                url_for('campus_services'),
            )
            staff = db.execute("SELECT id FROM users WHERE role IN ('supervisor', 'admin') AND is_active = 1").fetchall()
            for recipient in staff:
                create_service_notification(
                    recipient['id'],
                    f'A possible match needs review for {item["reference_number"]}.',
                    url_for('campus_services'),
                )
            add_audit(user['id'], 'Submit possible item match', f'Possible match submitted for {item["reference_number"]}.')
            db.commit()
            flash('Possible match submitted for staff review.', 'success')
        except sqlite3.IntegrityError:
            db.rollback()
            flash('You have already submitted a possible match for this notice.', 'warning')
    return redirect(url_for('campus_services'))


@app.route('/services/claims/<int:claim_id>/review', methods=['POST'])
@role_required('supervisor', 'admin')
def review_lost_found_claim(claim_id):
    decision = request.form.get('decision', '')
    if decision not in ['Approved', 'Rejected']:
        flash('Choose a valid match decision.', 'warning')
        return redirect(url_for('campus_services'))
    db = get_db()
    claim = db.execute(
        '''
        SELECT c.*, i.reference_number, i.status AS item_status
        FROM lost_found_claims c JOIN lost_found_items i ON i.id = c.item_id
        WHERE c.id = ?
        ''',
        (claim_id,),
    ).fetchone()
    if not claim or claim['status'] != 'Pending':
        flash('That possible match has already been reviewed or no longer exists.', 'warning')
        return redirect(url_for('campus_services'))
    if decision == 'Approved' and claim['item_status'] != 'Open':
        flash('The item notice is no longer open, so this match cannot be approved.', 'warning')
        return redirect(url_for('campus_services'))
    db.execute(
        'UPDATE lost_found_claims SET status = ?, reviewed_at = CURRENT_TIMESTAMP, reviewer_id = ? WHERE id = ?',
        (decision, session['user_id'], claim_id),
    )
    if decision == 'Approved':
        db.execute("UPDATE lost_found_items SET status = 'Matched', updated_at = CURRENT_TIMESTAMP WHERE id = ?", (claim['item_id'],))
        db.execute(
            "UPDATE lost_found_claims SET status = 'Rejected', reviewed_at = CURRENT_TIMESTAMP, reviewer_id = ? WHERE item_id = ? AND id != ? AND status = 'Pending'",
            (session['user_id'], claim['item_id'], claim_id),
        )
    create_service_notification(
        claim['claimant_id'],
        f'Your possible item match for {claim["reference_number"]} was {decision.lower()}.',
        url_for('campus_services'),
    )
    if decision == 'Approved':
        item = db.execute('SELECT reporter_id FROM lost_found_items WHERE id = ?', (claim['item_id'],)).fetchone()
        create_service_notification(
            item['reporter_id'],
            f'Staff approved a possible match for {claim["reference_number"]}.',
            url_for('campus_services'),
        )
    add_audit(session['user_id'], 'Review possible item match', f'{decision} possible match for {claim["reference_number"]}.')
    db.commit()
    flash(f'Possible match {decision.lower()}.', 'success')
    return redirect(url_for('campus_services'))


@app.route('/services/lost-found/<int:item_id>/status', methods=['POST'])
@login_required
def update_lost_found_status(item_id):
    user = user_from_session()
    new_status = request.form.get('status', '')
    if new_status not in ['Open', 'Returned', 'Closed']:
        flash('Choose a valid item status.', 'warning')
        return redirect(url_for('campus_services'))
    db = get_db()
    item = db.execute('SELECT * FROM lost_found_items WHERE id = ?', (item_id,)).fetchone()
    if not item:
        flash('Lost-and-found notice not found.', 'warning')
        return redirect(url_for('campus_services'))
    is_owner = item['reporter_id'] == user['id']
    if (is_owner and new_status != 'Returned') or (not is_owner and user['role'] not in ['supervisor', 'admin']):
        flash('Only the notice owner can mark an item returned; staff can close or reopen notices.', 'danger')
        return redirect(url_for('campus_services'))
    if is_owner and item['status'] != 'Matched':
        flash('A notice can be marked returned after staff confirm a possible match.', 'warning')
        return redirect(url_for('campus_services'))
    db.execute(
        'UPDATE lost_found_items SET status = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?',
        (new_status, item_id),
    )
    if new_status in ['Returned', 'Closed']:
        claims = db.execute(
            "SELECT claimant_id FROM lost_found_claims WHERE item_id = ? AND status = 'Approved'",
            (item_id,),
        ).fetchall()
        for claim in claims:
            create_service_notification(
                claim['claimant_id'],
                f'Lost-and-found notice {item["reference_number"]} is now {new_status.lower()}.',
                url_for('campus_services'),
            )
    add_audit(user['id'], 'Update lost-and-found notice', f'{item["reference_number"]} marked {new_status}.')
    db.commit()
    flash(f'Notice updated: {new_status}.', 'success')
    return redirect(url_for('campus_services'))


@app.route('/services/vehicles', methods=['POST'])
@login_required
def register_vehicle():
    user = user_from_session()
    if user['role'] not in REPORTER_ROLES:
        flash('Only students and lecturers can request a campus vehicle sticker.', 'danger')
        return redirect(url_for('campus_services'))
    registration_number = ' '.join(request.form.get('registration_number', '').upper().split())
    make = request.form.get('make', '').strip()
    model = request.form.get('model', '').strip()
    colour = request.form.get('colour', '').strip()
    vehicle_type = request.form.get('vehicle_type', '')
    if (
        not all([registration_number, make, model, colour])
        or len(registration_number) > 20
        or len(make) > 60
        or len(model) > 60
        or len(colour) > 40
        or vehicle_type not in ['Car', 'Motorcycle', 'Van', 'Other']
    ):
        flash('Enter a valid registration number and complete the vehicle details.', 'danger')
        return redirect(url_for('campus_services'))
    db = get_db()
    try:
        db.execute(
            '''
            INSERT INTO vehicle_registrations
                (owner_id, registration_number, make, model, colour, vehicle_type)
            VALUES (?, ?, ?, ?, ?, ?)
            ''',
            (user['id'], registration_number, make, model, colour, vehicle_type),
        )
        staff = db.execute("SELECT id FROM users WHERE role IN ('supervisor', 'admin') AND is_active = 1").fetchall()
        for recipient in staff:
            create_service_notification(
                recipient['id'],
                f'Vehicle sticker request {registration_number} needs review.',
                url_for('campus_services'),
            )
        add_audit(user['id'], 'Register campus vehicle', f'Vehicle {registration_number} submitted for sticker approval.')
        db.commit()
        flash('Vehicle registration submitted. Staff will review it before issuing a sticker.', 'success')
    except sqlite3.IntegrityError:
        db.rollback()
        flash('That registration number is already on file. Contact campus administration if this is your vehicle.', 'warning')
    return redirect(url_for('campus_services'))


@app.route('/services/vehicles/<int:vehicle_id>/review', methods=['POST'])
@role_required('supervisor', 'admin')
def review_vehicle(vehicle_id):
    decision = request.form.get('decision', '')
    if decision not in ['Approved', 'Rejected']:
        flash('Choose a valid vehicle registration decision.', 'warning')
        return redirect(url_for('campus_services'))
    db = get_db()
    vehicle = db.execute('SELECT * FROM vehicle_registrations WHERE id = ?', (vehicle_id,)).fetchone()
    if not vehicle or vehicle['status'] != 'Pending':
        flash('That vehicle request has already been reviewed or no longer exists.', 'warning')
        return redirect(url_for('campus_services'))
    sticker_number = f"CF-ST-{vehicle_id:06d}" if decision == 'Approved' else None
    db.execute(
        '''
        UPDATE vehicle_registrations
        SET status = ?, sticker_number = ?, reviewed_at = CURRENT_TIMESTAMP, reviewer_id = ?
        WHERE id = ?
        ''',
        (decision, sticker_number, session['user_id'], vehicle_id),
    )
    add_audit(session['user_id'], 'Review vehicle sticker request', f'{vehicle["registration_number"]} {decision.lower()}.')
    create_service_notification(
        vehicle['owner_id'],
        f'Your vehicle sticker request for {vehicle["registration_number"]} was {decision.lower()}.' +
        (f' Sticker number: {sticker_number}.' if sticker_number else ''),
        url_for('campus_services'),
    )
    db.commit()
    flash(
        f'Vehicle registration {decision.lower()}.' + (f' Sticker number: {sticker_number}.' if sticker_number else ''),
        'success',
    )
    return redirect(url_for('campus_services'))


@app.route('/issues/new', methods=['POST'])
@login_required
def create_issue():
    user = user_from_session()
    if not is_reporter(user['role']):
        flash('Only students and lecturers can submit issues.', 'danger')
        return redirect(url_for('dashboard'))

    category_id = request.form.get('category_id')
    building_id = request.form.get('building_id')
    room_id = request.form.get('room_id')
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    priority = request.form.get('priority', 'Medium')

    if not all([category_id, building_id, room_id, title, description]) or len(title) > 160 or len(description) > 3000:
        flash('Complete all issue fields. Titles are limited to 160 characters and descriptions to 3,000.', 'danger')
        return redirect(url_for('dashboard'))
    if priority not in ['Low', 'Medium', 'High']:
        flash('Choose a valid issue priority.', 'danger')
        return redirect(url_for('dashboard'))

    db = get_db()
    location = db.execute(
        'SELECT r.id FROM rooms r WHERE r.id = ? AND r.building_id = ?',
        (room_id, building_id),
    ).fetchone()
    category = db.execute('SELECT id FROM categories WHERE id = ?', (category_id,)).fetchone()
    if not location or not category:
        flash('Choose a valid category, building and room combination.', 'danger')
        return redirect(url_for('dashboard'))

    file = request.files.get('photo')
    photo_url = None
    if file and file.filename:
        safe_original = secure_filename(file.filename)
        extension = os.path.splitext(safe_original)[1].lower()
        if extension not in {'.jpg', '.jpeg', '.png', '.webp'}:
            flash('Issue photos must be JPG, PNG or WebP images.', 'danger')
            return redirect(url_for('dashboard'))
        filename = f'{uuid.uuid4().hex}{extension}'
        target = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(target)
        photo_url = f'/static/uploads/{filename}'

    ticket_number = f"CF-{datetime.now().strftime('%Y%m%d')}-{str(uuid.uuid4())[:8].upper()}"
    with db:
        db.execute(
            '''
            INSERT INTO issues (ticket_number, reporter_id, category_id, building_id, room_id, title, description, priority, status, photo_url)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'Pending', ?)
            ''',
            (ticket_number, user['id'], category_id, building_id, room_id, title, description, priority, photo_url),
        )
        issue_id = db.execute('SELECT last_insert_rowid() AS id').fetchone()['id']
        supervisors = db.execute(
            "SELECT id FROM users WHERE role IN ('supervisor', 'admin') AND is_active = 1"
        ).fetchall()
        for supervisor in supervisors:
            db.execute(
                'INSERT INTO notifications (user_id, issue_id, message) VALUES (?, ?, ?)',
                (supervisor['id'], issue_id, f'New issue reported: {title}.'),
            )
        db.execute(
            'INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)',
            (user['id'], 'Create issue', f'Issue {ticket_number} created.'),
        )

    flash('Issue submitted successfully. A supervisor will review it shortly.', 'success')
    return redirect(url_for('dashboard'))


@app.route('/issues/<int:issue_id>')
@login_required
def issue_detail(issue_id):
    db = get_db()
    issue = db.execute(
        '''
        SELECT i.*, c.name AS category_name, b.name AS building_name, r.room_number,
               u.first_name || ' ' || u.last_name AS reporter_name
        FROM issues i
        JOIN categories c ON c.id = i.category_id
        JOIN buildings b ON b.id = i.building_id
        JOIN rooms r ON r.id = i.room_id
        JOIN users u ON u.id = i.reporter_id
        WHERE i.id = ?
        ''',
        (issue_id,),
    ).fetchone()
    if not issue:
        flash('Issue not found.', 'warning')
        return redirect(url_for('dashboard'))
    current_user = user_from_session()
    owns_issue = issue['reporter_id'] == current_user['id']
    is_staff = current_user['role'] in ['admin', 'supervisor']
    is_assigned_technician = current_user['role'] == 'technician' and db.execute(
        'SELECT 1 FROM assignments WHERE issue_id = ? AND technician_id = ?',
        (issue_id, current_user['id']),
    ).fetchone()
    if not (owns_issue or is_staff or is_assigned_technician):
        flash('You do not have access to that issue.', 'danger')
        return redirect(url_for('dashboard'))

    assignment = db.execute(
        '''
        SELECT a.*, u.first_name || ' ' || u.last_name AS technician_name, s.first_name || ' ' || s.last_name AS supervisor_name
        FROM assignments a
        JOIN users u ON u.id = a.technician_id
        JOIN users s ON s.id = a.supervisor_id
        WHERE a.issue_id = ?
        ORDER BY a.assigned_at DESC, a.id DESC
        LIMIT 1
        ''',
        (issue_id,),
    ).fetchone()

    work_logs = db.execute(
        '''
        SELECT w.*, u.first_name || ' ' || u.last_name AS technician_name
        FROM work_logs w
        JOIN users u ON u.id = w.technician_id
        WHERE w.assignment_id = ?
        ORDER BY w.created_at DESC
        ''',
        (assignment['id'],) if assignment else (-1,),
    ).fetchall()

    feedback = db.execute('SELECT * FROM feedback WHERE issue_id = ?', (issue_id,)).fetchone()
    technicians = db.execute('SELECT * FROM users WHERE role = ?', ('technician',)).fetchall()

    return render_template('issue_detail.html', issue=issue, assignment=assignment, work_logs=work_logs, feedback=feedback, technicians=technicians)


@app.route('/issues/<int:issue_id>/update', methods=['POST'])
@login_required
def update_issue(issue_id):
    user = user_from_session()
    db = get_db()
    issue = db.execute('SELECT * FROM issues WHERE id = ?', (issue_id,)).fetchone()
    if not issue:
        flash('Issue not found.', 'warning')
        return redirect(url_for('dashboard'))

    if issue['reporter_id'] != user['id'] and user['role'] != 'admin':
        flash('Only the reporter or admin can update this issue.', 'danger')
        return redirect(url_for('dashboard'))
    if user['role'] != 'admin' and issue['status'] != 'Pending':
        flash('Only pending reports can be edited or cancelled by the reporter.', 'warning')
        return redirect(url_for('issue_detail', issue_id=issue_id))

    action = request.form.get('action', 'update')
    if action == 'cancel':
        if issue['status'] != 'Pending':
            flash('Only pending reports can be cancelled.', 'warning')
            return redirect(url_for('issue_detail', issue_id=issue_id))
        db.execute("UPDATE issues SET status = 'Cancelled' WHERE id = ?", (issue_id,))
        add_audit(user['id'], 'Cancel issue', f'Issue {issue_id} cancelled.')
        flash('Issue cancelled.', 'info')
    else:
        title = request.form.get('title', issue['title']).strip()
        description = request.form.get('description', issue['description']).strip()
        category_id = request.form.get('category_id', issue['category_id'])
        building_id = request.form.get('building_id', issue['building_id'])
        room_id = request.form.get('room_id', issue['room_id'])
        priority = request.form.get('priority', issue['priority'])
        if not title or not description or len(title) > 160 or len(description) > 3000:
            flash('Enter a title and description within the specified limits.', 'danger')
            return redirect(url_for('issue_detail', issue_id=issue_id))
        if priority not in ['Low', 'Medium', 'High']:
            flash('Choose a valid issue priority.', 'danger')
            return redirect(url_for('issue_detail', issue_id=issue_id))
        valid_location = db.execute(
            'SELECT 1 FROM rooms WHERE id = ? AND building_id = ?',
            (room_id, building_id),
        ).fetchone()
        valid_category = db.execute('SELECT 1 FROM categories WHERE id = ?', (category_id,)).fetchone()
        if not valid_location or not valid_category:
            flash('Choose a valid category, building and room combination.', 'danger')
            return redirect(url_for('issue_detail', issue_id=issue_id))
        db.execute(
            '''
            UPDATE issues
            SET title = ?, description = ?, category_id = ?, building_id = ?, room_id = ?, priority = ?
            WHERE id = ?
            ''',
            (title, description, category_id, building_id, room_id, priority, issue_id),
        )
        add_audit(user['id'], 'Edit issue', f'Issue {issue_id} was updated.')
        flash('Issue details updated.', 'success')
    db.commit()
    return redirect(url_for('issue_detail', issue_id=issue_id))


@app.route('/issues/<int:issue_id>/assign', methods=['POST'])
@role_required('supervisor', 'admin')
def assign_issue(issue_id):
    technician_id = request.form.get('technician_id')
    priority = request.form.get('priority', 'Medium')
    due_date = request.form.get('due_date', '').strip() or None
    if not technician_id or priority not in ['Low', 'Medium', 'High']:
        flash('Select a technician and a valid priority before assigning the issue.', 'warning')
        return redirect(url_for('dashboard'))
    if due_date:
        try:
            datetime.strptime(due_date, '%Y-%m-%d')
        except ValueError:
            flash('Enter a valid due date.', 'warning')
            return redirect(url_for('dashboard'))

    db = get_db()
    issue = db.execute('SELECT * FROM issues WHERE id = ?', (issue_id,)).fetchone()
    if not issue:
        flash('Issue not found.', 'warning')
        return redirect(url_for('dashboard'))
    technician = db.execute(
        "SELECT id FROM users WHERE id = ? AND role = 'technician' AND is_active = 1",
        (technician_id,),
    ).fetchone()
    if not technician:
        flash('Select an active technician account.', 'warning')
        return redirect(url_for('issue_detail', issue_id=issue_id))

    with db:
        db.execute(
            'INSERT INTO assignments (issue_id, technician_id, supervisor_id, status) VALUES (?, ?, ?, ?)',
            (issue_id, technician_id, session['user_id'], 'Assigned'),
        )
        db.execute(
            "UPDATE issues SET status = 'Assigned', priority = ?, due_date = ? WHERE id = ?",
            (priority, due_date, issue_id),
        )
        db.execute(
            'INSERT INTO notifications (user_id, issue_id, message) VALUES (?, ?, ?)',
            (technician_id, issue_id, f"You have been assigned issue #{issue['ticket_number']}."),
        )
        db.execute(
            'INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)',
            (session['user_id'], 'Assign issue', f"Issue {issue['ticket_number']} assigned to technician {technician_id}."),
        )
    flash('Issue assigned successfully.', 'success')
    return redirect(url_for('issue_detail', issue_id=issue_id))


@app.route('/issues/<int:issue_id>/status', methods=['POST'])
@role_required('technician')
def update_status(issue_id):
    new_status = request.form.get('status')
    work_note = request.form.get('work_note', '').strip()
    user = user_from_session()
    db = get_db()
    assignment = db.execute(
        'SELECT * FROM assignments WHERE issue_id = ? AND technician_id = ? ORDER BY assigned_at DESC LIMIT 1',
        (issue_id, user['id']),
    ).fetchone()
    issue = db.execute('SELECT * FROM issues WHERE id = ?', (issue_id,)).fetchone()

    if not assignment or not issue:
        flash('You are not assigned to that issue.', 'danger')
        return redirect(url_for('dashboard'))
    if new_status not in ['Assigned', 'In Progress', 'Resolved']:
        flash('Choose a valid work status.', 'warning')
        return redirect(url_for('issue_detail', issue_id=issue_id))
    if issue['status'] in ['Resolved', 'Closed'] or (
        issue['status'] == 'In Progress' and new_status == 'Assigned'
    ):
        flash('This status transition is not allowed. Contact a supervisor if the issue needs to be reopened.', 'warning')
        return redirect(url_for('issue_detail', issue_id=issue_id))

    with db:
        db.execute("UPDATE issues SET status = ? WHERE id = ?", (new_status, issue_id))
        if new_status == 'Resolved':
            db.execute("UPDATE issues SET resolved_at = CURRENT_TIMESTAMP WHERE id = ?", (issue_id,))
        db.execute("UPDATE assignments SET status = ? WHERE id = ?", (new_status, assignment['id']))
        if work_note:
            db.execute(
                'INSERT INTO work_logs (assignment_id, technician_id, note) VALUES (?, ?, ?)',
                (assignment['id'], user['id'], work_note),
            )
        db.execute(
            'INSERT INTO notifications (user_id, issue_id, message) VALUES (?, ?, ?)',
            (issue['reporter_id'], issue_id, f'Issue status updated to {new_status} for ticket {issue["ticket_number"]}.'),
        )
        db.execute(
            'INSERT INTO audit_logs (user_id, action, details) VALUES (?, ?, ?)',
            (user['id'], 'Update status', f'Issue {issue["ticket_number"]} changed to {new_status}.'),
        )
    flash('Task status updated.', 'success')
    return redirect(url_for('issue_detail', issue_id=issue_id))


@app.route('/issues/<int:issue_id>/feedback', methods=['POST'])
@login_required
def submit_feedback(issue_id):
    user = user_from_session()
    rating = request.form.get('rating')
    comment = request.form.get('comment', '').strip()
    db = get_db()
    issue = db.execute('SELECT * FROM issues WHERE id = ?', (issue_id,)).fetchone()
    if not issue:
        flash('Issue not found.', 'warning')
        return redirect(url_for('dashboard'))
    if issue['reporter_id'] != user['id']:
        flash('Only the original reporter can confirm the fix.', 'danger')
        return redirect(url_for('dashboard'))

    action = request.form.get('action', 'confirm')
    if action == 'reopen':
        if issue['status'] != 'Resolved':
            flash('Only a resolved issue can be reopened.', 'warning')
            return redirect(url_for('issue_detail', issue_id=issue_id))
        db.execute("UPDATE issues SET status = 'Pending', resolved_at = NULL WHERE id = ?", (issue_id,))
        db.execute('DELETE FROM feedback WHERE issue_id = ?', (issue_id,))
        db.execute('UPDATE issues SET reporter_rating = NULL, reporter_comment = NULL WHERE id = ?', (issue_id,))
        supervisors = db.execute("SELECT id FROM users WHERE role IN ('supervisor', 'admin') AND is_active = 1").fetchall()
        for recipient in supervisors:
            create_notification(recipient['id'], issue_id, f'Reporter reopened ticket {issue["ticket_number"]}.')
        add_audit(user['id'], 'Reopen issue', f'Reporter reopened ticket {issue["ticket_number"]}.')
        db.commit()
        flash('The issue has been reopened for staff review.', 'info')
    elif action == 'confirm' and issue['status'] == 'Resolved' and rating:
        try:
            rating_value = int(rating)
        except ValueError:
            flash('Choose a rating from 1 to 5.', 'warning')
            return redirect(url_for('issue_detail', issue_id=issue_id))
        if rating_value not in range(1, 6):
            flash('Choose a rating from 1 to 5.', 'warning')
            return redirect(url_for('issue_detail', issue_id=issue_id))
        db.execute(
            'INSERT INTO feedback (issue_id, rating, comment) VALUES (?, ?, ?) ON CONFLICT(issue_id) DO UPDATE SET rating=excluded.rating, comment=excluded.comment',
            (issue_id, rating_value, comment),
        )
        db.execute("UPDATE issues SET reporter_rating = ?, reporter_comment = ?, status = 'Closed' WHERE id = ?", (rating_value, comment, issue_id))
        add_audit(user['id'], 'Confirm fix', f'Reporter confirmed closure for issue {issue["ticket_number"]}.')
        db.commit()
        flash('Thanks for confirming the fix and rating the service.', 'success')
    else:
        flash('A rating can be submitted after the technician resolves the issue.', 'warning')
    return redirect(url_for('issue_detail', issue_id=issue_id))


@app.route('/admin', methods=['GET', 'POST'])
@role_required('admin')
def admin_panel():
    db = get_db()
    if request.method == 'POST':
        action = request.form.get('action', '')
        if action == 'add_user':
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            email = request.form.get('email', '').strip().lower()
            password = request.form.get('password', '')
            role = request.form.get('role', 'student')
            if not all([first_name, last_name, email]) or len(password) < 10 or role not in ROLES:
                flash('Provide a name and valid email. New passwords must contain at least 10 characters.', 'danger')
                return redirect(url_for('admin_panel'))
            require_2fa = int(request.form.get('two_factor_enabled', 0) == 'on' and role in ['admin', 'supervisor'])
            try:
                db.execute(
                    'INSERT INTO users (first_name, last_name, email, password_hash, role, phone, two_factor_enabled) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    (first_name, last_name, email, generate_password_hash(password), role, request.form.get('phone', '').strip(), require_2fa),
                )
                add_audit(session['user_id'], 'Create user', f'Admin created {email} in role {role}.')
                db.commit()
                flash('User created successfully.', 'success')
            except sqlite3.IntegrityError:
                db.rollback()
                flash('That email address is already registered.', 'warning')
            return redirect(url_for('admin_panel'))

        if action == 'edit_user':
            try:
                user_id = int(request.form.get('user_id', ''))
            except ValueError:
                flash('Invalid user record.', 'warning')
                return redirect(url_for('admin_panel'))
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            email = request.form.get('email', '').strip().lower()
            role = request.form.get('role', '')
            phone = request.form.get('phone', '').strip()
            password = request.form.get('password', '')
            two_factor_enabled = int(request.form.get('two_factor_enabled') == 'on' and role in ['admin', 'supervisor'])
            if not all([first_name, last_name, email]) or role not in ROLES or (password and len(password) < 10):
                flash('Enter a name, valid role and email. Optional passwords must be at least 10 characters.', 'danger')
                return redirect(url_for('admin_panel'))
            if user_id == session['user_id'] and role != 'admin':
                flash('You cannot remove your own administrator role.', 'warning')
                return redirect(url_for('admin_panel'))
            try:
                if password:
                    db.execute(
                        'UPDATE users SET first_name = ?, last_name = ?, email = ?, role = ?, phone = ?, password_hash = ?, two_factor_enabled = ?, auth_version = auth_version + 1 WHERE id = ?',
                        (first_name, last_name, email, role, phone, generate_password_hash(password), two_factor_enabled, user_id),
                    )
                else:
                    db.execute(
                        'UPDATE users SET first_name = ?, last_name = ?, email = ?, role = ?, phone = ?, two_factor_enabled = ? WHERE id = ?',
                        (first_name, last_name, email, role, phone, two_factor_enabled, user_id),
                    )
                if db.execute('SELECT changes()').fetchone()[0] == 0:
                    flash('User not found.', 'warning')
                else:
                    add_audit(session['user_id'], 'Edit user', f'Admin updated account {email}.')
                    db.commit()
                    flash('User details updated.', 'success')
            except sqlite3.IntegrityError:
                db.rollback()
                flash('That email address is already in use.', 'warning')
            return redirect(url_for('admin_panel'))

        if action in ['deactivate_user', 'activate_user']:
            try:
                user_id = int(request.form.get('user_id', ''))
            except ValueError:
                flash('Invalid user record.', 'warning')
                return redirect(url_for('admin_panel'))
            if user_id == session['user_id'] and action == 'deactivate_user':
                flash('You cannot deactivate your own account.', 'warning')
                return redirect(url_for('admin_panel'))
            active = int(action == 'activate_user')
            db.execute(
                'UPDATE users SET is_active = ?, auth_version = auth_version + 1 WHERE id = ?',
                (active, user_id),
            )
            add_audit(session['user_id'], 'Update user access', f'User {user_id} active set to {active}.')
            db.commit()
            flash('User access updated.', 'success')
            return redirect(url_for('admin_panel'))

        if action == 'edit_room':
            try:
                room_id = int(request.form.get('room_id', ''))
                building_id = int(request.form.get('building_id', ''))
            except ValueError:
                flash('Select a valid building and room.', 'warning')
                return redirect(url_for('admin_panel'))
            room_number = request.form.get('room_number', '').strip()
            if not room_number or len(room_number) > 60:
                flash('Enter a room name (up to 60 characters).', 'warning')
                return redirect(url_for('admin_panel'))
            try:
                db.execute(
                    'UPDATE rooms SET room_number = ?, building_id = ? WHERE id = ?',
                    (room_number, building_id, room_id),
                )
                add_audit(session['user_id'], 'Edit room', f'Room {room_id} updated.')
                db.commit()
                flash('Room updated.', 'success')
            except sqlite3.IntegrityError:
                db.rollback()
                flash('That room already exists in the selected building.', 'warning')
            return redirect(url_for('admin_panel'))

        if action == 'delete_user':
            try:
                user_id = int(request.form.get('user_id', ''))
            except ValueError:
                flash('Invalid user record.', 'warning')
                return redirect(url_for('admin_panel'))
            if user_id == session['user_id']:
                flash('You cannot delete your own account.', 'warning')
                return redirect(url_for('admin_panel'))
            target_user = db.execute('SELECT email FROM users WHERE id = ?', (user_id,)).fetchone()
            if not target_user:
                flash('User not found.', 'warning')
                return redirect(url_for('admin_panel'))
            try:
                db.execute('UPDATE audit_logs SET user_id = NULL WHERE user_id = ?', (user_id,))
                db.execute('DELETE FROM users WHERE id = ?', (user_id,))
                add_audit(session['user_id'], 'Delete user', f'Admin deleted account {target_user["email"]}.')
                db.commit()
                flash('User deleted.', 'success')
            except sqlite3.IntegrityError:
                db.rollback()
                flash('This user is referenced by system records. Deactivate the account instead to preserve history.', 'warning')
            return redirect(url_for('admin_panel'))

        if action == 'add_category':
            name = request.form.get('name', '').strip()
            if not name or len(name) > 80:
                flash('Enter a category name (up to 80 characters).', 'warning')
                return redirect(url_for('admin_panel'))
            db.execute('INSERT OR IGNORE INTO categories (name) VALUES (?)', (name,))
            add_audit(session['user_id'], 'Create category', f'Category {name} added.')
            db.commit()
            flash('Category added or already exists.', 'success')
            return redirect(url_for('admin_panel'))

        if action in ['edit_category', 'delete_category']:
            try:
                category_id = int(request.form.get('category_id', ''))
            except ValueError:
                flash('Invalid category record.', 'warning')
                return redirect(url_for('admin_panel'))
            if action == 'edit_category':
                name = request.form.get('name', '').strip()
                if not name or len(name) > 80:
                    flash('Enter a category name (up to 80 characters).', 'warning')
                    return redirect(url_for('admin_panel'))
                try:
                    db.execute('UPDATE categories SET name = ? WHERE id = ?', (name, category_id))
                    if db.execute('SELECT changes()').fetchone()[0]:
                        add_audit(session['user_id'], 'Edit category', f'Category {category_id} renamed to {name}.')
                        db.commit()
                        flash('Category updated.', 'success')
                    else:
                        flash('Category not found.', 'warning')
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash('A category with that name already exists.', 'warning')
            else:
                try:
                    db.execute('DELETE FROM categories WHERE id = ?', (category_id,))
                    add_audit(session['user_id'], 'Delete category', f'Category {category_id} deleted.')
                    db.commit()
                    flash('Category deleted.', 'success')
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash('This category is used by existing issues and cannot be deleted.', 'warning')
            return redirect(url_for('admin_panel'))

        if action == 'add_building':
            name = request.form.get('building_name', '').strip()
            if not name or len(name) > 120:
                flash('Enter a building name (up to 120 characters).', 'warning')
                return redirect(url_for('admin_panel'))
            db.execute('INSERT OR IGNORE INTO buildings (name) VALUES (?)', (name,))
            add_audit(session['user_id'], 'Create building', f'Building {name} added.')
            db.commit()
            flash('Building added or already exists.', 'success')
            return redirect(url_for('admin_panel'))

        if action in ['edit_building', 'delete_building']:
            try:
                building_id = int(request.form.get('building_id', ''))
            except ValueError:
                flash('Invalid building record.', 'warning')
                return redirect(url_for('admin_panel'))
            if action == 'edit_building':
                name = request.form.get('building_name', '').strip()
                if not name or len(name) > 120:
                    flash('Enter a building name (up to 120 characters).', 'warning')
                    return redirect(url_for('admin_panel'))
                try:
                    db.execute('UPDATE buildings SET name = ? WHERE id = ?', (name, building_id))
                    if db.execute('SELECT changes()').fetchone()[0]:
                        add_audit(session['user_id'], 'Edit building', f'Building {building_id} renamed to {name}.')
                        db.commit()
                        flash('Building updated.', 'success')
                    else:
                        flash('Building not found.', 'warning')
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash('A building with that name already exists.', 'warning')
            else:
                try:
                    db.execute('DELETE FROM buildings WHERE id = ?', (building_id,))
                    add_audit(session['user_id'], 'Delete building', f'Building {building_id} deleted.')
                    db.commit()
                    flash('Building deleted.', 'success')
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash('Remove its rooms and resolve location references before deleting this building.', 'warning')
            return redirect(url_for('admin_panel'))

        if action == 'add_room':
            building_id = request.form.get('building_id', '')
            room_number = request.form.get('room_number', '').strip()
            if not building_id or not room_number or len(room_number) > 60:
                flash('Select a building and enter a room name (up to 60 characters).', 'warning')
                return redirect(url_for('admin_panel'))
            try:
                db.execute('INSERT OR IGNORE INTO rooms (building_id, room_number) VALUES (?, ?)', (building_id, room_number))
                if db.execute('SELECT changes()').fetchone()[0]:
                    add_audit(session['user_id'], 'Create room', f'Room {room_number} added.')
                    db.commit()
                    flash('Room added.', 'success')
                else:
                    flash('That room already exists in the selected building.', 'warning')
            except sqlite3.IntegrityError:
                db.rollback()
                flash('Select a valid building for this room.', 'warning')
            return redirect(url_for('admin_panel'))

        if action in ['edit_room', 'delete_room']:
            try:
                room_id = int(request.form.get('room_id', ''))
            except ValueError:
                flash('Invalid room record.', 'warning')
                return redirect(url_for('admin_panel'))
            if action == 'edit_room':
                room_number = request.form.get('room_number', '').strip()
                building_id = request.form.get('building_id', '')
                if not room_number or len(room_number) > 60:
                    flash('Enter a room name (up to 60 characters).', 'warning')
                    return redirect(url_for('admin_panel'))
                try:
                    db.execute('UPDATE rooms SET room_number = ?, building_id = ? WHERE id = ?', (room_number, building_id, room_id))
                    if db.execute('SELECT changes()').fetchone()[0]:
                        add_audit(session['user_id'], 'Edit room', f'Room {room_id} updated.')
                        db.commit()
                        flash('Room updated.', 'success')
                    else:
                        flash('Room not found.', 'warning')
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash('That room already exists in the selected building, or the building is invalid.', 'warning')
            else:
                try:
                    db.execute('DELETE FROM rooms WHERE id = ?', (room_id,))
                    add_audit(session['user_id'], 'Delete room', f'Room {room_id} deleted.')
                    db.commit()
                    flash('Room deleted.', 'success')
                except sqlite3.IntegrityError:
                    db.rollback()
                    flash('This room is referenced by existing issues and cannot be deleted.', 'warning')
            return redirect(url_for('admin_panel'))

    search = request.args.get('q', '').strip()[:100]
    search_pattern = f'%{search}%'
    categories = db.execute(
        'SELECT * FROM categories WHERE ? = "" OR name LIKE ? ORDER BY name',
        (search, search_pattern),
    ).fetchall()
    buildings = db.execute(
        'SELECT * FROM buildings WHERE ? = "" OR name LIKE ? ORDER BY name',
        (search, search_pattern),
    ).fetchall()
    rooms = db.execute(
        '''
        SELECT r.*, b.name AS building_name FROM rooms r JOIN buildings b ON b.id = r.building_id
        WHERE ? = "" OR r.room_number LIKE ? OR b.name LIKE ?
        ORDER BY b.name, r.room_number
        ''',
        (search, search_pattern, search_pattern),
    ).fetchall()
    users = db.execute(
        '''
        SELECT * FROM users
        WHERE ? = "" OR first_name LIKE ? OR last_name LIKE ? OR email LIKE ? OR role LIKE ?
        ORDER BY role, last_name, first_name
        ''',
        (search, search_pattern, search_pattern, search_pattern, search_pattern),
    ).fetchall()
    audit_logs = db.execute(
        '''
        SELECT a.*, u.email AS user_email FROM audit_logs a
        LEFT JOIN users u ON u.id = a.user_id
        ORDER BY a.created_at DESC LIMIT 50
        '''
    ).fetchall()
    issue_search = f'%{search}%'
    issues = db.execute(
        '''
        SELECT i.*, c.name AS category_name, b.name AS building_name, r.room_number,
               u.first_name || ' ' || u.last_name AS reporter_name
        FROM issues i
        JOIN categories c ON c.id = i.category_id
        JOIN buildings b ON b.id = i.building_id
        JOIN rooms r ON r.id = i.room_id
        JOIN users u ON u.id = i.reporter_id
        WHERE ? = "" OR i.ticket_number LIKE ? OR i.title LIKE ? OR u.email LIKE ?
        ORDER BY i.created_at DESC LIMIT 50
        ''',
        (search, issue_search, issue_search, issue_search),
    ).fetchall()
    stats = {
        'issues_total': db.execute('SELECT COUNT(*) FROM issues').fetchone()[0],
        'users_total': db.execute('SELECT COUNT(*) FROM users').fetchone()[0],
        'resolved_total': db.execute("SELECT COUNT(*) FROM issues WHERE status IN ('Resolved', 'Closed')").fetchone()[0],
        'pending_total': db.execute("SELECT COUNT(*) FROM issues WHERE status IN ('Pending', 'Assigned', 'In Progress')").fetchone()[0],
        'lost_found_total': db.execute("SELECT COUNT(*) FROM lost_found_items WHERE status IN ('Open', 'Matched')").fetchone()[0],
        'vehicle_pending_total': db.execute("SELECT COUNT(*) FROM vehicle_registrations WHERE status = 'Pending'").fetchone()[0],
    }

    return render_template('admin.html', user=user_from_session(), stats=stats, audit_logs=audit_logs, categories=categories, buildings=buildings, rooms=rooms, users=users, issues=issues, search=search)


def get_issue_report_rows(filters):
    db = get_db()
    query = '''
        SELECT i.*, c.name AS category_name, b.name AS building_name, r.room_number, u.first_name || ' ' || u.last_name AS reporter_name,
               tech.first_name || ' ' || tech.last_name AS technician_name
        FROM issues i
        JOIN categories c ON c.id = i.category_id
        JOIN buildings b ON b.id = i.building_id
        JOIN rooms r ON r.id = i.room_id
        JOIN users u ON u.id = i.reporter_id
        LEFT JOIN assignments a ON a.id = (
            SELECT MAX(a2.id) FROM assignments a2 WHERE a2.issue_id = i.id
        )
        LEFT JOIN users tech ON tech.id = a.technician_id
        WHERE 1 = 1
    '''
    params = []
    if filters.get('category_id'):
        query += ' AND i.category_id = ?'
        params.append(filters['category_id'])
    if filters.get('building_id'):
        query += ' AND i.building_id = ?'
        params.append(filters['building_id'])
    if filters.get('status'):
        query += ' AND i.status = ?'
        params.append(filters['status'])
    if filters.get('technician_id'):
        query += ' AND a.technician_id = ?'
        params.append(filters['technician_id'])
    if filters.get('start_date'):
        query += ' AND date(i.created_at) >= date(?)'
        params.append(filters['start_date'])
    if filters.get('end_date'):
        query += ' AND date(i.created_at) <= date(?)'
        params.append(filters['end_date'])
    if filters.get('q'):
        query += ' AND (i.ticket_number LIKE ? OR i.title LIKE ? OR i.description LIKE ? OR u.email LIKE ?)'
        search_pattern = f'%{filters["q"]}%'
        params.extend([search_pattern] * 4)
    sort_columns = {
        'created_at': 'i.created_at',
        'due_date': 'i.due_date',
        'priority': 'i.priority',
        'status': 'i.status',
        'ticket_number': 'i.ticket_number',
        'category': 'c.name',
        'building': 'b.name',
    }
    sort_column = sort_columns.get(filters.get('sort'), 'i.created_at')
    direction = 'ASC' if filters.get('direction') == 'asc' else 'DESC'
    query += f' ORDER BY {sort_column} {direction}, i.id DESC'
    return db.execute(query, params).fetchall()


def parse_report_filters():
    filters = {
        'category_id': request.args.get('category_id', '').strip(),
        'building_id': request.args.get('building_id', '').strip(),
        'status': request.args.get('status', '').strip(),
        'technician_id': request.args.get('technician_id', '').strip(),
        'start_date': request.args.get('start_date', '').strip(),
        'end_date': request.args.get('end_date', '').strip(),
        'q': request.args.get('q', '').strip()[:100],
        'sort': request.args.get('sort', 'created_at').strip(),
        'direction': request.args.get('direction', 'desc').strip().lower(),
    }
    if filters['status'] and filters['status'] not in ['Pending', 'Assigned', 'In Progress', 'Resolved', 'Closed', 'Cancelled']:
        raise ValueError('Choose a valid report status.')
    for key in ['category_id', 'building_id', 'technician_id']:
        if filters[key] and not filters[key].isdigit():
            raise ValueError('Category, building and technician filters must be valid selections.')
    for key in ['start_date', 'end_date']:
        if filters[key]:
            try:
                datetime.strptime(filters[key], '%Y-%m-%d')
            except ValueError as error:
                raise ValueError('Enter valid start and end dates.') from error
    if filters['start_date'] and filters['end_date'] and filters['start_date'] > filters['end_date']:
        raise ValueError('The start date must be on or before the end date.')
    if filters['sort'] not in ['created_at', 'due_date', 'priority', 'status', 'ticket_number', 'category', 'building']:
        raise ValueError('Choose a valid report sort field.')
    if filters['direction'] not in ['asc', 'desc']:
        raise ValueError('Choose ascending or descending sort order.')
    return filters


@app.route('/reports')
@role_required('admin', 'supervisor')
def reports():
    db = get_db()
    categories = db.execute('SELECT * FROM categories ORDER BY name').fetchall()
    buildings = db.execute('SELECT * FROM buildings ORDER BY name').fetchall()
    technicians = db.execute('SELECT * FROM users WHERE role = ? ORDER BY last_name', ('technician',)).fetchall()

    try:
        filters = parse_report_filters()
    except ValueError as error:
        flash(str(error), 'warning')
        return redirect(url_for('reports'))
    rows = get_issue_report_rows(filters)
    return render_template(
        'reports.html',
        rows=rows,
        categories=categories,
        buildings=buildings,
        technicians=technicians,
        filters=filters,
        generated_at=datetime.now().strftime('%Y-%m-%d %H:%M'),
        organization_name=os.environ.get('CAMPUSFIX_ORGANIZATION_NAME', 'CampusFix Campus Services'),
    )


@app.route('/reports/export/<string:format>')
@role_required('admin', 'supervisor')
def export_reports(format):
    if format not in ['pdf', 'xlsx']:
        abort(404)
    try:
        filters = parse_report_filters()
    except ValueError as error:
        abort(400, description=str(error))
    rows = get_issue_report_rows(filters)
    generated_at = datetime.now().strftime('%Y-%m-%d %H:%M')
    organization_name = os.environ.get('CAMPUSFIX_ORGANIZATION_NAME', 'CampusFix Campus Services')

    if format == 'xlsx':
        import xlsxwriter
        output = io.BytesIO()
        workbook = xlsxwriter.Workbook(output, {'in_memory': True})
        worksheet = workbook.add_worksheet('CampusFix Reports')
        title_format = workbook.add_format({'bold': True, 'font_size': 16, 'font_color': '#17365D'})
        detail_format = workbook.add_format({'italic': True, 'font_color': '#666666'})
        header_format = workbook.add_format({'bold': True, 'font_color': '#FFFFFF', 'bg_color': '#0D6EFD', 'border': 1})
        worksheet.insert_image(
            'A1',
            os.path.join(BASE_DIR, 'static', 'campusfix-logo.png'),
            {'x_scale': 0.75, 'y_scale': 0.75, 'x_offset': 4, 'y_offset': 5},
        )
        worksheet.merge_range(0, 1, 0, 7, organization_name, title_format)
        worksheet.merge_range(1, 1, 1, 7, f'CampusFix issue report · Generated {generated_at}', detail_format)
        headers = ['Ticket', 'Title', 'Category', 'Location', 'Technician', 'Reporter', 'Status', 'Submitted']
        for col, header in enumerate(headers):
            worksheet.write(3, col, header, header_format)
        for row_index, row in enumerate(rows, start=4):
            data = [
                row['ticket_number'],
                row['title'],
                row['category_name'],
                f"{row['building_name']} - {row['room_number']}",
                row['technician_name'] or 'Unassigned',
                row['reporter_name'],
                row['status'],
                row['created_at'],
            ]
            for col_index, value in enumerate(data):
                worksheet.write_string(row_index, col_index, str(value))
        worksheet.freeze_panes(4, 0)
        worksheet.autofilter(3, 0, max(3, len(rows) + 3), len(headers) - 1)
        worksheet.set_column('A:A', 22)
        worksheet.set_column('B:B', 36)
        worksheet.set_column('C:C', 22)
        worksheet.set_column('D:D', 28)
        worksheet.set_column('E:F', 24)
        worksheet.set_column('G:G', 16)
        worksheet.set_column('H:H', 22)
        worksheet.set_row(0, 24)
        worksheet.set_row(1, 24)
        workbook.close()
        output.seek(0)
        return send_file(output, as_attachment=True, download_name='campusfix_reports.xlsx', mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

    if format == 'pdf':
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

        output = io.BytesIO()
        doc = SimpleDocTemplate(output, pagesize=landscape(A4), leftMargin=24, rightMargin=24, topMargin=60, bottomMargin=38)
        elements = []
        styles = getSampleStyleSheet()
        elements.append(Paragraph('Campus maintenance issue report', styles['Heading2']))
        elements.append(Paragraph(f'Filters applied: {html.escape(str(filters))}', styles['Normal']))
        elements.append(Spacer(1, 12))
        table_data = [['Ticket', 'Title', 'Category', 'Location', 'Technician', 'Status', 'Submitted']]
        for row in rows:
            table_data.append([
                row['ticket_number'],
                row['title'],
                row['category_name'],
                f"{row['building_name']} - {row['room_number']}",
                row['technician_name'] or 'Unassigned',
                row['status'],
                row['created_at'],
            ])
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#17365D')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ]))
        elements.append(table)
        def draw_report_brand(canvas, document):
            canvas.saveState()
            page_width, page_height = landscape(A4)
            canvas.setFillColor(colors.HexColor('#17365D'))
            canvas.roundRect(24, page_height - 40, 24, 24, 5, stroke=0, fill=1)
            canvas.setFillColor(colors.white)
            canvas.setFont('Helvetica-Bold', 13)
            canvas.drawCentredString(36, page_height - 32, 'C')
            canvas.setFillColor(colors.HexColor('#17365D'))
            canvas.setFont('Helvetica-Bold', 16)
            canvas.drawString(56, page_height - 32, 'CampusFix')
            canvas.setFont('Helvetica', 9)
            canvas.drawString(150, page_height - 32, organization_name)
            canvas.drawRightString(page_width - 24, page_height - 32, generated_at)
            canvas.setStrokeColor(colors.HexColor('#D8E0EA'))
            canvas.line(24, 28, page_width - 24, 28)
            canvas.setFillColor(colors.HexColor('#666666'))
            canvas.drawString(24, 16, 'CampusFix campus services · Standalone demonstration system')
            canvas.drawRightString(page_width - 24, 16, f'Page {document.page}')
            canvas.restoreState()

        doc.build(elements, onFirstPage=draw_report_brand, onLaterPages=draw_report_brand)
        output.seek(0)
        return send_file(output, as_attachment=True, download_name='campusfix_reports.pdf', mimetype='application/pdf')

    return redirect(url_for('reports'))


@app.route('/database-diagram')
@role_required('admin', 'supervisor')
def database_diagram():
    return render_template('database_diagram.html')


@app.route('/help')
def help_page():
    return render_template('help.html')


@app.route('/help/guide')
def download_user_guide():
    path = os.path.join(BASE_DIR, 'docs', 'user_and_deployment_guide.md')
    if not os.path.isfile(path):
        app.logger.error('CampusFix user and deployment guide is missing.')
        abort(404)
    return send_file(path, as_attachment=True, download_name='campusfix_user_and_deployment_guide.md', mimetype='text/markdown')


@app.route('/admin/backup')
@role_required('admin')
def download_backup():
    backup_path = create_manual_backup(get_db())
    if not backup_path or not os.path.isfile(backup_path):
        app.logger.error('CampusFix database backup is unavailable.')
        abort(500, description='Database backup could not be created.')
    return send_file(backup_path, as_attachment=True, download_name=os.path.basename(backup_path), mimetype='application/vnd.sqlite3')


@app.route('/database-diagram/download')
@role_required('admin', 'supervisor')
def database_diagram_download():
    path = os.path.join(BASE_DIR, 'docs', 'campusfix_er_diagram.md')
    if not os.path.exists(path):
        flash('Diagram file not found.', 'warning')
        return redirect(url_for('database_diagram'))
    return send_file(path, as_attachment=True, download_name='campusfix_er_diagram.md', mimetype='text/markdown')


@app.route('/api/notifications')
@login_required
def notifications_api():
    db = get_db()
    rows = db.execute(
        '''
        SELECT id, issue_id, message, created_at, NULL AS target_url, is_read, 'issue' AS kind
        FROM notifications WHERE user_id = ?
        UNION ALL
        SELECT id, NULL AS issue_id, message, created_at, target_url, (read_at IS NOT NULL) AS is_read, 'service' AS kind
        FROM service_notifications WHERE user_id = ?
        ORDER BY created_at DESC LIMIT 10
        ''',
        (session['user_id'], session['user_id']),
    ).fetchall()
    return {'notifications': [dict(row) for row in rows]}


@app.route('/notifications/<string:kind>/<int:notification_id>/read', methods=['POST'])
@login_required
def mark_notification_read(kind, notification_id):
    db = get_db()
    if kind == 'issue':
        cursor = db.execute(
            'UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?',
            (notification_id, session['user_id']),
        )
    elif kind == 'service':
        cursor = db.execute(
            'UPDATE service_notifications SET read_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?',
            (notification_id, session['user_id']),
        )
    else:
        abort(404)
    if cursor.rowcount == 0:
        flash('Notification not found.', 'warning')
    else:
        db.commit()
        flash('Notification marked as read.', 'success')
    return redirect(url_for('dashboard'))


init_db()


if __name__ == '__main__':
    debug_mode = os.environ.get('CAMPUSFIX_DEBUG', '').lower() == 'true'
    backup_stop = threading.Event()
    backup_thread = threading.Thread(target=daily_backup_worker, args=(backup_stop,), name='campusfix-daily-backup', daemon=True)
    backup_thread.start()
    try:
        app.run(debug=debug_mode, host=os.environ.get('CAMPUSFIX_HOST', '127.0.0.1'), port=int(os.environ.get('CAMPUSFIX_PORT', '5000')))
    finally:
        backup_stop.set()
