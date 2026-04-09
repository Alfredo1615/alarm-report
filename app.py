import json
import os
import re
import sqlite3
import socket
import threading
import time
from datetime import datetime
from functools import wraps
from typing import Optional

import requests

from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from pywebpush import webpush, WebPushException
except Exception:
    webpush = None
    WebPushException = Exception

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, 'alarms.db')
SECRET_KEY = os.environ.get('SECRET_KEY', 'change-this-secret-key')
SITE_NAME = os.environ.get('SITE_NAME', 'CPC Alarm Center Pro')
PORT = int(os.environ.get('PORT', '5000'))
HOST = os.environ.get('HOST', '0.0.0.0')
PUBLIC_BASE_URL = os.environ.get('PUBLIC_BASE_URL', '')
VAPID_PUBLIC_KEY = os.environ.get('VAPID_PUBLIC_KEY', '')
VAPID_PRIVATE_KEY = os.environ.get('VAPID_PRIVATE_KEY', '')
VAPID_CLAIMS_EMAIL = os.environ.get('VAPID_CLAIMS_EMAIL', 'mailto:admin@example.com')
MAX_CPCS_PER_USER = 5
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '').strip()
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '').strip()
TWILIO_FROM_NUMBER = os.environ.get('TWILIO_FROM_NUMBER', '').strip()

app = Flask(__name__)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SITE_NAME'] = SITE_NAME

BRIDGE_THREADS = {}
BRIDGE_STOP_FLAGS = {}
BRIDGE_LOCK = threading.Lock()


def utc_now() -> str:
    return datetime.utcnow().isoformat(timespec='seconds') + 'Z'


def db_connect():
    db = sqlite3.connect(DB_PATH, check_same_thread=False)
    db.row_factory = sqlite3.Row
    return db


def get_db():
    if 'db' not in g:
        g.db = db_connect()
    return g.db


@app.teardown_appcontext
def close_db(exc=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def column_exists(db, table, column):
    rows = db.execute(f'PRAGMA table_info({table})').fetchall()
    return any(r['name'] == column for r in rows)


def init_db():
    db = db_connect()
    cur = db.cursor()
    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL,
            is_admin INTEGER NOT NULL DEFAULT 0,
            phone_number TEXT DEFAULT '',
            sms_enabled INTEGER NOT NULL DEFAULT 0
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS cpcs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL DEFAULT 1,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 14106,
            timeout INTEGER NOT NULL DEFAULT 15,
            buffer_mode TEXT NOT NULL DEFAULT 'line',
            parser_hint TEXT NOT NULL DEFAULT 'auto',
            enabled INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS bridge_status (
            cpc_id INTEGER PRIMARY KEY,
            running INTEGER NOT NULL DEFAULT 0,
            connected INTEGER NOT NULL DEFAULT 0,
            last_connect_at TEXT DEFAULT '',
            last_message_at TEXT DEFAULT '',
            last_error TEXT DEFAULT '',
            messages_seen INTEGER NOT NULL DEFAULT 0,
            last_bytes INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(cpc_id) REFERENCES cpcs(id) ON DELETE CASCADE
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS alarms (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL DEFAULT 1,
            cpc_id INTEGER,
            source TEXT NOT NULL,
            site TEXT NOT NULL,
            rack TEXT DEFAULT '',
            priority TEXT NOT NULL DEFAULT 'MEDIUM',
            message TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'ACTIVE',
            created_at TEXT NOT NULL,
            acknowledged_at TEXT DEFAULT '',
            resolved_at TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            external_id TEXT UNIQUE,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(cpc_id) REFERENCES cpcs(id) ON DELETE SET NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS raw_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL DEFAULT 1,
            cpc_id INTEGER,
            source TEXT NOT NULL,
            payload TEXT NOT NULL,
            created_at TEXT NOT NULL,
            parsed INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
            FOREIGN KEY(cpc_id) REFERENCES cpcs(id) ON DELETE SET NULL
        )
    ''')
    cur.execute('''
        CREATE TABLE IF NOT EXISTS push_subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            endpoint TEXT UNIQUE NOT NULL,
            p256dh TEXT NOT NULL,
            auth TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
        )
    ''')

    # migrations for prior versions
    if not column_exists(db, 'cpcs', 'user_id'):
        cur.execute('ALTER TABLE cpcs ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1')
    if not column_exists(db, 'alarms', 'user_id'):
        cur.execute('ALTER TABLE alarms ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1')
    if not column_exists(db, 'raw_events', 'user_id'):
        cur.execute('ALTER TABLE raw_events ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1')
    if not column_exists(db, 'users', 'phone_number'):
        cur.execute("ALTER TABLE users ADD COLUMN phone_number TEXT DEFAULT ''")
    if not column_exists(db, 'users', 'sms_enabled'):
        cur.execute('ALTER TABLE users ADD COLUMN sms_enabled INTEGER NOT NULL DEFAULT 0')

    defaults = {
        'company_name': 'My Store',
        'theme': 'dark',
        'public_base_url': PUBLIC_BASE_URL,
        'notify_browser': '1',
        'language': 'en',
    }
    for k, v in defaults.items():
        cur.execute('INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)', (k, v))
    db.commit()
    db.close()


def get_settings(db=None):
    db = db or get_db()
    rows = db.execute('SELECT key, value FROM app_settings').fetchall()
    data = {
        'company_name': 'My Store',
        'theme': 'dark',
        'public_base_url': PUBLIC_BASE_URL,
        'notify_browser': '1',
        'language': 'en',
    }
    data.update({r['key']: r['value'] for r in rows})
    return data


def save_setting(key, value, db=None):
    db = db or get_db()
    db.execute('REPLACE INTO app_settings (key, value) VALUES (?, ?)', (key, str(value)))


def current_user():
    if not session.get('user_id'):
        return None
    return get_db().execute('SELECT * FROM users WHERE id = ?', (session['user_id'],)).fetchone()


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login', next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            return redirect(url_for('login'))
        if not user['is_admin']:
            flash('Only the administrator can do that.', 'error')
            return redirect(url_for('dashboard'))
        return fn(*args, **kwargs)
    return wrapper


def owner_or_admin_required_for_cpc(cpc_id):
    user = current_user()
    db = get_db()
    cpc = db.execute('SELECT * FROM cpcs WHERE id = ?', (cpc_id,)).fetchone()
    if not cpc:
        return None, redirect(url_for('settings'))
    if not user['is_admin'] and cpc['user_id'] != user['id']:
        flash('You do not have access to that CPC.', 'error')
        return None, redirect(url_for('settings'))
    return cpc, None


def normalize_priority(text: str) -> str:
    value = (text or '').upper()
    if any(x in value for x in ['CRIT', 'URGENT', 'HIGH', 'FAIL', 'ALARM']):
        return 'HIGH'
    if any(x in value for x in ['LOW']):
        return 'LOW'
    return 'MEDIUM'


def normalize_phone_number(value: str) -> str:
    raw = (value or '').strip()
    if not raw:
        return ''
    keep = []
    for i, ch in enumerate(raw):
        if ch.isdigit():
            keep.append(ch)
        elif ch == '+' and i == 0:
            keep.append(ch)
    cleaned = ''.join(keep)
    if cleaned.startswith('00'):
        cleaned = '+' + cleaned[2:]
    if cleaned and not cleaned.startswith('+'):
        digits = ''.join(ch for ch in cleaned if ch.isdigit())
        if len(digits) == 10:
            cleaned = '+1' + digits
        else:
            cleaned = '+' + digits
    return cleaned


def send_sms_notification(phone_number: str, message: str) -> bool:
    phone = normalize_phone_number(phone_number)
    if not phone or not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_FROM_NUMBER:
        return False
    body = (message or '').strip()[:1500]
    try:
        response = requests.post(
            f'https://api.twilio.com/2010-04-01/Accounts/{TWILIO_ACCOUNT_SID}/Messages.json',
            data={'From': TWILIO_FROM_NUMBER, 'To': phone, 'Body': body},
            auth=(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN),
            timeout=20,
        )
        return response.ok
    except Exception:
        return False


def send_sms_notifications(db, user_id: int, site: str, message: str, priority: str):
    user = db.execute('SELECT phone_number, sms_enabled FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user or not user['sms_enabled'] or not (user['phone_number'] or '').strip():
        return
    sms_text = f"CPC ALERT [{normalize_priority(priority)}] {site}: {message}"
    send_sms_notification(user['phone_number'], sms_text)


def parse_direct_payload(payload: str):
    text = payload.strip()
    if not text:
        return None
    upper = text.upper()
    if not any(token in upper for token in ['ALARM', 'FAIL', 'NOTICE', 'ADVISORY', 'TEMP', 'SENSOR']):
        return None
    priority = 'HIGH' if any(token in upper for token in ['ALARM', 'FAIL', 'CRITICAL']) else 'MEDIUM'
    cleaned = re.sub(r'\s+', ' ', text)[:350]
    return {'priority': priority, 'message': cleaned}


def send_push_notifications(db, user_id, payload):
    if not webpush or not VAPID_PUBLIC_KEY or not VAPID_PRIVATE_KEY:
        return
    subs = db.execute('SELECT * FROM push_subscriptions WHERE user_id = ?', (user_id,)).fetchall()
    vapid_claims = {'sub': VAPID_CLAIMS_EMAIL}
    body = json.dumps(payload)
    for sub in subs:
        sub_info = {'endpoint': sub['endpoint'], 'keys': {'p256dh': sub['p256dh'], 'auth': sub['auth']}}
        try:
            webpush(subscription_info=sub_info, data=body, vapid_private_key=VAPID_PRIVATE_KEY, vapid_claims=vapid_claims)
        except Exception:
            continue


def create_alarm(db, user_id: int, cpc_id: Optional[int], source: str, site: str, message: str, priority='MEDIUM', external_id=None, rack=''):
    now = utc_now()
    try:
        db.execute(
            '''INSERT INTO alarms (user_id, cpc_id, source, site, rack, priority, message, status, created_at, external_id)
               VALUES (?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)''',
            (user_id, cpc_id, source, site, rack, normalize_priority(priority), message, now, external_id)
        )
        db.commit()
        alarm_id = db.execute('SELECT last_insert_rowid() AS id').fetchone()['id']
        send_push_notifications(db, user_id, {'id': alarm_id, 'title': f'CPC Alarm · {site}', 'body': message, 'url': '/'})
        send_sms_notifications(db, user_id, site, message, priority)
        return alarm_id
    except sqlite3.IntegrityError:
        return None


def save_raw_event(db, user_id: int, cpc_id: int, source: str, payload: str, parsed=0):
    db.execute(
        'INSERT INTO raw_events (user_id, cpc_id, source, payload, created_at, parsed) VALUES (?, ?, ?, ?, ?, ?)',
        (user_id, cpc_id, source, payload[:8000], utc_now(), parsed)
    )
    db.commit()


def update_bridge_status(cpc_id: int, **kwargs):
    db = db_connect()
    db.execute('INSERT OR IGNORE INTO bridge_status (cpc_id) VALUES (?)', (cpc_id,))
    fields = ', '.join(f"{key} = ?" for key in kwargs.keys())
    values = list(kwargs.values()) + [cpc_id]
    db.execute(f'UPDATE bridge_status SET {fields} WHERE cpc_id = ?', values)
    db.commit()
    db.close()


def get_bridge_status_rows(db=None, user_id=None, is_admin=False):
    db = db or get_db()
    where = '' if is_admin else 'WHERE c.user_id = ?'
    params = () if is_admin else (user_id,)
    return db.execute(f'''
        SELECT c.id, c.user_id, u.username AS owner_username, c.name, c.host, c.port, c.enabled,
               COALESCE(bs.running, 0) AS running,
               COALESCE(bs.connected, 0) AS connected,
               COALESCE(bs.last_connect_at, '') AS last_connect_at,
               COALESCE(bs.last_message_at, '') AS last_message_at,
               COALESCE(bs.last_error, '') AS last_error,
               COALESCE(bs.messages_seen, 0) AS messages_seen,
               COALESCE(bs.last_bytes, 0) AS last_bytes
        FROM cpcs c
        JOIN users u ON u.id = c.user_id
        LEFT JOIN bridge_status bs ON bs.cpc_id = c.id
        {where}
        ORDER BY c.name COLLATE NOCASE
    ''', params).fetchall()


def bridge_worker(cpc_id: int):
    stop_event = BRIDGE_STOP_FLAGS[cpc_id]
    while not stop_event.is_set():
        db = db_connect()
        cpc = db.execute('SELECT * FROM cpcs WHERE id = ?', (cpc_id,)).fetchone()
        if not cpc or not cpc['enabled']:
            update_bridge_status(cpc_id, running=0, connected=0, last_error='Disabled')
            db.close()
            return
        host = cpc['host'].strip()
        port = int(cpc['port'])
        timeout = int(cpc['timeout'])
        buffer_mode = cpc['buffer_mode']
        update_bridge_status(cpc_id, running=1, connected=0, last_error='')
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                update_bridge_status(cpc_id, connected=1, last_connect_at=utc_now(), last_error='')
                buffer = b''
                while not stop_event.is_set():
                    chunk = sock.recv(4096)
                    if not chunk:
                        raise ConnectionError('Connection closed by CPC')
                    buffer += chunk
                    current_seen = db.execute('SELECT COALESCE(messages_seen, 0) + 1 AS v FROM bridge_status WHERE cpc_id = ?', (cpc_id,)).fetchone()['v']
                    update_bridge_status(cpc_id, last_message_at=utc_now(), last_bytes=len(chunk), messages_seen=current_seen)
                    pieces = []
                    if buffer_mode == 'line':
                        decoded = buffer.decode('utf-8', errors='replace')
                        if '\n' not in decoded and '\r' not in decoded and len(decoded) < 2048:
                            continue
                        pieces = [p.strip() for p in re.split(r'[\r\n]+', decoded) if p.strip()]
                        buffer = b''
                    else:
                        if len(buffer) < 128:
                            continue
                        pieces = [buffer.decode('utf-8', errors='replace').strip()]
                        buffer = b''
                    for piece in pieces:
                        parsed = parse_direct_payload(piece)
                        save_raw_event(db, cpc['user_id'], cpc_id, cpc['name'], piece, 1 if parsed else 0)
                        if parsed:
                            external_id = f'{cpc_id}:{hash(piece)}'
                            create_alarm(db, cpc['user_id'], cpc_id, cpc['name'], cpc['name'], parsed['message'], parsed['priority'], external_id=external_id)
        except Exception as exc:
            update_bridge_status(cpc_id, connected=0, running=1, last_error=str(exc)[:250])
            db.close()
            time.sleep(4)
            continue
        finally:
            update_bridge_status(cpc_id, connected=0)
            db.close()
        time.sleep(2)


def ensure_bridge_threads():
    db = db_connect()
    rows = db.execute('SELECT id, enabled FROM cpcs').fetchall()
    db.close()
    with BRIDGE_LOCK:
        active_ids = {r['id'] for r in rows if r['enabled']}
        for cpc_id in list(BRIDGE_THREADS.keys()):
            if cpc_id not in active_ids:
                BRIDGE_STOP_FLAGS[cpc_id].set()
                BRIDGE_THREADS.pop(cpc_id, None)
                BRIDGE_STOP_FLAGS.pop(cpc_id, None)
        for cpc_id in active_ids:
            thread = BRIDGE_THREADS.get(cpc_id)
            if thread and thread.is_alive():
                continue
            stop_event = threading.Event()
            BRIDGE_STOP_FLAGS[cpc_id] = stop_event
            thread = threading.Thread(target=bridge_worker, args=(cpc_id,), daemon=True)
            BRIDGE_THREADS[cpc_id] = thread
            thread.start()


def stop_and_restart_bridge(cpc_id: Optional[int] = None):
    with BRIDGE_LOCK:
        ids = [cpc_id] if cpc_id is not None else list(BRIDGE_THREADS.keys())
        for cid in ids:
            ev = BRIDGE_STOP_FLAGS.get(cid)
            if ev:
                ev.set()
            BRIDGE_THREADS.pop(cid, None)
            BRIDGE_STOP_FLAGS.pop(cid, None)
    time.sleep(0.5)
    ensure_bridge_threads()


@app.context_processor
def inject_globals():
    return {'site_name': SITE_NAME, 'current_user': current_user(), 'vapid_public_key': VAPID_PUBLIC_KEY, 'max_cpcs_per_user': MAX_CPCS_PER_USER}


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    db = get_db()
    existing = db.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']
    if existing:
        return redirect(url_for('login'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not username or not password:
            flash('Enter a username and password.', 'error')
        elif password != confirm:
            flash('Passwords do not match.', 'error')
        else:
            db.execute('INSERT INTO users (username, password_hash, created_at, is_admin) VALUES (?, ?, ?, 1)', (username, generate_password_hash(password), utc_now()))
            db.commit()
            flash('Administrator created. Please sign in.', 'success')
            return redirect(url_for('login'))
    return render_template('setup.html', settings=get_settings(db))


@app.route('/login', methods=['GET', 'POST'])
def login():
    db = get_db()
    if not db.execute('SELECT COUNT(*) AS c FROM users').fetchone()['c']:
        return redirect(url_for('setup'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(request.args.get('next') or url_for('dashboard'))
        flash('Invalid username or password.', 'error')
    return render_template('login.html', settings=get_settings(db))


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/')
@login_required
def dashboard():
    db = get_db()
    user = current_user()
    where = '' if user['is_admin'] else 'WHERE a.user_id = ?'
    params = () if user['is_admin'] else (user['id'],)
    stats = db.execute(f'''
        SELECT
          SUM(CASE WHEN status = 'ACTIVE' THEN 1 ELSE 0 END) AS active,
          SUM(CASE WHEN status = 'ACK' THEN 1 ELSE 0 END) AS ack,
          SUM(CASE WHEN status = 'RESOLVED' THEN 1 ELSE 0 END) AS resolved,
          COUNT(*) AS total
        FROM alarms a {where}
    ''', params).fetchone()
    active = db.execute(f'''
        SELECT a.*, c.name AS cpc_name
        FROM alarms a LEFT JOIN cpcs c ON c.id = a.cpc_id
        {where} {'AND' if where else 'WHERE'} a.status = 'ACTIVE'
        ORDER BY a.created_at DESC
        LIMIT 100
    ''', params).fetchall()
    recent = db.execute(f'''
        SELECT a.*, c.name AS cpc_name
        FROM alarms a LEFT JOIN cpcs c ON c.id = a.cpc_id
        {where}
        ORDER BY a.created_at DESC
        LIMIT 30
    ''', params).fetchall()
    raw_recent = db.execute(f'''
        SELECT r.*, c.name AS cpc_name
        FROM raw_events r LEFT JOIN cpcs c ON c.id = r.cpc_id
        {'' if user['is_admin'] else 'WHERE r.user_id = ?'}
        ORDER BY r.created_at DESC
        LIMIT 20
    ''', () if user['is_admin'] else (user['id'],)).fetchall()
    bridges = get_bridge_status_rows(db, user['id'], bool(user['is_admin']))
    cpcs = db.execute(f'''
        SELECT c.*, u.username AS owner_username
        FROM cpcs c JOIN users u ON u.id = c.user_id
        {'' if user['is_admin'] else 'WHERE c.user_id = ?'}
        ORDER BY c.name COLLATE NOCASE
    ''', () if user['is_admin'] else (user['id'],)).fetchall()
    return render_template('dashboard.html', stats=stats, active=active, recent=recent, raw_recent=raw_recent, bridges=bridges, cpcs=cpcs, settings=get_settings(db))


@app.route('/history')
@login_required
def history():
    db = get_db()
    user = current_user()
    status = request.args.get('status', 'all')
    clauses = []
    params = []
    if not user['is_admin']:
        clauses.append('a.user_id = ?')
        params.append(user['id'])
    if status in ('ACTIVE', 'ACK', 'RESOLVED'):
        clauses.append('a.status = ?')
        params.append(status)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    alarms = db.execute(f'''
        SELECT a.*, c.name AS cpc_name
        FROM alarms a LEFT JOIN cpcs c ON c.id = a.cpc_id
        {where}
        ORDER BY a.created_at DESC LIMIT 500
    ''', tuple(params)).fetchall()
    return render_template('history.html', alarms=alarms, status_filter=status, settings=get_settings(db))


@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    db = get_db()
    user = current_user()
    if request.method == 'POST' and user['is_admin']:
        save_setting('company_name', request.form.get('company_name', '').strip(), db)
        save_setting('theme', request.form.get('theme', 'dark'), db)
        save_setting('public_base_url', request.form.get('public_base_url', '').strip(), db)
        save_setting('notify_browser', request.form.get('notify_browser', '1'), db)
        save_setting('language', 'en', db)
        db.commit()
        flash('Settings saved.', 'success')
        return redirect(url_for('settings'))
    settings_data = get_settings(db)
    cpcs = db.execute(f'''SELECT c.*, u.username AS owner_username FROM cpcs c JOIN users u ON u.id = c.user_id {'' if user['is_admin'] else 'WHERE c.user_id = ?'} ORDER BY c.name COLLATE NOCASE''', () if user['is_admin'] else (user['id'],)).fetchall()
    bridges = get_bridge_status_rows(db, user['id'], bool(user['is_admin']))
    users = db.execute('SELECT id, username, created_at, is_admin FROM users ORDER BY username COLLATE NOCASE').fetchall() if user['is_admin'] else []
    cpc_counts = {r['user_id']: r['cnt'] for r in db.execute('SELECT user_id, COUNT(*) AS cnt FROM cpcs GROUP BY user_id').fetchall()}
    return render_template('settings.html', settings=settings_data, cpcs=cpcs, bridges=bridges, user=user, users=users, cpc_counts=cpc_counts)


@app.route('/settings/account', methods=['POST'])
@login_required
def update_account():
    db = get_db()
    user = current_user()
    username = request.form.get('username', '').strip()
    current_password = request.form.get('current_password', '')
    new_password = request.form.get('new_password', '')
    confirm_password = request.form.get('confirm_password', '')
    phone_number = normalize_phone_number(request.form.get('phone_number', ''))
    sms_enabled = 1 if request.form.get('sms_enabled') == '1' else 0

    if username and username != user['username']:
        try:
            db.execute('UPDATE users SET username = ? WHERE id = ?', (username, user['id']))
            session['username'] = username
        except sqlite3.IntegrityError:
            flash('That username already exists.', 'error')
            return redirect(url_for('settings'))
    db.execute('UPDATE users SET phone_number = ?, sms_enabled = ? WHERE id = ?', (phone_number, sms_enabled, user['id']))

    if new_password:
        if not check_password_hash(user['password_hash'], current_password):
            flash('Current password is not correct.', 'error')
            return redirect(url_for('settings'))
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('settings'))
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (generate_password_hash(new_password), user['id']))
    db.commit()
    flash('Account updated.', 'success')
    return redirect(url_for('settings'))


@app.route('/users/add', methods=['POST'])
@login_required
@admin_required
def add_user():
    db = get_db()
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    is_admin = 1 if request.form.get('is_admin') == '1' else 0
    if not username or not password:
        flash('Enter a username and password.', 'error')
        return redirect(url_for('settings'))
    try:
        db.execute('INSERT INTO users (username, password_hash, created_at, is_admin) VALUES (?, ?, ?, ?)', (username, generate_password_hash(password), utc_now(), is_admin))
        db.commit()
        flash('User created.', 'success')
    except sqlite3.IntegrityError:
        flash('That username already exists.', 'error')
    return redirect(url_for('settings'))


@app.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    user = current_user()
    if user_id == user['id']:
        flash('You cannot delete the current administrator.', 'error')
        return redirect(url_for('settings'))
    db = get_db()
    db.execute('DELETE FROM users WHERE id = ?', (user_id,))
    db.commit()
    ensure_bridge_threads()
    flash('User deleted.', 'success')
    return redirect(url_for('settings'))


def current_target_user_id():
    user = current_user()
    if user['is_admin']:
        try:
            target = int(request.form.get('user_id', user['id']))
        except Exception:
            target = user['id']
        return target
    return user['id']


@app.route('/cpcs/add', methods=['POST'])
@login_required
def add_cpc():
    db = get_db()
    user = current_user()
    target_user_id = current_target_user_id()
    count = db.execute('SELECT COUNT(*) AS c FROM cpcs WHERE user_id = ?', (target_user_id,)).fetchone()['c']
    if count >= MAX_CPCS_PER_USER:
        flash(f'Each user can have up to {MAX_CPCS_PER_USER} CPC connections.', 'error')
        return redirect(url_for('settings'))
    name = request.form.get('name', '').strip()
    host = request.form.get('host', '').strip()
    port = int(request.form.get('port', '14106') or 14106)
    timeout = int(request.form.get('timeout', '15') or 15)
    buffer_mode = request.form.get('buffer_mode', 'line')
    parser_hint = request.form.get('parser_hint', 'auto')
    enabled = 1 if request.form.get('enabled') == '1' else 0
    if not name or not host:
        flash('Enter a name and IP/host.', 'error')
        return redirect(url_for('settings'))
    now = utc_now()
    db.execute('''INSERT INTO cpcs (user_id, name, host, port, timeout, buffer_mode, parser_hint, enabled, created_at, updated_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (target_user_id, name, host, port, timeout, buffer_mode, parser_hint, enabled, now, now))
    db.commit()
    ensure_bridge_threads()
    flash('CPC added.', 'success')
    return redirect(url_for('settings'))


@app.route('/cpcs/<int:cpc_id>/update', methods=['POST'])
@login_required
def update_cpc(cpc_id):
    cpc, denied = owner_or_admin_required_for_cpc(cpc_id)
    if denied:
        return denied
    db = get_db()
    now = utc_now()
    db.execute('''UPDATE cpcs SET name=?, host=?, port=?, timeout=?, buffer_mode=?, parser_hint=?, enabled=?, updated_at=? WHERE id=?''',
               (request.form.get('name', '').strip(), request.form.get('host', '').strip(), int(request.form.get('port', '14106') or 14106), int(request.form.get('timeout', '15') or 15), request.form.get('buffer_mode', 'line'), request.form.get('parser_hint', 'auto'), 1 if request.form.get('enabled') == '1' else 0, now, cpc_id))
    db.commit()
    stop_and_restart_bridge(cpc_id)
    flash('CPC updated.', 'success')
    return redirect(url_for('settings'))


@app.route('/cpcs/<int:cpc_id>/delete', methods=['POST'])
@login_required
def delete_cpc(cpc_id):
    cpc, denied = owner_or_admin_required_for_cpc(cpc_id)
    if denied:
        return denied
    db = get_db()
    db.execute('DELETE FROM cpcs WHERE id = ?', (cpc_id,))
    db.commit()
    stop_and_restart_bridge(cpc_id)
    flash('CPC deleted.', 'success')
    return redirect(url_for('settings'))


@app.route('/api/alarms')
@login_required
def api_alarms():
    db = get_db()
    user = current_user()
    rows = db.execute(f'''SELECT a.*, c.name AS cpc_name FROM alarms a LEFT JOIN cpcs c ON c.id = a.cpc_id {'' if user['is_admin'] else 'WHERE a.user_id = ?'} ORDER BY a.created_at DESC LIMIT 100''', () if user['is_admin'] else (user['id'],)).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route('/api/alarm/test', methods=['POST'])
@login_required
def api_alarm_test():
    db = get_db()
    user = current_user()
    cpc = db.execute(f'''SELECT * FROM cpcs {'' if user['is_admin'] else 'WHERE user_id = ?'} ORDER BY id LIMIT 1''', () if user['is_admin'] else (user['id'],)).fetchone()
    target_user_id = cpc['user_id'] if cpc else user['id']
    cpc_id = cpc['id'] if cpc else None
    source = cpc['name'] if cpc else 'Local Test'
    site = cpc['name'] if cpc else get_settings(db).get('company_name', 'My Store')
    alarm_id = create_alarm(db, target_user_id, cpc_id, source, site, 'Test alarm from the app', 'HIGH', external_id=f'test:{time.time()}')
    return jsonify({'ok': True, 'id': alarm_id})


def user_alarm_filter_clause(user):
    return ('', ()) if user['is_admin'] else (' AND user_id = ?', (user['id'],))


@app.route('/api/alarm/<int:alarm_id>/ack', methods=['POST'])
@login_required
def api_alarm_ack(alarm_id):
    db = get_db()
    user = current_user()
    clause, params = user_alarm_filter_clause(user)
    db.execute(f"UPDATE alarms SET status='ACK', acknowledged_at=? WHERE id=?{clause}", (utc_now(), alarm_id, *params))
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/alarm/<int:alarm_id>/resolve', methods=['POST'])
@login_required
def api_alarm_resolve(alarm_id):
    db = get_db()
    user = current_user()
    clause, params = user_alarm_filter_clause(user)
    db.execute(f"UPDATE alarms SET status='RESOLVED', resolved_at=? WHERE id=?{clause}", (utc_now(), alarm_id, *params))
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/alarm/<int:alarm_id>/delete', methods=['POST'])
@login_required
def api_alarm_delete(alarm_id):
    db = get_db()
    user = current_user()
    clause, params = user_alarm_filter_clause(user)
    db.execute(f'DELETE FROM alarms WHERE id=?{clause}', (alarm_id, *params))
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/alarms/delete', methods=['POST'])
@login_required
def api_alarms_delete_bulk():
    db = get_db()
    user = current_user()
    mode = (request.get_json() or {}).get('mode', 'resolved') if request.is_json else 'resolved'
    clauses = []
    params = []
    if not user['is_admin']:
        clauses.append('user_id = ?')
        params.append(user['id'])
    if mode == 'resolved':
        clauses.append("status = 'RESOLVED'")
    elif mode == 'history':
        clauses.append("status IN ('ACK','RESOLVED')")
    elif mode == 'all':
        pass
    else:
        return jsonify({'error': 'Invalid mode'}), 400
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ''
    db.execute(f'DELETE FROM alarms {where}', tuple(params))
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/bridges/status')
@login_required
def api_bridges_status():
    user = current_user()
    return jsonify([dict(r) for r in get_bridge_status_rows(get_db(), user['id'], bool(user['is_admin']))])


@app.route('/api/bridges/reconnect', methods=['POST'])
@login_required
def api_bridges_reconnect():
    user = current_user()
    cpc_id = request.json.get('cpc_id') if request.is_json else None
    if cpc_id and not user['is_admin']:
        cpc = get_db().execute('SELECT * FROM cpcs WHERE id = ? AND user_id = ?', (cpc_id, user['id'])).fetchone()
        if not cpc:
            return jsonify({'error': 'Not found'}), 404
    stop_and_restart_bridge(cpc_id)
    return jsonify({'ok': True})


@app.route('/api/notifications/vapid-public-key')
@login_required
def api_vapid_public_key():
    return jsonify({'publicKey': VAPID_PUBLIC_KEY})


@app.route('/api/notifications/subscribe', methods=['POST'])
@login_required
def api_subscribe_notifications():
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    data = request.get_json() or {}
    endpoint = data.get('endpoint')
    keys = data.get('keys') or {}
    p256dh = keys.get('p256dh')
    auth = keys.get('auth')
    if not endpoint or not p256dh or not auth:
        return jsonify({'error': 'Incomplete subscription'}), 400
    db = get_db()
    db.execute('REPLACE INTO push_subscriptions (id, user_id, endpoint, p256dh, auth, created_at) VALUES ((SELECT id FROM push_subscriptions WHERE endpoint = ?), ?, ?, ?, ?, ?)', (endpoint, session['user_id'], endpoint, p256dh, auth, utc_now()))
    db.commit()
    return jsonify({'ok': True})


@app.route('/api/notifications/unsubscribe', methods=['POST'])
@login_required
def api_unsubscribe_notifications():
    if not request.is_json:
        return jsonify({'error': 'JSON required'}), 400
    endpoint = (request.get_json() or {}).get('endpoint', '')
    if endpoint:
        db = get_db()
        db.execute('DELETE FROM push_subscriptions WHERE endpoint = ? AND user_id = ?', (endpoint, session['user_id']))
        db.commit()
    return jsonify({'ok': True})


@app.route('/manifest.json')
@login_required
def manifest():
    return jsonify({
        'name': SITE_NAME,
        'short_name': 'CPC Alert',
        'start_url': '/',
        'display': 'standalone',
        'background_color': '#0e1628',
        'theme_color': '#0e1628',
        'icons': [
            {'src': url_for('static', filename='icon-192.png'), 'sizes': '192x192', 'type': 'image/png'},
            {'src': url_for('static', filename='icon-512.png'), 'sizes': '512x512', 'type': 'image/png'},
            {'src': url_for('static', filename='icon-maskable-512.png'), 'sizes': '512x512', 'type': 'image/png', 'purpose': 'maskable any'}
        ]
    })


@app.route('/service-worker.js')
def service_worker():
    return app.send_static_file('service-worker.js')


@app.route('/healthz')
def healthz():
    return 'ok', 200


def bootstrap():
    init_db()
    ensure_bridge_threads()


bootstrap()

if __name__ == '__main__':
    app.run(host=HOST, port=PORT, debug=False)
