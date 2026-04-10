import json
import os
import re
import select
import sqlite3
import socket
import threading
import time
from datetime import datetime
from functools import wraps
from typing import Optional

from flask import Flask, flash, g, jsonify, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

try:
    from pywebpush import webpush
except Exception:
    webpush = None

try:
    from twilio.rest import Client as TwilioClient
except Exception:
    TwilioClient = None

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
TWILIO_ACCOUNT_SID = os.environ.get('TWILIO_ACCOUNT_SID', '')
TWILIO_AUTH_TOKEN = os.environ.get('TWILIO_AUTH_TOKEN', '')
TWILIO_FROM_NUMBER = os.environ.get('TWILIO_FROM_NUMBER', '')
MAX_CPCS_PER_USER = 5
ALARM_DEDUPE_SECONDS = int(os.environ.get('ALARM_DEDUPE_SECONDS', '180'))

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
            site_label TEXT DEFAULT '',
            store_code TEXT DEFAULT '',
            device_notes TEXT DEFAULT '',
            scan_every_seconds INTEGER NOT NULL DEFAULT 0,
            host TEXT NOT NULL,
            port INTEGER NOT NULL DEFAULT 14106,
            timeout INTEGER NOT NULL DEFAULT 15,
            buffer_mode TEXT NOT NULL DEFAULT 'fsd',
            parser_hint TEXT NOT NULL DEFAULT 'fsd_auto',
            role TEXT NOT NULL DEFAULT 'client',
            startup_hex TEXT DEFAULT '',
            heartbeat_hex TEXT DEFAULT '',
            heartbeat_interval INTEGER NOT NULL DEFAULT 30,
            scan_hex TEXT DEFAULT '',
            scan_read_seconds INTEGER NOT NULL DEFAULT 4,
            auto_scan_on_connect INTEGER NOT NULL DEFAULT 0,
            crawl_mode INTEGER NOT NULL DEFAULT 1,
            crawl_interval INTEGER NOT NULL DEFAULT 45,
            crawl_payloads TEXT DEFAULT '',
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

    migrations = {
        ('users', 'phone_number'): "ALTER TABLE users ADD COLUMN phone_number TEXT DEFAULT ''",
        ('users', 'sms_enabled'): "ALTER TABLE users ADD COLUMN sms_enabled INTEGER NOT NULL DEFAULT 0",
        ('cpcs', 'user_id'): 'ALTER TABLE cpcs ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1',
        ('alarms', 'user_id'): 'ALTER TABLE alarms ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1',
        ('raw_events', 'user_id'): 'ALTER TABLE raw_events ADD COLUMN user_id INTEGER NOT NULL DEFAULT 1',
        ('cpcs', 'role'): "ALTER TABLE cpcs ADD COLUMN role TEXT NOT NULL DEFAULT 'client'",
        ('cpcs', 'startup_hex'): "ALTER TABLE cpcs ADD COLUMN startup_hex TEXT DEFAULT ''",
        ('cpcs', 'heartbeat_hex'): "ALTER TABLE cpcs ADD COLUMN heartbeat_hex TEXT DEFAULT ''",
        ('cpcs', 'heartbeat_interval'): 'ALTER TABLE cpcs ADD COLUMN heartbeat_interval INTEGER NOT NULL DEFAULT 30',
        ('cpcs', 'scan_hex'): "ALTER TABLE cpcs ADD COLUMN scan_hex TEXT DEFAULT ''",
        ('cpcs', 'scan_read_seconds'): 'ALTER TABLE cpcs ADD COLUMN scan_read_seconds INTEGER NOT NULL DEFAULT 4',
        ('cpcs', 'auto_scan_on_connect'): 'ALTER TABLE cpcs ADD COLUMN auto_scan_on_connect INTEGER NOT NULL DEFAULT 0',
        ('cpcs', 'site_label'): "ALTER TABLE cpcs ADD COLUMN site_label TEXT DEFAULT ''",
        ('cpcs', 'store_code'): "ALTER TABLE cpcs ADD COLUMN store_code TEXT DEFAULT ''",
        ('cpcs', 'device_notes'): "ALTER TABLE cpcs ADD COLUMN device_notes TEXT DEFAULT ''",
        ('cpcs', 'scan_every_seconds'): 'ALTER TABLE cpcs ADD COLUMN scan_every_seconds INTEGER NOT NULL DEFAULT 0',
        ('cpcs', 'crawl_mode'): "ALTER TABLE cpcs ADD COLUMN crawl_mode INTEGER NOT NULL DEFAULT 1",
        ('cpcs', 'crawl_interval'): 'ALTER TABLE cpcs ADD COLUMN crawl_interval INTEGER NOT NULL DEFAULT 45',
        ('cpcs', 'crawl_payloads'): "ALTER TABLE cpcs ADD COLUMN crawl_payloads TEXT DEFAULT ''",
    }
    for (table, column), sql in migrations.items():
        if not column_exists(db, table, column):
            cur.execute(sql)

    defaults = {
        'company_name': 'My Store',
        'theme': 'dark',
        'public_base_url': PUBLIC_BASE_URL,
        'notify_browser': '1',
        'language': 'en',
        'connection_notes': 'FSD direct mode enabled',
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
        'connection_notes': 'FSD direct mode enabled',
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


def normalize_phone(value: str) -> str:
    value = (value or '').strip()
    if not value:
        return ''
    if value.startswith('+'):
        return '+' + re.sub(r'\D', '', value)
    digits = re.sub(r'\D', '', value)
    return ('+' + digits) if digits else ''


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


def send_sms_notification(db, user_id: int, site: str, message: str):
    if not (TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER and TwilioClient):
        return
    user = db.execute('SELECT phone_number, sms_enabled FROM users WHERE id = ?', (user_id,)).fetchone()
    if not user or not user['sms_enabled'] or not user['phone_number']:
        return
    try:
        client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        body = f'🚨 CPC ALERT\nSite: {site}\n{message[:280]}'
        client.messages.create(to=user['phone_number'], from_=TWILIO_FROM_NUMBER, body=body)
    except Exception:
        pass


def split_alarm_candidates(message: str):
    text = re.sub(r'\s+', ' ', message or '').strip()
    if not text:
        return []
    parts = re.split(r'\s*(?:\||;|\s{2,})\s*', text)
    return [p.strip() for p in parts if len(p.strip()) >= 6][:6]


def site_display_name(cpc):
    return (cpc['site_label'] or cpc['name'] or 'CPC').strip()


def should_create_alarm(db, user_id: int, cpc_id: Optional[int], message: str):
    since = time.time() - ALARM_DEDUPE_SECONDS
    since_iso = datetime.utcfromtimestamp(since).isoformat(timespec='seconds') + 'Z'
    row = db.execute(
        """SELECT id FROM alarms WHERE user_id = ? AND COALESCE(cpc_id,0) = COALESCE(?,0)
           AND message = ? AND status IN ('ACTIVE','ACK') AND created_at >= ?
           ORDER BY id DESC LIMIT 1""",
        (user_id, cpc_id, message[:350], since_iso)
    ).fetchone()
    return row is None


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
        send_sms_notification(db, user_id, site, message)
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
    if kwargs:
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
        SELECT c.id, c.user_id, u.username AS owner_username, c.name, c.host, c.port, c.enabled, c.role,
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


def clean_hex_string(text: str) -> str:
    text = (text or '').strip().replace('0x', '').replace(',', ' ').replace('-', ' ')
    return ''.join(ch for ch in text if ch in '0123456789abcdefABCDEF')


def hex_to_bytes(text: str) -> bytes:
    cleaned = clean_hex_string(text)
    if not cleaned:
        return b''
    if len(cleaned) % 2:
        cleaned = '0' + cleaned
    try:
        return bytes.fromhex(cleaned)
    except Exception:
        return b''


def bytes_to_hex(data: bytes, limit: int = 256) -> str:
    return data[:limit].hex(' ').upper()


def extract_ascii_sequences(data: bytes, min_len: int = 4):
    text = ''.join(chr(b) if 32 <= b < 127 else ' ' for b in data)
    parts = [re.sub(r'\s+', ' ', p).strip() for p in re.split(r'\s{2,}', text)]
    return [p for p in parts if len(p) >= min_len]


def format_raw_payload(data: bytes) -> str:
    ascii_parts = extract_ascii_sequences(data)
    ascii_text = ' | '.join(ascii_parts[:8]) if ascii_parts else '(no printable text)'
    return f'HEX: {bytes_to_hex(data)}\nASCII: {ascii_text}'


def parse_direct_payload(raw_bytes: bytes, parser_hint: str = 'fsd_auto'):
    ascii_parts = extract_ascii_sequences(raw_bytes)
    joined = ' | '.join(ascii_parts[:10])
    if not joined and parser_hint not in ('hex_only',):
        return None
    upper = joined.upper()
    hot_words = ['ALARM', 'FAIL', 'FAILED', 'NOTICE', 'ADVISORY', 'TEMP', 'TEMPERATURE', 'SENSOR', 'DEFROST', 'SUCTION', 'COMP', 'COMPRESSOR', 'CASE', 'LOSS', 'DOOR', 'POWER', 'HI ', 'HIGH', 'LOW ', 'LOW', 'DISCHARGE', 'TRIP', 'FAULT', 'CUTOUT', 'CUT OUT', 'PHASE', 'PRESS', 'PRESSURE', 'COND', 'FAN', 'RACK', 'SYS', 'SYSTEM', 'OVERRIDE', 'ALR', 'NOTICES', 'ALARMS']
    if parser_hint in ('plain', 'plain_text') and ascii_parts:
        candidates = ascii_parts[:3]
    else:
        candidates = [p for p in ascii_parts if any(token in p.upper() for token in hot_words)]
    if not candidates and any(token in upper for token in hot_words):
        candidates = [joined]
    if not candidates:
        return None
    pieces = []
    for cand in candidates:
        pieces.extend(split_alarm_candidates(cand))
    pieces = list(dict.fromkeys(pieces))[:6]
    if not pieces:
        return None
    priority = 'HIGH' if any(x in upper for x in ['ALARM', 'FAIL', 'FAILED', 'CRIT', 'CRITICAL', 'HIGH TEMP', 'LOSS', 'POWER', 'FAULT', 'TRIP', 'CUTOUT']) else 'MEDIUM'
    return {'priority': priority, 'messages': pieces, 'message': ' | '.join(pieces)[:350]}


def increment_message_count(db, cpc_id: int) -> int:
    row = db.execute('SELECT COALESCE(messages_seen, 0) AS v FROM bridge_status WHERE cpc_id = ?', (cpc_id,)).fetchone()
    current = (row['v'] if row else 0) + 1
    update_bridge_status(cpc_id, messages_seen=current)
    return current


def handle_incoming_bytes(db, cpc, chunk: bytes):
    parsed = parse_direct_payload(chunk, cpc['parser_hint'])
    display_site = site_display_name(cpc)
    save_raw_event(db, cpc['user_id'], cpc['id'], cpc['name'], format_raw_payload(chunk), 1 if parsed else 0)
    if parsed:
        for piece in parsed.get('messages', [parsed['message']]):
            if should_create_alarm(db, cpc['user_id'], cpc['id'], piece):
                external_id = f"{cpc['id']}:{hash((piece+str(chunk[:48])).encode())}"
                create_alarm(db, cpc['user_id'], cpc['id'], cpc['name'], display_site, piece, parsed['priority'], external_id=external_id)


def send_optional(sock, hex_text: str):
    payload = hex_to_bytes(hex_text)
    if payload:
        sock.sendall(payload)


def read_scan_chunks(sock, read_seconds: int = 4, idle_timeout: float = 0.8):
    chunks = []
    deadline = time.time() + max(1, read_seconds)
    last_data = time.time()
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
            if chunk:
                chunks.append(chunk)
                last_data = time.time()
                continue
            break
        except socket.timeout:
            if chunks and (time.time() - last_data) >= idle_timeout:
                break
            continue
    return chunks




def default_crawl_payloads():
    return [
        bytes([0x05]),
        b'alarms\r\n',
        b'alarm\r\n',
        b'advisories\r\n',
        b'notices\r\n',
        b'status\r\n',
        b'list alarms\r\n',
    ]


def parse_payload_lines(text: str):
    items = []
    for raw in (text or '').splitlines():
        line = raw.strip()
        if not line:
            continue
        hb = hex_to_bytes(line)
        if hb:
            items.append(hb)
        else:
            items.append(line.encode('utf-8', errors='ignore') + b'\r\n')
    return items


def get_crawl_payloads(cpc):
    custom = parse_payload_lines(cpc['crawl_payloads'] or '')
    return custom if custom else default_crawl_payloads()


def perform_crawl_sequence(sock, cpc):
    if not int(cpc['crawl_mode'] or 0):
        return 0
    count = 0
    for payload in get_crawl_payloads(cpc):
        try:
            sock.sendall(payload)
            count += 1
            time.sleep(0.15)
        except Exception:
            continue
    return count

def perform_scan(db, cpc, source_label='manual-scan'):
    if cpc['role'] != 'client':
        raise RuntimeError('Scanning is only available in client mode.')
    host = cpc['host'].strip()
    port = int(cpc['port'])
    timeout = int(cpc['timeout'])
    startup_hex = cpc['startup_hex'] or ''
    scan_hex = cpc['scan_hex'] or ''
    read_seconds = max(1, int(cpc['scan_read_seconds'] or 4))
    scanned = 0
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(0.8)
        update_bridge_status(cpc['id'], connected=1, last_connect_at=utc_now(), last_error='')
        send_optional(sock, startup_hex)
        time.sleep(0.2)
        if scan_hex.strip():
            send_optional(sock, scan_hex)
        else:
            perform_crawl_sequence(sock, cpc)
        chunks = read_scan_chunks(sock, read_seconds=read_seconds)
        if not chunks:
            note = f'SCAN: no bytes returned for {source_label}'
            if not scan_hex.strip():
                note += ' (passive listen mode)'
            save_raw_event(db, cpc['user_id'], cpc['id'], cpc['name'], note, 0)
            return 0
        for chunk in chunks:
            increment_message_count(db, cpc['id'])
            update_bridge_status(cpc['id'], last_message_at=utc_now(), last_bytes=len(chunk), connected=1)
            handle_incoming_bytes(db, cpc, chunk)
            scanned += 1
    return scanned


def client_bridge_loop(db, cpc, stop_event):
    host = cpc['host'].strip()
    port = int(cpc['port'])
    timeout = int(cpc['timeout'])
    heartbeat_interval = max(5, int(cpc['heartbeat_interval'] or 30))
    startup_hex = cpc['startup_hex'] or ''
    heartbeat_hex = cpc['heartbeat_hex'] or ''
    update_bridge_status(cpc['id'], running=1, connected=0, last_error='')
    with socket.create_connection((host, port), timeout=timeout) as sock:
        sock.settimeout(1.0)
        update_bridge_status(cpc['id'], connected=1, last_connect_at=utc_now(), last_error='')
        send_optional(sock, startup_hex)
        if cpc['auto_scan_on_connect']:
            try:
                time.sleep(0.2)
                if (cpc['scan_hex'] or '').strip():
                    send_optional(sock, cpc['scan_hex'] or '')
                else:
                    perform_crawl_sequence(sock, cpc)
            except Exception:
                pass
        last_hb = time.time()
        last_scan = time.time()
        last_crawl = time.time()
        scan_every = max(0, int(cpc['scan_every_seconds'] or 0))
        crawl_every = max(10, int(cpc['crawl_interval'] or 45)) if int(cpc['crawl_mode'] or 0) else 0
        while not stop_event.is_set():
            if heartbeat_hex and time.time() - last_hb >= heartbeat_interval:
                send_optional(sock, heartbeat_hex)
                last_hb = time.time()
            if scan_every and (cpc['scan_hex'] or '').strip() and time.time() - last_scan >= scan_every:
                try:
                    send_optional(sock, cpc['scan_hex'] or '')
                    last_scan = time.time()
                except Exception:
                    pass
            if crawl_every and time.time() - last_crawl >= crawl_every:
                try:
                    perform_crawl_sequence(sock, cpc)
                    last_crawl = time.time()
                except Exception:
                    pass
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                continue
            if not chunk:
                raise ConnectionError('Connection closed by CPC')
            increment_message_count(db, cpc['id'])
            update_bridge_status(cpc['id'], last_message_at=utc_now(), last_bytes=len(chunk))
            handle_incoming_bytes(db, cpc, chunk)


def listener_bridge_loop(db, cpc, stop_event):
    host = cpc['host'].strip() or '0.0.0.0'
    port = int(cpc['port'])
    timeout = int(cpc['timeout'])
    update_bridge_status(cpc['id'], running=1, connected=0, last_error='')
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen(5)
    server.setblocking(False)
    clients = []
    try:
        while not stop_event.is_set():
            readable, _, _ = select.select([server] + clients, [], [], 1.0)
            for ready in readable:
                if ready is server:
                    conn, addr = server.accept()
                    conn.settimeout(timeout)
                    clients.append(conn)
                    update_bridge_status(cpc['id'], connected=1, last_connect_at=utc_now(), last_error=f'Inbound {addr[0]}:{addr[1]}')
                    send_optional(conn, cpc['startup_hex'] or '')
                else:
                    try:
                        chunk = ready.recv(4096)
                        if not chunk:
                            clients.remove(ready)
                            ready.close()
                            continue
                        increment_message_count(db, cpc['id'])
                        update_bridge_status(cpc['id'], last_message_at=utc_now(), last_bytes=len(chunk), connected=1)
                        handle_incoming_bytes(db, cpc, chunk)
                    except Exception:
                        if ready in clients:
                            clients.remove(ready)
                        try:
                            ready.close()
                        except Exception:
                            pass
            if not clients:
                update_bridge_status(cpc['id'], connected=0)
    finally:
        for conn in clients:
            try:
                conn.close()
            except Exception:
                pass
        server.close()


def bridge_worker(cpc_id: int):
    stop_event = BRIDGE_STOP_FLAGS[cpc_id]
    while not stop_event.is_set():
        db = db_connect()
        cpc = db.execute('SELECT * FROM cpcs WHERE id = ?', (cpc_id,)).fetchone()
        if not cpc or not cpc['enabled']:
            update_bridge_status(cpc_id, running=0, connected=0, last_error='Disabled')
            db.close()
            return
        try:
            if cpc['role'] == 'listener':
                listener_bridge_loop(db, cpc, stop_event)
            else:
                client_bridge_loop(db, cpc, stop_event)
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
    return {
        'site_name': SITE_NAME,
        'current_user': current_user(),
        'vapid_public_key': VAPID_PUBLIC_KEY,
        'max_cpcs_per_user': MAX_CPCS_PER_USER,
        'twilio_ready': bool(TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN and TWILIO_FROM_NUMBER),
    }


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
    site_cards = []
    for c in cpcs:
        active_count = db.execute("SELECT COUNT(*) AS c FROM alarms WHERE cpc_id = ? AND status = 'ACTIVE'", (c['id'],)).fetchone()['c']
        recent_count = db.execute("SELECT COUNT(*) AS c FROM raw_events WHERE cpc_id = ?", (c['id'],)).fetchone()['c']
        bridge = next((b for b in bridges if b['id'] == c['id']), None)
        site_cards.append({'cpc': c, 'active_count': active_count, 'recent_count': recent_count, 'bridge': bridge})
    return render_template('dashboard.html', stats=stats, active=active, recent=recent, raw_recent=raw_recent, bridges=bridges, cpcs=cpcs, site_cards=site_cards, settings=get_settings(db))


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




@app.route('/sites/<int:cpc_id>')
@login_required
def site_detail(cpc_id):
    cpc, denied = owner_or_admin_required_for_cpc(cpc_id)
    if denied:
        return denied
    db = get_db()
    alarms = db.execute("SELECT * FROM alarms WHERE cpc_id = ? ORDER BY created_at DESC LIMIT 200", (cpc_id,)).fetchall()
    raw_events = db.execute("SELECT * FROM raw_events WHERE cpc_id = ? ORDER BY created_at DESC LIMIT 50", (cpc_id,)).fetchall()
    bridge = db.execute("SELECT * FROM bridge_status WHERE cpc_id = ?", (cpc_id,)).fetchone()
    return render_template('site_detail.html', cpc=cpc, alarms=alarms, raw_events=raw_events, bridge=bridge, settings=get_settings(db))

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
    phone_number = normalize_phone(request.form.get('phone_number', ''))
    sms_enabled = 1 if request.form.get('sms_enabled') == '1' else 0

    if username and username != user['username']:
        try:
            db.execute('UPDATE users SET username = ? WHERE id = ?', (username, user['id']))
            session['username'] = username
        except sqlite3.IntegrityError:
            flash('That username already exists.', 'error')
            return redirect(url_for('settings'))
    if new_password:
        if not check_password_hash(user['password_hash'], current_password):
            flash('Current password is not correct.', 'error')
            return redirect(url_for('settings'))
        if new_password != confirm_password:
            flash('New passwords do not match.', 'error')
            return redirect(url_for('settings'))
        db.execute('UPDATE users SET password_hash = ? WHERE id = ?', (generate_password_hash(new_password), user['id']))
    db.execute('UPDATE users SET phone_number = ?, sms_enabled = ? WHERE id = ?', (phone_number, sms_enabled, user['id']))
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


def int_form(name: str, default: int) -> int:
    try:
        return int(request.form.get(name, str(default)) or default)
    except Exception:
        return default


@app.route('/cpcs/add', methods=['POST'])
@login_required
def add_cpc():
    db = get_db()
    target_user_id = current_target_user_id()
    count = db.execute('SELECT COUNT(*) AS c FROM cpcs WHERE user_id = ?', (target_user_id,)).fetchone()['c']
    if count >= MAX_CPCS_PER_USER:
        flash(f'Each user can have up to {MAX_CPCS_PER_USER} CPC connections.', 'error')
        return redirect(url_for('settings'))
    name = request.form.get('name', '').strip()
    site_label = request.form.get('site_label', '').strip()
    store_code = request.form.get('store_code', '').strip()
    device_notes = request.form.get('device_notes', '').strip()
    host = request.form.get('host', '').strip()
    port = int_form('port', 14106)
    timeout = int_form('timeout', 15)
    buffer_mode = request.form.get('buffer_mode', 'fsd')
    parser_hint = request.form.get('parser_hint', 'fsd_auto')
    role = request.form.get('role', 'client')
    startup_hex = request.form.get('startup_hex', '').strip()
    heartbeat_hex = request.form.get('heartbeat_hex', '').strip()
    heartbeat_interval = int_form('heartbeat_interval', 30)
    scan_hex = request.form.get('scan_hex', '').strip()
    scan_read_seconds = int_form('scan_read_seconds', 4)
    scan_every_seconds = int_form('scan_every_seconds', 0)
    auto_scan_on_connect = 1 if request.form.get('auto_scan_on_connect') == '1' else 0
    enabled = 1 if request.form.get('enabled') == '1' else 0
    if not name:
        flash('Enter a name.', 'error')
        return redirect(url_for('settings'))
    if role == 'client' and not host:
        flash('Enter a CPC IP/host for client mode.', 'error')
        return redirect(url_for('settings'))
    if role == 'listener' and not host:
        host = '0.0.0.0'
    now = utc_now()
    db.execute('''INSERT INTO cpcs (user_id, name, site_label, store_code, device_notes, scan_every_seconds, host, port, timeout, buffer_mode, parser_hint, role, startup_hex, heartbeat_hex, heartbeat_interval, scan_hex, scan_read_seconds, auto_scan_on_connect, crawl_mode, crawl_interval, crawl_payloads, enabled, created_at, updated_at)
                  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', (target_user_id, name, site_label, store_code, device_notes, scan_every_seconds, host, port, timeout, buffer_mode, parser_hint, role, startup_hex, heartbeat_hex, heartbeat_interval, scan_hex, scan_read_seconds, auto_scan_on_connect, 1 if request.form.get('crawl_mode', '1') == '1' else 0, int_form('crawl_interval', 45), request.form.get('crawl_payloads', '').strip(), enabled, now, now))
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
    host = request.form.get('host', '').strip()
    role = request.form.get('role', 'client')
    if role == 'listener' and not host:
        host = '0.0.0.0'
    db.execute('''UPDATE cpcs SET name=?, site_label=?, store_code=?, device_notes=?, scan_every_seconds=?, host=?, port=?, timeout=?, buffer_mode=?, parser_hint=?, role=?, startup_hex=?, heartbeat_hex=?, heartbeat_interval=?, scan_hex=?, scan_read_seconds=?, auto_scan_on_connect=?, crawl_mode=?, crawl_interval=?, crawl_payloads=?, enabled=?, updated_at=? WHERE id=?''',
               (request.form.get('name', '').strip(), request.form.get('site_label', '').strip(), request.form.get('store_code', '').strip(), request.form.get('device_notes', '').strip(), int_form('scan_every_seconds', 0), host, int_form('port', 14106), int_form('timeout', 15), request.form.get('buffer_mode', 'fsd'), request.form.get('parser_hint', 'fsd_auto'), role, request.form.get('startup_hex', '').strip(), request.form.get('heartbeat_hex', '').strip(), int_form('heartbeat_interval', 30), request.form.get('scan_hex', '').strip(), int_form('scan_read_seconds', 4), 1 if request.form.get('auto_scan_on_connect') == '1' else 0, 1 if request.form.get('crawl_mode', '1') == '1' else 0, int_form('crawl_interval', 45), request.form.get('crawl_payloads', '').strip(), 1 if request.form.get('enabled') == '1' else 0, now, cpc_id))
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


@app.route('/api/cpcs/<int:cpc_id>/probe', methods=['POST'])
@login_required
def api_cpc_probe(cpc_id):
    cpc, denied = owner_or_admin_required_for_cpc(cpc_id)
    if denied:
        return jsonify({'error': 'Not allowed'}), 403
    db = get_db()
    payload = hex_to_bytes(request.json.get('hex', '') if request.is_json else '')
    if not payload:
        return jsonify({'error': 'Provide a hex payload'}), 400
    try:
        with socket.create_connection((cpc['host'], int(cpc['port'])), timeout=int(cpc['timeout'])) as sock:
            sock.sendall(payload)
            sock.settimeout(2.0)
            try:
                data = sock.recv(4096)
            except socket.timeout:
                data = b''
        if data:
            handle_incoming_bytes(db, cpc, data)
        return jsonify({'ok': True, 'reply_hex': bytes_to_hex(data), 'reply_ascii': ' | '.join(extract_ascii_sequences(data))})
    except Exception as exc:
        return jsonify({'error': str(exc)}), 500


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



@app.route('/cpcs/<int:cpc_id>/scan', methods=['POST'])
@login_required
def scan_cpc(cpc_id):
    cpc, denied = owner_or_admin_required_for_cpc(cpc_id)
    if denied:
        return denied
    db = get_db()
    try:
        scanned = perform_scan(db, cpc, source_label='dashboard-scan')
        flash(f'Scan finished. Frames captured: {scanned}', 'success')
    except Exception as exc:
        flash(f'Scan failed: {str(exc)}', 'error')
    return redirect(url_for('dashboard'))


@app.route('/api/cpcs/<int:cpc_id>/scan', methods=['POST'])
@login_required
def api_scan_cpc(cpc_id):
    cpc, denied = owner_or_admin_required_for_cpc(cpc_id)
    if denied:
        return jsonify({'error': 'forbidden'}), 403
    db = get_db()
    try:
        scanned = perform_scan(db, cpc, source_label='api-scan')
        return jsonify({'ok': True, 'frames': scanned})
    except Exception as exc:
        return jsonify({'ok': False, 'error': str(exc)}), 400

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
            {'src': '/static/icon-192.png', 'sizes': '192x192', 'type': 'image/png'},
            {'src': '/static/icon-512.png', 'sizes': '512x512', 'type': 'image/png'},
        ],
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
