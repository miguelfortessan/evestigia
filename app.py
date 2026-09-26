"""
eVestigia - Plataforma de portafolios de aprendizaje (software libre, Licencia MIT, 2026)
========================================================================================
Novedades V.4:

  * BUSCADOR de personas en Comunidad (por nombre o usuario).
  * CONOCIDOS: enviar solicitud, aceptar / rechazar, listar contactos.
  * MENSAJERIA privada 1 a 1 con bandeja de entrada y contador de no leidos.
  * CAPA SOCIAL testeo realizado.

Ademas:
  * Editor visual con menu lateral (arrastrar bloques; subir archivos ahi mismo).
  * Páginas con estructura de columnas personalizable.
  * Bloque de texto con tipografia. Artefactos multimedia (YouTube/Vimeo, PDF, audio).
  * Perfiles, seguir, feed, me gusta y comentarios.

Stack: Python + Flask + SQLite (un solo archivo, sin build).
Ejecutar:  pip install flask   &&   python app.py
Abrir:     http://127.0.0.1:5000


"""
import os
import re
import json
import sqlite3
import secrets
from datetime import datetime
from functools import wraps
from html import escape

try:
    import PIL  # noqa: F401  (lectura de EXIF de fotos)
    _PIL_OK = True
except Exception:
    _PIL_OK = False
try:
    import pillow_heif  # noqa: F401  (soporte HEIC)
    _HEIF_OK = True
except Exception:
    _HEIF_OK = False

from flask import (Flask, g, request, redirect, url_for, session, jsonify,
                   render_template_string, flash, abort, send_from_directory)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
import smtplib
from email.message import EmailMessage

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_PATH = os.path.join(BASE_DIR, "evestigia.db")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED = {"png", "jpg", "jpeg", "gif", "webp", "heic", "heif", "pdf", "doc", "docx", "ppt", "pptx",
           "xls", "xlsx", "txt", "md", "zip", "mp4", "webm", "mov", "mp3", "wav", "m4a"}
IMAGE_EXT = {"png", "jpg", "jpeg", "gif", "webp"}
VIDEO_EXT = {"mp4", "webm", "mov"}
AUDIO_EXT = {"mp3", "wav", "m4a"}

HASH = "pbkdf2:sha256"

STORAGE_QUOTA = 600 * 1024 * 1024  # 600 MB por persona
LS_GROUP_QUOTA = 5 * 1024 * 1024 * 1024  # 5 GB de evidencias por grupo
LS_BULK_MAX = 100  # maximo de archivos por subida masiva

LAYOUTS = {"1": [1], "1-1": [1, 1], "1-1-1": [1, 1, 1], "2-1": [2, 1], "1-2": [1, 2]}
LAYOUT_LABELS = {"1": "1 columna", "1-1": "2 columnas", "1-1-1": "3 columnas",
                 "2-1": "2 col. (ancha + estrecha)", "1-2": "2 col. (estrecha + ancha)"}
FONTS = {"sans": "-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif",
         "serif": "Georgia,'Times New Roman',serif",
         "mono": "'SF Mono',Menlo,Consolas,monospace"}
KIND_LABELS = {"text": "Texto", "link": "Enlace", "image": "Imagen",
               "video": "Vídeo", "audio": "Audio", "file": "Documento"}
BLK_LABELS = {"text": "Texto", "heading": "Título", "artefact": "Artefacto"}
VIS = {"private": "Privada", "teachers": "Docentes", "public": "Pública"}

os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)


def _load_secret_key():
    """Clave de sesión estable y secreta: de variable de entorno o de un archivo local generado."""
    k = os.environ.get("EVESTIGIA_SECRET_KEY")
    if k:
        return k
    path = os.path.join(BASE_DIR, "flask_secret.key")
    try:
        if os.path.exists(path):
            return open(path).read().strip()
        k = secrets.token_hex(32)
        with open(path, "w") as f:
            f.write(k)
        try:
            os.chmod(path, 0o600)
        except Exception:
            pass
        return k
    except Exception:
        return secrets.token_hex(32)


app.config["SECRET_KEY"] = _load_secret_key()
app.config["MAX_CONTENT_LENGTH"] = 1024 * 1024 * 1024  # 1 GB (permite subidas masivas)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,        # la cookie no es accesible desde JavaScript (mitiga robo por XSS)
    SESSION_COOKIE_SAMESITE="Lax",       # mitiga CSRF entre sitios
    SESSION_COOKIE_SECURE=(os.environ.get("EVESTIGIA_HTTPS") == "1"),  # solo por HTTPS si se despliega con TLS
    PERMANENT_SESSION_LIFETIME=60 * 60 * 12,  # la sesión caduca a las 12 h
)


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "SAMEORIGIN")
    resp.headers.setdefault("Referrer-Policy", "same-origin")
    resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(self), camera=(self)")
    return resp


# --------------------------------------------------------------------------- #
#  Base de datos
# --------------------------------------------------------------------------- #
def get_db():
    if "db" not in g:
        # timeout: espera si la BD está bloqueada por otra petición (evita errores con varios usuarios).
        g.db = sqlite3.connect(DB_PATH, timeout=15)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
        g.db.execute("PRAGMA busy_timeout = 8000")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db is not None:
        db.close()


SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
    name TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'student', bio TEXT DEFAULT '', email TEXT DEFAULT '',
    avatar TEXT DEFAULT '', profile_page_id INTEGER, onboarded INTEGER DEFAULT 0,
    login_count INTEGER DEFAULT 0, notify_changes INTEGER DEFAULT 1,
    last_seen TEXT, show_online INTEGER DEFAULT 1, show_contacts INTEGER DEFAULT 1,
    default_vis TEXT DEFAULT 'private');
CREATE TABLE IF NOT EXISTS artefacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, title TEXT NOT NULL, body TEXT, url TEXT, filename TEXT,
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL, description TEXT,
    visibility TEXT NOT NULL DEFAULT 'private', share_token TEXT, created_at TEXT NOT NULL,
    group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE);
CREATE TABLE IF NOT EXISTS groups (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL,
    pages_create TEXT DEFAULT 'all', default_vis TEXT DEFAULT 'private', evidence_quota_mb INTEGER);
CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id));
CREATE TABLE IF NOT EXISTS group_requests (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, PRIMARY KEY (group_id, user_id));
CREATE TABLE IF NOT EXISTS group_visits (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    visits INTEGER NOT NULL DEFAULT 0, last_at TEXT, PRIMARY KEY (group_id, user_id));
CREATE TABLE IF NOT EXISTS ls_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL, lesson_date TEXT, lesson_done INTEGER DEFAULT 0,
    reflexion TEXT DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ls_objectives (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES ls_sessions(id) ON DELETE CASCADE,
    text TEXT NOT NULL, position INTEGER NOT NULL DEFAULT 0, assessment TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS ls_contents (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES ls_sessions(id) ON DELETE CASCADE,
    text TEXT NOT NULL, position INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS ls_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES ls_sessions(id) ON DELETE CASCADE,
    text TEXT NOT NULL, position INTEGER NOT NULL DEFAULT 0, assessment TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS ls_evidences (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES ls_sessions(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, filename TEXT, url TEXT, note TEXT,
    captured_at TEXT, meta_ok INTEGER DEFAULT 1, all_day INTEGER DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ls_evidence_links (
    evidence_id INTEGER NOT NULL REFERENCES ls_evidences(id) ON DELETE CASCADE,
    target_type TEXT NOT NULL, target_id INTEGER NOT NULL,
    PRIMARY KEY (evidence_id, target_type, target_id));
CREATE TABLE IF NOT EXISTS ls_evidence_comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL REFERENCES ls_evidences(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    t_seconds INTEGER, body TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ls_discussions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES ls_sessions(id) ON DELETE CASCADE,
    title TEXT NOT NULL, context_type TEXT DEFAULT 'general', context_id INTEGER,
    closed INTEGER DEFAULT 0, conclusion TEXT DEFAULT '',
    created_by INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ls_discussion_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    discussion_id INTEGER NOT NULL REFERENCES ls_discussions(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS ls_reflection_posts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER NOT NULL REFERENCES ls_sessions(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT DEFAULT 'aporte', body TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rows (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    position INTEGER NOT NULL, layout TEXT NOT NULL DEFAULT '1');
CREATE TABLE IF NOT EXISTS blocks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    row_id INTEGER NOT NULL REFERENCES rows(id) ON DELETE CASCADE,
    col_index INTEGER NOT NULL DEFAULT 0, position INTEGER NOT NULL,
    block_type TEXT NOT NULL, artefact_id INTEGER REFERENCES artefacts(id) ON DELETE CASCADE,
    text_content TEXT, font_family TEXT DEFAULT 'sans', font_size INTEGER DEFAULT 16,
    text_color TEXT DEFAULT '#25202a', align TEXT DEFAULT 'left',
    bold INTEGER DEFAULT 0, italic INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS collections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    title TEXT NOT NULL, visibility TEXT NOT NULL DEFAULT 'private', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS collection_pages (
    collection_id INTEGER NOT NULL REFERENCES collections(id) ON DELETE CASCADE,
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    position INTEGER NOT NULL, PRIMARY KEY (collection_id, page_id));
CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    author_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id INTEGER REFERENCES comments(id) ON DELETE CASCADE,
    body TEXT NOT NULL, created_at TEXT NOT NULL);
-- Archivo de comentarios del profesorado (evidencia): persiste aunque se borre la página.
CREATE TABLE IF NOT EXISTS comment_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    page_id INTEGER, page_title TEXT,
    author_id INTEGER, author_name TEXT, author_role TEXT,
    owner_id INTEGER, owner_name TEXT,
    body TEXT NOT NULL, created_at TEXT NOT NULL);
-- Bloqueo de edición por bloque (para edición concurrente en páginas de grupo).
CREATE TABLE IF NOT EXISTS block_locks (
    block_id INTEGER PRIMARY KEY,
    page_id INTEGER, user_id INTEGER, user_name TEXT, heartbeat_at TEXT NOT NULL);
-- Cola de tareas de IA (generación en segundo plano).
CREATE TABLE IF NOT EXISTS ai_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id INTEGER, student_id INTEGER, student_name TEXT, student_username TEXT,
    session_id INTEGER,
    instruction TEXT, mode TEXT DEFAULT 'feedback', status TEXT DEFAULT 'pending', result TEXT, error TEXT,
    created_at TEXT, done_at TEXT);
-- Ejemplos anonimizados (portafolio -> feedback) para guiar a la IA (few-shot) y exportar a JSONL (LoRA con Ollama).
CREATE TABLE IF NOT EXISTS ai_examples (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT DEFAULT 'feedback', title TEXT DEFAULT '',
    portfolio TEXT NOT NULL, feedback TEXT NOT NULL, note TEXT DEFAULT '',
    active INTEGER DEFAULT 1, created_by INTEGER, created_at TEXT);
-- Estructura académica: asignatura ↔ alumnado ↔ profesorado (+ archivado por docente).
CREATE TABLE IF NOT EXISTS subjects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL, code TEXT DEFAULT '', created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS subject_teachers (
    subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY(subject_id, teacher_id));
CREATE TABLE IF NOT EXISTS subject_students (
    subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY(subject_id, student_id));
CREATE TABLE IF NOT EXISTS subject_archived (
    subject_id INTEGER NOT NULL REFERENCES subjects(id) ON DELETE CASCADE,
    teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY(subject_id, teacher_id));
CREATE TABLE IF NOT EXISTS follows (
    follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    followee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (follower_id, followee_id));
CREATE TABLE IF NOT EXISTS likes (
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    PRIMARY KEY (page_id, user_id));
CREATE TABLE IF NOT EXISTS page_reads (
    page_id INTEGER NOT NULL REFERENCES pages(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL, PRIMARY KEY (page_id, user_id));
CREATE TABLE IF NOT EXISTS contacts (
    requester_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    addressee_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    status TEXT NOT NULL DEFAULT 'pending',   -- pending | accepted
    created_at TEXT NOT NULL,
    PRIMARY KEY (requester_id, addressee_id));
CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL, created_at TEXT NOT NULL, is_read INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kind TEXT NOT NULL,                 -- 'dm' | 'group'
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    recipient_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    group_id INTEGER REFERENCES groups(id) ON DELETE CASCADE,
    body_enc TEXT NOT NULL, enc INTEGER DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS chat_reads (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    conv_key TEXT NOT NULL,
    last_read_id INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY(user_id, conv_key));
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL, text TEXT NOT NULL, link TEXT,
    is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS student_changes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    teacher_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    page_id INTEGER, page_title TEXT, kind TEXT, detail TEXT,
    is_read INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS student_activity (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    student_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    page_id INTEGER, page_title TEXT, visibility TEXT, kind TEXT, detail TEXT,
    created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS email_templates (
    event TEXT PRIMARY KEY, subject TEXT, body TEXT, enabled INTEGER DEFAULT 1);
CREATE TABLE IF NOT EXISTS email_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    to_addr TEXT, subject TEXT, status TEXT, detail TEXT, created_at TEXT NOT NULL);
"""


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def migrate(db):
    """Añade columnas nuevas a bases de datos creadas con versiónes anteriores."""
    cols = [r["name"] for r in db.execute("PRAGMA table_info(comments)").fetchall()]
    if "parent_id" not in cols:
        db.execute("ALTER TABLE comments ADD COLUMN parent_id INTEGER")
    ucols = [r["name"] for r in db.execute("PRAGMA table_info(users)").fetchall()]
    if "email" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN email TEXT DEFAULT ''")
    if "avatar" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN avatar TEXT DEFAULT ''")
    if "profile_page_id" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN profile_page_id INTEGER")
    ccols = [r["name"] for r in db.execute("PRAGMA table_info(collections)").fetchall()]
    if "visibility" not in ccols:
        db.execute("ALTER TABLE collections ADD COLUMN visibility TEXT NOT NULL DEFAULT 'private'")
    pcols = [r["name"] for r in db.execute("PRAGMA table_info(pages)").fetchall()]
    if "group_id" not in pcols:
        db.execute("ALTER TABLE pages ADD COLUMN group_id INTEGER")
    if "onboarded" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN onboarded INTEGER DEFAULT 0")
        # Los usuarios que ya existian no deben ver la sesión guiada.
        db.execute("UPDATE users SET onboarded=1")
    if "login_count" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN login_count INTEGER DEFAULT 0")
    if "notify_changes" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN notify_changes INTEGER DEFAULT 1")
    if "last_seen" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN last_seen TEXT")
    if "show_online" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN show_online INTEGER DEFAULT 1")
    if "show_contacts" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN show_contacts INTEGER DEFAULT 1")
    if "default_vis" not in ucols:
        db.execute("ALTER TABLE users ADD COLUMN default_vis TEXT DEFAULT 'private'")
    try:
        ajc = [r["name"] for r in db.execute("PRAGMA table_info(ai_jobs)").fetchall()]
        if ajc and "session_id" not in ajc:
            db.execute("ALTER TABLE ai_jobs ADD COLUMN session_id INTEGER")
        if ajc and "mode" not in ajc:
            db.execute("ALTER TABLE ai_jobs ADD COLUMN mode TEXT DEFAULT 'feedback'")
    except Exception:
        pass
    try:
        gcols = [r["name"] for r in db.execute("PRAGMA table_info(groups)").fetchall()]
        if gcols and "pages_create" not in gcols:
            db.execute("ALTER TABLE groups ADD COLUMN pages_create TEXT DEFAULT 'all'")
        if gcols and "default_vis" not in gcols:
            db.execute("ALTER TABLE groups ADD COLUMN default_vis TEXT DEFAULT 'private'")
        if gcols and "evidence_quota_mb" not in gcols:
            db.execute("ALTER TABLE groups ADD COLUMN evidence_quota_mb INTEGER")
    except Exception:
        pass
    try:
        ecols = [r["name"] for r in db.execute("PRAGMA table_info(ls_evidences)").fetchall()]
        if ecols and "all_day" not in ecols:
            db.execute("ALTER TABLE ls_evidences ADD COLUMN all_day INTEGER DEFAULT 0")
    except Exception:
        pass
    for tbl in ("ls_objectives", "ls_items"):
        try:
            cols = [r["name"] for r in db.execute("PRAGMA table_info(%s)" % tbl).fetchall()]
            if cols and "assessment" not in cols:
                db.execute("ALTER TABLE %s ADD COLUMN assessment TEXT DEFAULT ''" % tbl)
        except Exception:
            pass
    try:
        dcols = [r["name"] for r in db.execute("PRAGMA table_info(ls_discussions)").fetchall()]
        if dcols and "closed" not in dcols:
            db.execute("ALTER TABLE ls_discussions ADD COLUMN closed INTEGER DEFAULT 0")
        if dcols and "conclusion" not in dcols:
            db.execute("ALTER TABLE ls_discussions ADD COLUMN conclusion TEXT DEFAULT ''")
    except Exception:
        pass
    try:
        rpcols = [r["name"] for r in db.execute("PRAGMA table_info(ls_reflection_posts)").fetchall()]
        if rpcols and "kind" not in rpcols:
            db.execute("ALTER TABLE ls_reflection_posts ADD COLUMN kind TEXT DEFAULT 'aporte'")
    except Exception:
        pass
    # Archivo de comentarios del profesorado (evidencia).
    try:
        clcols = [r["name"] for r in db.execute("PRAGMA table_info(comment_log)").fetchall()]
        if clcols and "author_role" not in clcols:
            db.execute("ALTER TABLE comment_log ADD COLUMN author_role TEXT")
        # Relleno único con los comentarios existentes SOLO del profesorado/admin.
        if db.execute("SELECT COUNT(*) c FROM comment_log").fetchone()["c"] == 0:
            db.execute("""INSERT INTO comment_log(page_id,page_title,author_id,author_name,author_role,owner_id,owner_name,body,created_at)
                SELECT c.page_id, p.title, c.author_id, ua.name, ua.role, p.owner_id, uo.name, c.body, c.created_at
                FROM comments c JOIN pages p ON p.id=c.page_id
                LEFT JOIN users ua ON ua.id=c.author_id
                LEFT JOIN users uo ON uo.id=p.owner_id
                WHERE ua.role IN ('teacher','admin')""")
        # Corrección de datos previos: completar rol y descartar comentarios que no sean del profesorado.
        db.execute("UPDATE comment_log SET author_role=(SELECT role FROM users WHERE users.id=comment_log.author_id) "
                   "WHERE author_role IS NULL")
        db.execute("DELETE FROM comment_log WHERE author_role NOT IN ('teacher','admin') OR author_role IS NULL")
    except Exception:
        pass
    # Rebranding a eVestigia: si quedó guardado el nombre antiguo "Vestigia", actualízalo.
    try:
        r = db.execute("SELECT value FROM settings WHERE key='theme_site_name'").fetchone()
        if r and (r["value"] or "").strip() in ("Vestigia", "E-Vestigia", ""):
            db.execute("UPDATE settings SET value='eVestigia' WHERE key='theme_site_name'")
    except Exception:
        pass


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    # WAL: permite leer mientras otra petición escribe (mejor con varios usuarios a la vez).
    try:
        db.execute("PRAGMA journal_mode=WAL")
    except Exception:
        pass
    db.executescript(SCHEMA)
    migrate(db)
    if db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        seed(db)
    seed_email_templates(db)
    seed_demo(db)
    ensure_demo_links(db)
    db.commit()
    db.close()
    harden_file_perms()


def ensure_db_ready():
    """Crea las tablas/columnas que falten al ARRANCAR, también bajo WSGI (PythonAnywhere),
    donde no se ejecuta el bloque __main__. No siembra datos de demostración: solo estructura."""
    try:
        db = sqlite3.connect(DB_PATH)
        db.row_factory = sqlite3.Row
        try:
            db.execute("PRAGMA journal_mode=WAL")
        except Exception:
            pass
        db.executescript(SCHEMA)
        migrate(db)
        db.commit()
        db.close()
    except Exception:
        pass


# Se ejecuta al importar el módulo (WSGI) y también en local: aplica esquema y migraciones.
ensure_db_ready()


def harden_file_perms():
    """Restringe a 600 (solo el propietario) los archivos sensibles: base de datos y claves."""
    import stat as _stat
    for name in ("evestigia.db", "evestigia.db-wal", "evestigia.db-shm", "evestigia.db-journal",
                 "evestigia_secret.key", "evestigia_fallback.key"):
        p = os.path.join(BASE_DIR, name)
        try:
            if os.path.exists(p):
                cur = _stat.S_IMODE(os.stat(p).st_mode)
                if cur & 0o077:
                    os.chmod(p, 0o600)
        except Exception:
            pass


def ensure_demo_links(db):
    """Crea un vinculo de conocidos de ejemplo profesor<->alumno para poder probar los avisos de cambios."""
    try:
        prof = db.execute("SELECT id FROM users WHERE username='profesor'").fetchone()
        if not prof:
            return
        for uname in ("ana", "lucia"):
            st = db.execute("SELECT id FROM users WHERE username=?", (uname,)).fetchone()
            if not st:
                continue
            exists = db.execute("""SELECT 1 FROM contacts WHERE
                (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)""",
                (prof["id"], st["id"], st["id"], prof["id"])).fetchone()
            if not exists:
                db.execute("INSERT INTO contacts(requester_id,addressee_id,status,created_at) VALUES(?,?,?,?)",
                           (st["id"], prof["id"], "accepted", now()))
    except Exception:
        pass


def seed(db):
    def mkuser(u, pw, name, role, bio="", email=None):
        return db.execute("INSERT INTO users(username,password,name,role,bio,email) VALUES(?,?,?,?,?,?)",
                          (u, generate_password_hash(pw, method=HASH), name, role, bio,
                           email or (u + "@ejemplo.org"))).lastrowid

    mkuser("admin", "admin123", "Administrador", "admin")
    prof = mkuser("profesor", "profe123", "Prof. Elena Ruiz", "teacher",
                  "Docente de Diseño de Interacción.")
    ana = mkuser("ana", "ana123", "Ana Garcia", "student",
                 "Estudiante de 2 de Diseño. Me interesa la investigación con usuarios.")
    luis = mkuser("luis", "luis123", "Luis Martin", "student", "Aprendiendo prototipado y front-end.")
    maria = mkuser("maria", "maria123", "Maria Lopez", "student", "Interesada en accesibilidad.")

    a1 = db.execute("INSERT INTO artefacts(owner_id,kind,title,body,created_at) VALUES(?,?,?,?,?)",
                    (ana, "text", "Reflexion: mi primer semestre",
                     "En este semestre he aprendido los fundamentos del diseño centrado en el "
                     "usuario. Lo que mas me ha marcado ha sido el trabajo de campo.", now())).lastrowid
    a2 = db.execute("INSERT INTO artefacts(owner_id,kind,title,url,body,created_at) VALUES(?,?,?,?,?,?)",
                    (ana, "video", "Vídeo: Design Thinking",
                     "https://www.youtube.com/watch?v=_r0VX-aU_T8",
                     "Resumen del proceso que segui.", now())).lastrowid

    page = db.execute("""INSERT INTO pages(owner_id,title,description,visibility,share_token,created_at)
                         VALUES(?,?,?,?,?,?)""",
                      (ana, "Mi portafolio de aprendizaje",
                       "Evidencias y reflexiones del curso 2025-26.",
                       "public", secrets.token_urlsafe(10), now())).lastrowid
    r1 = db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)", (page, 0, "1")).lastrowid
    db.execute("""INSERT INTO blocks(row_id,col_index,position,block_type,text_content,
                  font_family,font_size,text_color,align,bold) VALUES(?,?,?,?,?,?,?,?,?,?)""",
               (r1, 0, 0, "heading", "Presentacion", "serif", 30, "#7a1f3d", "center", 1))
    r2 = db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)", (page, 1, "1-1")).lastrowid
    db.execute("INSERT INTO blocks(row_id,col_index,position,block_type,text_content,font_size) VALUES(?,?,?,?,?,?)",
               (r2, 0, 0, "text", "Este es mi portafolio para Diseño de Interacción. Recojo aqui mis "
                "evidencias y reflexiones del curso.", 16))
    db.execute("INSERT INTO blocks(row_id,col_index,position,block_type,artefact_id) VALUES(?,?,?,?,?)",
               (r2, 1, 0, "artefact", a2))
    r3 = db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)", (page, 2, "1")).lastrowid
    db.execute("INSERT INTO blocks(row_id,col_index,position,block_type,artefact_id) VALUES(?,?,?,?,?)",
               (r3, 0, 0, "artefact", a1))

    # Feedback docente de ejemplo (con una respuesta de Ana)
    fb = db.execute("""INSERT INTO comments(page_id,author_id,parent_id,body,created_at)
                       VALUES(?,?,?,?,?)""",
                    (page, prof, None,
                     "Muy buen trabajo, Ana. Añade alguna evidencia mas del trabajo de campo.",
                     now())).lastrowid
    db.execute("""INSERT INTO comments(page_id,author_id,parent_id,body,created_at) VALUES(?,?,?,?,?)""",
               (page, ana, fb, "Gracias! Subo esta semana las fotos de las entrevistas.", now()))

    # Red social de ejemplo
    db.execute("INSERT INTO contacts(requester_id,addressee_id,status,created_at) VALUES(?,?,?,?)",
               (ana, luis, "accepted", now()))
    db.execute("INSERT INTO contacts(requester_id,addressee_id,status,created_at) VALUES(?,?,?,?)",
               (maria, ana, "pending", now()))  # Maria envio solicitud a Ana
    db.execute("INSERT INTO messages(sender_id,recipient_id,body,created_at,is_read) VALUES(?,?,?,?,?)",
               (luis, ana, "Hola Ana! Me ha encantado tu portafolio.", now(), 0))
    db.execute("INSERT INTO messages(sender_id,recipient_id,body,created_at,is_read) VALUES(?,?,?,?,?)",
               (ana, luis, "Gracias Luis! El tuyo también pinta genial.", now(), 1))


def _demo_page(db, owner_id, title, description, visibility, group_id, blocks):
    pid = db.execute("""INSERT INTO pages(owner_id,title,description,visibility,created_at,group_id)
                        VALUES(?,?,?,?,?,?)""",
                     (owner_id, title, description, visibility, now(), group_id)).lastrowid
    for pos, (bt, text) in enumerate(blocks):
        rid = db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)",
                         (pid, pos, "1")).lastrowid
        if bt == "heading":
            db.execute("""INSERT INTO blocks(row_id,col_index,position,block_type,text_content,
                          font_family,font_size,text_color,bold) VALUES(?,?,?,?,?,?,?,?,?)""",
                       (rid, 0, 0, "heading", text, "serif", 24, "#7a1f3d", 1))
        else:
            db.execute("""INSERT INTO blocks(row_id,col_index,position,block_type,text_content,font_size)
                          VALUES(?,?,?,?,?,?)""",
                       (rid, 0, 0, "text", text, 16))
    return pid


def seed_demo(db):
    """Perfil desarrollado + segundo usuario + grupo con página de investigación. Idempotente."""
    if db.execute("SELECT id FROM users WHERE username=?", ("lucia",)).fetchone():
        return

    def mk(u, pw, name, email, onboarded, bio=""):
        return db.execute("""INSERT INTO users(username,password,name,role,email,bio,onboarded)
                             VALUES(?,?,?,?,?,?,?)""",
                          (u, generate_password_hash(pw, method=HASH), name, "student",
                           email, bio, onboarded)).lastrowid

    lucia = mk("lucia", "lucia123", "Lucia Fernandez", "lucia@ejemplo.org", 1,
               "Futura maestra de Educación Infantil. Me apasionan los ambientes de aprendizaje.")
    marta = mk("marta", "marta123", "Marta Ortega", "marta@ejemplo.org", 0,
               "Estudiante del Grado de Educación Infantil.")

    _demo_page(db, lucia, "Mi filosofía docente en Educación Infantil",
               "Quien soy como futura maestra", "public", None, [
        ("heading", "Mi mirada sobre la infancia"),
        ("text", "Concibo a cada niño y niña como una persona competente, curiosa y capaz, protagonista "
                 "de su propio aprendizaje. Mi tarea como futura maestra no es llenar un recipiente vacio, "
                 "sino crear las condiciones para que ese potencial se despliegue: un entorno seguro, "
                 "materiales cuidados y tiempo para explorar sin prisa."),
        ("heading", "El papel de la maestra"),
        ("text", "Entiendo la enseñanza como un acto de acompanamiento. Observo con atencion lo que hacen y "
                 "dicen los niños, formulo buenas preguntas y ajusto las propuestas a partir de lo que veo. "
                 "Documentar lo que ocurre en el aula me permite tomar decisiones fundamentadas y hacer "
                 "visible el aprendizaje a las familias y al equipo."),
        ("heading", "Valores que guian mi práctica"),
        ("text", "La escucha, el respeto por los ritmos individuales, la cooperacion y el vinculo con la "
                 "comunidad son los pilares sobre los que quiero construir mi identidad docente. Aspiro a una "
                 "escuela infantil amable, rica en experiencias y profundamente respetuosa con la infancia."),
    ])

    _demo_page(db, lucia, "Diseño de ambientes de aprendizaje",
               "El espacio que educa", "public", None, [
        ("heading", "El espacio como tercer educador"),
        ("text", "El ambiente comunica y educa. Un espacio ordenado, luminoso y con materiales al alcance de "
                 "los niños invita a la autonomía y a la iniciativa. Cada rincon se piensa con intencion: que "
                 "aprendizajes favorece, que relaciones propicia y como permite que cada niño encuentre su reto."),
        ("heading", "Materiales y provocaciones"),
        ("text", "Prefiero materiales naturales, no estructurados y esteticamente cuidados, que admiten "
                 "multiples usos y despiertan la imaginacion. Las provocaciones (una mesa de luz, una colección "
                 "de elementos naturales, un espejo) son invitaciones abiertas que no dirigen la respuesta, "
                 "sino que abren posibilidades de exploracion."),
        ("heading", "Organizacion del tiempo"),
        ("text", "Un ambiente potente necesita también un tiempo sin prisas. Franjas amplias de juego y "
                 "exploracion permiten la concentracion profunda, que es donde ocurre el aprendizaje "
                 "significativo en estas edades."),
    ])

    _demo_page(db, lucia, "Documentacion pedagogica",
               "Aprender observando", "public", None, [
        ("heading", "Hacer visible el aprendizaje"),
        ("text", "Documentar es recoger huellas del proceso (fotografias, transcripciones de conversaciones, "
                 "producciones de los niños) y darles sentido. No se trata de acumular evidencias, sino de "
                 "interpretar que esta aprendiendo cada niño y como, para compartirlo y seguir avanzando."),
        ("heading", "De la observacion a la decision"),
        ("text", "La documentación cierra un ciclo: observo, registro, interpreto y decido mi siguiente "
                 "propuesta. Es, a la vez, una herramienta de evaluación formativa, un cauce de comunicación "
                 "con las familias y una via de investigación sobre mi propia práctica."),
    ])

    _demo_page(db, lucia, "El juego como motor del aprendizaje",
               "Jugar es aprender", "public", None, [
        ("heading", "Jugar es aprender"),
        ("text", "En la etapa 0-6 el juego no es un descanso entre tareas: es la forma privilegiada de "
                 "aprender. Jugando, los niños ensayan roles, resuelven problemas, negocian con otros y "
                 "construyen su comprension del mundo. Proteger el juego es proteger el aprendizaje."),
        ("heading", "Juego libre y propuestas guiadas"),
        ("text", "Combino el juego libre, donde el niño decide y dirige, con propuestas guiadas que introducen "
                 "nuevos retos o lenguajes. El equilibrio entre ambos, y una intervencion respetuosa que no "
                 "interrumpe sino que enriquece, es clave para que el juego mantenga todo su potencial."),
    ])

    _demo_page(db, lucia, "Evaluación autentica en la etapa 0-6",
               "Evaluar para acompanar", "public", None, [
        ("heading", "Evaluar para acompanar"),
        ("text", "Evaluo para comprender y acompanar, no para clasificar. La evaluación en Infantil es "
                 "continua, formativa y basada en la observacion en contextos reales de actividad. Su fin es "
                 "ajustar mi enseñanza a lo que cada niño necesita en cada momento."),
        ("heading", "Instrumentos que utilizo"),
        ("text", "Me apoyo en el diario de aula, las escalas de observacion, la documentación pedagogica y el "
                 "portafolio del niño. Cruzados entre si, ofrecen una imagen rica y respetuosa del proceso de "
                 "cada criatura, evitando reducir su desarrollo a una nota."),
    ])

    gid = db.execute("INSERT INTO groups(name,owner_id,created_at) VALUES(?,?,?)",
                     ("Seminario de Lesson Study - Infantil", lucia, now())).lastrowid
    db.execute("INSERT INTO group_members(group_id,user_id) VALUES(?,?)", (gid, lucia))
    db.execute("INSERT INTO group_members(group_id,user_id) VALUES(?,?)", (gid, marta))

    _demo_page(db, lucia, "Investigación: Montessori y Reggio Emilia",
               "Marco para el diseño de nuestra leccion de investigación", "private", gid, [
        ("heading", "Objeto de la investigación"),
        ("text", "Como equipo de Lesson Study nos proponemos estudiar dos enfoques de referencia en Educación "
                 "Infantil (el metodo Montessori y la experiencia de Reggio Emilia) para fundamentar el diseño "
                 "de nuestra leccion de investigación. Buscamos identificar principios comunes que podamos "
                 "observar en el aula con niños reales."),
        ("heading", "Maria Montessori: autonomía y ambiente preparado"),
        ("text", "Montessori parte de la confianza en la capacidad del niño para autoeducarse cuando dispone "
                 "de un ambiente preparado. Sus pilares son el material sensorial autocorrectivo, los periodos "
                 "de concentracion, la libertad de eleccion dentro de limites, las aulas de edades mezcladas y "
                 "el papel del adulto como guia discreto que observa y presenta el material en el momento justo."),
        ("heading", "Reggio Emilia: los cien lenguajes y la documentación"),
        ("text", "La experiencia de Reggio Emilia, impulsada por Loris Malaguzzi, parte de una imagen del niño "
                 "rico y competente. Destacan el trabajo por proyectos surgidos de los intereses infantiles, "
                 "los cien lenguajes o multiples formas de expresion, el taller (atelier) y la figura del "
                 "atelierista, la documentación pedagogica como motor de reflexion y el ambiente como tercer "
                 "educador, en estrecho vinculo con la comunidad."),
        ("heading", "Convergencias y matices"),
        ("text", "Ambos enfoques situan al niño en el centro, cuidan el ambiente y dan gran valor a la "
                 "observacion del adulto. Se diferencian en el papel del material: muy estructurado y "
                 "secuenciado en Montessori, mas abierto y ligado al proyecto en Reggio. Tambien varia el "
                 "origen de la propuesta: preparada por la guia en Montessori, co-construida a partir de los "
                 "intereses del grupo en Reggio."),
        ("heading", "Implicaciones para nuestra leccion de investigación"),
        ("text", "De este análisis extraemos criterios para diseñar la leccion: preparar un ambiente cuidado "
                 "con materiales que inviten a la exploracion autonoma, plantear una propuesta abierta que "
                 "admita multiples lenguajes y respuestas, y reservar el papel del adulto para observar y "
                 "documentar. Estos principios guiaran los objetivos de aprendizaje y los items de observacion "
                 "que acordemos para la sesión."),
    ])

    # Sesión de Lesson Study de ejemplo (ya con la leccion realizada y evidencias)
    lsid = db.execute("""INSERT INTO ls_sessions(group_id,owner_id,title,lesson_date,lesson_done,created_at)
                         VALUES(?,?,?,?,?,?)""",
                      (gid, lucia, "Ciclo 1 - Exploracion con luz y sombra", "2026-05-14", 1, now())).lastrowid
    o1 = db.execute("INSERT INTO ls_objectives(session_id,text,position) VALUES(?,?,?)",
                    (lsid, "Explorar con autonomía materiales transluidos y fuentes de luz.", 0)).lastrowid
    o2 = db.execute("INSERT INTO ls_objectives(session_id,text,position) VALUES(?,?,?)",
                    (lsid, "Verbalizar descubrimientos sobre luz y sombra en interacción con iguales.", 1)).lastrowid
    i1 = db.execute("INSERT INTO ls_items(session_id,text,position) VALUES(?,?,?)",
                    (lsid, "Elige y combina los materiales con iniciativa propia.", 0)).lastrowid
    i2 = db.execute("INSERT INTO ls_items(session_id,text,position) VALUES(?,?,?)",
                    (lsid, "Comparte hallazgos o pregunta a otros niños.", 1)).lastrowid
    e1 = db.execute("""INSERT INTO ls_evidences(session_id,author_id,kind,note,captured_at,meta_ok,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (lsid, marta, "note",
                     "Julia coloca acetatos de colores sobre la mesa de luz y nombra los colores que aparecen al mezclarlos.",
                     "2026-05-14 10:12:00", 1, now())).lastrowid
    e2 = db.execute("""INSERT INTO ls_evidences(session_id,author_id,kind,note,captured_at,meta_ok,created_at)
                       VALUES(?,?,?,?,?,?,?)""",
                    (lsid, lucia, "note",
                     "Hugo llama a un companero: mira, si pongo la mano sale una sombra grande. Explican juntos por que cambia el tamano.",
                     "2026-05-14 10:20:00", 1, now())).lastrowid
    for (ev, tt, tid) in [(e1, "objective", o1), (e1, "item", i1), (e2, "objective", o2), (e2, "item", i2)]:
        db.execute("INSERT INTO ls_evidence_links(evidence_id,target_type,target_id) VALUES(?,?,?)", (ev, tt, tid))


# --------------------------------------------------------------------------- #
#  Auth
# --------------------------------------------------------------------------- #
def current_user():
    uid = session.get("uid")
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone() if uid else None


def unread_count(uid):
    return get_db().execute("SELECT COUNT(*) c FROM messages WHERE recipient_id=? AND is_read=0",
                            (uid,)).fetchone()["c"]


def recent_convos(uid, limit=6):
    db = get_db()
    partners = db.execute("""SELECT CASE WHEN sender_id=? THEN recipient_id ELSE sender_id END pid, MAX(id) mid
        FROM messages WHERE sender_id=? OR recipient_id=? GROUP BY pid ORDER BY mid DESC LIMIT ?""",
        (uid, uid, uid, limit)).fetchall()
    out = []
    for pr in partners:
        o = db.execute("SELECT name,username FROM users WHERE id=?", (pr["pid"],)).fetchone()
        if not o:
            continue
        last = db.execute("SELECT body FROM messages WHERE id=?", (pr["mid"],)).fetchone()["body"]
        unread = db.execute("SELECT COUNT(*) c FROM messages WHERE sender_id=? AND recipient_id=? AND is_read=0",
                            (pr["pid"], uid)).fetchone()["c"]
        out.append({"name": o["name"], "username": o["username"], "last": last, "unread": unread})
    return out


def is_online(row):
    try:
        if not row or not row["show_online"]:
            return False
        ls = row["last_seen"]
        if not ls:
            return False
        from datetime import timedelta
        return ls >= (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
    except Exception:
        return False


app.jinja_env.globals["online"] = is_online


@app.context_processor
def inject():
    u = current_user()
    notifs = []
    convos = []
    changes = []
    changes_count = 0
    if u:
        # Presencia: actualiza last_seen como mucho una vez por minuto.
        try:
            nowm = now()
            ls = u["last_seen"] if "last_seen" in u.keys() else None
            if (not ls) or ls < nowm:
                get_db().execute("UPDATE users SET last_seen=? WHERE id=?", (nowm, u["id"]))
                get_db().commit()
        except Exception:
            pass
        notifs = get_db().execute("""SELECT * FROM notifications WHERE user_id=? AND kind<>'Nuevo mensaje'
                                     ORDER BY id DESC LIMIT 10""", (u["id"],)).fetchall()
        convos = recent_convos(u["id"])
        if u["role"] in ("teacher", "admin"):
            changes = get_db().execute("""SELECT sc.*, us.name student_name, us.username student_username,
                pg.visibility page_vis
                FROM student_changes sc JOIN users us ON us.id=sc.student_id
                LEFT JOIN pages pg ON pg.id=sc.page_id
                WHERE sc.teacher_id=? ORDER BY sc.id DESC LIMIT 10""", (u["id"],)).fetchall()
            changes_count = get_db().execute("SELECT COUNT(*) c FROM student_changes WHERE teacher_id=? AND is_read=0",
                                             (u["id"],)).fetchone()["c"]
    show_tour = (bool(u) and ("onboarded" in u.keys()) and (not u["onboarded"])
                 and (u["role"] != "student" or get_setting("stu_tour", "1") != "0"))
    chat_on = bool(u) and (chat_enabled_dm() or chat_enabled_group())
    th = theme_settings()
    return {"user": u, "LAYOUTS": LAYOUTS, "LAYOUT_LABELS": LAYOUT_LABELS,
            "unread": unread_count(u["id"]) if u else 0,
            "notif": notif_count(u["id"]) if u else 0, "notifs": notifs, "convos": convos,
            "changes": changes, "changes_count": changes_count, "show_tour": show_tour,
            "chat_on": chat_on, "theme_style": theme_css(), "site_name": th["site_name"],
            "theme_logo": th["logo"], "theme_favicon": th["favicon"]}


def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if not current_user():
            return redirect(url_for("login", next=request.path))
        return f(*a, **k)
    return w


def role_required(*roles):
    def deco(f):
        @wraps(f)
        def w(*a, **k):
            u = current_user()
            if not u or u["role"] not in roles:
                abort(403)
            return f(*a, **k)
        return w
    return deco


# --------------------------------------------------------------------------- #
#  Contactos (conocidos) - helpers
# --------------------------------------------------------------------------- #
def contact_status(me, other):
    """none | pending_out | pending_in | accepted"""
    db = get_db()
    mo = db.execute("SELECT status FROM contacts WHERE requester_id=? AND addressee_id=?", (me, other)).fetchone()
    om = db.execute("SELECT status FROM contacts WHERE requester_id=? AND addressee_id=?", (other, me)).fetchone()
    if (mo and mo["status"] == "accepted") or (om and om["status"] == "accepted"):
        return "accepted"
    if mo and mo["status"] == "pending":
        return "pending_out"
    if om and om["status"] == "pending":
        return "pending_in"
    return "none"


# --------------------------------------------------------------------------- #
#  Render de artefactos y bloques
# --------------------------------------------------------------------------- #
def youtube_embed(url):
    m = re.search(r"(?:youtube\.com/(?:watch\?v=|embed/)|youtu\.be/)([\w-]{11})", url or "")
    return f"https://www.youtube.com/embed/{m.group(1)}" if m else None


def vimeo_embed(url):
    m = re.search(r"vimeo\.com/(\d+)", url or "")
    return f"https://player.vimeo.com/video/{m.group(1)}" if m else None


def artefact_html(a):
    if not a:
        return '<span class="muted">[artefacto eliminado]</span>'
    kind, title = a["kind"], escape(a["title"])
    head = f'<div class="art-title">{title}</div>'
    if kind == "text":
        return head + f'<div class="art-text">{escape(a["body"] or "")}</div>'
    if kind == "link":
        d = f'<div class="muted">{escape(a["body"] or "")}</div>' if a["body"] else ""
        return head + d + f'<a href="{escape(_safe_url(a["url"]))}" target="_blank" rel="noopener">{escape(a["url"] or "")}</a>'
    if kind == "image":
        src = f'/uploads/{a["filename"]}' if a["filename"] else escape(a["url"] or "")
        return head + f'<img class="art-media" src="{src}" alt="{title}">'
    if kind == "video":
        if a["url"]:
            emb = youtube_embed(a["url"]) or vimeo_embed(a["url"])
            if emb:
                return head + f'<div class="art-embed"><iframe src="{emb}" frameborder="0" allowfullscreen></iframe></div>'
            return head + f'<video class="art-media" src="{escape(a["url"])}" controls></video>'
        if a["filename"]:
            return head + f'<video class="art-media" src="/uploads/{a["filename"]}" controls></video>'
    if kind == "audio":
        src = f'/uploads/{a["filename"]}' if a["filename"] else escape(a["url"] or "")
        return head + f'<audio src="{src}" controls style="width:100%"></audio>'
    if kind == "file":
        fn = a["filename"] or ""
        if fn.lower().endswith(".pdf"):
            return head + (f'<div class="art-embed pdf"><iframe src="/uploads/{fn}"></iframe></div>'
                           f'<a href="/uploads/{fn}" target="_blank">Abrir / descargar PDF</a>')
        disp = escape(fn.split("_", 1)[-1] if "_" in fn else fn)
        return head + (f'<a class="btn sec sm" href="/uploads/{fn}" target="_blank">'
                       f'&#128196; Abrir / descargar {disp}</a>')
    return head


from html.parser import HTMLParser

_ALLOWED_TAGS = {"b", "strong", "i", "em", "u", "s", "strike", "del", "br", "span", "font",
                 "p", "div", "ul", "ol", "li", "a", "h3", "h4", "blockquote"}
_ALLOWED_ATTRS = {"span": ["style"], "font": ["color", "size"], "p": ["style"], "div": ["style"],
                  "a": ["href", "target", "rel"], "li": ["style"], "ul": ["style"], "ol": ["style"]}
_SAFE_STYLE = ("color", "font-weight", "font-style", "text-decoration", "font-size", "background-color")


class _Sanitizer(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.out = []

    def _clean_style(self, style):
        props = []
        for part in (style or "").split(";"):
            if ":" in part:
                k, v = part.split(":", 1)
                k = k.strip().lower(); v = v.strip()
                if k in _SAFE_STYLE and "url(" not in v.lower() and "expression" not in v.lower():
                    props.append("%s:%s" % (k, v))
        return ";".join(props)

    def handle_starttag(self, tag, attrs):
        if tag == "br":
            self.out.append("<br>"); return
        if tag not in _ALLOWED_TAGS:
            return
        allowed = _ALLOWED_ATTRS.get(tag, [])
        kept = []
        for k, v in attrs:
            if k not in allowed:
                continue
            if k == "style":
                v = self._clean_style(v)
                if not v:
                    continue
            if tag == "a" and k == "href":
                v = _safe_url(v)  # bloquea javascript: y esquemas peligrosos
            kept.append((k, v or ""))
        if tag == "a":  # forzar apertura segura de enlaces
            kd = dict(kept)
            kd["target"] = "_blank"
            kd["rel"] = "noopener nofollow"
            kept = list(kd.items())
        s = "<" + tag
        for k, v in kept:
            s += ' %s="%s"' % (k, escape(v, quote=True))
        self.out.append(s + ">")

    def handle_startendtag(self, tag, attrs):
        if tag == "br":
            self.out.append("<br>")

    def handle_endtag(self, tag):
        if tag in _ALLOWED_TAGS and tag != "br":
            self.out.append("</%s>" % tag)

    def handle_data(self, data):
        self.out.append(escape(data))


def sanitize_html(s):
    p = _Sanitizer()
    p.feed(s or "")
    return "".join(p.out)


def block_html(b):
    if b["block_type"] == "artefact":
        a = get_db().execute("SELECT * FROM artefacts WHERE id=?", (b["artefact_id"],)).fetchone()
        return artefact_html(a)
    fam = FONTS.get(b["font_family"], FONTS["sans"])
    size = b["font_size"] or (26 if b["block_type"] == "heading" else 16)
    base_weight = "700" if b["block_type"] == "heading" else "400"
    content = b["text_content"] or ""
    if "<" in content:
        inner = sanitize_html(content); ws = "normal"
    elif content:
        inner = escape(content).replace("\n", "<br>"); ws = "pre-wrap"
    else:
        inner = '<span class="muted">(vacio: pulsa Editar)</span>'; ws = "normal"
    style = "font-family:%s;font-size:%spx;color:%s;text-align:%s;font-weight:%s;white-space:%s;" % (
        fam, size, b["text_color"] or "#1c1922", b["align"] or "left", base_weight, ws)
    tag = "h2" if b["block_type"] == "heading" else "div"
    return '<%s class="art-text" style="%s">%s</%s>' % (tag, style, inner, tag)


# --------------------------------------------------------------------------- #
#  Plantilla base
# --------------------------------------------------------------------------- #
BASE = """
<!doctype html><html lang="es"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<script>
// Aplica el tema (claro/oscuro) antes de pintar para evitar parpadeo.
(function(){ try{ var t=localStorage.getItem('evestigia-theme');
  if(!t) t=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light';
  document.documentElement.setAttribute('data-theme', t);
  if(localStorage.getItem('evestigia-bigtext')==='1') document.documentElement.setAttribute('data-bigtext','1');
  if(localStorage.getItem('evestigia-reduce')==='1') document.documentElement.setAttribute('data-reduce','1');
}catch(e){} })();
function toggleTheme(){ var r=document.documentElement;
  var cur=r.getAttribute('data-theme')==='dark'?'light':'dark';
  r.setAttribute('data-theme',cur);
  try{ localStorage.setItem('evestigia-theme',cur); }catch(e){} }
function prefTheme(v){ try{
  if(v==='auto'){ localStorage.removeItem('evestigia-theme');
    v=(window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches)?'dark':'light'; }
  else localStorage.setItem('evestigia-theme',v);
  document.documentElement.setAttribute('data-theme',v);
}catch(e){} }
</script>
<title>{% if title and title != site_name %}{{ title }} &middot; {{ site_name }}{% else %}{{ site_name }}{% endif %}</title>
{% if theme_favicon %}<link rel="icon" href="{{ url_for('brand_favicon') }}">
{% else %}<link rel="icon" type="image/svg+xml" href="/favicon.svg">
<link rel="icon" type="image/png" sizes="64x64" href="/favicon.png">
<link rel="apple-touch-icon" href="/favicon.png">
<link rel="mask-icon" href="/favicon.svg" color="var(--brand)">{% endif %}
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
 :root{--brand:#7a1f3d;--brand2:#c0325f;--accent:#ff5c8a;--bg:#f2f0f5;--card:#fff;
  --ink:#1c1922;--muted:#8b8492;--line:#ece7ef;--radius:16px;--shadow:0 6px 24px rgba(28,20,42,.07);
  --bg-glow:#efe7f2;--input-bg:#fff;--input-ink:#1c1922}
 :root[data-theme="dark"]{--brand:#c0325f;--brand2:#e0578a;--accent:#ff5c8a;--bg:#141118;--card:#1e1a24;
  --ink:#ece7ef;--muted:#9a92a5;--line:#332c3b;--shadow:0 6px 24px rgba(0,0,0,.45);
  --bg-glow:#241a2b;--input-bg:#26212e;--input-ink:#ece7ef}
 *{box-sizing:border-box}
 body{margin:0;font-family:'Inter',-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  background:radial-gradient(1200px 600px at 100% -10%,var(--bg-glow),transparent),var(--bg);color:var(--ink);letter-spacing:-.01em}
 :root[data-theme="dark"] input,:root[data-theme="dark"] textarea,:root[data-theme="dark"] select{background:var(--input-bg);color:var(--input-ink);border-color:var(--line)}
 :root[data-theme="dark"] .rt-edit,:root[data-theme="dark"] .block-text{color:var(--ink)}
 .ico-sun{display:none}
 :root[data-theme="dark"] .ico-moon{display:none}
 :root[data-theme="dark"] .ico-sun{display:inline}
 :root[data-bigtext="1"] body{font-size:18px}
 :root[data-reduce="1"] *{animation:none!important;transition:none!important;scroll-behavior:auto!important}
 a{color:var(--brand2);text-decoration:none}a:hover{text-decoration:underline}
 header{background:linear-gradient(135deg,#6e1836,#98234a 55%,#c0325f);color:#fff;padding:0 20px;
  display:flex;align-items:center;gap:14px;height:62px;position:sticky;top:0;z-index:30;
  box-shadow:0 6px 24px rgba(122,31,61,.30);border-bottom:1px solid rgba(255,255,255,.10);
  backdrop-filter:saturate(1.1)}
 header .logo{font-weight:800;font-size:20px;letter-spacing:-.02em;display:flex;align-items:center;
  padding-right:6px;margin-right:4px;text-shadow:0 1px 2px rgba(0,0,0,.18);white-space:nowrap}
 header nav{display:flex;gap:3px;flex:1;flex-wrap:wrap;align-items:center}
 header nav a{position:relative;color:rgba(255,255,255,.9);font-size:13.5px;font-weight:500;
  padding:8px 12px;border-radius:10px;transition:background .16s ease,color .16s ease,transform .12s ease;white-space:nowrap}
 header nav a:hover{color:#fff;text-decoration:none;background:rgba(255,255,255,.14);transform:translateY(-1px)}
 header nav a:active{transform:translateY(0)}
 header nav a.active{color:#fff;background:rgba(255,255,255,.18);font-weight:600}
 header nav a.active::after{content:"";position:absolute;left:12px;right:12px;bottom:2px;height:2px;
  border-radius:2px;background:rgba(255,255,255,.85)}
 header .badge{background:var(--accent);color:#fff;border-radius:20px;padding:1px 7px;font-size:11px;font-weight:700;margin-left:4px;box-shadow:0 2px 6px rgba(255,92,138,.45)}
 header .me{font-size:13px;display:flex;gap:10px;align-items:center;font-weight:500;
  padding-left:14px;margin-left:4px;border-left:1px solid rgba(255,255,255,.16)}
 header .me>a{color:#fff;opacity:.92;transition:opacity .15s ease}
 header .me>a:hover{opacity:1;text-decoration:none}
 header .me .uname{padding:5px 10px;border-radius:10px;font-weight:600}
 header .me .uname:hover{background:rgba(255,255,255,.14)}
 header .me .logout{font-size:12px;padding:5px 10px;border-radius:10px;background:rgba(255,255,255,.12);font-weight:600}
 header .me .logout:hover{background:rgba(255,255,255,.22)}
 .role{background:rgba(255,255,255,.20);padding:3px 9px;border-radius:20px;font-size:10px;text-transform:uppercase;letter-spacing:.04em;font-weight:700}
 .wrap{max-width:1080px;margin:28px auto;padding:0 18px}
 .card{background:var(--card);border:1px solid var(--line);border-radius:var(--radius);padding:22px;margin-bottom:18px;box-shadow:var(--shadow)}
 h1{font-size:26px;margin:.2em 0;font-weight:800;letter-spacing:-.02em}
 h2{font-size:20px;margin:.6em 0 .4em;font-weight:700;letter-spacing:-.01em}
 .muted{color:var(--muted);font-size:14px}
 .btn{display:inline-block;background:linear-gradient(135deg,#7a1f3d,#c0325f);color:#fff;border:0;
  padding:10px 18px;border-radius:11px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;
  box-shadow:0 4px 14px rgba(122,31,61,.22);transition:.16s}
 .btn:hover{text-decoration:none;transform:translateY(-1px);box-shadow:0 8px 20px rgba(122,31,61,.3)}
 .btn.sec{background:#f2edf1;color:var(--brand);box-shadow:none}
 .btn.sec:hover{background:#ece3ea}
 .btn.sm{padding:5px 11px;font-size:12px;border-radius:9px}
 .btn.danger{background:linear-gradient(135deg,#b23,#d34)}
 input,textarea,select{width:100%;padding:10px 12px;border:1px solid var(--line);border-radius:11px;
  font-size:14px;font-family:inherit;margin:4px 0 12px;background:#fbfafc;transition:.15s;color:var(--ink)}
 input:focus,textarea:focus,select:focus{outline:none;border-color:var(--brand2);box-shadow:0 0 0 3px rgba(192,50,95,.12);background:#fff}
 textarea{min-height:80px}
 label{font-size:13px;font-weight:600;color:#4a444d}
 .grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:14px}
 .tile{background:linear-gradient(160deg,#fff,#faf6f9);border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:var(--shadow)}
 .tile .k{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--brand2);font-weight:700}
 .flash{background:linear-gradient(135deg,#fff4e0,#ffe9ef);border:1px solid #f0d9b8;padding:12px 16px;border-radius:12px;margin-bottom:14px;font-size:14px;box-shadow:var(--shadow)}
 .flash.err{background:#fdecec;border-color:#e6b0b0}
 .pill{display:inline-block;font-size:11px;padding:3px 10px;border-radius:20px;background:#f2edf1;color:var(--brand);margin-left:6px;font-weight:600}
 .row-flex{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
 .between{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}
 .prow{display:grid;gap:16px;margin-bottom:16px}
 .pcol{min-width:0}
 .art-title{font-weight:700;color:var(--brand);margin-bottom:6px}
 .art-text{line-height:1.55;margin:0}
 .art-media{max-width:100%;border-radius:12px;border:1px solid var(--line);display:block}
 .art-embed{position:relative;padding-bottom:56.25%;height:0;border-radius:12px;overflow:hidden;border:1px solid var(--line)}
 .art-embed iframe{position:absolute;top:0;left:0;width:100%;height:100%}
 .art-embed.pdf{padding-bottom:0;height:480px}
 .blk{border:1px solid var(--line);border-radius:12px;padding:12px;margin-bottom:10px;background:#fff;box-shadow:0 2px 8px rgba(28,20,42,.04)}
 .blk .bar{display:flex;gap:6px;justify-content:space-between;align-items:center;margin-bottom:8px}
 /* El menu de edicion solo aparece en el bloque activo; el resto se ve "como quedaria" */
 .blk .rt-toolbar{display:none}
 .blk.editing .rt-toolbar{display:flex}
 .blk .rt-edit.block-text{border:1px solid transparent;background:transparent;min-height:0;padding:4px 2px;box-shadow:none}
 .blk.editing .rt-edit.block-text{border-color:var(--line);background:#fff;min-height:60px;padding:10px 12px}
 .blk .bar{opacity:.28;transition:opacity .15s ease}
 .blk:hover .bar,.blk.editing .bar{opacity:1}
 .colbox{border:1.5px dashed #ddd3dc;border-radius:12px;padding:10px;background:#fbf9fc}
 .pcol.dropzone{min-height:70px}
 .pal-item{border:1px solid var(--line);border-radius:11px;padding:10px 12px;margin:7px 0;background:#fff;cursor:grab;font-size:13px;font-weight:500;user-select:none;transition:.15s;box-shadow:0 2px 8px rgba(28,20,42,.04)}
 .pal-item:hover{border-color:var(--brand2);color:var(--brand);transform:translateX(2px)}
 .drag-handle{cursor:grab;color:var(--muted);font-size:12px;font-weight:600}
 .sortable-ghost{opacity:.35}.sortable-drag{opacity:.9}
 details.add summary{cursor:pointer;color:var(--brand2);font-size:13px;font-weight:600;list-style:none}
 details.add summary::-webkit-details-marker{display:none}
 .rt-toolbar{display:flex;gap:6px;align-items:center;flex-wrap:wrap;margin-bottom:6px}
 .rt-toolbar button{background:#f2edf1;border:1px solid var(--line);border-radius:8px;width:32px;height:32px;cursor:pointer;font-size:14px}
 .rt-toolbar button:hover{background:#e7dde8}
 .rt-toolbar input[type=color]{width:34px;height:32px;padding:2px;margin:0}
 .rt-toolbar select{width:auto;margin:0;padding:5px 8px}
 .rt-edit{min-height:80px;border:1px solid var(--line);border-radius:11px;padding:10px 12px;background:#fff;line-height:1.5;font-size:14px}
 .rt-edit:focus{outline:none;border-color:var(--brand2);box-shadow:0 0 0 3px rgba(192,50,95,.12)}
 .modal-ov{position:fixed;inset:0;background:rgba(20,12,26,.5);display:flex;align-items:center;justify-content:center;z-index:100;backdrop-filter:blur(3px)}
 .modal{background:#fff;border-radius:18px;padding:24px;width:440px;max-width:92vw;max-height:90vh;overflow:auto;box-shadow:0 20px 60px rgba(0,0,0,.3)}
 .toolbar{display:grid;grid-template-columns:repeat(auto-fit,minmax(110px,1fr));gap:8px}
 .comment{border-left:3px solid var(--brand2);padding:8px 14px;margin:10px 0;background:#faf6f9;border-radius:0 10px 10px 0}
 .avatar{width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,#7a1f3d,#c0325f);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700;flex-shrink:0;box-shadow:0 3px 10px rgba(122,31,61,.3)}
 .prow-list>div{padding:10px 0;border-bottom:1px solid var(--line)}
 .bubble{max-width:70%;padding:10px 14px;border-radius:16px;margin:6px 0;font-size:14px;line-height:1.4;box-shadow:0 2px 8px rgba(28,20,42,.06)}
 .bubble.me{background:linear-gradient(135deg,#7a1f3d,#c0325f);color:#fff;margin-left:auto;border-bottom-right-radius:5px}
 .bubble.them{background:#fff;color:var(--ink);margin-right:auto;border:1px solid var(--line);border-bottom-left-radius:5px}
 .bubble .t{display:block;font-size:10px;opacity:.7;margin-top:3px}
 .coll-card{background:linear-gradient(160deg,#fff,#f1e9fb);border-color:#e2d5f0}
 .tag-coll{display:inline-block;font-size:10px;text-transform:uppercase;letter-spacing:.05em;font-weight:700;color:#6b3fa0;background:#ece0f7;padding:2px 8px;border-radius:20px;margin-right:4px}
 .qbar{height:14px;background:#eee6ee;border-radius:20px;overflow:hidden;margin-top:12px;box-shadow:inset 0 1px 3px rgba(28,20,42,.12)}
 .qbar-fill{height:100%;background:linear-gradient(90deg,#7a1f3d,#c0325f);border-radius:20px;transition:width .5s cubic-bezier(.16,1,.3,1)}
 .qbar-fill.warn{background:linear-gradient(90deg,#d38b1e,#e0a92e)}
 .qbar-fill.over{background:linear-gradient(90deg,#c0392b,#e04b3a)}
 footer{text-align:center;color:var(--muted);font-size:12px;padding:34px}
 table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 6px;border-bottom:1px solid var(--line)}
 th{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted)}
 .bell-wrap{position:relative;display:inline-block}
 .bell{background:transparent;border:0;color:#fff;cursor:pointer;position:relative;padding:6px 8px;line-height:0;display:inline-flex;align-items:center;justify-content:center}
 .bell svg{width:20px;height:20px;display:block}
 .bell .badge{position:absolute;top:-3px;right:-3px;min-width:17px;height:17px;padding:0 4px;
  margin:0;background:var(--accent);color:#fff;border-radius:9px;font-size:10px;font-weight:700;
  line-height:17px;text-align:center;text-decoration:none;box-sizing:border-box;box-shadow:0 0 0 2px var(--brand)}
 .bell-menu{position:absolute;right:0;top:46px;width:330px;max-height:440px;overflow:auto;background:#fff;border:1px solid var(--line);border-radius:16px;box-shadow:0 18px 50px rgba(20,12,26,.28);z-index:60;opacity:0;visibility:hidden;transform:translateY(-8px) scale(.97);transform-origin:top right;transition:opacity .16s ease,transform .2s cubic-bezier(.16,1,.3,1),visibility .2s}
 .bell-menu.open{opacity:1;visibility:visible;transform:none}
 .bell{transition:transform .12s ease,opacity .15s ease}.bell:hover{opacity:.85}.bell:active{transform:scale(.9)}
 .bell-head{font-weight:700;padding:12px 14px;border-bottom:1px solid var(--line);color:var(--ink)}
 .bell-item{display:block;padding:11px 14px;border-bottom:1px solid var(--line);color:var(--ink)}
 .bell-item:hover{background:#faf6f9;text-decoration:none}
 .bell-item.unread{background:#fdf0f4}
 .bell-item b{color:var(--brand);font-size:13px}
 .bell-item .bt{font-size:11px;color:var(--muted);margin-top:2px}
 .bell-empty{padding:18px 14px}
 .bell-all{display:block;text-align:center;padding:11px;font-weight:600}
 /* --- Craft / micro-interacciones --- */
 .toasts{position:fixed;top:74px;right:18px;z-index:200;display:flex;flex-direction:column;gap:10px;max-width:340px}
 .toast{background:#fff;border:1px solid var(--line);border-left:4px solid var(--brand2);border-radius:12px;padding:12px 16px;font-size:14px;color:var(--ink);box-shadow:0 14px 38px rgba(20,12,26,.18);cursor:pointer;animation:toastIn .3s cubic-bezier(.16,1,.3,1)}
 .toast.err{border-left-color:#d34}
 .toast.hide{animation:toastOut .22s ease forwards}
 @keyframes toastIn{from{opacity:0;transform:translateX(22px) scale(.97)}to{opacity:1;transform:none}}
 @keyframes toastOut{to{opacity:0;transform:translateX(22px);height:0;margin:0;padding-top:0;padding-bottom:0;border-width:0}}
 .btn{transition:transform .14s cubic-bezier(.16,1,.3,1),background .16s ease,box-shadow .18s ease}
 .btn:active{transform:translateY(0) scale(.97)}
 a{transition:color .15s ease}
 .tile{transition:transform .18s cubic-bezier(.16,1,.3,1),box-shadow .18s ease}
 a.tile:hover{transform:translateY(-3px);box-shadow:0 14px 32px rgba(28,20,42,.13)}
 .pal-item{transition:transform .16s cubic-bezier(.16,1,.3,1),border-color .16s ease,color .16s ease}
 .card{transition:box-shadow .2s ease}
 :focus-visible{outline:2px solid var(--brand2);outline-offset:2px;border-radius:6px}
 .wrap{animation:pageIn .34s cubic-bezier(.16,1,.3,1)}
 @keyframes pageIn{from{opacity:0;transform:translateY(7px)}to{opacity:1;transform:none}}
 @media (prefers-reduced-motion: reduce){*{animation:none!important;transition:none!important}}
</style>{{ theme_style|safe }}</head><body>
{% if user %}
<header><span class="logo">{% if theme_logo %}<img src="{{ url_for('brand_logo') }}" style="height:26px;vertical-align:-7px;margin-right:8px">{% else %}<svg width="24" height="24" viewBox="0 0 24 24" style="vertical-align:-6px;margin-right:7px"><g fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round"><path d="M4 18 Q12 6 20 18"/><path d="M6.5 18.4 Q12 9 17.5 18.4"/><path d="M9 18.2 Q12 12 15 18.2"/></g><circle cx="12" cy="15.6" r="1.25" fill="#ff5c8a"/></svg>{% endif %}{{ site_name }}</span>
 <nav>
  <a href="{{ url_for('dashboard') }}">Inicio</a>
  <a href="{{ url_for('pages') }}">Mis páginas</a>
  {% if feat('stu_community') %}<a href="{{ url_for('feed') }}">Comunidad</a>{% endif %}
  {% if user['role'] in ('teacher','admin') %}<a href="{{ url_for('analytics') }}">Analíticas</a>{% endif %}
  {% if user['role']=='admin' %}<a href="{{ url_for('admin_home') }}">Administración</a>{% endif %}
 </nav>
 <span class="me">
  {% if feat('stu_messages') %}
  <span class="bell-wrap">
   <button type="button" class="bell" id="msgBtn" onclick="toggleMsg(event)" title="Mensajes"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="5" width="18" height="14" rx="2"/><path d="m3 7 9 6 9-6"/></svg><span class="badge" id="msgCount" style="{{ '' if unread else 'display:none' }}">{{ unread }}</span></button>
   <div class="bell-menu" id="msgMenu">
    <div class="bell-head">Mensajes</div>
    <div id="msgList">
    {% for c in convos %}
     <a class="bell-item {{ 'unread' if c['unread'] else '' }}" href="{{ url_for('thread', username=c['username']) }}">
      <b>{{ c['name'] }}</b>{% if c['unread'] %} <span class="pill">{{ c['unread'] }}</span>{% endif %}
      <div class="muted" style="font-size:13px">{{ c['last'][:60] }}</div></a>
    {% else %}<div class="bell-empty muted">No tienes mensajes.</div>{% endfor %}
    </div>
    <a class="bell-all" href="{{ url_for('inbox') }}">Ver todos</a>
   </div>
  </span>
  {% endif %}
  <span class="bell-wrap">
   <button type="button" class="bell" id="bellBtn" onclick="toggleBell(event)" title="Avisos"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 0 1-3.46 0"/></svg><span class="badge" id="bellCount" style="{{ '' if notif else 'display:none' }}">{{ notif }}</span></button>
   <div class="bell-menu" id="bellMenu">
    <div class="bell-head">Avisos</div>
    <div id="bellList">
    {% for n in notifs %}
     <a class="bell-item {{ '' if n['is_read'] else 'unread' }}" href="{{ url_for('notif_go', nid=n['id']) }}">
      <b>{{ n['kind'] }}</b><div class="muted" style="font-size:13px">{{ n['text'][:72] }}</div>
      <div class="bt">{{ n['created_at'] }}</div></a>
    {% else %}<div class="bell-empty muted">No tienes avisos.</div>{% endfor %}
    </div>
    <a class="bell-all" href="{{ url_for('notifications') }}">Ver todos</a>
   </div>
  </span>
  {% if user['role'] in ('teacher','admin') %}
  <span class="bell-wrap">
   <button type="button" class="bell" id="chgBtn" onclick="toggleChg(event)" title="Cambios de estudiantes"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.12 2.12 0 0 1 3 3L7 19l-4 1 1-4Z"/></svg><span class="badge" id="chgCount" style="{{ '' if changes_count else 'display:none' }}">{{ changes_count }}</span></button>
   <div class="bell-menu" id="chgMenu">
    <div class="bell-head">Cambios de estudiantes</div>
    <div>
    {% for ch in changes %}
     <a class="bell-item {{ '' if ch['is_read'] else 'unread' }}" href="{{ url_for('changes') }}">
      <b>{{ ch['student_name'] }}</b><div class="muted" style="font-size:13px">{{ ch['detail'] }}: {{ (ch['page_title'] or '')[:40] }}</div>
      <div class="bt">{{ ch['created_at'] }}</div></a>
    {% else %}<div class="bell-empty muted">Sin cambios recientes.</div>{% endfor %}
    </div>
    <a class="bell-all" href="{{ url_for('changes') }}">Ver todos</a>
   </div>
  </span>
  {% endif %}
 <button type="button" class="bell" onclick="toggleTheme()" title="Modo claro / oscuro" aria-label="Cambiar tema">
   <svg class="ico-moon" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg>
   <svg class="ico-sun" viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg></button>
 {% if user['avatar'] %}<img src="{{ url_for('uploaded', fn=user['avatar']) }}" style="width:28px;height:28px;border-radius:50%;object-fit:cover;border:1.5px solid rgba(255,255,255,.4)">{% endif %}<a class="uname" href="{{ url_for('profile', username=user['username']) }}">{{ user['name'] }}</a>
  <a class="logout" href="{{ url_for('logout') }}">Salir</a></span>
</header>{% endif %}
<div class="wrap">
 <div class="toasts" id="toasts">
 {% with ms=get_flashed_messages(with_categories=true) %}{% for c,m in ms %}
   <div class="toast {{ 'err' if c=='error' else '' }}">{{ m }}</div>{% endfor %}{% endwith %}
 </div>
 {{ body|safe }}
</div>
<footer>
 <div style="font-weight:700;color:var(--brand);font-size:14px">{{ site_name }}</div>
 <div style="margin-top:7px;font-size:11px;opacity:.75">Software libre y de código abierto, bajo <a href="https://opensource.org/licenses/MIT" target="_blank" rel="noopener" style="color:inherit;text-decoration:underline">Licencia MIT</a> &middot; &copy; 2026
  &middot; <a href="https://github.com/miguelfortessan/evestigia" target="_blank" rel="noopener" title="Ver el código en GitHub" style="color:inherit;vertical-align:middle"><svg height="15" width="15" viewBox="0 0 16 16" fill="currentColor" style="vertical-align:-2px"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82a7.6 7.6 0 012-.27c.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.01 8.01 0 0016 8c0-4.42-3.58-8-8-8z"/></svg></a></div>
</footer>
<script>
function _esc(s){var d=document.createElement('div');d.textContent=(s==null?'':s);return d.innerHTML;}
function _closeMenus(keep){document.querySelectorAll('.bell-menu').forEach(function(x){if(x.id!==keep)x.classList.remove('open');});}
function toggleBell(e){e.stopPropagation();_closeMenus('bellMenu');var m=document.getElementById('bellMenu');if(m)m.classList.toggle('open');}
function toggleMsg(e){e.stopPropagation();_closeMenus('msgMenu');var m=document.getElementById('msgMenu');if(m)m.classList.toggle('open');}
function toggleChg(e){e.stopPropagation();_closeMenus('chgMenu');var m=document.getElementById('chgMenu');if(m)m.classList.toggle('open');}
document.addEventListener('click',function(e){if(!e.target.closest('.bell-wrap'))_closeMenus('');});
function _setBadge(id,n){var c=document.getElementById(id);if(!c)return;if(n>0){c.textContent=n;c.style.display='inline';}else{c.style.display='none';}}
function _fill(id,items,fn,empty){var l=document.getElementById(id);if(!l)return;l.innerHTML=items.length?items.map(fn).join(''):('<div class="bell-empty muted">'+empty+'</div>');}
function _notifItem(n){return '<a class="bell-item '+(n.is_read?'':'unread')+'" href="/n/'+n.id+'"><b>'+_esc(n.kind)+'</b><div class="muted" style="font-size:13px">'+_esc((n.text||'').slice(0,72))+'</div><div class="bt">'+_esc(n.created_at)+'</div></a>';}
function _msgItem(c){return '<a class="bell-item '+(c.unread?'unread':'')+'" href="/messages/'+encodeURIComponent(c.username)+'"><b>'+_esc(c.name)+'</b>'+(c.unread?' <span class="pill">'+c.unread+'</span>':'')+'<div class="muted" style="font-size:13px">'+_esc((c.last||'').slice(0,60))+'</div></a>';}
function renderPoll(d){_setBadge('bellCount',d.count);_fill('bellList',d.items||[],_notifItem,'No tienes avisos.');_setBadge('msgCount',d.msg_count);_fill('msgList',d.msg_items||[],_msgItem,'No tienes mensajes.');}
function pollAll(){fetch('/api/notifications').then(function(r){return r.ok?r.json():null;}).then(function(d){if(d&&typeof d.count!=='undefined')renderPoll(d);}).catch(function(){});}
if(document.getElementById('bellBtn')||document.getElementById('msgBtn')){setInterval(pollAll,20000);document.addEventListener('visibilitychange',function(){if(!document.hidden)pollAll();});}
(function(){var ts=document.querySelectorAll('#toasts .toast');ts.forEach(function(t,i){function go(){t.classList.add('hide');setTimeout(function(){t.remove();},240);}setTimeout(go,4200+i*250);t.addEventListener('click',go);});})();
</script>
{% if user and chat_on %}
<div id="chatDock" style="position:fixed;right:16px;bottom:0;z-index:250;width:320px;font-size:14px;box-shadow:0 -6px 30px rgba(20,12,26,.18);border-radius:12px 12px 0 0">
 <div onclick="chatToggle()" style="background:linear-gradient(135deg,#6e1836,#c0325f);color:#fff;padding:10px 14px;border-radius:12px 12px 0 0;cursor:pointer;display:flex;justify-content:space-between;align-items:center">
  <b>&#128172; Chat <span id="chatBadge" style="display:none;background:#e23b5a;color:#fff;border-radius:10px;padding:1px 7px;font-size:12px;margin-left:4px">0</span></b><span id="chatCaret">&#9650;</span></div>
 <div id="chatBody" style="display:none;background:var(--card);color:var(--ink);border:1px solid var(--line);border-top:0;height:380px;flex-direction:column">
  <div id="chatList" style="flex:1;overflow:auto;padding:6px"></div>
  <div id="chatConv" style="display:none;flex-direction:column;height:100%">
   <div style="padding:8px 10px;border-bottom:1px solid var(--line);display:flex;align-items:center;gap:8px">
    <button type="button" class="btn sec sm" onclick="chatBack()">&larr;</button><b id="chatTitle"></b></div>
   <div id="chatOffNote" style="display:none;font-size:12px;background:#fff4e6;color:#7a4a00;padding:6px 10px;border-bottom:1px solid var(--line)"></div>
   <div id="chatMsgs" style="flex:1;overflow:auto;padding:8px;display:flex;flex-direction:column;gap:6px"></div>
   <form onsubmit="return chatSend(event)" style="display:flex;gap:6px;padding:8px;border-top:1px solid var(--line);margin:0">
    <input id="chatInput" placeholder="Escribe un mensaje..." style="flex:1;margin:0" autocomplete="off">
    <button class="btn sm">Enviar</button></form>
  </div>
  <div style="font-size:11px;color:var(--muted);padding:5px 10px;border-top:1px solid var(--line)">Mensajes cifrados. Por seguridad, el profesorado puede revisarlos.</div>
 </div>
</div>
<script>
(function(){
var open=false, cur=null, unreadConvs={}, lastTotal=0, baseTitle=document.title, actx=null;
function el(id){return document.getElementById(id);}
function chatAudioUnlock(){ try{ if(!actx) actx=new (window.AudioContext||window.webkitAudioContext)();
  if(actx.state==='suspended') actx.resume(); }catch(e){} }
// Los navegadores bloquean el sonido hasta que el usuario interactúa: lo desbloqueamos al primer gesto.
['click','keydown','touchstart'].forEach(function(ev){
  document.addEventListener(ev, chatAudioUnlock, {once:false, passive:true}); });
function chatBeep(){ try{ chatAudioUnlock(); if(!actx) return;
  var o=actx.createOscillator(), g=actx.createGain(); o.connect(g); g.connect(actx.destination);
  o.type='sine'; o.frequency.value=680; g.gain.value=0.09; o.start();
  o.frequency.setValueAtTime(880, actx.currentTime+0.09);
  g.gain.exponentialRampToValueAtTime(0.0001, actx.currentTime+0.28); o.stop(actx.currentTime+0.3);
  }catch(e){} }
function chatUnread(){ fetch('/api/chat/unread').then(function(r){return r.json();}).then(function(d){
  unreadConvs=d.convs||{};
  var b=el('chatBadge');
  if(d.total>0){ b.textContent=d.total; b.style.display='inline-block'; }
  else b.style.display='none';
  document.title=(d.total>0?('('+d.total+') '):'')+baseTitle;
  if(d.total>lastTotal){ chatBeep(); }
  lastTotal=d.total;
  if(open && !cur) chatLoadList();
  }).catch(function(){}); }
window.addEventListener('focus', function(){ if(lastTotal>0) chatUnread(); });
window.chatToggle=function(){open=!open;
  el('chatBody').style.display=open?'flex':'none';
  el('chatCaret').innerHTML=open?'&#9660;':'&#9650;';
  if(open) chatLoadList(); };
function chatLoadList(){ cur=null; el('chatConv').style.display='none'; el('chatList').style.display='block';
  fetch('/api/chat/peers').then(function(r){return r.json();}).then(function(d){
    var h='';
    function badge(k){ var n=unreadConvs[k]||0; return n>0?('<span style="float:right;background:#e23b5a;color:#fff;border-radius:10px;padding:0 7px;font-size:12px">'+n+'</span>'):''; }
    if(d.pending && d.pending.length){ h+='<div class="muted" style="font-weight:700;padding:6px 8px">Pendientes</div>';
      d.pending.forEach(function(p){ h+='<div class="chat-item" data-k="dm" data-id="'+p.id+'" data-n="'+_esc(p.name)+'" data-off="1" data-u="'+_esc(p.username)+'" style="padding:8px 10px;border-radius:8px;cursor:pointer"><span style="color:#b0a8bb">&#9679;</span> '+_esc(p.name)+'<span style="float:right;background:#e23b5a;color:#fff;border-radius:10px;padding:0 7px;font-size:12px">'+p.n+'</span></div>'; }); }
    if(d.group_on && d.groups.length){ h+='<div class="muted" style="font-weight:700;padding:6px 8px">Grupos</div>';
      d.groups.forEach(function(g){ h+='<div class="chat-item" data-k="group" data-id="'+g.id+'" data-n="'+_esc(g.name)+'" style="padding:8px 10px;border-radius:8px;cursor:pointer">&#128101; '+_esc(g.name)+badge('grp:'+g.id)+'</div>'; }); }
    if(d.dm_on){ h+='<div class="muted" style="font-weight:700;padding:6px 8px">En l&iacute;nea</div>';
      if(d.people.length){ d.people.forEach(function(p){ h+='<div class="chat-item" data-k="dm" data-id="'+p.id+'" data-n="'+_esc(p.name)+'" style="padding:8px 10px;border-radius:8px;cursor:pointer"><span style="color:#2e9e5b">&#9679;</span> '+_esc(p.name)+badge('dm:'+p.id)+'</div>'; }); }
      else h+='<div class="muted" style="padding:8px 10px">Nadie en l&iacute;nea ahora.</div>'; }
    if(!h) h='<div class="muted" style="padding:8px 10px">Chat no disponible.</div>';
    el('chatList').innerHTML=h;
    el('chatList').querySelectorAll('.chat-item').forEach(function(it){ it.onclick=function(){ chatOpen(it.dataset.k, it.dataset.id, it.dataset.n, it.dataset.off==='1', it.dataset.u); }; });
  }); }
function chatOpen(kind,id,name,off,uname){ cur={kind:kind,id:id,name:name};
  el('chatList').style.display='none'; el('chatConv').style.display='flex';
  el('chatTitle').textContent=name;
  var note=el('chatOffNote');
  if(kind==='dm' && off){ note.innerHTML='Esta persona est&aacute; desconectada. Puedes responder, pero para continuar la conversaci&oacute;n usa <a href="/messages/'+encodeURIComponent(uname||'')+'">Mensajes</a>.'; note.style.display='block'; }
  else note.style.display='none';
  el('chatMsgs').innerHTML=''; chatPoll(); setTimeout(chatUnread,400); }
window.chatBack=function(){ chatLoadList(); };
function chatPoll(){ if(!cur||!open) return;
  var url='/api/chat/history?kind='+cur.kind+(cur.kind==='dm'?('&with='+cur.id):('&gid='+cur.id));
  fetch(url).then(function(r){return r.json();}).then(function(d){ if(!cur) return;
    el('chatMsgs').innerHTML=d.messages.map(function(m){
      return '<div style="align-self:'+(m.me?'flex-end':'flex-start')+';max-width:82%;background:'+(m.me?'#c0325f':'#f0eaef')+';color:'+(m.me?'#fff':'#25202a')+';padding:6px 10px;border-radius:12px">'+((cur.kind==='group'&&!m.me)?('<b style="font-size:11px">'+_esc(m.sender)+'</b><br>'):'')+_esc(m.body)+'<div style="font-size:10px;opacity:.6">'+_esc(m.at)+'</div></div>'; }).join('');
    el('chatMsgs').scrollTop=el('chatMsgs').scrollHeight; }); }
setInterval(function(){ if(open&&cur) chatPoll(); }, 3000);
setInterval(chatUnread, 10000);
chatUnread();
window.chatSend=function(e){ e.preventDefault(); if(!cur) return false;
  var inp=el('chatInput'); var body=inp.value.trim(); if(!body) return false; inp.value='';
  var fd=new FormData(); fd.append('kind',cur.kind); fd.append('body',body);
  if(cur.kind==='dm') fd.append('to',cur.id); else fd.append('gid',cur.id);
  fetch('/api/chat/send',{method:'POST',body:fd}).then(function(r){ return r.json().then(function(d){ return {ok:r.ok, d:d}; }); })
   .then(function(res){ if(!res.ok || (res.d && res.d.error)){
      var n=el('chatOffNote'); n.style.display='block';
      n.style.background='#fdecea'; n.style.color='#8a1c1c';
      n.textContent=(res.d && res.d.error) ? res.d.error : 'No se pudo enviar el mensaje.';
      inp.value=body; // devolvemos el texto para no perderlo
    } else { chatPoll(); } })
   .catch(function(){ chatPoll(); }); return false; };
})();
</script>
{% endif %}
{% if show_tour %}
<div class="modal-ov" id="tourOv" style="z-index:300">
 <div class="modal" style="width:470px">
  <div style="color:var(--brand2);font-weight:700;font-size:12px;letter-spacing:.05em" id="tourStep"></div>
  <h2 style="margin:.15em 0 .3em" id="tourTitle"></h2>
  <p id="tourBody" style="line-height:1.6;color:#4a444d"></p>
  <div class="between" style="margin-top:18px">
   <button type="button" class="btn sec sm" id="tourSkip">Saltar</button>
   <div class="row-flex">
    <button type="button" class="btn sec sm" id="tourPrev">Anterior</button>
    <button type="button" class="btn sm" id="tourNext">Siguiente</button>
   </div>
  </div>
 </div>
</div>
<script>
(function(){
 var steps=[
  ["Te damos la bienvenida a Vestigia","Aquí construyes tu portafolio de aprendizaje y colaboras con tu grupo. Te enseñamos lo básico en unos segundos."],
  ["Mis páginas","Crea páginas y compón cada una con bloques: texto, imágenes, vídeos o documentos. También puedes agrupar varias páginas en una colección."],
  ["Comunidad","Busca personas, añádelas como conocidos y escríbeles. Además puedes crear grupos o unirte a ellos: en un grupo se crean páginas grupales que editáis entre todos."],
  ["Tu perfil y tu almacenamiento","Desde tu perfil editas tu biografía, cambias tu contraseña y gestionas tus archivos (tienes 600 MB de espacio)."],
  ["Todo listo","Al publicar una página eliges su privacidad; por defecto todo es privado. Ya puedes empezar a crear."]
 ];
 var i=0, ov=document.getElementById('tourOv');
 function paint(){document.getElementById('tourStep').textContent='PASO '+(i+1)+' DE '+steps.length;
  document.getElementById('tourTitle').textContent=steps[i][0];
  document.getElementById('tourBody').textContent=steps[i][1];
  document.getElementById('tourPrev').style.visibility=(i===0)?'hidden':'visible';
  document.getElementById('tourNext').textContent=(i===steps.length-1)?'Empezar':'Siguiente';}
 function done(){try{fetch('/onboarding/done',{method:'POST'});}catch(e){}ov.style.display='none';}
 document.getElementById('tourNext').onclick=function(){if(i<steps.length-1){i++;paint();}else{done();}};
 document.getElementById('tourPrev').onclick=function(){if(i>0){i--;paint();}};
 document.getElementById('tourSkip').onclick=done;
 paint();
})();
</script>
{% endif %}
{% if user %}
<script>
/* Menciones con @: autocompleta tus conocidos en cualquier campo de texto o comentario. */
(function(){
  var CACHE=null, box=null, items=[], active=-1, targetEl=null, tokenStart=-1;
  function ensure(){ if(CACHE) return Promise.resolve(CACHE);
    return fetch('/api/mentionable').then(function(r){return r.json();}).then(function(d){CACHE=d.people||[];return CACHE;}).catch(function(){CACHE=[];return CACHE;}); }
  function isField(el){ if(!el) return false;
    if(el.tagName==='TEXTAREA') return true;
    if(el.tagName==='INPUT'){ var t=(el.getAttribute('type')||'text').toLowerCase(); return ['text','search',''].indexOf(t)>=0; }
    return false; }
  function closeBox(){ if(box){ box.remove(); box=null; } items=[]; active=-1; }
  function token(el){ var pos=el.selectionStart; if(pos==null) return null;
    var s=el.value.slice(0,pos); var at=s.lastIndexOf('@'); if(at<0) return null;
    var prev=at>0?s.charAt(at-1):' '; if(prev.trim()!=='') return null;
    var q=s.slice(at+1); if(!/^[A-Za-z0-9_.-]{0,30}$/.test(q)) return null;
    return {q:q, start:at}; }
  function hi(){ if(!box) return; [].forEach.call(box.children,function(c,i){ c.style.background=(i===active)?'#f0eaef':''; }); }
  function pick(i){ if(!targetEl||i<0||i>=items.length) return;
    var p=items[i], el=targetEl, pos=el.selectionStart;
    var before=el.value.slice(0,tokenStart), after=el.value.slice(pos), ins='@'+p.username+' ';
    el.value=before+ins+after; var np=(before+ins).length; el.setSelectionRange(np,np);
    el.dispatchEvent(new Event('input',{bubbles:true})); closeBox(); el.focus(); }
  function show(el,list){ closeBox(); if(!list.length) return;
    box=document.createElement('div');
    box.style.cssText='position:absolute;z-index:600;background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:10px;box-shadow:0 8px 24px rgba(20,12,26,.18);max-height:220px;overflow:auto;min-width:210px;font-size:14px';
    items=list;
    list.forEach(function(p,i){ var it=document.createElement('div');
      it.style.cssText='padding:7px 12px;cursor:pointer';
      it.innerHTML='<b>'+_esc(p.name)+'</b> <span class="muted" style="font-size:12px">@'+_esc(p.username)+'</span>';
      it.onmousedown=function(e){ e.preventDefault(); pick(i); }; box.appendChild(it); });
    document.body.appendChild(box);
    var r=el.getBoundingClientRect();
    box.style.left=(window.scrollX+r.left)+'px'; box.style.top=(window.scrollY+r.bottom+4)+'px';
    active=0; hi(); }
  document.addEventListener('input',function(e){ var el=e.target; if(!isField(el)){ return; }
    targetEl=el; var tok=token(el); if(!tok){ closeBox(); return; } tokenStart=tok.start;
    ensure().then(function(people){ var q=tok.q.toLowerCase();
      var list=people.filter(function(p){ return !q||p.username.toLowerCase().indexOf(q)>=0||(p.name||'').toLowerCase().indexOf(q)>=0; }).slice(0,8);
      show(el,list); }); });
  document.addEventListener('keydown',function(e){ if(!box) return;
    if(e.key==='ArrowDown'){ e.preventDefault(); active=Math.min(active+1,items.length-1); hi(); }
    else if(e.key==='ArrowUp'){ e.preventDefault(); active=Math.max(active-1,0); hi(); }
    else if(e.key==='Enter'||e.key==='Tab'){ if(active>=0){ e.preventDefault(); pick(active); } }
    else if(e.key==='Escape'){ closeBox(); } });
  document.addEventListener('click',function(e){ if(box && !box.contains(e.target)) closeBox(); });
  window.addEventListener('scroll',function(){ closeBox(); }, true);
})();
</script>
{% endif %}
<div id="cookieBar" style="display:none;position:fixed;left:12px;right:12px;bottom:12px;z-index:400;max-width:920px;margin:0 auto;background:#25202a;color:#fff;border-radius:14px;padding:14px 18px;box-shadow:0 8px 30px rgba(0,0,0,.35);font-size:14px">
 <div style="display:flex;gap:14px;align-items:center;flex-wrap:wrap;justify-content:space-between">
  <div style="flex:1;min-width:240px">Esta plataforma usa <b>solo cookies estrictamente necesarias</b> para mantener tu sesión iniciada. No usamos cookies de publicidad ni de seguimiento. <a href="/privacidad" style="color:#ff9ebd">Más información</a>.</div>
  <button onclick="cookieOk()" class="btn" style="white-space:nowrap">Entendido</button>
 </div>
</div>
<script>
(function(){ try{
  if(localStorage.getItem('evestigia-cookies')!=='1'){
    var b=document.getElementById('cookieBar'); if(b) b.style.display='block';
  }
}catch(e){} })();
function cookieOk(){ try{ localStorage.setItem('evestigia-cookies','1'); }catch(e){}
  var b=document.getElementById('cookieBar'); if(b) b.style.display='none'; }
</script>
</body></html>
"""


def render(body_tpl, title="Vestigia", **ctx):
    body = render_template_string(body_tpl, **ctx)
    return render_template_string(BASE, body=body, title=title, **ctx)


def avatar_tag(u, size=42):
    """Devuelve la foto de perfil del usuario, o su inicial si no tiene."""
    from markupsafe import Markup
    av = None
    name = "?"
    try:
        av = u["avatar"]
    except Exception:
        av = None
    try:
        name = u["name"] or "?"
    except Exception:
        name = "?"
    initial = (name.strip()[:1] or "?").upper()
    fs = max(11, int(size * 0.42))
    if av:
        return Markup('<img src="%s" alt="" style="width:%dpx;height:%dpx;border-radius:50%%;'
                      'object-fit:cover;flex-shrink:0">' % (url_for("uploaded", fn=av), size, size))
    return Markup('<div class="avatar" style="width:%dpx;height:%dpx;font-size:%dpx">%s</div>'
                  % (size, size, fs, initial))


app.jinja_env.globals["avatar"] = avatar_tag


def _safe_url(u):
    """Solo permite http(s), mailto o rutas internas; evita esquemas peligrosos como javascript:."""
    u = (u or "").strip()
    if u.lower().startswith(("http://", "https://", "mailto:")) or u.startswith("/"):
        return u
    return "#"


app.jinja_env.globals["safeurl"] = _safe_url


# --------------------------------------------------------------------------- #
#  Login / logout
# --------------------------------------------------------------------------- #
LOGIN_TPL = """
<div class="card" style="max-width:420px;margin:8vh auto">
 <form method="post"><label>Usuario</label><input name="username" autofocus>
  <label>Contraseña</label><input type="password" name="password">
  <button class="btn" style="width:100%">Entrar</button></form>
 <p class="muted" style="margin-top:16px">Demo: <b>ana</b>/ana123 &middot; <b>luis</b>/luis123 &middot;
   <b>maria</b>/maria123 &middot; <b>profesor</b>/profe123 &middot; <b>admin</b>/admin123</p>
</div>
"""


_LOGIN_FAILS = {}  # ip -> [intentos, primer_ts]
_LOGIN_MAX = 8
_LOGIN_WINDOW = 300  # 5 minutos


def _login_blocked(key):
    import time
    rec = _LOGIN_FAILS.get(key)
    if not rec:
        return False
    if time.time() - rec[1] >= _LOGIN_WINDOW:
        _LOGIN_FAILS.pop(key, None)
        return False
    return rec[0] >= _LOGIN_MAX


def _login_fail(key):
    import time
    rec = _LOGIN_FAILS.get(key)
    if not rec or (time.time() - rec[1]) >= _LOGIN_WINDOW:
        _LOGIN_FAILS[key] = [1, time.time()]
    else:
        rec[0] += 1


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        key = request.remote_addr or "?"
        if _login_blocked(key):
            flash("Demasiados intentos fallidos. Espera unos minutos e inténtalo de nuevo.", "error")
            return render(LOGIN_TPL, title="Entrar")
        u = get_db().execute("SELECT * FROM users WHERE username=?",
                             (request.form["username"].strip(),)).fetchone()
        if u and check_password_hash(u["password"], request.form["password"]):
            _LOGIN_FAILS.pop(key, None)
            session.permanent = True
            session["uid"] = u["id"]
            db = get_db()
            db.execute("UPDATE users SET login_count=COALESCE(login_count,0)+1 WHERE id=?", (u["id"],))
            db.commit()
            nxt = request.args.get("next") or ""
            # Evita redirecciones abiertas: solo rutas internas.
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = url_for("dashboard")
            return redirect(nxt)
        _login_fail(key)
        flash("Credenciales incorrectas.", "error")
    return render(LOGIN_TPL, title="Entrar")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("dashboard"))


@app.route("/onboarding/done", methods=["POST"])
@login_required
def onboarding_done():
    db, u = get_db(), current_user()
    db.execute("UPDATE users SET onboarded=1 WHERE id=?", (u["id"],))
    db.commit()
    return ("", 204)


# --------------------------------------------------------------------------- #
#  Dashboard
# --------------------------------------------------------------------------- #
LANDING_TPL = """
<style>
 .lp-top{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;
   padding:14px 24px;background:rgba(122,31,61,.96);color:#fff;backdrop-filter:blur(6px)}
 .lp-top .logo{font-weight:800;font-size:20px;letter-spacing:.3px}
 .lp-top a.login{background:#fff;color:#7a1f3d;padding:8px 16px;border-radius:20px;font-weight:700;font-size:14px}
 .lp-wrap{max-width:1000px;margin:0 auto;padding:0 20px}
 .hero{text-align:center;padding:80px 20px 60px;background:linear-gradient(160deg,#7a1f3d,#b8365f)}
 .hero h1{color:#fff;font-size:44px;line-height:1.1;margin:0 0 16px}
 .hero p{color:#f3e6ec;font-size:19px;max-width:640px;margin:0 auto 26px}
 .hero .cta{display:inline-block;background:#fff;color:#7a1f3d;padding:13px 28px;border-radius:26px;font-weight:700;font-size:16px}
 .hero .cta:hover{transform:translateY(-2px)}
 .sec{padding:64px 0}
 .sec h2{font-size:30px;text-align:center;margin:0 0 8px}
 .sec .lead{text-align:center;color:var(--muted);max-width:620px;margin:0 auto 34px;font-size:17px}
 .feat{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:20px}
 .fcard{background:#fff;border:1px solid var(--line);border-radius:16px;padding:24px}
 .fcard .ic{font-size:30px}
 .fcard h3{margin:10px 0 6px;font-size:18px}
 .fcard p{color:var(--muted);font-size:14px;margin:0;line-height:1.5}
 .steps{counter-reset:s;max-width:680px;margin:0 auto}
 .step{display:flex;gap:16px;align-items:flex-start;margin:18px 0}
 .step .n{counter-increment:s;background:var(--brand);color:#fff;width:38px;height:38px;border-radius:50%;
   display:flex;align-items:center;justify-content:center;font-weight:700;flex-shrink:0}
 .step .n::before{content:counter(s)}
 .band{background:linear-gradient(160deg,#7a1f3d,#b8365f);color:#fff;text-align:center;padding:60px 20px;border-radius:20px}
 .band h2{color:#fff}.band .cta{display:inline-block;background:#fff;color:#7a1f3d;padding:12px 26px;border-radius:24px;font-weight:700;margin-top:10px}
 .reveal{opacity:0;transform:translateY(28px);transition:opacity .7s ease,transform .7s ease}
 .reveal.on{opacity:1;transform:none}
 .lpfoot{text-align:center;color:var(--muted);font-size:13px;padding:36px}
 .lp-modal{display:none;position:fixed;inset:0;background:rgba(20,15,25,.55);z-index:200;align-items:center;justify-content:center;padding:20px}
 .lp-modal.show{display:flex}
 .lp-modal-card{background:#fff;color:#1c1922;border-radius:16px;padding:26px;max-width:400px;width:100%;position:relative;box-shadow:0 20px 60px rgba(0,0,0,.35)}
 .lp-modal-card label{display:block;margin:10px 0 4px;font-size:13px;font-weight:600}
 .lp-modal-card input{width:100%;padding:10px 12px;border:1px solid #ddd;border-radius:10px;font-size:15px}
 .lp-x{position:absolute;top:8px;right:12px;border:none;background:none;font-size:26px;line-height:1;cursor:pointer;color:#8b8492}
 @media(max-width:640px){.hero h1{font-size:32px}}
</style>
<div class="lp-top"><span class="logo">{% if theme_logo %}<img src="{{ url_for('brand_logo') }}" style="height:24px;vertical-align:-6px;margin-right:8px">{% else %}<svg width="24" height="24" viewBox="0 0 24 24" style="vertical-align:-6px;margin-right:7px"><g fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round"><path d="M4 18 Q12 6 20 18"/><path d="M6.5 18.4 Q12 9 17.5 18.4"/><path d="M9 18.2 Q12 12 15 18.2"/></g><circle cx="12" cy="15.6" r="1.25" fill="#ff5c8a"/></svg>{% endif %}{{ site_name }}</span>
 <a class="login" href="{{ url_for('login') }}" onclick="openLogin();return false;">Iniciar sesión</a></div>

<div class="hero">
 <h1 class="reveal">Haz visible tu proceso de aprendizaje</h1>
 <p class="reveal">Crea portafolios digitales con evidencias, reflexiones y multimedia. Comparte con tus
  docentes, recibe feedback y conecta con tu comunidad de aprendizaje.</p>
 <a class="cta reveal" href="{{ url_for('login') }}" onclick="openLogin();return false;">Entrar a la plataforma &rarr;</a>
</div>

<div class="lp-wrap">
 <div class="sec">
  <h2 class="reveal">Todo lo que necesitas para tu portafolio</h2>
  <p class="lead reveal">Un editor visual y una capa social pensados para el aula universitaria</p>
  <div class="feat">
   <div class="fcard reveal"><div class="ic">&#129513;</div><h3>Editor por bloques</h3>
    <p>Añade títulos, textos, imágenes, vídeos o documentos a columnas personalizables con facilidad.</p></div>
   <div class="fcard reveal"><div class="ic">&#127916;</div><h3>Multimedia</h3>
    <p>Incrusta vídeos de YouTube o Vimeo, audio e imágenes directamente en la página.</p></div>
   <div class="fcard reveal"><div class="ic">&#128218;</div><h3>Colecciones</h3>
    <p>Agrupa páginas y recórrelas en modo presentación. Descárgalas en PDF cuando quieras.</p></div>
   <div class="fcard reveal"><div class="ic">&#128172;</div><h3>Feedback docente</h3>
    <p>El profesorado comenta tus páginas, tú respondes y la comunidad interactúa.</p></div>
   <div class="fcard reveal"><div class="ic">&#129309;</div><h3>Comunidad</h3>
    <p>Busca compañeros, añádelos como conocidos, envía mensajes y sigue sus portafolios.</p></div>
   <div class="fcard reveal"><div class="ic">&#128202;</div><h3>Analíticas de aprendizaje</h3>
    <p>Una mirada formativa para acompañar de cerca el proceso de cada estudiante.</p></div>
  </div>
 </div>

 <div class="sec">
  <h2 class="reveal">Cómo funciona</h2>
  <div class="steps">
   <div class="step reveal"><div class="n"></div><div><b>Reúne tus evidencias.</b>
    <div class="muted">Sube textos, imágenes, vídeos o documentos como artefactos.</div></div></div>
   <div class="step reveal"><div class="n"></div><div><b>Compón tu página.</b>
    <div class="muted">Arrastra bloques a las columnas y dale tu estilo con tipografía propia.</div></div></div>
   <div class="step reveal"><div class="n"></div><div><b>Comparte y agrupa.</b>
    <div class="muted">Publica, agrupa en colecciones y decide quién puede verlo.</div></div></div>
   <div class="step reveal"><div class="n"></div><div><b>Recibe feedback y conecta.</b>
    <div class="muted">Tu docente comenta, tú respondes, y la comunidad interactúa.</div></div></div>
  </div>
 </div>

 <div class="sec"><div class="band reveal">
  <h2>Empieza tu portafolio hoy</h2>
  <p>Accede con tu cuenta y crea tu primera página en minutos.</p>
  <a class="cta" href="{{ url_for('login') }}" onclick="openLogin();return false;">Iniciar sesión</a>
 </div></div>
</div>

<div id="loginModal" class="lp-modal" onclick="if(event.target===this)closeLogin()">
 <div class="lp-modal-card">
  <button type="button" class="lp-x" aria-label="Cerrar" onclick="closeLogin()">&times;</button>
  <h2 style="margin:0 0 4px">Iniciar sesión</h2>
  <p class="muted" style="margin:0 0 14px;font-size:13px">Accede con tu cuenta para entrar a la plataforma.</p>
  <form method="post" action="{{ url_for('login') }}">
   <label>Usuario</label><input name="username">
   <label>Contraseña</label><input type="password" name="password">
   <button class="btn" style="width:100%;margin-top:6px">Entrar</button>
  </form>
 </div>
</div>
<script>
(function(){
 var io=new IntersectionObserver(function(es){es.forEach(function(e){if(e.isIntersecting){e.target.classList.add('on');io.unobserve(e.target);}});},{threshold:0.12});
 document.querySelectorAll('.reveal').forEach(function(el){io.observe(el);});
})();
function openLogin(){var m=document.getElementById('loginModal');m.classList.add('show');var i=m.querySelector('input[name=username]');if(i)setTimeout(function(){i.focus();},50);}
function closeLogin(){document.getElementById('loginModal').classList.remove('show');}
document.addEventListener('keydown',function(e){if(e.key==='Escape')closeLogin();});
</script>
"""



DASH_TPL = """
<h1>Hola, {{ user['name'].split()[0] }}</h1><p class="muted">{{ subtitle }}</p>

<div class="card" style="margin-top:8px"><h2 style="margin-top:0">Cómo funciona</h2>
 <ol class="muted" style="line-height:1.9;margin:0">
  <li>Crea una <a href="{{ url_for('pages') }}">página</a>, arrastra bloques desde el menú lateral y comienza a crear tu portafolio.</li>
  <li>Publícala y aparecerá en <a href="{{ url_for('feed') }}">Comunidad</a>.</li>
  <li>Cuando tengas varias páginas afines, agrúpalas en una <a href="{{ url_for('pages') }}">colección</a>.</li>
  <li>Busca personas en Comunidad, añádelas como <a href="{{ url_for('contacts') }}">conocidos</a>, <a href="{{ url_for('inbox') }}">escríbeles</a> e interacciona con sus páginas.</li>
 </ol></div>

{% if show_checklist %}
<div class="card" style="margin-top:8px">
 <div class="between"><h2 style="margin:0">Primeros pasos</h2><span class="muted">{{ checklist_done }}/{{ checklist_total }} completado</span></div>
 <div class="qbar" style="margin:10px 0"><div class="qbar-fill" style="width:{{ checklist_pct }}%"></div></div>
 <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px">
  {% for it in checklist %}
  <a href="{{ it.url }}" style="display:flex;gap:10px;align-items:center;padding:9px 11px;border:1px solid var(--line);border-radius:10px;text-decoration:none;color:inherit">
   <span style="font-size:17px;flex-shrink:0">{{ it.icon }}</span>
   <span style="width:20px;height:20px;border-radius:50%;flex-shrink:0;display:flex;align-items:center;justify-content:center;font-size:12px;color:#fff;background:{{ '#2e9e5b' if it.done else '#c9c2d0' }}">{{ '✓' if it.done else '' }}</span>
   <span style="flex:1;font-size:13.5px;{{ 'text-decoration:line-through;opacity:.55' if it.done }}">{{ it.label }}</span></a>
  {% endfor %}
 </div>
 {% if checklist_can_close %}
 <form method="post" action="{{ url_for('onboarding_dismiss') }}" style="margin-top:12px">
  <button class="btn sec sm">Cerrar y no volver a mostrar</button>
  <span class="muted" style="font-size:12px;margin-left:8px">Ya has completado lo esencial. La interacción con la comunidad puedes hacerla cuando quieras.</span>
 </form>{% endif %}
</div>
{% endif %}

<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:16px;margin-top:18px;align-items:stretch">

 <div class="card" style="margin:0"><h2 style="margin-top:0">Acciones pendientes</h2>
  {% if actions %}
   {% for a in actions %}
   <div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-top:1px solid var(--line)">
    <a href="{{ a.url }}" style="display:flex;align-items:center;gap:10px;text-decoration:none;color:inherit;flex:1;min-width:0">
     <span style="min-width:24px;text-align:center;background:#e23b5a;color:#fff;border-radius:20px;padding:1px 7px;font-size:13px;font-weight:700">{{ a.count }}</span>
     <span style="font-size:13.5px">{{ a.label }}</span></a>
    {% if a.dismiss_id %}<form method="post" action="{{ url_for('notif_dismiss', nid=a.dismiss_id) }}" style="margin:0" title="Descartar (no es obligatorio responder)"><button class="btn sec sm" style="padding:2px 8px">&times;</button></form>{% endif %}
   </div>
   {% endfor %}
  {% else %}<p class="muted" style="margin:0">Nada pendiente. ✓</p>{% endif %}
 </div>

 <div class="card" style="margin:0"><div class="between"><h2 style="margin:0">Mis grupos</h2><a class="btn sec sm" href="{{ url_for('feed') }}">Comunidad</a></div>
  {% if my_groups %}
  <div style="margin-top:8px">
   {% for g in my_groups %}<a href="{{ url_for('group_view', gid=g['id']) }}" style="display:block;padding:8px 0;border-top:1px solid var(--line);text-decoration:none;color:inherit">
    <b style="font-size:14px">{{ g['name'] }}</b>
    <div class="muted" style="font-size:12px">{{ '★ Admin del grupo' if g['owner_id']==user['id'] else 'Miembro' }}</div></a>{% endfor %}
  </div>
  {% else %}<p class="muted" style="margin:6px 0 0;font-size:13px">No perteneces a ningún grupo. Únete desde <a href="{{ url_for('feed') }}">Comunidad</a>.</p>{% endif %}
 </div>

 <div class="card" style="margin:0"><h2 style="margin-top:0">En línea ahora {% if online_users %}({{ online_users|length }}){% endif %}</h2>
  {% for o in online_users %}<div class="row-flex" style="padding:5px 0;align-items:center;gap:8px">
   <span style="width:9px;height:9px;border-radius:50%;background:#2e9e5b;flex-shrink:0"></span>
   {{ avatar(o, 28) }}
   <div><b style="font-size:13.5px"><a href="{{ url_for('profile', username=o['username']) }}">{{ o['name'] }}</a></b>
    <span class="muted" style="font-size:11px">@{{ o['username'] }}</span></div>
  </div>{% else %}<p class="muted" style="margin:0;font-size:13px">Nadie en línea ahora.</p>{% endfor %}
 </div>

</div>

{% if user['role']=='admin' and sec_report %}<div class="card" style="margin-top:18px">
 <div class="between"><h2 style="margin:0">Estado de seguridad y privacidad</h2>
  <span class="muted" style="font-size:12px">Solo lo ve el administrador</span></div>
 {% if sec_bad or sec_warn %}<p style="margin:6px 0 2px;font-size:13px">
   {% if sec_bad %}<b style="color:#d33">{{ sec_bad }} crítico(s)</b>{% endif %}
   {% if sec_bad and sec_warn %} · {% endif %}
   {% if sec_warn %}<b style="color:#d98a00">{{ sec_warn }} a revisar</b>{% endif %}</p>
 {% else %}<p style="margin:6px 0 2px;font-size:13px;color:#2e9e5b"><b>Todo correcto.</b></p>{% endif %}
 {% for s in sec_report %}
 <div class="row-flex" style="padding:7px 0;align-items:flex-start;border-top:1px solid var(--line);gap:9px">
  <span style="width:11px;height:11px;border-radius:50%;flex-shrink:0;margin-top:4px;background:{{ {'ok':'#2e9e5b','warn':'#d98a00','bad':'#d33'}[s.level] }}"></span>
  <div style="flex:1"><b>{{ s.title }}</b><div class="muted" style="font-size:13px">{{ s.detail }}</div>
   {% if s.link %}<a class="btn sec sm" style="margin-top:5px" href="{{ url_for(s.link) }}">{{ s.link_label or 'Ver' }}</a>{% endif %}</div>
 </div>{% endfor %}
 <p style="margin-top:12px"><a class="btn sec sm" href="{{ url_for('admin_home') }}">Ir a Administración</a>
  <a class="btn sec sm" href="{{ url_for('admin_email') }}">Configurar correo</a></p>
</div>{% endif %}
"""


@app.route("/")
def dashboard():
    u = current_user()
    if not u:
        return render(LANDING_TPL, title="Portafolios de aprendizaje")
    db = get_db()
    sub = ("Crea tu portafolio y conecta con la comunidad." if u["role"] == "student"
           else "Acompaña portafolios y participa en la comunidad.")
    prof = db.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    uname = u["username"]
    n_contacts = db.execute("""SELECT COUNT(*) c FROM contacts WHERE status='accepted'
                               AND (requester_id=? OR addressee_id=?)""", (u["id"], u["id"])).fetchone()["c"]

    # --- Mis grupos ---
    my_groups = db.execute("""SELECT g.* FROM groups g JOIN group_members m ON m.group_id=g.id
                              WHERE m.user_id=? ORDER BY g.name""", (u["id"],)).fetchall()

    # --- Acciones pendientes ---
    actions = []
    req_contacts = db.execute("SELECT COUNT(*) c FROM contacts WHERE addressee_id=? AND status='pending'",
                              (u["id"],)).fetchone()["c"]
    if req_contacts:
        actions.append({"label": "Solicitudes de amistad por aceptar", "count": req_contacts,
                        "url": url_for("contacts")})
    unread = unread_count(u["id"])
    if unread:
        actions.append({"label": "Mensajes sin leer", "count": unread, "url": url_for("inbox")})
    # Comentarios en tus páginas (de otras personas) que aún no has respondido
    unans = db.execute("""SELECT cm.page_id pid FROM comments cm JOIN pages p ON p.id=cm.page_id
        WHERE p.owner_id=? AND cm.author_id<>? AND cm.parent_id IS NULL
          AND NOT EXISTS (SELECT 1 FROM comments r WHERE r.parent_id=cm.id AND r.author_id=?)
        ORDER BY cm.created_at DESC""", (u["id"], u["id"], u["id"])).fetchall()
    if unans:
        actions.append({"label": "Responder a un comentario en tu portafolio", "count": len(unans),
                        "url": url_for("page_view", pid=unans[0]["pid"])})
    for gr in db.execute("""SELECT g.id, g.name, COUNT(*) c FROM group_requests r JOIN groups g ON g.id=r.group_id
                            WHERE g.owner_id=? GROUP BY g.id ORDER BY g.name""", (u["id"],)).fetchall():
        actions.append({"label": "Solicitudes para unirse a «%s»" % gr["name"], "count": gr["c"],
                        "url": url_for("group_view", gid=gr["id"])})
    # Menciones (@) en comentarios: aparecen como pendientes y se pueden descartar (no obligan a responder).
    for m in db.execute("""SELECT id, text, link FROM notifications
                           WHERE user_id=? AND kind='Te han mencionado' AND is_read=0
                           ORDER BY id DESC""", (u["id"],)).fetchall():
        actions.append({"label": m["text"] or "Te han mencionado en un comentario", "count": "@",
                        "url": url_for("notif_go", nid=m["id"]), "dismiss_id": m["id"]})

    # --- Primeros pasos (checklist con progreso) ---
    ppid = prof["profile_page_id"]
    n_pages_real = db.execute("SELECT COUNT(*) c FROM pages WHERE owner_id=? AND (? IS NULL OR id<>?)",
                              (u["id"], ppid, ppid)).fetchone()["c"]
    n_cols = db.execute("SELECT COUNT(*) c FROM collections WHERE owner_id=?", (u["id"],)).fetchone()["c"]
    in_group = db.execute("SELECT 1 FROM group_members WHERE user_id=? LIMIT 1", (u["id"],)).fetchone() is not None
    privacy_ok = get_setting("privacy_reviewed_%d" % u["id"]) == "1"
    pw_ok = get_setting("pw_changed_%d" % u["id"]) == "1"
    community_done = db.execute("""SELECT 1 FROM comments c JOIN pages p ON p.id=c.page_id
        WHERE c.author_id=? AND p.owner_id<>? LIMIT 1""", (u["id"], u["id"])).fetchone() is not None
    checklist = [
        {"icon": "🔑", "label": "Cambiar tu contraseña", "done": pw_ok, "url": url_for("profile", username=uname)},
        {"icon": "📷", "label": "Poner una foto de perfil", "done": bool(prof["avatar"]), "url": url_for("profile", username=uname)},
        {"icon": "✍️", "label": "Añadir tu biografía", "done": bool((prof["bio"] or "").strip()), "url": url_for("profile", username=uname)},
        {"icon": "📄", "label": "Crear tu primera página", "done": n_pages_real > 0, "url": url_for("pages")},
        {"icon": "📚", "label": "Crear una colección", "done": n_cols > 0, "url": url_for("collections")},
        {"icon": "👥", "label": "Unirte a un grupo", "done": in_group, "url": url_for("feed")},
        {"icon": "🤝", "label": "Añadir un conocido", "done": n_contacts > 0, "url": url_for("contacts")},
        {"icon": "🔒", "label": "Revisar tus ajustes de privacidad", "done": privacy_ok, "url": url_for("profile", username=uname) + "#ajustes"},
        {"icon": "💬", "label": "Interactúa con la comunidad (comenta el portafolio de otra persona)",
         "done": community_done, "url": url_for("feed"), "community": True},
    ]
    ck_done = sum(1 for it in checklist if it["done"])
    ck_total = len(checklist)
    ck_pct = round(ck_done * 100 / ck_total)
    # Se puede cerrar cuando todo está hecho salvo la interacción con la comunidad.
    ck_can_close = all(it["done"] for it in checklist if not it.get("community"))
    onboarding_on = get_setting("onboarding_on", "1") != "0"
    dismissed = get_setting("onboarding_done_%d" % u["id"]) == "1"
    show_checklist = onboarding_on and not dismissed

    from datetime import timedelta
    threshold = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
    online_users = db.execute("""SELECT id,name,username,avatar,last_seen,show_online FROM users
        WHERE show_online=1 AND last_seen>=? AND id<>? ORDER BY name LIMIT 40""",
        (threshold, u["id"])).fetchall()
    sec = security_report() if u["role"] == "admin" else None
    sec_bad = sum(1 for s in sec if s["level"] == "bad") if sec else 0
    sec_warn = sum(1 for s in sec if s["level"] == "warn") if sec else 0
    return render(DASH_TPL, title="Inicio", subtitle=sub, n_contacts=n_contacts,
                  my_groups=my_groups, actions=actions, checklist=checklist,
                  checklist_done=ck_done, checklist_total=ck_total, checklist_pct=ck_pct,
                  checklist_can_close=ck_can_close, show_checklist=show_checklist,
                  online_users=online_users, sec_report=sec, sec_bad=sec_bad, sec_warn=sec_warn)


@app.route("/onboarding/dismiss", methods=["POST"])
@login_required
def onboarding_dismiss():
    u = current_user()
    set_setting("onboarding_done_%d" % u["id"], "1")
    return redirect(url_for("dashboard"))


PRIVACY_TPL = """
<div class="between"><h1>Privacidad y cookies</h1><a class="btn sec" href="{{ url_for('dashboard') }}">Volver</a></div>
<div class="card">
 <h2 style="margin-top:0">Cookies</h2>
 <p>Esta plataforma usa <b>únicamente cookies estrictamente necesarias</b> para su funcionamiento:
  una cookie de <b>sesión</b> que permite mantener tu acceso mientras usas la aplicación. No se utilizan
  cookies de publicidad, analítica de terceros ni de seguimiento entre sitios.</p>
 <p class="muted" style="font-size:13px">Al ser estrictamente necesarias, no requieren consentimiento previo,
  pero te informamos de su uso conforme al RGPD y la LSSI.</p>
 <h2>Datos personales</h2>
 <p>Se tratan los datos mínimos para el funcionamiento educativo de la plataforma (nombre, usuario, correo,
  contenidos que publicas y actividad de aprendizaje). El contenido es <b>privado por defecto</b> y tú decides
  qué compartir. La mensajería y el chat se almacenan cifrados; solo la administración puede supervisarlos por
  motivos de seguridad, conforme a la normativa del centro.</p>
 <h2>Tus derechos</h2>
 <p>Puedes solicitar acceso, rectificación o supresión de tus datos a la administración de la plataforma o al
  Delegado de Protección de Datos de la institución responsable.</p>
</div>
"""


@app.route("/privacidad")
def privacy_policy():
    return render(PRIVACY_TPL, title="Privacidad y cookies")


# --------------------------------------------------------------------------- #
#  Artefactos
# --------------------------------------------------------------------------- #
ART_TPL = """
<div class="between"><h1>Almacenamiento</h1>
 <a class="btn sec" href="{{ url_for('profile', username=user['username']) }}">Volver al perfil</a></div>
<div class="card">
 <div class="between"><h2 style="margin:0">Espacio ocupado</h2>
  <div class="muted"><b style="color:var(--brand);font-size:16px">{{ used_h }}</b> de {{ quota_h }}</div></div>
 <div class="qbar"><div class="qbar-fill {{ 'warn' if pct>=80 and not over }} {{ 'over' if over }}" style="width:{{ pct }}%"></div></div>
 <div class="muted" style="margin-top:8px">{{ pct }}% usado &middot; {{ files|length }} archivo(s){% if over %} &middot; <b style="color:#d34">Has superado tu cuota</b>{% endif %}</div>
</div>

<h2>Mis archivos</h2>
{% if files %}
<div class="card" style="padding:0;overflow:hidden">
 <table>
  <tr><th style="padding-left:16px">Archivo</th><th>Tipo</th><th>En página</th><th>Tamaño</th><th></th></tr>
  {% for f in files %}
  <tr>
   <td style="padding-left:16px"><a href="{{ url_for('uploaded', fn=f['filename']) }}" target="_blank">{{ f['orig'] }}</a>
    {% if f['title'] %}<div class="muted" style="font-size:12px">{{ f['title'] }}</div>{% endif %}</td>
   <td><span class="pill">{{ f['label'] }}</span></td>
   <td class="muted">{% if f['pages'] %}{% for pg in f['pages'] %}<a href="{{ url_for('page_view', pid=pg['id']) }}">{{ pg['title'] }}</a>{{ ', ' if not loop.last }}{% endfor %}{% else %}-{% endif %}</td>
   <td class="muted">{{ f['size_h'] }}</td>
   <td style="text-align:right;padding-right:16px">
    <form id="del-{{ f['kind'] }}-{{ f['id'] }}" method="post" action="{{ url_for('file_del') }}" style="margin:0;display:inline">
     <input type="hidden" name="kind" value="{{ f['kind'] }}"><input type="hidden" name="id" value="{{ f['id'] }}"></form>
    <button type="button" class="btn danger sm" data-form="del-{{ f['kind'] }}-{{ f['id'] }}" data-name="{{ f['orig'] }}" data-pages="{{ f['pages']|map(attribute='title')|join(', ') }}" onclick="askDel(this)">Eliminar</button>
   </td>
  </tr>{% endfor %}
 </table>
</div>
{% else %}<p class="muted">Aún no has subido archivos. Se añaden al insertar imágenes, vídeos o documentos en tus páginas.</p>{% endif %}

<div class="modal-ov" id="delOv" style="display:none">
 <div class="modal" style="width:430px">
  <h2 style="margin-top:0">Eliminar archivo</h2>
  <p>Vas a eliminar <b id="delName"></b>.</p>
  <p id="delPages" class="muted"></p>
  <p style="color:#b23;font-weight:500">Esta acción no se puede deshacer: el archivo desaparecerá de la página donde esté insertado.</p>
  <div class="row-flex" style="justify-content:flex-end;margin-top:14px">
   <button type="button" class="btn sec" onclick="closeDel()">Volver</button>
   <button type="button" class="btn danger" id="delConfirm">Eliminar definitivamente</button>
  </div>
 </div>
</div>
<script>
var _delForm=null;
function askDel(btn){_delForm=btn.getAttribute('data-form');
 document.getElementById('delName').textContent=btn.getAttribute('data-name')||'';
 var pages=btn.getAttribute('data-pages')||'';
 document.getElementById('delPages').textContent=pages?('Se quitará de: '+pages+'.'):'No está insertado en ninguna página.';
 document.getElementById('delOv').style.display='flex';}
function closeDel(){document.getElementById('delOv').style.display='none';_delForm=null;}
document.getElementById('delConfirm').onclick=function(){if(_delForm){var f=document.getElementById(_delForm);if(f)f.submit();}};
document.getElementById('delOv').addEventListener('click',function(e){if(e.target===this)closeDel();});
</script>
"""


def human_size(n):
    n = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return ("%.0f %s" % (n, unit)) if unit == "B" else ("%.1f %s" % (n, unit))
        n /= 1024
    return "%.1f TB" % n


def user_storage(uid):
    db = get_db()
    total = 0
    for a in db.execute("SELECT filename FROM artefacts WHERE owner_id=? AND filename IS NOT NULL AND filename<>''", (uid,)):
        try:
            total += os.path.getsize(os.path.join(UPLOAD_DIR, a["filename"]))
        except Exception:
            pass
    av = db.execute("SELECT avatar FROM users WHERE id=?", (uid,)).fetchone()["avatar"]
    if av:
        try:
            total += os.path.getsize(os.path.join(UPLOAD_DIR, av))
        except Exception:
            pass
    return total


def _orig_name(fn):
    return fn.split("_", 1)[1] if fn and "_" in fn else (fn or "")


@app.route("/settings")
@login_required
def artefacts():
    u = current_user()
    db = get_db()
    used = user_storage(u["id"])
    quota = storage_quota_bytes()
    pct = min(100, int(round(used * 100.0 / quota))) if quota else 0
    files = []
    for a in db.execute("""SELECT id,kind,title,filename FROM artefacts
                           WHERE owner_id=? AND filename IS NOT NULL AND filename<>''
                           ORDER BY id DESC""", (u["id"],)).fetchall():
        try:
            size = os.path.getsize(os.path.join(UPLOAD_DIR, a["filename"]))
        except Exception:
            size = 0
        pgs = db.execute("""SELECT DISTINCT p.id, p.title FROM blocks b
                            JOIN rows r ON r.id=b.row_id JOIN pages p ON p.id=r.page_id
                            WHERE b.artefact_id=?""", (a["id"],)).fetchall()
        files.append({"kind": "artefact", "id": a["id"], "title": a["title"],
                      "filename": a["filename"], "orig": _orig_name(a["filename"]),
                      "label": KIND_LABELS.get(a["kind"], a["kind"]),
                      "size_h": human_size(size), "pages": [dict(x) for x in pgs]})
    av = db.execute("SELECT avatar FROM users WHERE id=?", (u["id"],)).fetchone()["avatar"]
    if av:
        try:
            size = os.path.getsize(os.path.join(UPLOAD_DIR, av))
        except Exception:
            size = 0
        files.append({"kind": "avatar", "id": 0, "title": "Foto de perfil",
                      "filename": av, "orig": _orig_name(av), "label": "Avatar",
                      "size_h": human_size(size), "pages": []})
    return render(ART_TPL, title="Almacenamiento", files=files,
                  used_h=human_size(used), quota_h=human_size(quota),
                  pct=pct, over=(used > quota))


def _heic_to_jpg(path):
    """Convierte un HEIC/HEIF a JPG (conservando EXIF). Devuelve el nuevo nombre o None."""
    try:
        from pillow_heif import register_heif_opener
        register_heif_opener()
        from PIL import Image
        img = Image.open(path)
        exif = img.info.get("exif")
        newfn = os.path.splitext(os.path.basename(path))[0] + ".jpg"
        newpath = os.path.join(UPLOAD_DIR, newfn)
        rgb = img.convert("RGB")
        if exif:
            rgb.save(newpath, "JPEG", quality=90, exif=exif)
        else:
            rgb.save(newpath, "JPEG", quality=90)
        return newfn
    except Exception:
        return None


def _store_file(f):
    """Guarda un FileStorage. Devuelve (nombre, ext) o (None,'bad')/(None,None)."""
    if not f or not f.filename:
        return None, None
    ext = f.filename.rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED:
        return None, "bad"
    fn = f"{secrets.token_hex(6)}_{secure_filename(f.filename)}"
    path = os.path.join(UPLOAD_DIR, fn)
    f.save(path)
    if ext in ("heic", "heif"):
        conv = _heic_to_jpg(path)
        if conv:
            try:
                os.remove(path)
            except Exception:
                pass
            return conv, "jpg"
    return fn, ext


def _kind_from_ext(ext):
    if ext in IMAGE_EXT:
        return "photo"
    if ext in VIDEO_EXT:
        return "video"
    if ext in AUDIO_EXT:
        return "audio"
    return "file"


def save_upload():
    return _store_file(request.files.get("file"))


@app.route("/settings/file/delete", methods=["POST"])
@login_required
def file_del():
    db, u = get_db(), current_user()
    kind = request.form.get("kind")
    fn = None
    if kind == "avatar":
        row = db.execute("SELECT avatar FROM users WHERE id=?", (u["id"],)).fetchone()
        fn = row["avatar"] if row else None
        db.execute("UPDATE users SET avatar='' WHERE id=?", (u["id"],))
    else:
        a = db.execute("SELECT * FROM artefacts WHERE id=? AND owner_id=?",
                       (request.form.get("id"), u["id"])).fetchone()
        if not a:
            abort(403)
        fn = a["filename"]
        db.execute("DELETE FROM artefacts WHERE id=?", (a["id"],))
    db.commit()
    if fn:
        # Solo borra el archivo fisico si ya no lo referencia ningun artefacto.
        still = db.execute("SELECT 1 FROM artefacts WHERE filename=?", (fn,)).fetchone()
        other_av = db.execute("SELECT 1 FROM users WHERE avatar=?", (fn,)).fetchone()
        if not still and not other_av:
            try:
                os.remove(os.path.join(UPLOAD_DIR, fn))
            except Exception:
                pass
    flash("Archivo eliminado.")
    return redirect(url_for("artefacts"))


@app.route("/uploads/<path:fn>")
@login_required
def uploaded(fn):
    # Contenido confidencial del alumnado: solo accesible con sesión iniciada.
    return send_from_directory(UPLOAD_DIR, fn)


@app.route("/brand/logo")
def brand_logo():
    """Logo de marca: público (se necesita en la pantalla de inicio de sesión)."""
    fn = get_setting("theme_logo")
    if not fn:
        abort(404)
    return send_from_directory(UPLOAD_DIR, fn)


@app.route("/brand/favicon")
def brand_favicon():
    """Favicon de marca: público."""
    fn = get_setting("theme_favicon")
    if not fn:
        abort(404)
    return send_from_directory(UPLOAD_DIR, fn)


# --------------------------------------------------------------------------- #
#  Páginas: lista
# --------------------------------------------------------------------------- #
PAGES_TPL = """
<h1>Mis páginas</h1>
<div class="card"><form method="post" action="{{ url_for('page_new') }}" class="row-flex">
 <input name="title" placeholder="Título de la nueva página" required style="flex:1;margin:0">
 <button class="btn">Crear página</button></form>
 {% if feat('stu_collections') %}<details class="add" style="margin-top:10px"><summary>+ Crear una colección</summary>
  <form method="post" action="{{ url_for('collection_new') }}" class="row-flex" style="margin-top:8px">
   <input name="title" placeholder="Nombre de la colección" required style="flex:1;margin:0">
   <button class="btn sec sm">Crear colección</button></form>
  <div class="muted" style="font-size:12px;margin-top:4px">Una colección agrupa varias páginas para recorrerlas seguidas.</div>
 </details>{% endif %}
</div>
{% for c in cols %}<div class="card coll-card between">
 <div><span class="tag-coll">Colección</span> <b>{{ c['title'] }}</b> <span class="pill">{{ vis[c['visibility']] }}</span>
  <div class="muted">{% if c['pages'] %}{{ c['pages']|length }} página(s): {% for pg in c['pages'] %}{{ pg['title'] }}{{ ', ' if not loop.last }}{% endfor %}{% else %}Sin páginas todavía{% endif %}</div></div>
 <div class="row-flex">
  {% if c['pages'] %}<a class="btn sm" href="{{ url_for('collection_view', cid=c['id']) }}">Ver colección</a>{% endif %}
  <a class="btn sec sm" href="{{ url_for('collection_edit', cid=c['id']) }}">Modificar</a>
 </div>
</div>{% endfor %}
{% for p in pgs %}<div class="card between">
 <div><b><a href="{{ url_for('page_view', pid=p['id']) }}">{{ p['title'] }}</a></b>
  <span class="pill">{{ vis[p['visibility']] }}</span>
  <div class="muted">{{ p['description'] or 'Sin descripción' }}</div></div>
 <div class="row-flex"><a class="btn sec sm" href="{{ url_for('page_edit', pid=p['id']) }}">Editar</a>
  <a class="btn sec sm" href="{{ url_for('page_view', pid=p['id']) }}">Ver</a>
  <form method="post" action="{{ url_for('page_del', pid=p['id']) }}" onsubmit="return confirm('Eliminar página?')">
   <button class="btn danger sm">Eliminar</button></form></div>
</div>{% else %}<p class="muted">Aun no tienes páginas.</p>{% endfor %}
"""


@app.route("/pages")
@login_required
def pages():
    db, u = get_db(), current_user()
    pgs = db.execute("SELECT * FROM pages WHERE owner_id=? AND id IS NOT ? AND group_id IS NULL ORDER BY id DESC",
                     (u["id"], u["profile_page_id"])).fetchall()
    cols = [dict(c) for c in db.execute("SELECT * FROM collections WHERE owner_id=? ORDER BY id DESC",
                                        (u["id"],)).fetchall()]
    for c in cols:
        c["pages"] = db.execute("""SELECT p.* FROM collection_pages cp JOIN pages p ON p.id=cp.page_id
                                    WHERE cp.collection_id=? ORDER BY cp.position""", (c["id"],)).fetchall()
    return render(PAGES_TPL, title="Páginas", pgs=pgs, vis=VIS, cols=cols)


@app.route("/pages/new", methods=["POST"])
@login_required
def page_new():
    db, u = get_db(), current_user()
    title = request.form["title"].strip()
    dv = u["default_vis"] if ("default_vis" in u.keys() and u["default_vis"]) else "private"
    if dv not in ("private", "teachers", "public"):
        dv = "private"
    pid = db.execute("INSERT INTO pages(owner_id,title,description,visibility,created_at) VALUES(?,?,?,?,?)",
                     (u["id"], title, "", dv, now())).lastrowid
    db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)", (pid, 0, "1"))
    db.commit()
    return redirect(url_for("page_edit", pid=pid))


@app.route("/pages/<int:pid>/delete", methods=["POST"])
@login_required
def page_del(pid):
    owned_page(pid)
    get_db().execute("DELETE FROM pages WHERE id=?", (pid,))
    get_db().commit()
    flash("Página eliminada.")
    return redirect(url_for("pages"))


def is_group_member(gid, uid):
    if not gid:
        return False
    return bool(get_db().execute("SELECT 1 FROM group_members WHERE group_id=? AND user_id=?",
                                 (gid, uid)).fetchone())


def owned_page(pid):
    p = get_db().execute("SELECT * FROM pages WHERE id=?", (pid,)).fetchone()
    uid = current_user()["id"]
    if not p:
        abort(403)
    # El propietario siempre; en páginas de grupo, cualquier miembro puede editar.
    if p["owner_id"] == uid or (p["group_id"] and is_group_member(p["group_id"], uid)):
        return p
    abort(403)


def page_rows(pid):
    db = get_db()
    rows = db.execute("SELECT * FROM rows WHERE page_id=? ORDER BY position", (pid,)).fetchall()
    out = []
    for r in rows:
        weights = LAYOUTS.get(r["layout"], [1])
        cols = [[] for _ in weights]
        for b in db.execute("SELECT * FROM blocks WHERE row_id=? ORDER BY col_index,position", (r["id"],)).fetchall():
            ci = b["col_index"] if b["col_index"] < len(cols) else 0
            cols[ci].append(b)
        out.append({"row": r, "weights": weights, "cols": cols})
    return out


# --------------------------------------------------------------------------- #
#  Tarjeta de bloque + tipografia
# --------------------------------------------------------------------------- #
TYPO_TPL = """
<div class="muted" style="font-size:11px;margin-top:8px">Estilo base del bloque (la negrita/cursiva/color por palabra se aplica arriba):</div>
<div class="toolbar" style="margin-top:4px">
 <div><label>Fuente</label><select name="font_family">
  {% for v,l in [('sans','Sans'),('serif','Serif'),('mono','Mono')] %}
  <option value="{{ v }}" {{ 'selected' if b and b['font_family']==v }}>{{ l }}</option>{% endfor %}</select></div>
 <div><label>Tamano base</label><select name="font_size">
  {% for s in [14,16,18,20,24,28,32,40] %}
  <option value="{{ s }}" {{ 'selected' if b and b['font_size']==s else ('selected' if not b and s==16 else '') }}>{{ s }}px</option>{% endfor %}</select></div>
 <div><label>Color base</label><input type="color" name="text_color" value="{{ b['text_color'] if b else '#1c1922' }}" style="height:38px;padding:2px"></div>
 <div><label>Alineacion</label><select name="align">
  {% for v,l in [('left','Izquierda'),('center','Centro'),('right','Derecha'),('justify','Justificado')] %}
  <option value="{{ v }}" {{ 'selected' if b and b['align']==v }}>{{ l }}</option>{% endfor %}</select></div>
</div>
"""


def typo_controls(b):
    return render_template_string(TYPO_TPL, b=b)


def block_base_style(b):
    fam = FONTS.get(b["font_family"], FONTS["sans"])
    size = b["font_size"] or (26 if b["block_type"] == "heading" else 16)
    weight = "700" if b["block_type"] == "heading" else "400"
    return "font-family:%s;font-size:%spx;color:%s;text-align:%s;font-weight:%s;line-height:1.5;" % (
        fam, size, b["text_color"] or "#1c1922", b["align"] or "left", weight)


CARD_TPL = """
<div class="blk" data-block-id="{{ b['id'] }}" data-type="{{ b['block_type'] }}">
 <div class="bar">
  <span class="drag-handle" title="Arrastrar para mover">&#9776; {{ labels[b['block_type']] }}</span>
  <span class="row-flex" style="align-items:center">
   <span class="save-state muted" style="font-size:11px"></span>
   {% if b['block_type'] not in ('text','heading') %}<button type="button" class="btn sec sm art-edit-btn" data-id="{{ b['id'] }}">Cambiar</button>{% endif %}
   <button type="button" class="btn danger sm del-btn" data-id="{{ b['id'] }}">&times;</button></span></div>
 {% if b['block_type'] in ('text','heading') %}
  <div class="rt-toolbar">
   <button type="button" data-cmd="bold" title="Negrita"><b>B</b></button>
   <button type="button" data-cmd="italic" title="Cursiva"><i>I</i></button>
   <button type="button" data-cmd="underline" title="Subrayado"><u>U</u></button>
   <button type="button" data-cmd="strikeThrough" title="Tachado"><s>S</s></button>
   <button type="button" class="rt-mark" title="Resaltar en color"><span style="border-bottom:3px solid #ffd43b;font-weight:700">A</span></button>
   <input type="color" class="rt-mark-color" value="#fff3a3" title="Color del resaltador" style="width:34px;height:32px;padding:2px;margin:0">
   <input type="color" class="rt-color" value="#7a1f3d" title="Color del texto seleccionado">
   <select class="rt-size" title="Tamano del texto seleccionado">
    <option value="2">Peq</option><option value="3" selected>Normal</option>
    <option value="5">Grande</option><option value="6">XL</option></select>
   <button type="button" data-cmd="insertUnorderedList" title="Lista con viñetas">&#8226;</button>
   <button type="button" data-cmd="insertOrderedList" title="Lista numerada">1.</button>
   <button type="button" class="rt-link" title="Insertar enlace">&#128279;</button>
   <button type="button" data-cmd="removeFormat" title="Quitar formato">&#10006;</button>
   <button type="button" class="rt-html" title="Editar/insertar HTML">&lt;/&gt;</button>
  </div>
  <div class="rt-edit block-text" contenteditable="true" data-id="{{ b['id'] }}" style="{{ base_style }}">{{ b['text_content']|safe }}</div>
 {% else %}
  <div class="blk-content">{{ content|safe }}</div>
 {% endif %}
</div>
"""


def render_block_card(b):
    return render_template_string(CARD_TPL, b=b, content=block_html(b),
                                  typo=typo_controls(b), labels=BLK_LABELS,
                                  base_style=block_base_style(b))


# --------------------------------------------------------------------------- #
#  Editor visual (arrastrar y soltar)
# --------------------------------------------------------------------------- #
EDIT_TPL = r"""
<div class="between"><h1>Editar: {{ p['title'] }}</h1>
 <a class="btn sec" href="{{ url_for('page_view', pid=p['id']) }}">Vista previa</a></div>

<div class="card"><form id="metaForm" method="post" action="{{ url_for('page_meta', pid=p['id']) }}">
 <div class="row-flex"><div style="flex:2"><label>Título</label><input name="title" value="{{ p['title'] }}"></div>
  <div style="flex:1"><label>Visibilidad</label><select name="visibility">
   {% for v,l in [('private','Privada (solo tú)'),('teachers','Docentes'),('public','Pública (toda la plataforma)')] %}
   <option value="{{ v }}" {{ 'selected' if p['visibility']==v }}>{{ l }}</option>{% endfor %}</select></div></div>
 <p class="muted" style="font-size:12px;margin:2px 0 6px">La opción <b>Pública</b> hace la página visible para cualquier persona registrada en la plataforma. Nadie sin iniciar sesión puede verla.</p>
 <label>Descripción</label><textarea name="description" style="min-height:50px">{{ p['description'] or '' }}</textarea>
 <button class="btn">Guardar cambios</button>
 <span class="muted" style="font-size:12px;margin-left:8px">Los bloques se guardan solos; este botón fuerza el guardado de todo y avisa (si la página es compartida).</span>
 </form></div>

<div style="display:flex;gap:16px;align-items:flex-start">
 <aside class="card" style="width:190px;position:sticky;top:16px;flex-shrink:0">
  <b>Añadir bloques</b>
  <div class="pal-list" style="margin-top:8px">
   <div class="pal-item" data-type="heading">&#9776; Título</div>
   <div class="pal-item" data-type="text">&#182; Texto</div>
   <div class="pal-item" data-type="image">&#128247; Imagen</div>
   <div class="pal-item" data-type="video">&#9654; Vídeo</div>
   <div class="pal-item" data-type="audio">&#9835; Audio</div>
   <div class="pal-item" data-type="file">&#128196; PDF / Doc</div>
   <div class="pal-item" data-type="link">&#128279; Enlace</div>
   <div class="pal-item" data-type="artefact">&#9733; Artefacto existente</div>
  </div>
  <p class="muted" style="font-size:12px;margin-top:10px">Arrastra un bloque a cualquier columna. Los archivos se suben ahi mismo.</p>
 </aside>

 <div style="flex:1;min-width:0">
  {% for R in layout %}{% set r = R['row'] %}
   <div class="card">
    <div class="between" style="margin-bottom:10px">
     <b class="muted">Fila {{ loop.index }} &middot; {{ LAYOUT_LABELS[r['layout']] }}</b>
     <span class="row-flex">
      <a class="btn sec sm" href="{{ url_for('row_move', pid=p['id'], rid=r['id'], dir='up') }}">&uarr;</a>
      <a class="btn sec sm" href="{{ url_for('row_move', pid=p['id'], rid=r['id'], dir='down') }}">&darr;</a>
      <form method="post" action="{{ url_for('row_del', pid=p['id'], rid=r['id']) }}"><button class="btn danger sm">Eliminar fila</button></form>
     </span></div>
    <div class="prow" style="grid-template-columns:{{ R['weights']|join('fr ') }}fr">
     {% for col in R['cols'] %}
      <div class="pcol dropzone colbox" data-row="{{ r['id'] }}" data-col="{{ loop.index0 }}">
       {% for b in col %}{{ render_card(b)|safe }}{% endfor %}
      </div>{% endfor %}
    </div>
   </div>{% endfor %}

  <div class="card"><h2>Añadir fila</h2>
   <form method="post" action="{{ url_for('row_add', pid=p['id']) }}" class="row-flex">
    <select name="layout" style="flex:1;margin:0">
     {% for v,l in LAYOUT_LABELS.items() %}<option value="{{ v }}">{{ l }}</option>{% endfor %}</select>
    <button class="btn">Añadir fila</button></form></div>
 </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Sortable/1.15.0/Sortable.min.js"></script>
<script>
const PID = {{ p['id'] }};
const ARTS = {{ arts_json|safe }};
const IS_GROUP = {{ 'true' if is_group else 'false' }};

function saveLayout(){
  const cols=[...document.querySelectorAll('.pcol.dropzone')].map(c=>({
    row_id:+c.dataset.row, col_index:+c.dataset.col,
    block_ids:[...c.querySelectorAll(':scope > .blk')].map(b=>+b.dataset.blockId)}));
  return fetch('/api/pages/'+PID+'/layout',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({columns:cols})});
}
const dirty=new Set();
function setEditing(node){
  document.querySelectorAll('.blk.editing').forEach(function(b){ if(b!==node) b.classList.remove('editing'); });
  if(node) node.classList.add('editing');
}
function setState(node,txt){var s=node.querySelector('.save-state'); if(s) s.textContent=txt;}
function saveBlock(node){
  const rt=node.querySelector('.block-text'); if(!rt) return Promise.resolve();
  const fd=new FormData();
  fd.append('text_content', rt.innerHTML);
  const tw=node.querySelector('.typo-wrap');
  if(tw){ tw.querySelectorAll('select,input').forEach(function(i){ if(i.name) fd.append(i.name,i.value); }); }
  setState(node,'Guardando…');
  return fetch('/api/pages/'+PID+'/blocks/'+rt.dataset.id+'/update',{method:'POST',body:fd})
    .then(function(){ setState(node,'Guardado'); setTimeout(function(){setState(node,'');},1500); })
    .catch(function(){ setState(node,'Sin guardar'); });
}
function flushDirty(){ const arr=[...dirty]; dirty.clear(); return Promise.all(arr.map(saveBlock)); }
setInterval(function(){ if(dirty.size) flushDirty(); }, 2000);
window.addEventListener('beforeunload',function(){ if(dirty.size) flushDirty(); });

var FAMS={sans:"-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif",serif:"Georgia,'Times New Roman',serif",mono:"'SF Mono',Menlo,Consolas,monospace"};
function applyTypo(node){
  const rt=node.querySelector('.block-text'); const tw=node.querySelector('.typo-wrap'); if(!rt||!tw) return;
  function val(n){var e=tw.querySelector('[name='+n+']'); return e?e.value:null;}
  var ff=val('font_family'); if(ff) rt.style.fontFamily=FAMS[ff]||FAMS.sans;
  var fs=val('font_size'); if(fs) rt.style.fontSize=fs+'px';
  var tc=val('text_color'); if(tc) rt.style.color=tc;
  var al=val('align'); if(al) rt.style.textAlign=al;
}
function openArtEdit(node){
  const bid=node.querySelector('.art-edit-btn').dataset.id;
  var fields='<label>Título (opcional)</label><input name="title">'+
    '<label>Sube un archivo nuevo (imagen, video, audio o documento)</label><input type="file" name="file">'+
    '<label>...o pega una URL (YouTube/Vimeo o enlace)</label><input name="url" placeholder="https://...">';
  modal('<h2 style="margin-top:0">Cambiar contenido del bloque</h2>'+fields, function(ov){
    const fd=new FormData();
    ov.querySelectorAll('input').forEach(function(i){ if(i.type==='file'){ if(i.files[0]) fd.append('file',i.files[0]); } else if(i.value) fd.append(i.name,i.value); });
    fetch('/api/pages/'+PID+'/blocks/'+bid+'/media',{method:'POST',body:fd})
      .then(function(r){return r.json();})
      .then(function(d){ if(d.error){alert(d.error);return;}
        var tmp=document.createElement('div'); tmp.innerHTML=d.html.trim();
        var nn=tmp.firstElementChild; node.replaceWith(nn); wireBlock(nn); saveLayout(); });
  });
}
function wireBlock(node){
  const del=node.querySelector('.del-btn');
  if(del) del.onclick=function(){ if(!confirm('Eliminar bloque?'))return;
    dirty.delete(node);
    fetch('/api/pages/'+PID+'/blocks/'+del.dataset.id+'/delete',{method:'POST'})
      .then(function(){node.remove();saveLayout();}); };
  const rt=node.querySelector('.block-text');
  if(rt){
    rt.addEventListener('focus',function(){
      if(IS_GROUP){ acquireLock(node, function(by){ rt.blur(); alert('Este bloque lo está editando '+by+'. Podrás editarlo cuando termine.'); }); }
      setEditing(node); });
    rt.addEventListener('input',function(){ dirty.add(node); });
    rt.addEventListener('blur',function(){ if(dirty.has(node)){dirty.delete(node);saveBlock(node);} releaseLock(node); });
    node.querySelectorAll('.rt-toolbar [data-cmd]').forEach(function(btn){
      btn.addEventListener('mousedown',function(e){e.preventDefault();});
      btn.addEventListener('click',function(){document.execCommand(btn.getAttribute('data-cmd'),false,null);rt.focus();dirty.add(node);});
    });
    var colr=node.querySelector('.rt-color');
    if(colr) colr.addEventListener('input',function(){document.execCommand('foreColor',false,colr.value);rt.focus();dirty.add(node);});
    var sz=node.querySelector('.rt-size');
    if(sz) sz.addEventListener('change',function(){document.execCommand('fontSize',false,sz.value);rt.focus();dirty.add(node);});
    var mk=node.querySelector('.rt-mark');
    var mkc=node.querySelector('.rt-mark-color');
    if(mk){ mk.addEventListener('mousedown',function(e){e.preventDefault();});
      mk.addEventListener('click',function(){ document.execCommand('hiliteColor',false,(mkc?mkc.value:'#fff3a3')); rt.focus(); dirty.add(node); }); }
    if(mkc){ mkc.addEventListener('mousedown',function(e){e.stopPropagation();});
      mkc.addEventListener('input',function(){ document.execCommand('hiliteColor',false,mkc.value); rt.focus(); dirty.add(node); }); }
    var lnk=node.querySelector('.rt-link');
    if(lnk){ lnk.addEventListener('mousedown',function(e){e.preventDefault();});
      lnk.addEventListener('click',function(){ var u=prompt('Enlace (https://...)'); if(u){document.execCommand('createLink',false,u);} rt.focus(); dirty.add(node); }); }
    var htmlb=node.querySelector('.rt-html');
    if(htmlb){ htmlb.addEventListener('click',function(){
      modal('<h2 style="margin-top:0">HTML del bloque</h2><label>Puedes pegar o editar HTML (se limpia por seguridad al guardar)</label><textarea class="html-src" style="min-height:170px;width:100%;font-family:monospace"></textarea>', function(ov){
        var ta=ov.querySelector('.html-src'); rt.innerHTML=ta.value; dirty.add(node); saveBlock(node); });
      setTimeout(function(){ var t=document.querySelector('.modal-ov .html-src'); if(t){ t.value=rt.innerHTML; } },0);
    }); }
  }
  const aeb=node.querySelector('.art-edit-btn');
  if(aeb) aeb.onclick=function(){ openArtEdit(node); };
}
document.querySelectorAll('.blk').forEach(wireBlock);
document.addEventListener('mousedown',function(e){
  if(!e.target.closest('.blk')){ document.querySelectorAll('.blk.editing').forEach(function(b){b.classList.remove('editing');}); }
});

/* ---- Edición concurrente en páginas de grupo: bloqueo por bloque + presencia ---- */
var currentLockBid=null;
function blockIdOf(node){ var rt=node.querySelector('.block-text'); return rt?rt.dataset.id:null; }
function acquireLock(node,onFail){
  if(!IS_GROUP) return; var bid=blockIdOf(node); if(!bid) return;
  fetch('/api/pages/'+PID+'/blocks/'+bid+'/lock',{method:'POST'})
    .then(function(r){return r.json();})
    .then(function(d){ if(d.ok){ currentLockBid=bid; } else if(onFail){ onFail(d.by); } })
    .catch(function(){});
}
function releaseLock(node){
  if(!IS_GROUP) return; var bid=blockIdOf(node); if(!bid) return;
  if(currentLockBid===bid) currentLockBid=null;
  fetch('/api/pages/'+PID+'/blocks/'+bid+'/unlock',{method:'POST'}).catch(function(){});
}
function applyLocks(){
  if(!IS_GROUP) return;
  fetch('/api/pages/'+PID+'/locks').then(function(r){return r.json();}).then(function(d){
    var byId={}; (d.locks||[]).forEach(function(l){ byId[l.block_id]=l; });
    document.querySelectorAll('.blk').forEach(function(node){
      var rt=node.querySelector('.block-text'); if(!rt) return;
      var l=byId[rt.dataset.id]; var badge=node.querySelector('.lock-badge');
      if(l && !l.mine){
        rt.setAttribute('contenteditable','false'); node.style.opacity='0.75';
        if(!badge){ badge=document.createElement('div'); badge.className='lock-badge';
          badge.style.cssText='font-size:12px;color:#7a4a00;background:#fff7e6;border:1px solid #f0d9a8;border-radius:8px;padding:2px 8px;margin-bottom:6px;display:inline-block';
          node.insertBefore(badge,node.firstChild); }
        badge.textContent='✏️ '+l.name+' está editando';
      } else {
        if(rt.getAttribute('contenteditable')==='false'){ rt.setAttribute('contenteditable','true'); node.style.opacity=''; }
        if(badge) badge.remove();
      }
    });
  }).catch(function(){});
}
if(IS_GROUP){
  setInterval(function(){ if(currentLockBid) fetch('/api/pages/'+PID+'/blocks/'+currentLockBid+'/lock',{method:'POST'}).catch(function(){}); }, 15000);
  setInterval(applyLocks, 4000); applyLocks();
  window.addEventListener('beforeunload',function(){ if(currentLockBid){ navigator.sendBeacon('/api/pages/'+PID+'/blocks/'+currentLockBid+'/unlock'); } });
}
var metaForm=document.getElementById('metaForm');
if(metaForm) metaForm.addEventListener('submit',function(e){
  if(dirty.size){ e.preventDefault(); flushDirty().then(function(){ metaForm.submit(); }); }
});

function insertCard(html,colEl,idx){
  const tmp=document.createElement('div'); tmp.innerHTML=html.trim();
  const node=tmp.firstElementChild;
  const kids=colEl.querySelectorAll(':scope > .blk');
  if(kids[idx]) colEl.insertBefore(node,kids[idx]); else colEl.appendChild(node);
  wireBlock(node); return node;
}
function createBlock(fd,colEl,idx){
  fd.append('row_id',colEl.dataset.row); fd.append('col_index',colEl.dataset.col);
  fetch('/api/pages/'+PID+'/blocks/create',{method:'POST',body:fd})
    .then(function(r){return r.json();})
    .then(function(d){ if(d.error){alert(d.error);return;} insertCard(d.html,colEl,idx); saveLayout(); });
}
function handleAdd(type,colEl,idx){
  if(type==='text'||type==='heading'){ const fd=new FormData();
    fd.append('block_type',type); fd.append('text_content',''); createBlock(fd,colEl,idx); }
  else if(type==='artefact'){ openArtefactModal(colEl,idx); }
  else { openMediaModal(type,colEl,idx); }
}
function modal(inner,onOk){
  const ov=document.createElement('div'); ov.className='modal-ov';
  ov.innerHTML='<div class="modal">'+inner+'<div class="row-flex" style="justify-content:flex-end;margin-top:12px">'+
    '<button class="btn sec" data-x>Cancelar</button><button class="btn" data-ok>Insertar</button></div></div>';
  document.body.appendChild(ov);
  ov.querySelector('[data-x]').onclick=function(){ov.remove();};
  ov.querySelector('[data-ok]').onclick=function(){ onOk(ov); ov.remove(); };
  return ov;
}
function openMediaModal(type,colEl,idx){
  const titles={image:'Imagen',video:'Vídeo',audio:'Audio',file:'PDF / Documento',link:'Enlace'};
  let fields='<label>Título</label><input name="title" placeholder="Título del artefacto">';
  if(type==='link') fields+='<label>URL</label><input name="url" placeholder="https://..."><label>Descripción</label><input name="body">';
  else if(type==='video') fields+='<label>URL de YouTube/Vimeo</label><input name="url" placeholder="https://youtu.be/...">'+
    '<label>...o sube un archivo de video</label><input type="file" name="file" accept="video/*">';
  else { var acc=type==='image'?'image/*':(type==='audio'?'audio/*':(type==='file'?'.pdf,.doc,.docx,.ppt,.pptx,.xls,.xlsx,.txt,.md,.zip':''));
    fields+='<label>Archivo</label><input type="file" name="file"'+(acc?(' accept="'+acc+'"'):'')+'>'; }
  modal('<h2 style="margin-top:0">Añadir '+titles[type]+'</h2>'+fields, function(ov){
    const fd=new FormData(); fd.append('block_type',type);
    ov.querySelectorAll('input').forEach(function(i){
      if(i.type==='file'){ if(i.files[0]) fd.append('file',i.files[0]); }
      else fd.append(i.name,i.value); });
    createBlock(fd,colEl,idx); });
}
function openArtefactModal(colEl,idx){
  if(!ARTS.length){ alert('No tienes artefactos aun. Crea uno o arrastra un bloque multimedia.'); return; }
  let opts=''; ARTS.forEach(function(a){ opts+='<option value="'+a.id+'">['+a.kind+'] '+a.title+'</option>'; });
  modal('<h2 style="margin-top:0">Artefacto existente</h2><label>Elige</label><select name="artefact_id">'+opts+'</select>',
    function(ov){ const fd=new FormData(); fd.append('block_type','artefact');
      fd.append('artefact_id',ov.querySelector('select').value); createBlock(fd,colEl,idx); });
}
Sortable.create(document.querySelector('.pal-list'),{group:{name:'blocks',pull:'clone',put:false},sort:false});
document.querySelectorAll('.pcol.dropzone').forEach(function(col){
  Sortable.create(col,{group:'blocks',handle:'.drag-handle',draggable:'.blk',animation:150,
    onAdd:function(evt){ const it=evt.item;
      if(it.classList.contains('pal-item')){ const type=it.getAttribute('data-type'); const idx=evt.newIndex; it.remove(); handleAdd(type,evt.to,idx); }
      else { saveLayout(); } },
    onUpdate:function(){ saveLayout(); } });
});
</script>
"""


@app.route("/pages/<int:pid>/edit")
@login_required
def page_edit(pid):
    p = owned_page(pid)
    arts = get_db().execute("SELECT id,title,kind FROM artefacts WHERE owner_id=? ORDER BY title",
                            (p["owner_id"],)).fetchall()
    arts_json = json.dumps([{"id": a["id"], "title": a["title"], "kind": a["kind"]} for a in arts])
    return render(EDIT_TPL, title="Editar página", p=p, layout=page_rows(pid),
                  arts_json=arts_json, render_card=render_block_card,
                  is_group=bool(p["group_id"]))


@app.route("/pages/<int:pid>/meta", methods=["POST"])
@login_required
def page_meta(pid):
    p = owned_page(pid)
    db = get_db()
    vis = request.form["visibility"]
    if vis == "public" and not feature_on("stu_public"):
        vis = "teachers"  # publicar en abierto no permitido para este alumno
        flash("Públicar como 'Pública' no está permitido; se ha guardado como 'Docentes'.", "error")
    token = p["share_token"] or (secrets.token_urlsafe(10) if vis == "public" else None)
    newtitle = request.form["title"].strip()
    db.execute("UPDATE pages SET title=?,description=?,visibility=?,share_token=? WHERE id=?",
               (newtitle, request.form["description"].strip(), vis, token, pid))
    db.commit()
    grupal = " grupal" if p["group_id"] else ""
    record_student_change(current_user()["id"], pid, "guardado",
                          "ha guardado cambios en una página" + grupal)
    flash("Cambios guardados.")
    return redirect(url_for("page_edit", pid=pid))


# ---- Filas -------------------------------------------------------------- #
@app.route("/pages/<int:pid>/rows/add", methods=["POST"])
@login_required
def row_add(pid):
    owned_page(pid)
    db = get_db()
    layout = request.form.get("layout", "1")
    if layout not in LAYOUTS:
        layout = "1"
    pos = db.execute("SELECT COALESCE(MAX(position),-1)+1 n FROM rows WHERE page_id=?", (pid,)).fetchone()["n"]
    db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)", (pid, pos, layout))
    db.commit()
    return redirect(url_for("page_edit", pid=pid))


@app.route("/pages/<int:pid>/rows/<int:rid>/del", methods=["POST"])
@login_required
def row_del(pid, rid):
    owned_page(pid)
    get_db().execute("DELETE FROM rows WHERE id=? AND page_id=?", (rid, pid))
    get_db().commit()
    return redirect(url_for("page_edit", pid=pid))


@app.route("/pages/<int:pid>/rows/<int:rid>/move/<dir>")
@login_required
def row_move(pid, rid, dir):
    owned_page(pid)
    db = get_db()
    ids = [r["id"] for r in db.execute("SELECT id FROM rows WHERE page_id=? ORDER BY position", (pid,)).fetchall()]
    if rid in ids:
        i = ids.index(rid)
        j = i - 1 if dir == "up" else i + 1
        if 0 <= j < len(ids):
            db.execute("UPDATE rows SET position=? WHERE id=?", (j, ids[i]))
            db.execute("UPDATE rows SET position=? WHERE id=?", (i, ids[j]))
            db.commit()
    return redirect(url_for("page_edit", pid=pid))


# ---- API de bloques ----------------------------------------------------- #
def row_belongs(pid, rid):
    r = get_db().execute("SELECT * FROM rows WHERE id=? AND page_id=?", (rid, pid)).fetchone()
    if not r:
        abort(404)
    return r


def block_in_page(pid, bid):
    return get_db().execute("""SELECT b.* FROM blocks b JOIN rows r ON r.id=b.row_id
                               WHERE b.id=? AND r.page_id=?""", (bid, pid)).fetchone()


def read_typo(form):
    return (form.get("font_family", "sans"), int(form.get("font_size", 16) or 16),
            form.get("text_color", "#25202a"), form.get("align", "left"),
            1 if form.get("bold") else 0, 1 if form.get("italic") else 0)


@app.route("/api/pages/<int:pid>/blocks/create", methods=["POST"])
@login_required
def api_block_create(pid):
    p = owned_page(pid)
    db, u = get_db(), current_user()
    bt = request.form["block_type"]
    rid = int(request.form["row_id"])
    ci = int(request.form["col_index"])
    row_belongs(pid, rid)
    pos = db.execute("SELECT COALESCE(MAX(position),-1)+1 n FROM blocks WHERE row_id=? AND col_index=?",
                     (rid, ci)).fetchone()["n"]
    if bt in ("text", "heading"):
        bid = db.execute("""INSERT INTO blocks(row_id,col_index,position,block_type,text_content)
                            VALUES(?,?,?,?,?)""",
                         (rid, ci, pos, bt, request.form.get("text_content", "").strip())).lastrowid
    elif bt == "artefact":
        aid = request.form.get("artefact_id")
        a = db.execute("SELECT * FROM artefacts WHERE id=? AND owner_id=?", (aid, u["id"])).fetchone()
        if not a:
            return jsonify({"error": "Artefacto no valido"}), 400
        bid = db.execute("""INSERT INTO blocks(row_id,col_index,position,block_type,artefact_id)
                            VALUES(?,?,?,?,?)""", (rid, ci, pos, "artefact", aid)).lastrowid
    else:
        kind = bt
        title = request.form.get("title", "").strip() or KIND_LABELS.get(kind, "Artefacto")
        url = request.form.get("url", "").strip()
        body = request.form.get("body", "").strip()
        fn = None
        if kind in ("image", "audio", "file") or (kind == "video" and not url):
            fn, ext = save_upload()
            if ext == "bad":
                return jsonify({"error": "Tipo de archivo no permitido"}), 400
            if not fn:
                return jsonify({"error": "Debes adjuntar un archivo o una URL"}), 400
            if ext in IMAGE_EXT:
                kind = "image"
        aid = db.execute("""INSERT INTO artefacts(owner_id,kind,title,body,url,filename,created_at)
                            VALUES(?,?,?,?,?,?,?)""",
                         (u["id"], kind, title, body, url, fn, now())).lastrowid
        bid = db.execute("""INSERT INTO blocks(row_id,col_index,position,block_type,artefact_id)
                            VALUES(?,?,?,?,?)""", (rid, ci, pos, "artefact", aid)).lastrowid
    db.commit()
    b = db.execute("SELECT * FROM blocks WHERE id=?", (bid,)).fetchone()
    return jsonify({"id": bid, "html": render_block_card(b)})


@app.route("/api/pages/<int:pid>/layout", methods=["POST"])
@login_required
def api_layout(pid):
    owned_page(pid)
    db = get_db()
    data = request.get_json(force=True, silent=True) or {}
    valid = {r["id"] for r in db.execute("""SELECT b.id FROM blocks b JOIN rows r ON r.id=b.row_id
                                            WHERE r.page_id=?""", (pid,)).fetchall()}
    validrows = {r["id"] for r in db.execute("SELECT id FROM rows WHERE page_id=?", (pid,)).fetchall()}
    for col in data.get("columns", []):
        rid, ci = int(col["row_id"]), int(col["col_index"])
        if rid not in validrows:
            continue
        for i, bid in enumerate(col.get("block_ids", [])):
            if int(bid) in valid:
                db.execute("UPDATE blocks SET row_id=?,col_index=?,position=? WHERE id=?", (rid, ci, i, int(bid)))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/pages/<int:pid>/blocks/<int:bid>/update", methods=["POST"])
@login_required
def api_block_update(pid, bid):
    p = owned_page(pid)
    if not block_in_page(pid, bid):
        abort(404)
    db = get_db()
    db.execute("UPDATE blocks SET text_content=? WHERE id=?",
               (request.form.get("text_content", "").strip(), bid))
    # Solo tocar el estilo base si vienen esos controles (ya no existen en el editor).
    if "font_family" in request.form:
        ff, fs, col, al, bo, it = read_typo(request.form)
        db.execute("""UPDATE blocks SET font_family=?,font_size=?,text_color=?,align=?,bold=?,italic=? WHERE id=?""",
                   (ff, fs, col, al, bo, it, bid))
    db.commit()
    return block_html(db.execute("SELECT * FROM blocks WHERE id=?", (bid,)).fetchone())


def _locks_cutoff():
    from datetime import timedelta
    return (datetime.now() - timedelta(seconds=35)).strftime("%Y-%m-%d %H:%M:%S")


@app.route("/api/pages/<int:pid>/blocks/<int:bid>/lock", methods=["POST"])
@login_required
def api_block_lock(pid, bid):
    owned_page(pid)
    if not block_in_page(pid, bid):
        abort(404)
    db, u = get_db(), current_user()
    db.execute("DELETE FROM block_locks WHERE heartbeat_at < ?", (_locks_cutoff(),))
    row = db.execute("SELECT * FROM block_locks WHERE block_id=?", (bid,)).fetchone()
    if row and row["user_id"] != u["id"]:
        db.commit()
        return jsonify({"ok": False, "by": row["user_name"]})
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    db.execute("""INSERT INTO block_locks(block_id,page_id,user_id,user_name,heartbeat_at)
        VALUES(?,?,?,?,?) ON CONFLICT(block_id) DO UPDATE SET user_id=excluded.user_id,
        user_name=excluded.user_name, heartbeat_at=excluded.heartbeat_at""",
        (bid, pid, u["id"], u["name"], ts))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/pages/<int:pid>/blocks/<int:bid>/unlock", methods=["POST"])
@login_required
def api_block_unlock(pid, bid):
    owned_page(pid)
    db, u = get_db(), current_user()
    db.execute("DELETE FROM block_locks WHERE block_id=? AND user_id=?", (bid, u["id"]))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/pages/<int:pid>/locks")
@login_required
def api_page_locks(pid):
    owned_page(pid)
    db, u = get_db(), current_user()
    db.execute("DELETE FROM block_locks WHERE heartbeat_at < ?", (_locks_cutoff(),))
    db.commit()
    rows = db.execute("SELECT block_id,user_id,user_name FROM block_locks WHERE page_id=?", (pid,)).fetchall()
    return jsonify({"locks": [{"block_id": r["block_id"], "name": r["user_name"],
                               "mine": r["user_id"] == u["id"]} for r in rows]})


@app.route("/api/pages/<int:pid>/blocks/<int:bid>/delete", methods=["POST"])
@login_required
def api_block_delete(pid, bid):
    owned_page(pid)
    if block_in_page(pid, bid):
        get_db().execute("DELETE FROM blocks WHERE id=?", (bid,))
        get_db().commit()
    return jsonify({"ok": True})


@app.route("/api/pages/<int:pid>/blocks/<int:bid>/media", methods=["POST"])
@login_required
def api_block_media_update(pid, bid):
    owned_page(pid)
    b = block_in_page(pid, bid)
    if not b or b["block_type"] != "artefact":
        abort(404)
    db, u = get_db(), current_user()
    a = db.execute("SELECT * FROM artefacts WHERE id=?", (b["artefact_id"],)).fetchone()
    if not a:
        abort(404)
    title = (request.form.get("title", "") or "").strip() or a["title"]
    url = (request.form.get("url", "") or "").strip()
    fn, ext = save_upload()
    if ext == "bad":
        return jsonify({"error": "Tipo de archivo no permitido"}), 400
    if fn:  # archivo nuevo
        kind = ("image" if ext in IMAGE_EXT else "video" if ext in VIDEO_EXT
                else "audio" if ext in AUDIO_EXT else "file")
        db.execute("UPDATE artefacts SET title=?, url=NULL, filename=?, kind=? WHERE id=?",
                   (title, fn, kind, a["id"]))
    elif url:  # nueva URL
        kind = "video" if (youtube_embed(url) or vimeo_embed(url)) else "link"
        db.execute("UPDATE artefacts SET title=?, url=?, filename=NULL, kind=? WHERE id=?",
                   (title, url, kind, a["id"]))
    else:  # solo título
        db.execute("UPDATE artefacts SET title=? WHERE id=?", (title, a["id"]))
    db.commit()
    b2 = db.execute("SELECT * FROM blocks WHERE id=?", (bid,)).fetchone()
    return jsonify({"html": render_block_card(b2)})


# --------------------------------------------------------------------------- #
#  Vista de página + social
# --------------------------------------------------------------------------- #
VIEW_TPL = """
<div class="between"><h1>{{ p['title'] }}</h1>
 <div class="row-flex">
 {% if can_edit %}<a class="btn sec" href="{{ url_for('page_edit', pid=p['id']) }}">Editar</a>{% endif %}
 {% if can_pdf %}<a class="btn sec" href="{{ url_for('page_pdf', pid=p['id']) }}">Descargar PDF</a>{% endif %}
 </div></div>
<p class="muted">Por <a href="{{ url_for('profile', username=author['username']) }}">{{ author['name'] }}</a>
 <span class="pill">{{ vis[p['visibility']] }}</span></p>
{% if p['description'] %}<p>{{ p['description'] }}</p>{% endif %}
<div class="card">
 {% for R in layout %}
  <div class="prow" style="grid-template-columns:{{ R['weights']|join('fr ') }}fr">
   {% for col in R['cols'] %}<div class="pcol">
    {% for b in col %}<div style="margin-bottom:14px">{{ render_block(b)|safe }}</div>{% endfor %}
   </div>{% endfor %}</div>
 {% else %}<p class="muted">Esta página aun no tiene contenido.</p>{% endfor %}
</div>
{% if show_social %}<div class="card"><div class="row-flex">
 {% if is_staff and not is_owner %}
  <form method="post" action="{{ url_for('toggle_read', pid=p['id']) }}">
   <button class="btn {{ 'sec' if read_by_me }}">{{ '✓ Leída' if read_by_me else 'Marcar como leída' }}</button></form>
 {% endif %}
 <span class="muted">{% if is_staff %}Leída por {{ reads }} docente(s) &middot; {% endif %}{{ comments|length }} comentarios</span>
</div></div>{% endif %}
<div class="card"><h2>Comentarios y feedback</h2>
 {% for c in threads %}<div class="comment">
  <b>{{ c['name'] }}</b> <span class="pill">{{ role_es(c['role']) }}</span> <span class="muted">{{ c['created_at'] }}</span>
  <div>{{ c['body'] }}</div>
  {% for rp in c['replies'] %}<div class="comment" style="margin:8px 0 0 22px;background:#fff">
   <b>{{ rp['name'] }}</b> <span class="pill">{{ role_es(rp['role']) }}</span> <span class="muted">{{ rp['created_at'] }}</span>
   <div>{{ rp['body'] }}</div></div>{% endfor %}
  {% if can_comment %}<details class="add" style="margin-top:6px"><summary>Responder</summary>
   <form method="post" action="{{ url_for('add_comment', pid=p['id']) }}" style="margin-top:6px">
    <input type="hidden" name="parent_id" value="{{ c['id'] }}">
    <textarea name="body" placeholder="Escribe tu respuesta..." required></textarea>
    <button class="btn sm">Responder</button></form></details>{% endif %}
 </div>
 {% else %}<p class="muted">Sin comentarios todavia.</p>{% endfor %}
 {% if can_comment %}<form method="post" action="{{ url_for('add_comment', pid=p['id']) }}" style="margin-top:14px">
  <textarea name="body" placeholder="Escribe un comentario nuevo..." required></textarea>
  <button class="btn">Públicar comentario</button></form>{% endif %}
</div>
"""


def build_threads(comments):
    parents = [dict(c) for c in comments if c["parent_id"] is None]
    for p in parents:
        p["replies"] = [dict(c) for c in comments if c["parent_id"] == p["id"]]
    return parents


def can_view(p, u):
    if p["visibility"] == "public":
        return True
    if not u:
        return False
    if p["owner_id"] == u["id"]:
        return True
    if p["group_id"] and is_group_member(p["group_id"], u["id"]):
        return True
    # Los profesores/admin solo ven páginas compartidas con 'Docentes' o 'Pública'.
    return p["visibility"] == "teachers" and u["role"] in ("teacher", "admin")


def can_view_collection(col, u):
    if col["visibility"] == "public":
        return True
    if not u:
        return False
    if col["owner_id"] == u["id"]:
        return True
    return col["visibility"] == "teachers" and u["role"] in ("teacher", "admin")


def load_view(pid):
    db = get_db()
    p = db.execute("SELECT * FROM pages WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    author = db.execute("SELECT * FROM users WHERE id=?", (p["owner_id"],)).fetchone()
    comments = db.execute("""SELECT c.*,u.name,u.role FROM comments c JOIN users u ON u.id=c.author_id
                             WHERE page_id=? ORDER BY c.id""", (pid,)).fetchall()
    likes = db.execute("SELECT COUNT(*) c FROM likes WHERE page_id=?", (pid,)).fetchone()["c"]
    return p, author, comments, likes


@app.route("/pages/<int:pid>")
@login_required
def page_view(pid):
    u = current_user()
    p, author, comments, likes = load_view(pid)
    if not can_view(p, u):
        abort(403)
    is_owner = p["owner_id"] == u["id"]
    is_staff = u["role"] in ("teacher", "admin")
    can_edit = is_owner or (p["group_id"] and is_group_member(p["group_id"], u["id"]))
    db2 = get_db()
    read_by_me = bool(db2.execute("SELECT 1 FROM page_reads WHERE page_id=? AND user_id=?", (pid, u["id"])).fetchone())
    reads = db2.execute("SELECT COUNT(*) c FROM page_reads WHERE page_id=?", (pid,)).fetchone()["c"]
    return render(VIEW_TPL, title=p["title"], p=p, author=author, comments=comments,
                  threads=build_threads(comments), reads=reads, read_by_me=read_by_me, layout=page_rows(pid),
                  vis=VIS, is_owner=is_owner, is_staff=is_staff, can_edit=can_edit, can_comment=True, show_social=True,
                  can_pdf=((is_owner or is_staff) and feature_on("stu_pdf")),
                  render_block=lambda b: block_html(b))


@app.route("/view/<token>")
@login_required
def public_view(token):
    # Ya no hay acceso anónimo: los enlaces antiguos requieren sesión y llevan a la página normal.
    db = get_db()
    p = db.execute("SELECT * FROM pages WHERE share_token=?", (token,)).fetchone()
    if not p:
        abort(404)
    return redirect(url_for("page_view", pid=p["id"]))


@app.route("/pages/<int:pid>/comment", methods=["POST"])
@login_required
def add_comment(pid):
    if not feature_on("stu_comment"):
        abort(403)
    db, u = get_db(), current_user()
    p = db.execute("SELECT * FROM pages WHERE id=?", (pid,)).fetchone()
    if not p or not (can_view(p, u) or u["role"] in ("teacher", "admin")):
        abort(403)
    parent_id = request.form.get("parent_id") or None
    if parent_id:
        par = db.execute("SELECT id FROM comments WHERE id=? AND page_id=?", (parent_id, pid)).fetchone()
        if not par:
            parent_id = None
    body = request.form["body"].strip()
    ts = now()
    db.execute("INSERT INTO comments(page_id,author_id,parent_id,body,created_at) VALUES(?,?,?,?,?)",
               (pid, u["id"], parent_id, body, ts))
    # Archivo de evidencia: SOLO comentarios del profesorado/admin. Se conserva aunque se borre la página.
    if u["role"] in ("teacher", "admin"):
        owner = db.execute("SELECT name FROM users WHERE id=?", (p["owner_id"],)).fetchone()
        db.execute("""INSERT INTO comment_log(page_id,page_title,author_id,author_name,author_role,owner_id,owner_name,body,created_at)
                      VALUES(?,?,?,?,?,?,?,?,?)""",
                   (pid, p["title"], u["id"], u["name"], u["role"], p["owner_id"],
                    owner["name"] if owner else "", body, ts))
    link = url_for("page_view", pid=pid)
    is_staff = u["role"] in ("teacher", "admin")
    targets = set()
    if p["owner_id"] != u["id"]:
        targets.add(p["owner_id"])
    if parent_id:
        par = db.execute("SELECT author_id FROM comments WHERE id=?", (parent_id,)).fetchone()
        if par and par["author_id"] != u["id"]:
            targets.add(par["author_id"])
    for t in targets:
        notify(t, "comment", "%s ha comentado en '%s'." % (u["name"], p["title"]), link,
               {"actor": u["name"], "title": p["title"]})
    notify_mentions(u, body, link, "un comentario de «%s»" % p["title"], p)
    db.commit()
    flash("Respuesta publicada." if parent_id else "Comentario publicado.")
    nxt = request.form.get("next")
    return redirect(nxt if nxt and nxt.startswith("/") else url_for("page_view", pid=pid))


@app.route("/pages/<int:pid>/like", methods=["POST"])
@login_required
def toggle_like(pid):
    db, u = get_db(), current_user()
    p = db.execute("SELECT * FROM pages WHERE id=?", (pid,)).fetchone()
    if not p or not can_view(p, u):
        abort(403)
    if db.execute("SELECT 1 FROM likes WHERE page_id=? AND user_id=?", (pid, u["id"])).fetchone():
        db.execute("DELETE FROM likes WHERE page_id=? AND user_id=?", (pid, u["id"]))
    else:
        db.execute("INSERT INTO likes(page_id,user_id) VALUES(?,?)", (pid, u["id"]))
    db.commit()
    return redirect(url_for("page_view", pid=pid))


@app.route("/pages/<int:pid>/read", methods=["POST"])
@login_required
@role_required("teacher", "admin")
def toggle_read(pid):
    db, u = get_db(), current_user()
    p = db.execute("SELECT * FROM pages WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    if db.execute("SELECT 1 FROM page_reads WHERE page_id=? AND user_id=?", (pid, u["id"])).fetchone():
        db.execute("DELETE FROM page_reads WHERE page_id=? AND user_id=?", (pid, u["id"]))
    else:
        db.execute("INSERT INTO page_reads(page_id,user_id,created_at) VALUES(?,?,?)", (pid, u["id"], now()))
    db.commit()
    return redirect(url_for("page_view", pid=pid))


# --------------------------------------------------------------------------- #
#  Comunidad: buscador de personas + feed
# --------------------------------------------------------------------------- #
FEED_TPL = """
<h1>Comunidad</h1>
<div class="card">
 <h2>Buscar personas</h2>
 <form method="get" class="row-flex">
  <input name="q" value="{{ q }}" placeholder="Nombre o usuario..." style="flex:1;margin:0">
  <button class="btn">Buscar</button></form>
 <div class="prow-list" style="margin-top:10px">
 {% for pu in people %}
  <div class="between">
   <div class="row-flex">{{ avatar(pu) }}
    <div><b><a href="{{ url_for('profile', username=pu['username']) }}">{{ pu['name'] }}</a></b>
     <div class="muted">@{{ pu['username'] }}</div>
     {% if pu['groups'] %}<div style="display:flex;flex-wrap:wrap;gap:5px;margin-top:4px">
      {% for g in pu['groups'] %}<a href="{{ url_for('group_view', gid=g['id']) }}" class="pill" style="text-decoration:none;font-size:11px">&#128101; {{ g['name'] }}</a>{% endfor %}</div>{% endif %}
    </div></div>
   <div class="row-flex">
    {% if pu['status']=='accepted' %}<span class="pill">Conocido</span>
    {% elif pu['status']=='pending_out' %}<span class="muted">Solicitud enviada</span>
    {% elif pu['status']=='pending_in' %}
     <form method="post" action="{{ url_for('contact_action', username=pu['username']) }}"><input type="hidden" name="action" value="accept"><button class="btn sm">Aceptar</button></form>
    {% else %}
     <form method="post" action="{{ url_for('contact_action', username=pu['username']) }}"><input type="hidden" name="action" value="request"><button class="btn sm">Añadir</button></form>
    {% endif %}
    <a class="btn sec sm" href="{{ url_for('thread', username=pu['username']) }}">Mensaje</a>
   </div></div>
 {% else %}<p class="muted">{{ 'Nadie coincide con la busqueda.' if q else 'No hay mas usuarios.' }}</p>{% endfor %}
 </div>
</div>

{% if feat('stu_groups') %}<div class="card"><h2>Grupos</h2>
 <details class="add"><summary>+ Crear un grupo</summary>
  <form method="post" action="{{ url_for('group_new') }}" class="row-flex" style="margin-top:8px">
   <input name="name" placeholder="Nombre del grupo" required style="flex:1;margin:0">
   <button class="btn sec sm">Crear grupo</button></form>
  <div class="muted" style="font-size:12px;margin-top:4px">Un grupo puede crear páginas grupales que editan todos sus miembros.</div>
 </details>
 <div class="prow-list" style="margin-top:10px">
 {% for g in groups %}<div class="between">
   <div class="row-flex"><div class="avatar" style="background:linear-gradient(135deg,#6b3fa0,#9a5fd0)">{{ g['name'][0]|upper }}</div>
    <div><b><a href="{{ url_for('group_view', gid=g['id']) }}">{{ g['name'] }}</a></b>
     <div class="muted">{{ g['nmembers'] }} miembro(s) &middot; {{ g['npages'] }} página(s) &middot; admin: {{ g['owner_name'] }}</div></div></div>
   <a class="btn sec sm" href="{{ url_for('group_view', gid=g['id']) }}">Abrir</a>
  </div>
 {% else %}<p class="muted">No perteneces a ningún grupo todavía.</p>{% endfor %}
 </div>
 {% if other_groups %}<h3 style="margin:14px 0 4px">Descubrir grupos</h3>
 <div class="prow-list">
 {% for g in other_groups %}<div class="between">
   <div class="row-flex"><div class="avatar" style="background:linear-gradient(135deg,#8a8594,#b3adba)">{{ g['name'][0]|upper }}</div>
    <div><b><a href="{{ url_for('group_view', gid=g['id']) }}">{{ g['name'] }}</a></b><div class="muted">{{ g['nmembers'] }} miembro(s) &middot; admin: {{ g['owner_name'] }}</div></div></div>
   {% if g['requested'] %}<span class="muted">Solicitud enviada</span>
   {% else %}<form method="post" action="{{ url_for('group_request_join', gid=g['id']) }}" style="margin:0"><button class="btn sec sm">Solicitar unirse</button></form>{% endif %}
  </div>{% endfor %}
 </div>{% endif %}
</div>
{% endif %}

{% if incoming %}<div class="card"><h2>Solicitudes de conocido recibidas</h2>
 {% for p in incoming %}<div class="between" style="padding:6px 0">
  <div class="row-flex">{{ avatar(p) }}
   <div><b><a href="{{ url_for('profile', username=p['username']) }}">{{ p['name'] }}</a></b>
    <div class="muted">@{{ p['username'] }}</div></div></div>
  <div class="row-flex">
   <form method="post" action="{{ url_for('contact_action', username=p['username']) }}"><input type="hidden" name="action" value="accept"><button class="btn sm">Aceptar</button></form>
   <form method="post" action="{{ url_for('contact_action', username=p['username']) }}"><input type="hidden" name="action" value="remove"><button class="btn sec sm">Rechazar</button></form>
  </div></div>{% endfor %}
</div>{% endif %}

<div class="card"><h2>Mis conocidos ({{ friends|length }})</h2>
 {% for p in friends %}<div class="between" style="padding:6px 0">
  <div class="row-flex">{{ avatar(p) }}
   <div><b><a href="{{ url_for('profile', username=p['username']) }}">{{ p['name'] }}</a></b>
    <div class="muted">@{{ p['username'] }}</div></div></div>
  <div class="row-flex">
   <a class="btn sec sm" href="{{ url_for('thread', username=p['username']) }}">Mensaje</a>
   <form method="post" action="{{ url_for('contact_action', username=p['username']) }}" onsubmit="return confirm('Eliminar conocido?')"><input type="hidden" name="action" value="remove"><button class="btn sec sm">Eliminar</button></form>
  </div></div>
 {% else %}<p class="muted">Aún no tienes conocidos. Busca personas arriba y envía una solicitud.</p>{% endfor %}
</div>

{% if outgoing %}<div class="card"><h2>Solicitudes enviadas</h2>
 {% for p in outgoing %}<div class="between" style="padding:6px 0">
  <div><b>{{ p['name'] }}</b> <span class="muted">@{{ p['username'] }}</span></div>
  <form method="post" action="{{ url_for('contact_action', username=p['username']) }}"><input type="hidden" name="action" value="remove"><button class="btn sec sm">Cancelar</button></form>
 </div>{% endfor %}
</div>{% endif %}

<h2>Portafolios públicos</h2>
{% for p in items %}<div class="card between">
 <div><b><a href="{{ url_for('page_view', pid=p['id']) }}">{{ p['title'] }}</a></b>
  <div class="muted">por <a href="{{ url_for('profile', username=p['username']) }}">{{ p['name'] }}</a> &middot; {{ p['created_at'] }}</div>
  <div class="muted">{{ p['description'] or '' }}</div></div>
</div>{% else %}<p class="muted">Aun no hay portafolios públicos.</p>{% endfor %}
"""


@app.route("/feed")
@login_required
def feed():
    if not feature_on("stu_community"):
        abort(403)
    db, u = get_db(), current_user()
    q = request.args.get("q", "").strip()
    if q:
        rows = db.execute("""SELECT * FROM users WHERE id<>? AND (name LIKE ? OR username LIKE ?)
                             ORDER BY name LIMIT 50""",
                          (u["id"], f"%{q}%", f"%{q}%")).fetchall()
    else:
        rows = db.execute("SELECT * FROM users WHERE id<>? ORDER BY name LIMIT 50", (u["id"],)).fetchall()
    # Grupos de cada persona listada (una sola consulta para todas)
    gmap = {}
    ids = [r["id"] for r in rows]
    if ids:
        qm = ",".join("?" * len(ids))
        for gr in db.execute("SELECT m.user_id uid, g.id gid, g.name FROM group_members m "
                             "JOIN groups g ON g.id=m.group_id WHERE m.user_id IN (%s) ORDER BY g.name" % qm,
                             ids).fetchall():
            gmap.setdefault(gr["uid"], []).append({"id": gr["gid"], "name": gr["name"]})
    people = []
    for r in rows:
        d = dict(r)
        d["status"] = contact_status(u["id"], r["id"])
        d["groups"] = gmap.get(r["id"], [])
        people.append(d)
    items = db.execute("""
        SELECT p.*, us.name, us.username,
          (SELECT COUNT(*) FROM page_reads r WHERE r.page_id=p.id) reads,
          (SELECT COUNT(*) FROM comments c WHERE c.page_id=p.id) ncom
        FROM pages p JOIN users us ON us.id=p.owner_id
        WHERE p.visibility='public' ORDER BY p.id DESC""").fetchall()
    friends = db.execute("""
        SELECT us.* FROM contacts c JOIN users us
          ON us.id = CASE WHEN c.requester_id=? THEN c.addressee_id ELSE c.requester_id END
        WHERE c.status='accepted' AND (c.requester_id=? OR c.addressee_id=?)
        ORDER BY us.name""", (u["id"], u["id"], u["id"])).fetchall()
    incoming = db.execute("""SELECT us.* FROM contacts c JOIN users us ON us.id=c.requester_id
                             WHERE c.addressee_id=? AND c.status='pending' ORDER BY us.name""", (u["id"],)).fetchall()
    outgoing = db.execute("""SELECT us.* FROM contacts c JOIN users us ON us.id=c.addressee_id
                             WHERE c.requester_id=? AND c.status='pending' ORDER BY us.name""", (u["id"],)).fetchall()
    groups = db.execute("""
        SELECT g.*,
          (SELECT name FROM users WHERE id=g.owner_id) owner_name,
          (SELECT COUNT(*) FROM group_members m WHERE m.group_id=g.id) nmembers,
          (SELECT COUNT(*) FROM pages p WHERE p.group_id=g.id) npages
        FROM groups g JOIN group_members gm ON gm.group_id=g.id
        WHERE gm.user_id=? ORDER BY g.name""", (u["id"],)).fetchall()
    other_groups = db.execute("""
        SELECT g.*,
          (SELECT name FROM users WHERE id=g.owner_id) owner_name,
          (SELECT COUNT(*) FROM group_members m WHERE m.group_id=g.id) nmembers,
          EXISTS(SELECT 1 FROM group_requests r WHERE r.group_id=g.id AND r.user_id=?) requested
        FROM groups g
        WHERE g.id NOT IN (SELECT group_id FROM group_members WHERE user_id=?)
        ORDER BY g.name""", (u["id"], u["id"])).fetchall()
    return render(FEED_TPL, title="Comunidad", people=people, items=items, q=q,
                  friends=friends, incoming=incoming, outgoing=outgoing,
                  groups=groups, other_groups=other_groups)


# --------------------------------------------------------------------------- #
#  Conocidos (contactos)
# --------------------------------------------------------------------------- #
CONTACTS_TPL = """
<h1>Conocidos</h1>
{% if incoming %}<div class="card"><h2>Solicitudes recibidas</h2>
 {% for p in incoming %}<div class="between" style="padding:6px 0">
  <div class="row-flex">{{ avatar(p) }}
   <div><b><a href="{{ url_for('profile', username=p['username']) }}">{{ p['name'] }}</a></b>
    <div class="muted">@{{ p['username'] }}</div></div></div>
  <div class="row-flex">
   <form method="post" action="{{ url_for('contact_action', username=p['username']) }}"><input type="hidden" name="action" value="accept"><button class="btn sm">Aceptar</button></form>
   <form method="post" action="{{ url_for('contact_action', username=p['username']) }}"><input type="hidden" name="action" value="remove"><button class="btn sec sm">Rechazar</button></form>
  </div></div>{% endfor %}
</div>{% endif %}

<div class="card"><h2>Mis conocidos ({{ friends|length }})</h2>
 {% for p in friends %}<div class="between" style="padding:6px 0">
  <div class="row-flex"><div class="avatar">{{ p['name'][0] }}</div>
   <div><b><a href="{{ url_for('profile', username=p['username']) }}">{{ p['name'] }}</a></b>
    <div class="muted">@{{ p['username'] }} <span class="pill">{{ role_es(p['role']) }}</span></div></div></div>
  <div class="row-flex">
   <a class="btn sec sm" href="{{ url_for('thread', username=p['username']) }}">Mensaje</a>
   <form method="post" action="{{ url_for('contact_action', username=p['username']) }}" onsubmit="return confirm('Eliminar conocido?')"><input type="hidden" name="action" value="remove"><button class="btn sec sm">Eliminar</button></form>
  </div></div>
 {% else %}<p class="muted">Aun no tienes conocidos. Busca personas en <a href="{{ url_for('feed') }}">Comunidad</a>.</p>{% endfor %}
</div>

{% if outgoing %}<div class="card"><h2>Solicitudes enviadas</h2>
 {% for p in outgoing %}<div class="between" style="padding:6px 0">
  <div><b>{{ p['name'] }}</b> <span class="muted">@{{ p['username'] }}</span></div>
  <form method="post" action="{{ url_for('contact_action', username=p['username']) }}"><input type="hidden" name="action" value="remove"><button class="btn sec sm">Cancelar</button></form>
 </div>{% endfor %}
</div>{% endif %}
"""


@app.route("/contacts")
@login_required
def contacts():
    # 'Conocidos' se fusiono con 'Comunidad'; mantenemos la ruta para enlaces antiguos.
    return redirect(url_for("feed"))


@app.route("/u/<username>/contact", methods=["POST"])
@login_required
def contact_action(username):
    if not feature_on("stu_contacts"):
        abort(403)
    db, u = get_db(), current_user()
    other = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not other or other["id"] == u["id"]:
        abort(400)
    action = request.form.get("action")
    me, ot = u["id"], other["id"]
    if action == "request":
        if contact_status(me, ot) == "none":
            db.execute("INSERT INTO contacts(requester_id,addressee_id,status,created_at) VALUES(?,?,?,?)",
                       (me, ot, "pending", now()))
            notify(ot, "contact_request", "%s quiere añadirte como conocido." % u["name"],
                   url_for("feed"), {"actor": u["name"]})
            flash(f"Solicitud enviada a {other['name']}.")
    elif action == "accept":
        db.execute("UPDATE contacts SET status='accepted' WHERE requester_id=? AND addressee_id=? AND status='pending'",
                   (ot, me))
        flash(f"Ahora {other['name']} es tu conocido.")
    elif action == "remove":
        db.execute("DELETE FROM contacts WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)",
                   (me, ot, ot, me))
        flash("Contacto actualizado.")
    db.commit()
    return redirect(request.referrer or url_for("feed"))


# --------------------------------------------------------------------------- #
#  Grupos y páginas grupales
# --------------------------------------------------------------------------- #
GROUP_VIEW_TPL = """
<div class="between"><h1>{{ g['name'] }}</h1>
 <div class="row-flex">{% if is_owner or user['role'] == 'admin' %}<a class="btn sec" href="{{ url_for('group_settings', gid=g['id']) }}">Ajustes</a>{% endif %}
  <a class="btn sec" href="{{ url_for('feed') }}">Volver a Comunidad</a></div></div>
<p class="muted">Grupo &middot; {{ members|length }} miembro(s) &middot; Administrador/a del grupo: <a href="{{ url_for('profile', username=owner['username']) }}">{{ owner['name'] }}</a>{% if is_owner %} (tú){% endif %}</p>

{% if is_member %}<div class="card"><h2>Páginas del grupo</h2>
 <p class="muted" style="margin-top:0">Las páginas grupales las pueden editar todos los miembros del grupo.</p>
 <form method="post" action="{{ url_for('group_page_new', gid=g['id']) }}" class="row-flex">
  <input name="title" placeholder="Título de la nueva página grupal" required style="flex:1;margin:0">
  <button class="btn">Crear página grupal</button></form>
 <div style="margin-top:10px">
 {% for p in pages %}<div class="between" style="padding:8px 0;border-bottom:1px solid var(--line)">
   <div><b><a href="{{ url_for('page_view', pid=p['id']) }}">{{ p['title'] }}</a></b>
    <span class="pill">{{ vis[p['visibility']] }}</span>
    <div class="muted">creada por {{ p['owner_name'] }}</div></div>
   <div class="row-flex"><a class="btn sec sm" href="{{ url_for('page_edit', pid=p['id']) }}">Editar</a>
    <a class="btn sec sm" href="{{ url_for('page_view', pid=p['id']) }}">Ver</a></div>
  </div>
 {% else %}<p class="muted">El grupo aún no tiene páginas.</p>{% endfor %}
 </div>
</div>
{% else %}<div class="card"><h2>Páginas del grupo</h2>
 <p class="muted">Las páginas de este grupo solo están disponibles para sus miembros.</p>
 {% if requested %}<span class="muted">Ya has enviado una solicitud para unirte. El creador debe aceptarla.</span>
 {% else %}<form method="post" action="{{ url_for('group_request_join', gid=g['id']) }}" style="margin:0">
  <button class="btn">Solicitar unirse al grupo</button></form>{% endif %}
</div>{% endif %}

{% if is_member %}<div class="card"><h2>Lesson Study</h2>
 <p class="muted" style="margin-top:0">Ciclos de estudio de la lección: diseñáis los objetivos y la observación, impartís la lección de investigación y ponéis las evidencias en común.</p>
 <form method="post" action="{{ url_for('ls_new', gid=g['id']) }}" class="row-flex">
  <input name="title" placeholder="Título de la sesión (p. ej. Ciclo 1 - Exploración con luz)" required style="flex:1;margin:0">
  <button class="btn">Nueva sesión LS</button></form>
 <div style="margin-top:10px">
 {% for s in sessions %}<div class="between" style="padding:8px 0;border-bottom:1px solid var(--line)">
   <div><b><a href="{{ url_for('ls_view', sid=s['id']) }}">{{ s['title'] }}</a></b>
    <div class="muted">{% if s['lesson_date'] %}Lección: {{ s['lesson_date'] }} &middot; {% endif %}{{ s['nevid'] }} evidencia(s) &middot; {{ 'lección realizada' if s['lesson_done'] else 'en preparación' }}</div></div>
   <a class="btn sec sm" href="{{ url_for('ls_view', sid=s['id']) }}">Abrir</a>
  </div>
 {% else %}<p class="muted">Aún no hay sesiones de Lesson Study.</p>{% endfor %}
 </div>
</div>{% endif %}

{% if is_owner and requests %}<div class="card"><h2>Solicitudes de ingreso ({{ requests|length }})</h2>
 {% for r in requests %}<div class="between" style="padding:6px 0">
  <div class="row-flex">{{ avatar(r) }}
   <div><b><a href="{{ url_for('profile', username=r['username']) }}">{{ r['name'] }}</a></b>
    <div class="muted">@{{ r['username'] }} &middot; solicitó el {{ r['created_at'] }}</div></div></div>
  <div class="row-flex">
   <form method="post" action="{{ url_for('group_request_accept', gid=g['id']) }}"><input type="hidden" name="user_id" value="{{ r['id'] }}"><button class="btn sm">Aceptar</button></form>
   <form method="post" action="{{ url_for('group_request_reject', gid=g['id']) }}"><input type="hidden" name="user_id" value="{{ r['id'] }}"><button class="btn sec sm">Rechazar</button></form>
  </div>
 </div>{% endfor %}
</div>{% endif %}

<div class="card"><h2>Miembros ({{ members|length }})</h2>
 {% for m in members %}<div class="between" style="padding:6px 0">
  <div class="row-flex">{{ avatar(m, 34) }}
   <div><b><a href="{{ url_for('profile', username=m['username']) }}">{{ m['name'] }}</a></b>
    <div class="muted">@{{ m['username'] }}{% if m['id']==g['owner_id'] %} &middot; administrador/a{% endif %}</div></div></div>
  {% if is_owner and m['id']!=g['owner_id'] %}
   <form method="post" action="{{ url_for('group_remove_member', gid=g['id']) }}"><input type="hidden" name="user_id" value="{{ m['id'] }}"><button class="btn sec sm">Quitar</button></form>{% endif %}
 </div>{% endfor %}
 {% if is_owner %}
 <h3 style="margin:14px 0 4px">Añadir miembro</h3>
 <input id="memSearch" placeholder="Busca personas por nombre o usuario..." autocomplete="off" onkeyup="filterMem()">
 <div id="memList" class="prow-list" style="max-height:250px;overflow:auto;border:1px solid var(--line);border-radius:12px;margin-top:6px">
  {% for c in candidates %}<div class="between mem-row" data-s="{{ (c['name'] ~ ' @' ~ c['username'])|lower }}" style="padding:8px 12px;border-bottom:1px solid var(--line)">
   <div class="row-flex">{{ avatar(c, 32) }}
    <div><b>{{ c['name'] }}</b> <span class="muted">@{{ c['username'] }}</span></div></div>
   <form method="post" action="{{ url_for('group_add_member', gid=g['id']) }}" style="margin:0"><input type="hidden" name="username" value="{{ c['username'] }}"><button class="btn sec sm">Añadir</button></form>
  </div>{% else %}<div class="muted" style="padding:12px">No hay más personas para añadir.</div>{% endfor %}
 </div>
 <script>
 function filterMem(){var q=(document.getElementById('memSearch').value||'').toLowerCase().trim();
  document.querySelectorAll('#memList .mem-row').forEach(function(r){
   r.style.display=(!q||r.getAttribute('data-s').indexOf(q)>=0)?'':'none';});}
 </script>{% endif %}
</div>

{% if is_owner %}<div class="card"><h2>Eliminar grupo</h2>
 <p class="muted">Se elimina el grupo y sus páginas grupales. Esta acción no se puede deshacer.</p>
 <form method="post" action="{{ url_for('group_del', gid=g['id']) }}" onsubmit="return confirm('¿Eliminar el grupo y sus páginas grupales?')">
  <button class="btn danger sm">Eliminar grupo</button></form></div>{% endif %}
"""


def _group_or_403(gid, must_own=False):
    db, u = get_db(), current_user()
    g = db.execute("SELECT * FROM groups WHERE id=?", (gid,)).fetchone()
    if not g:
        abort(404)
    if must_own:
        if g["owner_id"] != u["id"] and u["role"] != "admin":
            abort(403)
    elif not is_group_member(gid, u["id"]):
        abort(403)
    return g


@app.route("/groups/new", methods=["POST"])
@login_required
def group_new():
    if not feature_on("stu_groups"):
        abort(403)
    db, u = get_db(), current_user()
    name = request.form.get("name", "").strip()
    if not name:
        return redirect(url_for("feed"))
    gid = db.execute("INSERT INTO groups(name,owner_id,created_at) VALUES(?,?,?)",
                     (name, u["id"], now())).lastrowid
    db.execute("INSERT INTO group_members(group_id,user_id) VALUES(?,?)", (gid, u["id"]))
    db.commit()
    flash("Grupo creado. Añade miembros y páginas.")
    return redirect(url_for("group_view", gid=gid))


@app.route("/groups/<int:gid>")
@login_required
def group_view(gid):
    db, u = get_db(), current_user()
    g = db.execute("SELECT * FROM groups WHERE id=?", (gid,)).fetchone()
    if not g:
        abort(404)
    db.execute("""INSERT INTO group_visits(group_id,user_id,visits,last_at) VALUES(?,?,1,?)
                  ON CONFLICT(group_id,user_id) DO UPDATE SET visits=visits+1, last_at=excluded.last_at""",
               (gid, u["id"], now()))
    db.commit()
    is_member = is_group_member(gid, u["id"])
    is_owner = (g["owner_id"] == u["id"])
    members = db.execute("""SELECT us.* FROM group_members gm JOIN users us ON us.id=gm.user_id
                            WHERE gm.group_id=? ORDER BY us.name""", (gid,)).fetchall()
    pages, candidates, requests, sessions = [], [], [], []
    requested = False
    if is_member:
        pages = db.execute("""SELECT p.*, us.name owner_name FROM pages p JOIN users us ON us.id=p.owner_id
                              WHERE p.group_id=? ORDER BY p.id DESC""", (gid,)).fetchall()
        sessions = db.execute("""SELECT s.*,
                                   (SELECT COUNT(*) FROM ls_evidences e WHERE e.session_id=s.id) nevid
                                 FROM ls_sessions s WHERE s.group_id=? ORDER BY s.id DESC""", (gid,)).fetchall()
    else:
        requested = bool(db.execute("SELECT 1 FROM group_requests WHERE group_id=? AND user_id=?",
                                    (gid, u["id"])).fetchone())
    if is_owner:
        candidates = db.execute("""SELECT id, username, name, avatar FROM users
            WHERE id NOT IN (SELECT user_id FROM group_members WHERE group_id=?)
            ORDER BY name""", (gid,)).fetchall()
        requests = db.execute("""SELECT us.*, r.created_at FROM group_requests r
            JOIN users us ON us.id=r.user_id WHERE r.group_id=? ORDER BY r.created_at""", (gid,)).fetchall()
    owner = db.execute("SELECT name, username FROM users WHERE id=?", (g["owner_id"],)).fetchone()
    return render(GROUP_VIEW_TPL, title=g["name"], g=g, members=members, pages=pages,
                  candidates=candidates, requests=requests, vis=VIS, owner=owner, sessions=sessions,
                  is_owner=is_owner, is_member=is_member, requested=requested)


@app.route("/groups/<int:gid>/members/add", methods=["POST"])
@login_required
def group_add_member(gid):
    db = get_db()
    g = _group_or_403(gid, must_own=True)
    uname = request.form.get("username", "").strip().lstrip("@")
    target = db.execute("SELECT * FROM users WHERE username=?", (uname,)).fetchone()
    if not target:
        flash("No existe ese usuario.", "error")
    else:
        try:
            db.execute("INSERT INTO group_members(group_id,user_id) VALUES(?,?)", (gid, target["id"]))
            db.execute("DELETE FROM group_requests WHERE group_id=? AND user_id=?", (gid, target["id"]))
            db.commit()
            notify(target["id"], "group_accepted",
                   "Te han añadido al grupo %s." % g["name"],
                   url_for("group_view", gid=gid), {"group": g["name"]}, in_app=True)
            flash("%s añadido al grupo (se le ha enviado un aviso)." % target["name"])
        except sqlite3.IntegrityError:
            flash("Ese usuario ya está en el grupo.", "error")
    return redirect(url_for("group_view", gid=gid))


@app.route("/groups/<int:gid>/members/remove", methods=["POST"])
@login_required
def group_remove_member(gid):
    db = get_db()
    g = _group_or_403(gid, must_own=True)
    uid = request.form.get("user_id")
    if str(uid) == str(g["owner_id"]):
        flash("No puedes quitar al propietario.", "error")
    else:
        db.execute("DELETE FROM group_members WHERE group_id=? AND user_id=?", (gid, uid))
        db.commit()
        flash("Miembro quitado del grupo.")
    return redirect(url_for("group_view", gid=gid))


@app.route("/groups/<int:gid>/pages/new", methods=["POST"])
@login_required
def group_page_new(gid):
    if not feature_on("stu_groups"):
        abort(403)
    db, u = get_db(), current_user()
    g = _group_or_403(gid)
    if (g["pages_create"] == "owner") and (u["id"] != g["owner_id"]):
        flash("En este grupo solo su administrador puede crear páginas.", "error")
        return redirect(url_for("group_view", gid=gid))
    dv = g["default_vis"] if (g["default_vis"] in ("private", "teachers", "public")) else "private"
    title = request.form["title"].strip()
    pid = db.execute("INSERT INTO pages(owner_id,title,description,visibility,created_at,group_id) VALUES(?,?,?,?,?,?)",
                     (u["id"], title, "", dv, now(), gid)).lastrowid
    db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)", (pid, 0, "1"))
    db.commit()
    return redirect(url_for("page_edit", pid=pid))


@app.route("/groups/<int:gid>/delete", methods=["POST"])
@login_required
def group_del(gid):
    db = get_db()
    g = _group_or_403(gid, must_own=True)
    db.execute("DELETE FROM groups WHERE id=?", (gid,))
    db.commit()
    flash("Grupo eliminado.")
    return redirect(url_for("feed"))


GROUP_SETTINGS_TPL = """
<div class="between"><h1>Ajustes del grupo</h1><a class="btn sec" href="{{ url_for('group_view', gid=g['id']) }}">Volver al grupo</a></div>
<form method="post" action="{{ url_for('group_settings', gid=g['id']) }}">
 <div class="card"><h2>Nombre del grupo</h2>
  <input name="name" value="{{ g['name'] }}" required maxlength="80" style="max-width:420px">
 </div>
 <div class="card"><h2>Páginas grupales</h2>
  <label>¿Quién puede crear páginas del grupo?</label>
  <select name="pages_create">
   <option value="all" {{ 'selected' if g['pages_create']!='owner' }}>Todos los miembros</option>
   <option value="owner" {{ 'selected' if g['pages_create']=='owner' }}>Solo el administrador del grupo</option></select>
  <label>Visibilidad por defecto de las páginas nuevas</label>
  <select name="default_vis">
   <option value="private" {{ 'selected' if g['default_vis']=='private' or not g['default_vis'] }}>Privada</option>
   <option value="teachers" {{ 'selected' if g['default_vis']=='teachers' }}>Docentes</option>
   <option value="public" {{ 'selected' if g['default_vis']=='public' }}>Pública</option></select>
 </div>
 <button class="btn">Guardar ajustes</button>
</form>
"""


@app.route("/groups/<int:gid>/settings", methods=["GET", "POST"])
@login_required
def group_settings(gid):
    db = get_db()
    g = _group_or_403(gid, must_own=True)
    if request.method == "POST":
        pc = "owner" if request.form.get("pages_create") == "owner" else "all"
        dv = request.form.get("default_vis", "private")
        if dv not in VIS:
            dv = "private"
        # La cuota de evidencias del grupo se gestiona en Administración → Cuotas de grupos.
        name = (request.form.get("name", "") or "").strip()[:80]
        if name:
            db.execute("UPDATE groups SET name=?, pages_create=?, default_vis=? WHERE id=?", (name, pc, dv, gid))
        else:
            db.execute("UPDATE groups SET pages_create=?, default_vis=? WHERE id=?", (pc, dv, gid))
        db.commit()
        flash("Ajustes del grupo guardados.")
        return redirect(url_for("group_settings", gid=gid))
    return render(GROUP_SETTINGS_TPL, title="Ajustes del grupo", g=g)


@app.route("/groups/<int:gid>/request", methods=["POST"])
@login_required
def group_request_join(gid):
    if not feature_on("stu_groups"):
        abort(403)
    db, u = get_db(), current_user()
    g = db.execute("SELECT * FROM groups WHERE id=?", (gid,)).fetchone()
    if not g:
        abort(404)
    if is_group_member(gid, u["id"]):
        flash("Ya eres miembro de este grupo.")
        return redirect(url_for("group_view", gid=gid))
    try:
        db.execute("INSERT INTO group_requests(group_id,user_id,created_at) VALUES(?,?,?)",
                   (gid, u["id"], now()))
        db.commit()
        notify(g["owner_id"], "group_request",
               "%s ha solicitado unirse a tu grupo %s." % (u["name"], g["name"]),
               url_for("group_view", gid=gid),
               {"actor": u["name"], "group": g["name"]}, in_app=True)
        flash("Solicitud enviada. El creador del grupo debe aceptarla.")
    except sqlite3.IntegrityError:
        flash("Ya has solicitado unirte a este grupo.")
    return redirect(url_for("feed"))


@app.route("/groups/<int:gid>/request/accept", methods=["POST"])
@login_required
def group_request_accept(gid):
    db = get_db()
    g = _group_or_403(gid, must_own=True)
    uid = request.form.get("user_id")
    req = db.execute("SELECT 1 FROM group_requests WHERE group_id=? AND user_id=?", (gid, uid)).fetchone()
    if req:
        try:
            db.execute("INSERT INTO group_members(group_id,user_id) VALUES(?,?)", (gid, uid))
        except sqlite3.IntegrityError:
            pass
        db.execute("DELETE FROM group_requests WHERE group_id=? AND user_id=?", (gid, uid))
        db.commit()
        notify(int(uid), "group_accepted",
               "Ya formas parte del grupo %s." % g["name"],
               url_for("group_view", gid=gid), {"group": g["name"]}, in_app=True)
        flash("Solicitud aceptada.")
    return redirect(url_for("group_view", gid=gid))


@app.route("/groups/<int:gid>/request/reject", methods=["POST"])
@login_required
def group_request_reject(gid):
    db = get_db()
    g = _group_or_403(gid, must_own=True)
    db.execute("DELETE FROM group_requests WHERE group_id=? AND user_id=?",
               (gid, request.form.get("user_id")))
    db.commit()
    flash("Solicitud rechazada.")
    return redirect(url_for("group_view", gid=gid))


# --------------------------------------------------------------------------- #
#  Lesson Study
# --------------------------------------------------------------------------- #
LS_TABS = [("objetivos", "1. Objetivos"), ("contenidos", "2. Contenidos"),
           ("items", "3. Ítems de observación"),
           ("leccion", "4. Lección de investigación"), ("evidencias", "5. Evidencias"),
           ("reflexion", "6. Reflexión"), ("discusiones", "7. Discusiones")]
LS_THEMES = ["Rol docente", "Rol de las familias", "Materiales usados",
             "Gestión del aula", "Participación de los niños", "Diseño de la lección"]
LS_KIND_LABELS = {"photo": "Foto", "video": "Vídeo", "audio": "Audio",
                  "file": "Documento", "note": "Nota", "link": "Enlace"}


def evi_thumb(e, size=80):
    """Miniatura de una evidencia (imagen/vídeo en línea, ampliable al pinchar; icono para el resto)."""
    from markupsafe import Markup
    try:
        fn = e["filename"]
    except Exception:
        fn = None
    kind = ""
    note = ""
    tm = ""
    try:
        kind = e["kind"] or ""
        note = e["note"] or ""
        cap = e["captured_at"] or ""
        tm = cap[11:16] if len(cap) >= 16 else ""
    except Exception:
        pass
    title = escape(((tm + " ") if tm else "") + LS_KIND_LABELS.get(kind, kind) + ((" — " + note) if note else ""))
    ext = fn.rsplit(".", 1)[-1].lower() if (fn and "." in fn) else ""
    box = ("width:%dpx;height:%dpx;object-fit:cover;border-radius:8px;border:1px solid var(--line);"
           "cursor:pointer;background:#f0eaef" % (size, size))
    if fn and ext in IMAGE_EXT:
        src = "/uploads/" + fn
        return Markup('<img class="evi-thumb" src="%s" data-full="%s" data-type="image" title="%s" style="%s">'
                      % (src, src, title, box))
    if fn and ext in VIDEO_EXT:
        src = "/uploads/" + fn
        return Markup('<video class="evi-thumb" src="%s" data-full="%s" data-type="video" title="%s" muted style="%s"></video>'
                      % (src, src, title, box))
    icon = {"audio": "&#127908;", "note": "&#128221;", "link": "&#128279;",
            "file": "&#128196;", "video": "&#127916;", "photo": "&#128444;"}.get(kind, "&#128196;")
    ibox = ("width:%dpx;height:%dpx;display:flex;align-items:center;justify-content:center;font-size:26px;"
            "border-radius:8px;border:1px solid var(--line);background:#f7f4fa;text-decoration:none" % (size, size))
    if fn:
        return Markup('<a class="evi-thumb" href="/uploads/%s" target="_blank" title="%s" style="%s">%s</a>'
                      % (fn, title, ibox, icon))
    return Markup('<div title="%s" style="%s">%s</div>' % (title, ibox, icon))


app.jinja_env.globals["evi_thumb"] = evi_thumb


def _ls_load_discussions(db, sid):
    """Carga las discusiones de una sesión con sus intervenciones y la evidencia asociada (si la hay)."""
    out = []
    for d in db.execute("""SELECT d.*, u.name creator FROM ls_discussions d JOIN users u ON u.id=d.created_by
                           WHERE d.session_id=? ORDER BY d.id DESC""", (sid,)).fetchall():
        posts = db.execute("""SELECT p.*, u.name author_name FROM ls_discussion_posts p
                              JOIN users u ON u.id=p.author_id WHERE p.discussion_id=? ORDER BY p.id""",
                           (d["id"],)).fetchall()
        clabel = ({"evidence": "sobre una evidencia", "reflection": "desde la reflexión"}
                  .get(d["context_type"], "tema general"))
        evid = None
        if d["context_type"] == "evidence" and d["context_id"]:
            evid = db.execute("SELECT * FROM ls_evidences WHERE id=?", (d["context_id"],)).fetchone()
        out.append({"id": d["id"], "title": d["title"], "creator": d["creator"],
                    "created_at": d["created_at"], "created_by": d["created_by"],
                    "context_label": clabel, "posts": posts, "closed": d["closed"],
                    "conclusion": d["conclusion"], "evidence": evid})
    return out


def _ls_evi_context(db, e):
    """Devuelve la evidencia como dict con sus anotaciones y discusiones (para la reflexión)."""
    d = dict(e)
    d["comments"] = db.execute("""SELECT c.*, u.name author_name FROM ls_evidence_comments c
        JOIN users u ON u.id=c.author_id WHERE c.evidence_id=?
        ORDER BY (t_seconds IS NULL), t_seconds, c.id""", (e["id"],)).fetchall()
    discs = []
    for dd in db.execute("""SELECT d.*, u.name creator FROM ls_discussions d JOIN users u ON u.id=d.created_by
                            WHERE d.context_type='evidence' AND d.context_id=? ORDER BY d.id DESC""",
                         (e["id"],)).fetchall():
        posts = db.execute("""SELECT p.*, u.name author_name FROM ls_discussion_posts p
                              JOIN users u ON u.id=p.author_id WHERE p.discussion_id=? ORDER BY p.id""",
                           (dd["id"],)).fetchall()
        discs.append({"title": dd["title"], "creator": dd["creator"], "closed": dd["closed"],
                      "conclusion": dd["conclusion"], "posts": posts})
    d["discussions"] = discs
    return d


def _now_full():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _norm_dt(s):
    s = (s or "").strip().replace("T", " ")
    return s or None


def _extract_captured_at(path, ext):
    """Devuelve (fecha_hora, ok). ok=False si es una estimacion (no metadatos reales)."""
    if ext in IMAGE_EXT:
        try:
            from PIL import Image
            img = Image.open(path)
            dt = None
            # EXIF moderno: DateTimeOriginal/Digitized viven en el sub-IFD 0x8769
            try:
                exif = img.getexif()
                if exif:
                    try:
                        sub = exif.get_ifd(0x8769)
                    except Exception:
                        sub = {}
                    dt = sub.get(36867) or sub.get(36868) or exif.get(306)
            except Exception:
                dt = None
            # Respaldo con la API antigua
            if not dt:
                try:
                    old = img._getexif() or {}
                    dt = old.get(36867) or old.get(36868) or old.get(306)
                except Exception:
                    dt = None
            if dt:
                dt = str(dt).strip()
                if len(dt) >= 10 and dt[4] == ":" and dt[7] == ":":  # 'YYYY:MM:DD ...'
                    dt = dt[:4] + "-" + dt[5:7] + "-" + dt[8:]
                return dt, True
        except Exception:
            pass
    try:
        ts = os.path.getmtime(path)
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S"), False
    except Exception:
        return _now_full(), False


def _ls_session(sid):
    db, u = get_db(), current_user()
    s = db.execute("SELECT * FROM ls_sessions WHERE id=?", (sid,)).fetchone()
    if not s:
        abort(404)
    if not is_group_member(s["group_id"], u["id"]):
        abort(403)
    return s


def _group_evidence_bytes(gid):
    """Suma el tamano de los archivos de evidencia de todas las sesiones del grupo."""
    total = 0
    for e in get_db().execute("""SELECT e.filename FROM ls_evidences e JOIN ls_sessions s ON s.id=e.session_id
                                 WHERE s.group_id=? AND e.filename IS NOT NULL AND e.filename<>''""", (gid,)):
        try:
            total += os.path.getsize(os.path.join(UPLOAD_DIR, e["filename"]))
        except Exception:
            pass
    return total


def _group_quota(gid):
    """Cuota de evidencias del grupo: la del grupo si esta definida, o el valor por defecto (5 GB)."""
    try:
        row = get_db().execute("SELECT evidence_quota_mb FROM groups WHERE id=?", (gid,)).fetchone()
        if row and row["evidence_quota_mb"]:
            return int(row["evidence_quota_mb"]) * 1024 * 1024
    except Exception:
        pass
    return LS_GROUP_QUOTA


def _ls_evidence(sid, eid):
    e = get_db().execute("SELECT * FROM ls_evidences WHERE id=? AND session_id=?", (eid, sid)).fetchone()
    if not e:
        abort(404)
    return e


LS_VIEW_TPL = """
<div class="between"><h1>{{ s['title'] }}</h1>
 <div class="row-flex" style="gap:8px"><a class="btn sec" href="{{ url_for('ls_print', sid=s['id']) }}" target="_blank">Descargar / Imprimir PDF</a><a class="btn sec" href="{{ url_for('group_view', gid=s['group_id']) }}">Volver al grupo</a></div></div>
<p class="muted">Sesión de Lesson Study{% if s['lesson_date'] %} &middot; lección: {{ s['lesson_date'] }}{% endif %} &middot; {{ 'lección realizada' if s['lesson_done'] else 'en preparación' }}</p>
<div class="row-flex" style="margin-bottom:14px;flex-wrap:wrap">
 {% for key,label in tabs %}<a class="btn {{ '' if tab==key else 'sec' }} sm" href="{{ url_for('ls_view', sid=s['id']) }}?tab={{ key }}">{{ label }}</a>{% endfor %}
</div>

{% if tab=='objetivos' %}
<div class="card"><h2>Objetivos de aprendizaje</h2>
 <p class="muted" style="margin-top:0">Lo que queremos que el alumnado desarrolle con la lección diseñada.</p>
 <div style="background:#f6f2f5;border-left:3px solid var(--brand);border-radius:8px;padding:10px 12px;margin:0 0 12px;font-size:13px">
  <b style="color:var(--brand)">Para pensar los objetivos:</b> ¿Para qué diseñamos la propuesta? ¿Qué queremos conseguir? ¿Qué competencias nos gustaría que desarrollasen los alumnos y las alumnas con la propuesta que diseñemos? ¿En qué consisten esas competencias?
 </div>
 {% for o in objectives %}<div class="between" style="padding:6px 0;border-bottom:1px solid var(--line)">
   <div>{{ loop.index }}. {{ o['text'] }} <span class="pill">{{ o['nevid'] }} evidencia(s)</span></div>
   <form method="post" action="{{ url_for('ls_objective_del', sid=s['id']) }}" style="margin:0"><input type="hidden" name="oid" value="{{ o['id'] }}"><button class="btn sec sm">Quitar</button></form>
  </div>{% else %}<p class="muted">Aún no hay objetivos.</p>{% endfor %}
 <form method="post" action="{{ url_for('ls_objective_add', sid=s['id']) }}" class="row-flex" style="margin-top:10px">
  <input name="text" placeholder="Nuevo objetivo de aprendizaje..." required style="flex:1;margin:0"><button class="btn sec sm">Añadir</button></form>
</div>
{% elif tab=='contenidos' %}
<div class="card"><h2>Contenidos</h2>
 <p class="muted" style="margin-top:0">Contenidos curriculares que se desarrollan con la propuesta.</p>
 <div style="background:#f6f2f5;border-left:3px solid var(--brand);border-radius:8px;padding:10px 12px;margin:0 0 12px;font-size:13px">
  <b style="color:var(--brand)">Para pensar los contenidos:</b> ¿Qué contenidos presentes en el currículum oficial o plan de estudios pensáis que los aprendices desarrollarán con vuestra propuesta? ¿Existen en vuestra propuesta contenidos que, entendéis, trascenderán el currículum?
 </div>
 {% for c in contents %}<div class="between" style="padding:6px 0;border-bottom:1px solid var(--line)">
   <div>{{ loop.index }}. {{ c['text'] }}</div>
   <form method="post" action="{{ url_for('ls_content_del', sid=s['id']) }}" style="margin:0"><input type="hidden" name="cid" value="{{ c['id'] }}"><button class="btn sec sm">Quitar</button></form>
  </div>{% else %}<p class="muted">Aún no hay contenidos.</p>{% endfor %}
 <form method="post" action="{{ url_for('ls_content_add', sid=s['id']) }}" class="row-flex" style="margin-top:10px">
  <input name="text" placeholder="Nuevo contenido..." required style="flex:1;margin:0"><button class="btn sec sm">Añadir</button></form>
</div>
{% elif tab=='items' %}
<div class="card"><h2>Ítems de observación</h2>
 <p class="muted" style="margin-top:0">Tabla de observación: indicadores en los que fijaremos la mirada durante la lección.</p>
 <div style="background:#f6f2f5;border-left:3px solid var(--brand);border-radius:8px;padding:10px 12px;margin:0 0 12px;font-size:13px">
  <b style="color:var(--brand)">Para pensar los ítems:</b> ¿En qué me debería fijar para saber si el alumnado está alcanzando los propósitos que me he planteado? ¿Cómo sabré que el alumnado ha superado sus dificultades? ¿Cómo detectaré que los aprendizajes se están desarrollando? ¿Qué información voy a recoger para evidenciarlo?
 </div>
 {% for it in items %}<div class="between" style="padding:6px 0;border-bottom:1px solid var(--line)">
   <div>{{ loop.index }}. {{ it['text'] }} <span class="pill">{{ it['nevid'] }} evidencia(s)</span></div>
   <form method="post" action="{{ url_for('ls_item_del', sid=s['id']) }}" style="margin:0"><input type="hidden" name="iid" value="{{ it['id'] }}"><button class="btn sec sm">Quitar</button></form>
  </div>{% else %}<p class="muted">Aún no hay ítems de observación.</p>{% endfor %}
 <form method="post" action="{{ url_for('ls_item_add', sid=s['id']) }}" class="row-flex" style="margin-top:10px">
  <input name="text" placeholder="Nuevo ítem de observación..." required style="flex:1;margin:0"><button class="btn sec sm">Añadir</button></form>
</div>
{% elif tab=='leccion' %}
<div class="card"><h2>Lección de investigación</h2>
 <p class="muted" style="margin-top:0">Día en que las futuras docentes imparten la lección diseñada con niños reales. Las evidencias se ponen en común <b>después</b> de la lección.</p>
 <form method="post" action="{{ url_for('ls_leccion_save', sid=s['id']) }}">
  <label>Fecha de la lección</label>
  <input type="date" name="lesson_date" value="{{ s['lesson_date'] or '' }}">
  <label style="font-weight:400;display:block;margin:10px 0"><input type="checkbox" name="lesson_done" style="width:auto" {{ 'checked' if s['lesson_done'] }}> La lección ya se ha realizado (habilita subir y compartir evidencias)</label>
  <button class="btn">Guardar</button></form>
</div>
{% elif tab=='evidencias' %}
<div class="card"><h2>Evidencias</h2>
 {% if not s['lesson_done'] %}
  <p class="muted">Las evidencias se ponen en común tras impartir la lección. Marca la lección como <b>realizada</b> en la pestaña «Lección de investigación» para empezar a subirlas.</p>
 {% else %}
  <p class="muted" style="margin-top:0">Sube fotos, vídeos, notas de voz, documentos, notas escritas o enlaces. Se ordenan por su <b>hora real</b>. Puedes ir subiéndolas poco a poco.</p>
  <div class="flash" style="margin-top:0">📷 Recomendación: añade las fotos y vídeos <b>desde la galería o los archivos originales del dispositivo</b>. Evita descargarlos de WhatsApp u otras apps de mensajería, porque suelen eliminar la fecha de los metadatos y no se podrá ordenar automáticamente por hora.<br>🎬 Si un vídeo es <b>muy largo</b>, recórtalo y sube solo la escena que te interesa: es más ligero, más rápido y más fácil de comentar.</div>

  <details class="add" style="margin:8px 0"><summary>⬆ Subida masiva (varios archivos a la vez)</summary>
   <form method="post" action="{{ url_for('ls_evidence_bulk', sid=s['id']) }}" enctype="multipart/form-data" style="margin-top:8px">
    <label>Selecciona varias fotos, vídeos, audios o documentos</label>
    <input type="file" name="files" multiple>
    <div class="muted" style="font-size:12px;margin:4px 0">Se detecta el tipo automáticamente (foto, vídeo, audio o documento) y se ordenan por la fecha de sus metadatos. Los que no la tengan quedarán marcados para que indiques la hora. Hasta <b>100 archivos por tanda</b>; el grupo dispone de <b>5 GB</b> de evidencias en total.</div>
    <button class="btn">Subir todo</button></form>
  </details>

  <details class="add" style="margin-bottom:6px"><summary>➕ Añadir una evidencia (con más detalle)</summary>
  <form method="post" action="{{ url_for('ls_evidence_add', sid=s['id']) }}" enctype="multipart/form-data" style="margin-top:8px">
   <div class="row-flex">
    <div style="flex:1"><label>Tipo de evidencia</label>
     <select name="kind" id="evKind" onchange="evTog()">
      <option value="photo">Foto</option><option value="video">Vídeo</option>
      <option value="audio">Nota de voz / audio</option><option value="file">Documento</option>
      <option value="note">Nota escrita</option><option value="link">Enlace</option></select></div>
    <div style="flex:1"><label>Hora (opcional)</label>
     <input type="datetime-local" name="captured_at">
     <div class="muted" style="font-size:12px">Si la dejas vacía: se toma de los metadatos del archivo, o del momento actual.</div></div>
   </div>
   <div id="evFile"><label>Archivo</label><input type="file" name="file"></div>
   <div id="evUrl" style="display:none"><label>Enlace</label><input name="url" placeholder="https://..."></div>
   <label>Descripción / nota</label><textarea name="note" placeholder="Qué muestra esta evidencia..."></textarea>
   <div id="evAllDay" style="display:none"><label style="font-weight:400"><input type="checkbox" name="all_day" style="width:auto"> Es una nota de <b>todo el día</b> (sin hora concreta; se mostrará aparte)</label></div>
   <button class="btn">Añadir evidencia</button></form>
  </details>
  <script>
  function evTog(){var k=document.getElementById('evKind').value;
   document.getElementById('evFile').style.display=(k=='note'||k=='link')?'none':'block';
   document.getElementById('evUrl').style.display=(k=='link')?'block':'none';
   document.getElementById('evAllDay').style.display=(k=='note')?'block':'none';}
  </script>
 {% endif %}
</div>

{% if day_notes %}<div class="card">
 <div style="font-weight:700;color:var(--brand2);font-size:13px;letter-spacing:.03em">📌 Notas del día (sin hora concreta)</div>
 {% for ev in day_notes %}<div style="{% if not loop.first %}border-top:1px solid var(--line);margin-top:12px;padding-top:12px{% else %}margin-top:10px{% endif %}">
  <div class="between">
   <div><span class="pill">{{ kind_labels[ev.e['kind']] }}</span> <span class="muted">{{ ev.e['author_name'] }}</span></div>
   <form method="post" action="{{ url_for('ls_evidence_del', sid=s['id']) }}" onsubmit="return confirm('¿Eliminar esta nota?')" style="margin:0"><input type="hidden" name="eid" value="{{ ev.e['id'] }}"><button class="btn sec sm">Eliminar</button></form>
  </div>
  {% if ev.e['note'] %}<p style="margin:6px 0 0">{{ ev.e['note'] }}</p>{% endif %}
  {% if ev.obj_ids or ev.item_ids %}<div style="margin-top:4px">
   {% for o in objectives if o['id'] in ev.obj_ids %}<span class="pill">🎯 {{ o['text'][:40] }}</span> {% endfor %}
   {% for it in items if it['id'] in ev.item_ids %}<span class="pill">👁 {{ it['text'][:40] }}</span> {% endfor %}</div>{% endif %}
  <details class="add" style="margin-top:6px"><summary>Relacionar con objetivos e ítems ({{ ev.obj_ids|length + ev.item_ids|length }})</summary>
   <form method="post" action="{{ url_for('ls_evidence_links', sid=s['id']) }}" style="margin-top:8px">
    <input type="hidden" name="eid" value="{{ ev.e['id'] }}">
    {% for o in objectives %}<label style="font-weight:400;display:block"><input type="checkbox" name="obj" value="{{ o['id'] }}" style="width:auto" {{ 'checked' if o['id'] in ev.obj_ids }}> {{ o['text'] }}</label>{% endfor %}
    {% for it in items %}<label style="font-weight:400;display:block"><input type="checkbox" name="item" value="{{ it['id'] }}" style="width:auto" {{ 'checked' if it['id'] in ev.item_ids }}> {{ it['text'] }}</label>{% endfor %}
    <button class="btn sec sm" style="margin-top:6px">Guardar relaciones</button></form>
  </details>
  <details class="add" style="margin-top:6px"><summary>Comentarios ({{ ev.comments|length }})</summary>
   <div style="margin-top:6px">
   {% for c in ev.comments %}<div class="comment"><b>{{ c['author_name'] }}</b> <span class="muted" style="font-size:12px">{{ c['created_at'] }}</span><div>{{ c['body'] }}</div></div>{% else %}<p class="muted">Sin comentarios.</p>{% endfor %}
   </div>
   <form method="post" action="{{ url_for('ls_comment_add', sid=s['id']) }}" style="margin-top:6px">
    <input type="hidden" name="eid" value="{{ ev.e['id'] }}">
    <textarea name="body" placeholder="Comentario o reflexion..." required></textarea>
    <button class="btn sec sm">Comentar</button></form>
  </details>
  <details class="add" style="margin-top:6px"><summary>Iniciar una discusión sobre esta nota</summary>
   <form method="post" action="{{ url_for('ls_discussion_new', sid=s['id']) }}" class="row-flex" style="margin-top:6px">
    <input type="hidden" name="context_type" value="evidence"><input type="hidden" name="context_id" value="{{ ev.e['id'] }}">
    <input name="title" placeholder="Tema emergente" required style="flex:1;margin:0">
    <button class="btn sec sm">Abrir discusión</button></form>
  </details>
 </div>{% endfor %}
</div>{% endif %}

{% for band in bands %}
<div class="card">
 <div style="font-weight:700;color:var(--brand2);font-size:13px;letter-spacing:.03em">&#128337; {{ band.label }}{% if band.evidences|length > 1 %} &middot; {{ band.evidences|length }} evidencias en esta franja{% endif %}</div>
 {% for ev in band.evidences %}
 <div style="{% if not loop.first %}border-top:1px solid var(--line);margin-top:14px;padding-top:14px{% else %}margin-top:12px{% endif %}">
 <div class="between">
  <div><b style="font-size:16px">{{ ev.e['captured_at'][11:16] if ev.e['captured_at'] else '--:--' }}</b>
   <span class="pill">{{ kind_labels[ev.e['kind']] }}</span>
   <span class="muted">{{ ev.e['captured_at'][:10] if ev.e['captured_at'] else '' }} &middot; {{ ev.e['author_name'] }}</span></div>
  <form method="post" action="{{ url_for('ls_evidence_del', sid=s['id']) }}" onsubmit="return confirm('¿Eliminar esta evidencia?')" style="margin:0"><input type="hidden" name="eid" value="{{ ev.e['id'] }}"><button class="btn sec sm">Eliminar</button></form>
 </div>
 {% if ev.mismatch %}<div class="flash err" style="margin-top:8px">La fecha de esta evidencia ({{ ev.e['captured_at'][:10] }}) no coincide con la fecha de la lección ({{ s['lesson_date'] }}). Corrige la hora abajo.</div>{% endif %}
 {% if not ev.e['meta_ok'] %}<div class="flash" style="margin-top:8px">{% if not pil_ok %}La app no puede leer metadatos porque falta la librería <b>Pillow</b> en el Python con el que ejecutas la app (instálala y reinicia). {% else %}Esta imagen no incluye la fecha en sus metadatos (habitual en capturas de pantalla o imágenes editadas/descargadas). {% endif %}La hora es estimada; indica la hora aproximada:
  <form method="post" action="{{ url_for('ls_evidence_time', sid=s['id']) }}" class="row-flex" style="margin-top:6px">
   <input type="hidden" name="eid" value="{{ ev.e['id'] }}">
   <input type="datetime-local" name="captured_at" value="{{ (ev.e['captured_at'][:16]|replace(' ','T')) if ev.e['captured_at'] else '' }}" style="margin:0">
   <button class="btn sec sm">Guardar hora</button></form>
 </div>
 {% else %}<details class="add" style="margin-top:6px"><summary>Corregir hora</summary>
  <form method="post" action="{{ url_for('ls_evidence_time', sid=s['id']) }}" class="row-flex" style="margin-top:6px">
   <input type="hidden" name="eid" value="{{ ev.e['id'] }}">
   <input type="datetime-local" name="captured_at" value="{{ (ev.e['captured_at'][:16]|replace(' ','T')) if ev.e['captured_at'] else '' }}" style="margin:0">
   <button class="btn sec sm">Guardar hora</button></form>
 </details>{% endif %}
 <div style="margin-top:10px">
  {% if ev.e['kind']=='photo' %}<a href="{{ url_for('uploaded', fn=ev.e['filename']) }}" target="_blank" title="Ampliar"><img src="{{ url_for('uploaded', fn=ev.e['filename']) }}" style="max-height:220px;max-width:100%;border-radius:10px;border:1px solid var(--line);cursor:zoom-in;display:block"></a>
  {% elif ev.e['kind']=='video' %}<video id="vid-{{ ev.e['id'] }}" controls playsinline style="max-height:240px;max-width:100%;border-radius:10px;display:block"><source src="{{ url_for('uploaded', fn=ev.e['filename']) }}"></video>
  {% elif ev.e['kind']=='audio' %}<audio id="vid-{{ ev.e['id'] }}" controls src="{{ url_for('uploaded', fn=ev.e['filename']) }}"></audio>
  {% elif ev.e['kind']=='file' %}<a class="btn sec sm" href="{{ url_for('uploaded', fn=ev.e['filename']) }}" target="_blank">Abrir documento</a>
  {% elif ev.e['kind']=='link' %}<a href="{{ safeurl(ev.e['url']) }}" target="_blank" rel="noopener">{{ ev.e['url'] }}</a>{% endif %}
  {% if ev.e['note'] %}<p style="margin-top:8px">{{ ev.e['note'] }}</p>{% endif %}
 </div>
 <details class="add" style="margin-top:8px"><summary>Relacionar con objetivos e ítems ({{ ev.obj_ids|length + ev.item_ids|length }})</summary>
  <form method="post" action="{{ url_for('ls_evidence_links', sid=s['id']) }}" style="margin-top:8px">
   <input type="hidden" name="eid" value="{{ ev.e['id'] }}">
   {% if objectives %}<div class="muted" style="font-weight:700;color:var(--brand)">Objetivos</div>
   {% for o in objectives %}<label style="font-weight:400;display:block"><input type="checkbox" name="obj" value="{{ o['id'] }}" style="width:auto" {{ 'checked' if o['id'] in ev.obj_ids }}> {{ o['text'] }}</label>{% endfor %}{% endif %}
   {% if items %}<div class="muted" style="font-weight:700;color:var(--brand);margin-top:6px">Ítems de observación</div>
   {% for it in items %}<label style="font-weight:400;display:block"><input type="checkbox" name="item" value="{{ it['id'] }}" style="width:auto" {{ 'checked' if it['id'] in ev.item_ids }}> {{ it['text'] }}</label>{% endfor %}{% endif %}
   {% if not objectives and not items %}<div class="muted">Define antes objetivos e ítems en sus pestañas.</div>{% endif %}
   <button class="btn sec sm" style="margin-top:8px">Guardar relaciones</button></form>
 </details>
 {% if ev.obj_ids or ev.item_ids %}<div style="margin-top:6px">
  {% for o in objectives if o['id'] in ev.obj_ids %}<span class="pill">🎯 {{ o['text'][:44] }}</span> {% endfor %}
  {% for it in items if it['id'] in ev.item_ids %}<span class="pill">👁 {{ it['text'][:44] }}</span> {% endfor %}
 </div>{% endif %}
 <details class="add" style="margin-top:8px"><summary>Comentarios / notas ({{ ev.comments|length }})</summary>
  <div style="margin-top:6px">
  {% for c in ev.comments %}<div class="comment">
   {% if c['t_seconds'] is not none %}<a href="#" onclick="return evSeek('{{ ev.e['id'] }}',{{ c['t_seconds'] }})"><b>{{ '%d:%02d'|format(c['t_seconds']//60, c['t_seconds']%60) }}</b></a> {% endif %}
   <b>{{ c['author_name'] }}</b> <span class="muted" style="font-size:12px">{{ c['created_at'] }}</span>
   <div>{{ c['body'] }}</div></div>{% else %}<p class="muted">Sin comentarios.</p>{% endfor %}
  </div>
  <form method="post" action="{{ url_for('ls_comment_add', sid=s['id']) }}" style="margin-top:6px">
   <input type="hidden" name="eid" value="{{ ev.e['id'] }}"><input type="hidden" name="t_seconds" id="ts-{{ ev.e['id'] }}">
   {% if ev.e['kind'] in ('video','audio') %}<button type="button" class="btn sec sm" onclick="evMark('{{ ev.e['id'] }}')">Marcar el momento actual del {{ 'vídeo' if ev.e['kind']=='video' else 'audio' }}</button> <span class="muted" id="tslbl-{{ ev.e['id'] }}"></span><br>{% endif %}
   <textarea name="body" placeholder="Comentario o nota sobre esta evidencia..." required></textarea>
   <button class="btn sec sm">Añadir comentario</button></form>
 </details>
 <details class="add" style="margin-top:8px"><summary>Iniciar una discusión sobre esta evidencia</summary>
  <form method="post" action="{{ url_for('ls_discussion_new', sid=s['id']) }}" class="row-flex" style="margin-top:6px">
   <input type="hidden" name="context_type" value="evidence"><input type="hidden" name="context_id" value="{{ ev.e['id'] }}">
   <input name="title" placeholder="Tema emergente (p. ej. materiales usados)" required style="flex:1;margin:0">
   <button class="btn sec sm">Abrir discusión</button></form>
 </details>
 </div>
 {% endfor %}
</div>
{% endfor %}
<script>
function evMark(id){var v=document.getElementById('vid-'+id);if(!v){return;}var t=Math.floor(v.currentTime||0);
 document.getElementById('ts-'+id).value=t;
 document.getElementById('tslbl-'+id).textContent='Momento marcado: '+Math.floor(t/60)+':'+('0'+(t%60)).slice(-2);}
function evSeek(id,t){var v=document.getElementById('vid-'+id);if(v){v.currentTime=t;if(v.play){v.play();}}return false;}
</script>
{% elif tab=='reflexion' %}
<div class="card"><h2>Reflexión del equipo</h2>
 <p class="muted" style="margin-top:0">Puesta en común tras la lección. Podéis apoyaros en estas preguntas guía:</p>
 <ul class="muted" style="line-height:1.7;margin-top:0">
  <li>¿Qué preveíamos que ocurriría y qué ocurrió realmente?</li>
  <li>¿Qué evidencias o momentos os sorprendieron?</li>
  <li>¿Qué aprendizajes de los niños pudisteis observar, y cuáles no?</li>
  <li>¿Qué revela esto sobre el diseño de la lección?</li>
  <li>¿Qué rediseñaríais para el próximo ciclo?</li>
  <li>¿Qué os lleváis para vuestra práctica docente?</li>
 </ul>

 <h3 style="margin:12px 0 4px">Aportaciones del equipo</h3>
 <p class="muted" style="font-size:13px;margin-top:0">Que cada una aporte su mirada; luego compondréis la conclusión definitiva.</p>
 {% for r in aportes %}<div class="comment"><b>{{ r['author_name'] }}</b> <span class="muted" style="font-size:12px">{{ r['created_at'] }}</span>
   <div>{{ r['body'] }}</div>
   {% if can_admin or r['author_id']==me_id %}<form method="post" action="{{ url_for('ls_reflection_post_del', sid=s['id']) }}" style="margin-top:4px"><input type="hidden" name="rid" value="{{ r['id'] }}"><button class="btn sec sm">Quitar</button></form>{% endif %}</div>
 {% else %}<p class="muted">Aún no hay aportaciones. Añade la tuya.</p>{% endfor %}
 <form method="post" action="{{ url_for('ls_reflection_post', sid=s['id']) }}" style="margin-top:6px">
  <input type="hidden" name="kind" value="aporte">
  <textarea name="body" placeholder="Tu aportación a la reflexion del equipo..." required></textarea>
  <button class="btn sec sm">Añadir mi aportación</button></form>

 <h3 style="margin:14px 0 4px">Aspectos emergentes (no previstos)</h3>
 <p class="muted" style="font-size:13px;margin-top:0">Cuestiones que surgieron y no estaban en los objetivos ni en los ítems de observación.</p>
 {% for r in emergentes %}<div class="comment" style="border-left-color:#e0a020"><b>{{ r['author_name'] }}</b> <span class="muted" style="font-size:12px">{{ r['created_at'] }}</span>
   <div>{{ r['body'] }}</div>
   {% if can_admin or r['author_id']==me_id %}<form method="post" action="{{ url_for('ls_reflection_post_del', sid=s['id']) }}" style="margin-top:4px"><input type="hidden" name="rid" value="{{ r['id'] }}"><button class="btn sec sm">Quitar</button></form>{% endif %}</div>
 {% else %}<p class="muted">Aún no se ha registrado ningún aspecto emergente.</p>{% endfor %}
 <form method="post" action="{{ url_for('ls_reflection_post', sid=s['id']) }}" class="row-flex" style="margin-top:6px">
  <input type="hidden" name="kind" value="emergente">
  <input name="body" placeholder="Aspecto emergente no previsto..." required style="flex:1;margin:0">
  <button class="btn sec sm">Añadir aspecto</button></form>

 <h3 style="margin:16px 0 4px">Conclusión definitiva del equipo</h3>
 <p class="muted" style="font-size:13px;margin-top:0">Componed aquí, entre todas, la conclusión final a partir de las aportaciones y los aspectos emergentes.</p>
 <form method="post" action="{{ url_for('ls_reflexion_save', sid=s['id']) }}">
  <textarea name="reflexion" style="min-height:150px" placeholder="Conclusión definitiva...">{{ s['reflexion'] or '' }}</textarea>
  <button class="btn">Guardar conclusión</button></form>
 <details class="add" style="margin-top:10px"><summary>Iniciar una discusión sobre un tema emergente</summary>
  <form method="post" action="{{ url_for('ls_discussion_new', sid=s['id']) }}" class="row-flex" style="margin-top:6px">
   <input type="hidden" name="context_type" value="reflection">
   <input name="title" list="themes" placeholder="Tema (rol docente, familias, materiales...)" required style="flex:1;margin:0">
   <datalist id="themes">{% for t in themes %}<option value="{{ t }}">{% endfor %}</datalist>
   <button class="btn sec sm">Abrir discusión</button></form>
 </details>
</div>

<div class="card"><h2>Evidencias por objetivo</h2>
 <p class="muted" style="margin-top:0">Revisad las evidencias que respaldan cada objetivo y dejad vuestra valoración.</p>
 {% for o in objectives %}<div style="padding:10px 0;border-bottom:1px solid var(--line)">
  <b>🎯 {{ o['text'] }}</b> <span class="pill">{{ o['nevid'] }} evidencia(s)</span>
  {% for ev in o['evidences'] %}<div style="display:flex;gap:10px;margin:10px 0 0 6px;align-items:flex-start">
   <div style="flex-shrink:0">{{ evi_thumb(ev, 78) }}</div>
   <div style="flex:1;min-width:0">
    <div class="muted" style="font-size:12px">{{ ev['captured_at'][11:16] if ev['captured_at'] else '' }} · {{ kind_labels[ev['kind']] }}{% if ev['note'] %} — {{ ev['note'] }}{% endif %}</div>
    {% for c in ev['comments'] %}<div class="comment" style="margin:6px 0;padding:6px 10px"><b>{{ c['author_name'] }}</b>{% if c['t_seconds'] is not none %} <span class="muted" style="font-size:11px">[{{ '%d:%02d'|format(c['t_seconds']//60, c['t_seconds']%60) }}]</span>{% endif %} <span class="muted" style="font-size:11px">{{ c['created_at'] }}</span><div>{{ c['body'] }}</div></div>{% endfor %}
    {% for d in ev['discussions'] %}<div style="border-left:3px solid #c0325f;padding:5px 10px;margin:6px 0;background:#faf6f9;border-radius:0 8px 8px 0">
     <b style="font-size:13px">💬 {{ d.title }}</b>{% if d.closed %} <span class="pill" style="background:#2e9e5b;color:#fff">Cerrada</span>{% endif %}
     {% for p in d.posts %}<div style="font-size:13px;margin-top:3px"><b>{{ p['author_name'] }}:</b> {{ p['body'] }}</div>{% endfor %}
     {% if d.closed and d.conclusion %}<div class="muted" style="font-size:12px;margin-top:3px"><b>Conclusión:</b> {{ d.conclusion }}</div>{% endif %}
    </div>{% endfor %}
   </div></div>
  {% else %}<div class="muted" style="font-size:13px;margin:4px 0 0 10px">Sin evidencias vinculadas.</div>{% endfor %}
  <form method="post" action="{{ url_for('ls_assess', sid=s['id']) }}" style="margin-top:8px">
   <input type="hidden" name="target_type" value="objective"><input type="hidden" name="target_id" value="{{ o['id'] }}">
   <textarea name="assessment" placeholder="¿Se logró? ¿Qué evidencian los datos?">{{ o['assessment'] or '' }}</textarea>
   <button class="btn sec sm">Guardar valoración</button></form>
 </div>{% else %}<p class="muted">Sin objetivos.</p>{% endfor %}
</div>

<div class="card"><h2>Evidencias por ítem de observación</h2>
 {% for it in items %}<div style="padding:10px 0;border-bottom:1px solid var(--line)">
  <b>👁 {{ it['text'] }}</b> <span class="pill">{{ it['nevid'] }} evidencia(s)</span>
  {% for ev in it['evidences'] %}<div style="display:flex;gap:10px;margin:10px 0 0 6px;align-items:flex-start">
   <div style="flex-shrink:0">{{ evi_thumb(ev, 78) }}</div>
   <div style="flex:1;min-width:0">
    <div class="muted" style="font-size:12px">{{ ev['captured_at'][11:16] if ev['captured_at'] else '' }} · {{ kind_labels[ev['kind']] }}{% if ev['note'] %} — {{ ev['note'] }}{% endif %}</div>
    {% for c in ev['comments'] %}<div class="comment" style="margin:6px 0;padding:6px 10px"><b>{{ c['author_name'] }}</b>{% if c['t_seconds'] is not none %} <span class="muted" style="font-size:11px">[{{ '%d:%02d'|format(c['t_seconds']//60, c['t_seconds']%60) }}]</span>{% endif %} <span class="muted" style="font-size:11px">{{ c['created_at'] }}</span><div>{{ c['body'] }}</div></div>{% endfor %}
    {% for d in ev['discussions'] %}<div style="border-left:3px solid #c0325f;padding:5px 10px;margin:6px 0;background:#faf6f9;border-radius:0 8px 8px 0">
     <b style="font-size:13px">💬 {{ d.title }}</b>{% if d.closed %} <span class="pill" style="background:#2e9e5b;color:#fff">Cerrada</span>{% endif %}
     {% for p in d.posts %}<div style="font-size:13px;margin-top:3px"><b>{{ p['author_name'] }}:</b> {{ p['body'] }}</div>{% endfor %}
     {% if d.closed and d.conclusion %}<div class="muted" style="font-size:12px;margin-top:3px"><b>Conclusión:</b> {{ d.conclusion }}</div>{% endif %}
    </div>{% endfor %}
   </div></div>
  {% else %}<div class="muted" style="font-size:13px;margin:4px 0 0 10px">Sin evidencias vinculadas.</div>{% endfor %}
  <form method="post" action="{{ url_for('ls_assess', sid=s['id']) }}" style="margin-top:8px">
   <input type="hidden" name="target_type" value="item"><input type="hidden" name="target_id" value="{{ it['id'] }}">
   <textarea name="assessment" placeholder="¿Qué observamos en este ítem?">{{ it['assessment'] or '' }}</textarea>
   <button class="btn sec sm">Guardar valoración</button></form>
 </div>{% else %}<p class="muted">Sin ítems.</p>{% endfor %}
</div>

<div class="card"><h2>Discusiones (referencia)</h2>
 <p class="muted" style="margin-top:0">Solo lectura, para tenerlas presentes al reflexionar. Para participar, ve a la pestaña <a href="{{ url_for('ls_view', sid=s['id'], tab='discusiones') }}">Discusiones</a>.</p>
 {% for d in ref_discussions %}<div style="padding:10px 0;border-bottom:1px solid var(--line)">
  <b>{{ d.title }}</b> <span class="muted" style="font-size:12px">{{ d.context_label }}{% if d.closed %} &middot; <span class="pill" style="background:#2e9e5b;color:#fff">Cerrada</span>{% endif %}</span>
  {% if d.evidence %}<div style="margin:6px 0">{{ evi_thumb(d.evidence, 70) }}</div>{% endif %}
  {% for p in d.posts %}<div class="comment"><b>{{ p['author_name'] }}</b> <span class="muted" style="font-size:12px">{{ p['created_at'] }}</span><div>{{ p['body'] }}</div></div>
  {% else %}<p class="muted" style="margin:4px 0">Sin intervenciones.</p>{% endfor %}
  {% if d.closed and d.conclusion %}<div class="flash" style="border-left:4px solid #2e9e5b"><b>Conclusión:</b> {{ d.conclusion }}</div>{% endif %}
 </div>{% else %}<p class="muted">Todavía no hay discusiones.</p>{% endfor %}
</div>
{% elif tab=='discusiones' %}
<div class="card"><h2>Nueva discusión</h2>
 <p class="muted" style="margin-top:0">Abrid hilos para tratar temas que emergen de la experiencia (rol docente, familias, materiales...). También podéis iniciarlos desde una evidencia o desde la reflexion.</p>
 <form method="post" action="{{ url_for('ls_discussion_new', sid=s['id']) }}" class="row-flex">
  <input name="title" list="themes2" placeholder="Tema de la discusión..." required style="flex:1;margin:0">
  <datalist id="themes2">{% for t in themes %}<option value="{{ t }}">{% endfor %}</datalist>
  <button class="btn">Abrir discusión</button></form>
</div>
{% for d in discussions %}<div class="card">
 <div class="between"><b>{{ d.title }}</b>
  <span class="muted" style="font-size:12px">{{ d.context_label }} &middot; {{ d.creator }} &middot; {{ d.created_at }}{% if d.closed %} &middot; <span class="pill" style="background:#2e9e5b;color:#fff">Cerrada</span>{% endif %}</span></div>
 {% if d.evidence %}<div style="margin-top:8px" title="Evidencia de referencia">{{ evi_thumb(d.evidence, 90) }}</div>{% endif %}
 {% if d.closed and d.conclusion %}<div class="flash" style="margin-top:8px;border-left:4px solid #2e9e5b"><b>Conclusión:</b> {{ d.conclusion }}</div>{% endif %}
 <div style="margin-top:8px">
 {% for p in d.posts %}<div class="comment"><b>{{ p['author_name'] }}</b> <span class="muted" style="font-size:12px">{{ p['created_at'] }}</span><div>{{ p['body'] }}</div></div>
 {% else %}<p class="muted">Aún no hay intervenciones.{% if not d.closed %} Escribe la primera.{% endif %}</p>{% endfor %}
 </div>
 {% if not d.closed %}
 <form method="post" action="{{ url_for('ls_discussion_post', sid=s['id']) }}" style="margin-top:6px">
  <input type="hidden" name="did" value="{{ d.id }}">
  <textarea name="body" placeholder="Aporta a la discusión..." required></textarea>
  <button class="btn sec sm">Enviar</button></form>
 {% if can_admin or d.created_by==me_id %}<details class="add" style="margin-top:6px"><summary>Cerrar discusión con una conclusión</summary>
  <form method="post" action="{{ url_for('ls_discussion_close', sid=s['id']) }}" style="margin-top:6px">
   <input type="hidden" name="did" value="{{ d.id }}"><input type="hidden" name="action" value="close">
   <textarea name="conclusion" placeholder="Conclusión tomada por el equipo..." required></textarea>
   <button class="btn">Cerrar discusión</button></form>
 </details>{% endif %}
 {% elif can_admin or d.created_by==me_id %}
 <form method="post" action="{{ url_for('ls_discussion_close', sid=s['id']) }}" style="margin-top:6px;display:inline"><input type="hidden" name="did" value="{{ d.id }}"><input type="hidden" name="action" value="reopen"><button class="btn sec sm">Reabrir</button></form>
 {% endif %}
 {% if can_admin or d.created_by==me_id %}<form method="post" action="{{ url_for('ls_discussion_del', sid=s['id']) }}" onsubmit="return confirm('¿Eliminar la discusión?')" style="margin-top:6px;display:inline"><input type="hidden" name="did" value="{{ d.id }}"><button class="btn sec sm">Eliminar discusión</button></form>{% endif %}
</div>{% else %}<p class="muted">Todavía no hay discusiones. Abre la primera arriba, o inícialas desde una evidencia o desde la reflexion.</p>{% endfor %}
{% endif %}

{% if can_admin %}<div class="card"><h2>Eliminar sesión</h2>
 <p class="muted">Se elimina la sesión con sus objetivos, ítems y evidencias.</p>
 <form method="post" action="{{ url_for('ls_del', sid=s['id']) }}" onsubmit="return confirm('¿Eliminar toda la sesión de Lesson Study?')">
  <button class="btn danger sm">Eliminar sesión</button></form></div>{% endif %}

<div id="eviLB" onclick="this.style.display='none'" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.85);z-index:800;align-items:center;justify-content:center;padding:20px;cursor:zoom-out"></div>
<script>
document.addEventListener('click',function(e){
  var t=e.target.closest('.evi-thumb'); if(!t) return;
  if(t.tagName==='A') return; /* documentos: se abren en pestaña nueva */
  e.preventDefault();
  var full=t.getAttribute('data-full'), ty=t.getAttribute('data-type'), lb=document.getElementById('eviLB');
  if(!full) return;
  lb.innerHTML = (ty==='video')
    ? '<video src="'+full+'" controls autoplay style="max-width:92vw;max-height:88vh;border-radius:10px"></video>'
    : '<img src="'+full+'" style="max-width:92vw;max-height:88vh;border-radius:10px">';
  lb.style.display='flex';
});
</script>

{% if ls_ai_on %}
<div id="lsaiBtn" onclick="lsaiToggle()" title="Facilitador de Lesson Study (IA)" style="position:fixed;left:16px;bottom:16px;z-index:320;width:54px;height:54px;border-radius:50%;background:linear-gradient(135deg,#6e1836,#c0325f);color:#fff;display:flex;align-items:center;justify-content:center;font-size:26px;cursor:pointer;box-shadow:0 6px 22px rgba(122,31,61,.42)">&#129302;</div>
<div id="lsaiPanel" style="display:none;position:fixed;left:16px;bottom:80px;z-index:320;width:350px;max-width:92vw;background:var(--card);color:var(--ink);border:1px solid var(--line);border-radius:14px;box-shadow:0 12px 36px rgba(20,12,26,.24)">
 <div style="background:linear-gradient(135deg,#6e1836,#c0325f);color:#fff;padding:10px 14px;border-radius:14px 14px 0 0;display:flex;justify-content:space-between;align-items:center">
  <b>&#129302; Facilitador de Lesson Study</b><span onclick="lsaiToggle()" style="cursor:pointer">&times;</span></div>
 <div id="lsaiBody" style="max-height:360px;overflow:auto;padding:10px">
  {% for j in ls_ai_jobs %}
  <div class="lsai-job" data-id="{{ j['id'] }}" data-status="{{ j['status'] }}" style="margin-bottom:12px">
   <div style="background:#f0eaef;color:#25202a;border-radius:10px;padding:6px 10px;font-size:13px">{{ j['instruction'] }}</div>
   <div class="lsai-ans" style="font-size:13px;padding:6px 10px;white-space:pre-wrap">{% if j['status']=='done' %}{{ j['result'] }}{% elif j['status']=='error' %}<span style="color:#d34">No se pudo generar: {{ j['error'] }}</span>{% else %}<span class="muted">Pensando&hellip;</span>{% endif %}</div>
  </div>{% else %}<p class="muted" style="font-size:13px;margin:4px">Pregúntame sobre esta sesión: objetivos, evidencias, cómo interpretar algo, qué mirar para la mejora&hellip;</p>{% endfor %}
 </div>
 <form method="post" action="{{ url_for('ls_ai', sid=s['id']) }}" style="display:flex;gap:6px;padding:10px;border-top:1px solid var(--line);margin:0">
  <input type="hidden" name="tab" value="{{ tab }}">
  <input name="q" placeholder="Pregunta al facilitador&hellip;" required autocomplete="off" style="flex:1;margin:0">
  <button class="btn sm">Enviar</button></form>
 <p style="font-size:11px;padding:6px 10px 8px;margin:0;color:#7a4a00;background:#fff7e6;border-top:1px solid #f0d9a8">&#9888; Es una IA y puede cometer errores: verifica siempre sus respuestas. Es un apoyo para pensar, no una evaluación; responde solo con los datos de esta sesión.</p>
</div>
<script>
function lsaiToggle(){ var p=document.getElementById('lsaiPanel'); var open=(p.style.display==='none'||!p.style.display);
 p.style.display=open?'block':'none'; if(open){ var b=document.getElementById('lsaiBody'); if(b) b.scrollTop=b.scrollHeight; } }
if(location.hash==='#lsai'){ var _p=document.getElementById('lsaiPanel'); if(_p) _p.style.display='block'; }
(function(){ document.querySelectorAll('.lsai-job').forEach(function(el){
  var st=el.getAttribute('data-status');
  if(st==='pending'||st==='running'){ var id=el.getAttribute('data-id');
    var t=setInterval(function(){ fetch('/api/aijob/'+id).then(function(r){return r.json();}).then(function(d){
      if(d.status==='done'||d.status==='error'){ clearInterval(t);
        el.querySelector('.lsai-ans').textContent=(d.status==='done'? d.result : ('No se pudo generar: '+(d.error||''))); }
    }).catch(function(){}); }, 3000);
  } }); })();
</script>
{% endif %}
"""


@app.route("/groups/<int:gid>/ls/new", methods=["POST"])
@login_required
def ls_new(gid):
    db, u = get_db(), current_user()
    _group_or_403(gid)
    sid = db.execute("INSERT INTO ls_sessions(group_id,owner_id,title,created_at) VALUES(?,?,?,?)",
                     (gid, u["id"], request.form["title"].strip(), now())).lastrowid
    db.commit()
    flash("Sesión de Lesson Study creada.")
    return redirect(url_for("ls_view", sid=sid))


@app.route("/ls/<int:sid>")
@login_required
def ls_view(sid):
    db, u = get_db(), current_user()
    s = _ls_session(sid)
    tab = request.args.get("tab", "objetivos")
    obj_list = []
    for o in db.execute("SELECT * FROM ls_objectives WHERE session_id=? ORDER BY position,id", (sid,)).fetchall():
        d = dict(o)
        d["nevid"] = db.execute("SELECT COUNT(*) c FROM ls_evidence_links WHERE target_type='objective' AND target_id=?",
                                (o["id"],)).fetchone()["c"]
        obj_list.append(d)
    cont_list = db.execute("SELECT * FROM ls_contents WHERE session_id=? ORDER BY position,id", (sid,)).fetchall()
    item_list = []
    for it in db.execute("SELECT * FROM ls_items WHERE session_id=? ORDER BY position,id", (sid,)).fetchall():
        d = dict(it)
        d["nevid"] = db.execute("SELECT COUNT(*) c FROM ls_evidence_links WHERE target_type='item' AND target_id=?",
                                (it["id"],)).fetchone()["c"]
        item_list.append(d)
    aportes, emergentes = [], []
    if tab == "reflexion":
        for o in obj_list:
            evs = db.execute("""SELECT e.* FROM ls_evidences e
                JOIN ls_evidence_links l ON l.evidence_id=e.id
                WHERE l.target_type='objective' AND l.target_id=? ORDER BY e.captured_at, e.id""",
                (o["id"],)).fetchall()
            o["evidences"] = [_ls_evi_context(db, e) for e in evs]
        for it in item_list:
            evs = db.execute("""SELECT e.* FROM ls_evidences e
                JOIN ls_evidence_links l ON l.evidence_id=e.id
                WHERE l.target_type='item' AND l.target_id=? ORDER BY e.captured_at, e.id""",
                (it["id"],)).fetchall()
            it["evidences"] = [_ls_evi_context(db, e) for e in evs]
        aportes = db.execute("""SELECT r.*, u.name author_name FROM ls_reflection_posts r JOIN users u ON u.id=r.author_id
                                WHERE r.session_id=? AND r.kind='aporte' ORDER BY r.id""", (sid,)).fetchall()
        emergentes = db.execute("""SELECT r.*, u.name author_name FROM ls_reflection_posts r JOIN users u ON u.id=r.author_id
                                   WHERE r.session_id=? AND r.kind='emergente' ORDER BY r.id""", (sid,)).fetchall()
        ref_discussions = _ls_load_discussions(db, sid)
    else:
        ref_discussions = []
    discussions = _ls_load_discussions(db, sid) if tab == "discusiones" else []
    evidences = []
    bands = []
    day_notes = []
    if tab == "evidencias":
        rows = db.execute("""SELECT e.*, u.name author_name FROM ls_evidences e JOIN users u ON u.id=e.author_id
                             WHERE e.session_id=? ORDER BY e.captured_at, e.id""", (sid,)).fetchall()
        for e in rows:
            links = db.execute("SELECT target_type,target_id FROM ls_evidence_links WHERE evidence_id=?",
                               (e["id"],)).fetchall()
            obj_ids = {l["target_id"] for l in links if l["target_type"] == "objective"}
            item_ids = {l["target_id"] for l in links if l["target_type"] == "item"}
            comments = db.execute("""SELECT c.*, u.name author_name FROM ls_evidence_comments c
                                     JOIN users u ON u.id=c.author_id WHERE evidence_id=?
                                     ORDER BY (t_seconds IS NULL), t_seconds, c.id""", (e["id"],)).fetchall()
            mismatch = bool(s["lesson_date"] and e["captured_at"] and e["captured_at"][:10] != s["lesson_date"])
            item = {"e": e, "obj_ids": obj_ids, "item_ids": item_ids,
                    "comments": comments, "mismatch": mismatch}
            if e["all_day"]:
                day_notes.append(item)
            else:
                evidences.append(item)
        # Agrupar en franjas de 2 minutos (evidencias solapadas en hora)
        from datetime import timedelta
        cur = None
        for ev in evidences:
            cap = ev["e"]["captured_at"] or ""
            try:
                d = datetime.strptime(cap[:16], "%Y-%m-%d %H:%M")
                start = d.replace(minute=(d.minute // 2) * 2, second=0, microsecond=0)
                end = start + timedelta(minutes=2)
                key = start.strftime("%Y%m%d%H%M")
                label = "%s · %s–%s" % (start.strftime("%d/%m/%Y"), start.strftime("%H:%M"),
                                        end.strftime("%H:%M"))
            except Exception:
                key, label = "sinhora", "Sin hora asignada"
            if cur is None or cur["key"] != key:
                cur = {"key": key, "label": label, "evidences": []}
                bands.append(cur)
            cur["evidences"].append(ev)
    g_owner = db.execute("SELECT owner_id FROM groups WHERE id=?", (s["group_id"],)).fetchone()["owner_id"]
    can_admin = (s["owner_id"] == u["id"]) or (g_owner == u["id"])
    return render(LS_VIEW_TPL, title=s["title"], s=s, tab=tab, tabs=LS_TABS,
                  objectives=obj_list, contents=cont_list, items=item_list, evidences=evidences, bands=bands,
                  day_notes=day_notes, kind_labels=LS_KIND_LABELS, can_admin=can_admin, pil_ok=_PIL_OK,
                  discussions=discussions, themes=LS_THEMES, me_id=u["id"],
                  aportes=aportes, emergentes=emergentes, ref_discussions=ref_discussions,
                  ls_ai_on=(ai_config()[0] is not None),
                  ls_ai_jobs=db.execute("SELECT * FROM ai_jobs WHERE session_id=? ORDER BY id DESC LIMIT 8",
                                        (sid,)).fetchall())


LS_AI_SYSTEM = (
    "Eres un facilitador de Lesson Study en la formación del profesorado. Acompañas a un equipo docente con "
    "una mirada socrática: NO das respuestas cerradas ni juicios evaluativos; ayudas a pensar. Basándote ÚNICAMENTE "
    "en el contexto de la sesión que se te aporta (objetivos, ítems de observación, evidencias y sus notas, "
    "reflexiones y discusiones), responde en español, breve (120-180 palabras), con un tono cálido y respetuoso. "
    "Termina SIEMPRE con 1 o 2 preguntas guía que inviten al equipo a justificar sus interpretaciones con evidencias "
    "y a pensar en la mejora de la próxima lección. Si falta información, dilo con claridad y sugiere qué evidencia "
    "buscar. No inventes datos que no estén en el contexto ni evalúes a personas.")


def _ls_context_text(db, sid, s):
    """Reúne el contexto de la sesión de Lesson Study para el facilitador de IA."""
    p = ["Sesión de Lesson Study: %s" % s["title"]]
    if s["lesson_date"]:
        p.append("Fecha de la lección: %s" % s["lesson_date"])
    objs = db.execute("SELECT text, assessment FROM ls_objectives WHERE session_id=? ORDER BY position,id", (sid,)).fetchall()
    if objs:
        p.append("\nObjetivos de aprendizaje:")
        for o in objs:
            p.append("- %s%s" % (o["text"], (" [valoración: %s]" % o["assessment"]) if o["assessment"] else ""))
    its = db.execute("SELECT text, assessment FROM ls_items WHERE session_id=? ORDER BY position,id", (sid,)).fetchall()
    if its:
        p.append("\nÍtems de observación:")
        for it in its:
            p.append("- %s%s" % (it["text"], (" [%s]" % it["assessment"]) if it["assessment"] else ""))
    evs = db.execute("SELECT kind, note FROM ls_evidences WHERE session_id=? ORDER BY captured_at, id", (sid,)).fetchall()
    if evs:
        p.append("\nEvidencias recogidas (%d):" % len(evs))
        for e in evs[:40]:
            p.append("- (%s) %s" % (e["kind"], (e["note"] or "")[:200]))
    refl = db.execute("SELECT kind, body FROM ls_reflection_posts WHERE session_id=? ORDER BY id", (sid,)).fetchall()
    if refl:
        p.append("\nAportaciones a la reflexión:")
        for r in refl[:30]:
            p.append("- [%s] %s" % (r["kind"], (r["body"] or "")[:200]))
    if s["reflexion"]:
        p.append("\nConclusión del equipo: " + s["reflexion"][:600])
    dis = db.execute("SELECT title, conclusion FROM ls_discussions WHERE session_id=? ORDER BY id", (sid,)).fetchall()
    if dis:
        p.append("\nDiscusiones:")
        for d in dis[:20]:
            p.append("- %s%s" % (d["title"], (" (conclusión: %s)" % d["conclusion"][:150]) if d["conclusion"] else ""))
    return "\n".join(p)[:6500]


@app.route("/ls/<int:sid>/ai", methods=["POST"])
@login_required
def ls_ai(sid):
    db, u = get_db(), current_user()
    s = _ls_session(sid)
    q = (request.form.get("q", "") or "").strip()[:600]
    tab = request.form.get("tab", "objetivos")
    if not q:
        return redirect(url_for("ls_view", sid=sid, tab=tab))
    if ai_config()[0] is None:
        flash("La IA no está configurada.", "error")
        return redirect(url_for("ls_view", sid=sid, tab=tab))
    system = os.environ.get("EVESTIGIA_LS_AI_SYSTEM") or LS_AI_SYSTEM
    user = _ls_context_text(db, sid, s) + "\n\nPregunta del equipo: " + q
    jid = db.execute("INSERT INTO ai_jobs(requester_id,session_id,instruction,status,created_at) "
                     "VALUES(?,?,?, 'pending', ?)", (u["id"], sid, q, now())).lastrowid
    db.commit()
    AI_QUEUE.put((jid, system, user))
    return redirect(url_for("ls_view", sid=sid, tab=tab) + "#lsai")


@app.route("/ls/<int:sid>/objectives/add", methods=["POST"])
@login_required
def ls_objective_add(sid):
    db = get_db()
    s = _ls_session(sid)
    text = request.form.get("text", "").strip()
    if text:
        pos = db.execute("SELECT COALESCE(MAX(position),-1)+1 n FROM ls_objectives WHERE session_id=?",
                         (sid,)).fetchone()["n"]
        db.execute("INSERT INTO ls_objectives(session_id,text,position) VALUES(?,?,?)", (sid, text, pos))
        db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="objetivos"))


@app.route("/ls/<int:sid>/objectives/del", methods=["POST"])
@login_required
def ls_objective_del(sid):
    db = get_db()
    _ls_session(sid)
    db.execute("DELETE FROM ls_objectives WHERE id=? AND session_id=?",
               (request.form.get("oid"), sid))
    db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="objetivos"))


@app.route("/ls/<int:sid>/contents/add", methods=["POST"])
@login_required
def ls_content_add(sid):
    db = get_db()
    _ls_session(sid)
    text = request.form.get("text", "").strip()
    if text:
        pos = db.execute("SELECT COALESCE(MAX(position),-1)+1 n FROM ls_contents WHERE session_id=?",
                         (sid,)).fetchone()["n"]
        db.execute("INSERT INTO ls_contents(session_id,text,position) VALUES(?,?,?)", (sid, text, pos))
        db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="contenidos"))


@app.route("/ls/<int:sid>/contents/del", methods=["POST"])
@login_required
def ls_content_del(sid):
    db = get_db()
    _ls_session(sid)
    db.execute("DELETE FROM ls_contents WHERE id=? AND session_id=?",
               (request.form.get("cid"), sid))
    db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="contenidos"))


LS_PRINT_TPL = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>{{ s['title'] }} - Ciclo de Lesson Study</title>
<style>
 *{box-sizing:border-box}
 body{font-family:Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif;color:#1c1922;margin:0;background:#fff;line-height:1.5}
 .wrap{max-width:820px;margin:0 auto;padding:32px 28px}
 .toolbar{position:sticky;top:0;background:#7a1f3d;color:#fff;padding:10px 16px;display:flex;justify-content:space-between;align-items:center}
 .toolbar button{background:#fff;color:#7a1f3d;border:none;border-radius:8px;padding:8px 14px;font-weight:700;cursor:pointer}
 h1{font-size:26px;margin:0 0 4px;color:#7a1f3d}
 h2{font-size:19px;margin:26px 0 8px;color:#7a1f3d;border-bottom:2px solid #ece7ef;padding-bottom:4px}
 h3{font-size:15px;margin:14px 0 4px}
 .muted{color:#8b8492}
 .meta{color:#8b8492;font-size:13px;margin-bottom:8px}
 ol,ul{margin:6px 0 6px 22px}
 li{margin:4px 0}
 .val{background:#f6f2f5;border-left:3px solid #c0325f;padding:6px 10px;margin:4px 0;font-size:13px}
 .evi{border:1px solid #ece7ef;border-radius:10px;padding:12px;margin:10px 0}
 .evi img{max-width:100%;border-radius:8px;margin-top:6px}
 .cmt{font-size:13px;border-top:1px solid #f0eaef;padding:5px 0}
 .pill{display:inline-block;background:#7a1f3d;color:#fff;border-radius:20px;padding:1px 9px;font-size:11px}
 @media print{.toolbar{display:none} .wrap{max-width:none;padding:0} h2{page-break-after:avoid} .evi{page-break-inside:avoid}}
</style></head><body>
<div class="toolbar"><span>eVestigia &middot; Ciclo de Lesson Study</span><button onclick="window.print()">Guardar como PDF / Imprimir</button></div>
<div class="wrap">
 <h1>{{ s['title'] }}</h1>
 <div class="meta">Grupo: {{ gname }} &middot; {% if s['lesson_date'] %}Lección: {{ s['lesson_date'] }} &middot; {% endif %}{{ 'lección realizada' if s['lesson_done'] else 'en preparación' }}</div>

 <h2>1. Objetivos de aprendizaje</h2>
 {% if objectives %}<ol>{% for o in objectives %}<li>{{ o['text'] }}{% if o['assessment'] %}<div class="val"><b>Valoración:</b> {{ o['assessment'] }}</div>{% endif %}</li>{% endfor %}</ol>{% else %}<p class="muted">Sin objetivos.</p>{% endif %}

 <h2>2. Contenidos</h2>
 {% if contents %}<ol>{% for c in contents %}<li>{{ c['text'] }}</li>{% endfor %}</ol>{% else %}<p class="muted">Sin contenidos.</p>{% endif %}

 <h2>3. Ítems de observación</h2>
 {% if items %}<ol>{% for it in items %}<li>{{ it['text'] }}{% if it['assessment'] %}<div class="val"><b>Valoración:</b> {{ it['assessment'] }}</div>{% endif %}</li>{% endfor %}</ol>{% else %}<p class="muted">Sin ítems.</p>{% endif %}

 <h2>4. Lección de investigación</h2>
 <p>{% if s['lesson_date'] %}Fecha: {{ s['lesson_date'] }}. {% endif %}Estado: {{ 'realizada' if s['lesson_done'] else 'en preparación' }}.</p>

 <h2>5. Evidencias</h2>
 {% if evidences %}{% for it in evidences %}<div class="evi">
   <div><span class="pill">{{ kind_labels.get(it.e['kind'], it.e['kind']) }}</span> <b>{{ it.e['author_name'] }}</b> <span class="muted">&middot; {{ it.e['captured_at'] or it.e['created_at'] }}</span></div>
   {% if it.e['note'] %}<div style="margin-top:4px">{{ it.e['note'] }}</div>{% endif %}
   {% if it.e['kind'] in ['photo','image'] and it.e['filename'] %}<img src="/uploads/{{ it.e['filename'] }}">{% endif %}
   {% for c in it.comments %}<div class="cmt"><b>{{ c['author_name'] }}</b>{% if c['t_seconds'] is not none %} <span class="muted">[{{ c['t_seconds'] }}s]</span>{% endif %}: {{ c['body'] }}</div>{% endfor %}
  </div>{% endfor %}{% else %}<p class="muted">Sin evidencias.</p>{% endif %}

 <h2>6. Reflexión</h2>
 {% if s['reflexion'] %}<p>{{ s['reflexion'] }}</p>{% endif %}
 <h3>Aportaciones</h3>
 {% if aportes %}<ul>{% for a in aportes %}<li><b>{{ a['author_name'] }}:</b> {{ a['body'] }}</li>{% endfor %}</ul>{% else %}<p class="muted">Sin aportaciones.</p>{% endif %}
 <h3>Cuestiones emergentes</h3>
 {% if emergentes %}<ul>{% for a in emergentes %}<li><b>{{ a['author_name'] }}:</b> {{ a['body'] }}</li>{% endfor %}</ul>{% else %}<p class="muted">Sin cuestiones emergentes.</p>{% endif %}

 <h2>7. Discusiones</h2>
 {% if discussions %}{% for d in discussions %}<div class="evi">
   <div><b>{{ d.title }}</b> <span class="muted">&middot; {{ d.context_label }}{% if d.closed %} &middot; cerrada{% endif %}</span></div>
   {% for p in d.posts %}<div class="cmt"><b>{{ p['author_name'] }}:</b> {{ p['body'] }}</div>{% endfor %}
   {% if d.conclusion %}<div class="val"><b>Conclusión:</b> {{ d.conclusion }}</div>{% endif %}
  </div>{% endfor %}{% else %}<p class="muted">Sin discusiones.</p>{% endif %}

 <div class="meta" style="margin-top:30px;border-top:1px solid #ece7ef;padding-top:10px">Generado desde eVestigia</div>
</div>
</body></html>"""


@app.route("/ls/<int:sid>/print")
@login_required
def ls_print(sid):
    db = get_db()
    s = _ls_session(sid)
    gname = db.execute("SELECT name FROM groups WHERE id=?", (s["group_id"],)).fetchone()["name"]
    objectives = db.execute("SELECT * FROM ls_objectives WHERE session_id=? ORDER BY position,id", (sid,)).fetchall()
    contents = db.execute("SELECT * FROM ls_contents WHERE session_id=? ORDER BY position,id", (sid,)).fetchall()
    items = db.execute("SELECT * FROM ls_items WHERE session_id=? ORDER BY position,id", (sid,)).fetchall()
    evrows = db.execute("""SELECT e.*, u.name author_name FROM ls_evidences e JOIN users u ON u.id=e.author_id
                           WHERE e.session_id=? ORDER BY (e.captured_at IS NULL), e.captured_at, e.id""", (sid,)).fetchall()
    evidences = []
    for e in evrows:
        comments = db.execute("""SELECT c.*, u.name author_name FROM ls_evidence_comments c JOIN users u ON u.id=c.author_id
                                 WHERE evidence_id=? ORDER BY (t_seconds IS NULL), t_seconds, c.id""", (e["id"],)).fetchall()
        evidences.append({"e": e, "comments": comments})
    aportes = db.execute("""SELECT r.*, u.name author_name FROM ls_reflection_posts r JOIN users u ON u.id=r.author_id
                            WHERE r.session_id=? AND r.kind='aporte' ORDER BY r.id""", (sid,)).fetchall()
    emergentes = db.execute("""SELECT r.*, u.name author_name FROM ls_reflection_posts r JOIN users u ON u.id=r.author_id
                               WHERE r.session_id=? AND r.kind='emergente' ORDER BY r.id""", (sid,)).fetchall()
    discussions = _ls_load_discussions(db, sid)
    return render_template_string(LS_PRINT_TPL, s=s, gname=gname, objectives=objectives, contents=contents,
                                  items=items, evidences=evidences, aportes=aportes, emergentes=emergentes,
                                  discussions=discussions, kind_labels=LS_KIND_LABELS)


@app.route("/ls/<int:sid>/items/add", methods=["POST"])
@login_required
def ls_item_add(sid):
    db = get_db()
    _ls_session(sid)
    text = request.form.get("text", "").strip()
    if text:
        pos = db.execute("SELECT COALESCE(MAX(position),-1)+1 n FROM ls_items WHERE session_id=?",
                         (sid,)).fetchone()["n"]
        db.execute("INSERT INTO ls_items(session_id,text,position) VALUES(?,?,?)", (sid, text, pos))
        db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="items"))


@app.route("/ls/<int:sid>/items/del", methods=["POST"])
@login_required
def ls_item_del(sid):
    db = get_db()
    _ls_session(sid)
    db.execute("DELETE FROM ls_items WHERE id=? AND session_id=?", (request.form.get("iid"), sid))
    db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="items"))


@app.route("/ls/<int:sid>/leccion", methods=["POST"])
@login_required
def ls_leccion_save(sid):
    db = get_db()
    _ls_session(sid)
    ld = request.form.get("lesson_date", "").strip() or None
    done = 1 if request.form.get("lesson_done") else 0
    db.execute("UPDATE ls_sessions SET lesson_date=?, lesson_done=? WHERE id=?", (ld, done, sid))
    db.commit()
    flash("Datos de la lección guardados.")
    return redirect(url_for("ls_view", sid=sid, tab="leccion"))


@app.route("/ls/<int:sid>/evidence/add", methods=["POST"])
@login_required
def ls_evidence_add(sid):
    db, u = get_db(), current_user()
    s = _ls_session(sid)
    if not s["lesson_done"]:
        flash("Marca la lección como realizada antes de subir evidencias.", "error")
        return redirect(url_for("ls_view", sid=sid, tab="leccion"))
    kind = request.form.get("kind", "note")
    note = request.form.get("note", "").strip()
    manual = _norm_dt(request.form.get("captured_at", ""))
    fn = None
    url = None
    captured = None
    meta_ok = 1
    all_day = 0
    if kind in ("photo", "video", "audio", "file"):
        fn, ext = save_upload()
        if ext == "bad":
            flash("Tipo de archivo no permitido.", "error")
            return redirect(url_for("ls_view", sid=sid, tab="evidencias"))
        if not fn:
            flash("Debes adjuntar un archivo.", "error")
            return redirect(url_for("ls_view", sid=sid, tab="evidencias"))
        if ext in IMAGE_EXT:
            kind = "photo"
        elif ext in ("heic", "heif"):
            # HEIC sin convertir (falta pillow-heif): se guarda como documento descargable
            kind = "file"
            flash("No se pudo convertir el HEIC para visualizarlo (instala pillow-heif). Se ha guardado como documento.", "error")
        if manual:
            captured = manual
        else:
            captured, ok = _extract_captured_at(os.path.join(UPLOAD_DIR, fn), ext)
            meta_ok = 1 if ok else 0
    elif kind == "link":
        url = request.form.get("url", "").strip()
        if not url:
            flash("Añade un enlace.", "error")
            return redirect(url_for("ls_view", sid=sid, tab="evidencias"))
        captured = manual or _now_full()
    else:  # note
        kind = "note"
        if not note:
            flash("Escribe la nota.", "error")
            return redirect(url_for("ls_view", sid=sid, tab="evidencias"))
        if request.form.get("all_day"):
            all_day = 1
            captured = manual or ((s["lesson_date"] + " 00:00:00") if s["lesson_date"] else _now_full())
        else:
            captured = manual or _now_full()
    if fn:
        try:
            newsize = os.path.getsize(os.path.join(UPLOAD_DIR, fn))
        except Exception:
            newsize = 0
        if _group_evidence_bytes(s["group_id"]) + newsize > _group_quota(s["group_id"]):
            try:
                os.remove(os.path.join(UPLOAD_DIR, fn))
            except Exception:
                pass
            flash("Se ha alcanzado el límite de evidencias del grupo. Elimina algunas o trocea los vídeos.", "error")
            return redirect(url_for("ls_view", sid=sid, tab="evidencias"))
    db.execute("""INSERT INTO ls_evidences(session_id,author_id,kind,filename,url,note,captured_at,meta_ok,all_day,created_at)
                  VALUES(?,?,?,?,?,?,?,?,?,?)""",
               (sid, u["id"], kind, fn, url, note, captured, meta_ok, all_day, now()))
    db.commit()
    flash("Evidencia añadida.")
    return redirect(url_for("ls_view", sid=sid, tab="evidencias"))


@app.route("/ls/<int:sid>/evidence/bulk", methods=["POST"])
@login_required
def ls_evidence_bulk(sid):
    db, u = get_db(), current_user()
    s = _ls_session(sid)
    if not s["lesson_done"]:
        flash("Marca la lección como realizada antes de subir evidencias.", "error")
        return redirect(url_for("ls_view", sid=sid, tab="leccion"))
    allfiles = [f for f in request.files.getlist("files") if f and f.filename]
    over_count = len(allfiles) > LS_BULK_MAX
    files = allfiles[:LS_BULK_MAX]
    used = _group_evidence_bytes(s["group_id"])
    quota = _group_quota(s["group_id"])
    added = skipped = 0
    over_quota = False
    for f in files:
        fn, ext = _store_file(f)
        if not fn or ext == "bad":
            skipped += 1
            continue
        try:
            sz = os.path.getsize(os.path.join(UPLOAD_DIR, fn))
        except Exception:
            sz = 0
        if used + sz > quota:
            try:
                os.remove(os.path.join(UPLOAD_DIR, fn))
            except Exception:
                pass
            over_quota = True
            break
        used += sz
        kind = _kind_from_ext(ext)
        captured, ok = _extract_captured_at(os.path.join(UPLOAD_DIR, fn), ext)
        db.execute("""INSERT INTO ls_evidences(session_id,author_id,kind,filename,note,captured_at,meta_ok,all_day,created_at)
                      VALUES(?,?,?,?,?,?,?,?,?)""",
                   (sid, u["id"], kind, fn, "", captured, 1 if ok else 0, 0, now()))
        added += 1
    db.commit()
    msg = "Subida masiva: %d evidencia(s) añadida(s)%s. Se han ordenado por su fecha; revisa las que no tengan metadatos." \
          % (added, (", %d omitida(s)" % skipped) if skipped else "")
    if over_count:
        msg += " Solo se procesan %d archivos por tanda; sube el resto en otra." % LS_BULK_MAX
    if over_quota:
        msg += " Se alcanzó el límite de 5 GB de evidencias del grupo; no se subieron todas."
    flash(msg, "error" if over_quota else "")
    return redirect(url_for("ls_view", sid=sid, tab="evidencias"))


@app.route("/ls/<int:sid>/evidence/del", methods=["POST"])
@login_required
def ls_evidence_del(sid):
    db = get_db()
    _ls_session(sid)
    e = _ls_evidence(sid, request.form.get("eid"))
    fn = e["filename"]
    db.execute("DELETE FROM ls_evidences WHERE id=?", (e["id"],))
    db.commit()
    if fn and not db.execute("SELECT 1 FROM ls_evidences WHERE filename=?", (fn,)).fetchone() \
            and not db.execute("SELECT 1 FROM artefacts WHERE filename=?", (fn,)).fetchone():
        try:
            os.remove(os.path.join(UPLOAD_DIR, fn))
        except Exception:
            pass
    flash("Evidencia eliminada.")
    return redirect(url_for("ls_view", sid=sid, tab="evidencias"))


@app.route("/ls/<int:sid>/evidence/links", methods=["POST"])
@login_required
def ls_evidence_links(sid):
    db = get_db()
    _ls_session(sid)
    e = _ls_evidence(sid, request.form.get("eid"))
    db.execute("DELETE FROM ls_evidence_links WHERE evidence_id=?", (e["id"],))
    for oid in request.form.getlist("obj"):
        db.execute("INSERT OR IGNORE INTO ls_evidence_links(evidence_id,target_type,target_id) VALUES(?,?,?)",
                   (e["id"], "objective", oid))
    for iid in request.form.getlist("item"):
        db.execute("INSERT OR IGNORE INTO ls_evidence_links(evidence_id,target_type,target_id) VALUES(?,?,?)",
                   (e["id"], "item", iid))
    db.commit()
    flash("Relaciones guardadas.")
    return redirect(url_for("ls_view", sid=sid, tab="evidencias"))


@app.route("/ls/<int:sid>/comment/add", methods=["POST"])
@login_required
def ls_comment_add(sid):
    db, u = get_db(), current_user()
    _ls_session(sid)
    e = _ls_evidence(sid, request.form.get("eid"))
    body = request.form.get("body", "").strip()
    ts = request.form.get("t_seconds", "").strip()
    try:
        ts = int(ts) if ts != "" else None
    except ValueError:
        ts = None
    if body:
        db.execute("""INSERT INTO ls_evidence_comments(evidence_id,author_id,t_seconds,body,created_at)
                      VALUES(?,?,?,?,?)""", (e["id"], u["id"], ts, body, now()))
        db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="evidencias"))


@app.route("/ls/<int:sid>/evidence/time", methods=["POST"])
@login_required
def ls_evidence_time(sid):
    db = get_db()
    _ls_session(sid)
    e = _ls_evidence(sid, request.form.get("eid"))
    dt = _norm_dt(request.form.get("captured_at", ""))
    if dt:
        db.execute("UPDATE ls_evidences SET captured_at=?, meta_ok=1 WHERE id=?", (dt, e["id"]))
        db.commit()
        flash("Hora de la evidencia actualizada.")
    return redirect(url_for("ls_view", sid=sid, tab="evidencias"))


@app.route("/ls/<int:sid>/reflexion", methods=["POST"])
@login_required
def ls_reflexion_save(sid):
    db = get_db()
    _ls_session(sid)
    db.execute("UPDATE ls_sessions SET reflexion=? WHERE id=?",
               (request.form.get("reflexion", "").strip(), sid))
    db.commit()
    flash("Reflexión guardada.")
    return redirect(url_for("ls_view", sid=sid, tab="reflexion"))


@app.route("/ls/<int:sid>/assess", methods=["POST"])
@login_required
def ls_assess(sid):
    db = get_db()
    _ls_session(sid)
    tt = request.form.get("target_type")
    tid = request.form.get("target_id")
    text = request.form.get("assessment", "").strip()
    if tt == "objective":
        db.execute("UPDATE ls_objectives SET assessment=? WHERE id=? AND session_id=?", (text, tid, sid))
    elif tt == "item":
        db.execute("UPDATE ls_items SET assessment=? WHERE id=? AND session_id=?", (text, tid, sid))
    db.commit()
    flash("Valoración guardada.")
    return redirect(url_for("ls_view", sid=sid, tab="reflexion"))


@app.route("/ls/<int:sid>/reflection/post", methods=["POST"])
@login_required
def ls_reflection_post(sid):
    db, u = get_db(), current_user()
    _ls_session(sid)
    body = request.form.get("body", "").strip()
    kind = "emergente" if request.form.get("kind") == "emergente" else "aporte"
    if body:
        db.execute("INSERT INTO ls_reflection_posts(session_id,author_id,kind,body,created_at) VALUES(?,?,?,?,?)",
                   (sid, u["id"], kind, body, now()))
        db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="reflexion"))


@app.route("/ls/<int:sid>/reflection/del", methods=["POST"])
@login_required
def ls_reflection_post_del(sid):
    db, u = get_db(), current_user()
    s = _ls_session(sid)
    rid = request.form.get("rid")
    r = db.execute("SELECT * FROM ls_reflection_posts WHERE id=? AND session_id=?", (rid, sid)).fetchone()
    if not r:
        abort(404)
    g_owner = db.execute("SELECT owner_id FROM groups WHERE id=?", (s["group_id"],)).fetchone()["owner_id"]
    if r["author_id"] != u["id"] and s["owner_id"] != u["id"] and g_owner != u["id"]:
        abort(403)
    db.execute("DELETE FROM ls_reflection_posts WHERE id=?", (rid,))
    db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="reflexion"))


@app.route("/ls/<int:sid>/discussion/new", methods=["POST"])
@login_required
def ls_discussion_new(sid):
    db, u = get_db(), current_user()
    _ls_session(sid)
    title = request.form.get("title", "").strip()
    if not title:
        return redirect(url_for("ls_view", sid=sid, tab="discusiones"))
    ct = request.form.get("context_type", "general")
    cid = request.form.get("context_id") or None
    db.execute("""INSERT INTO ls_discussions(session_id,title,context_type,context_id,created_by,created_at)
                  VALUES(?,?,?,?,?,?)""", (sid, title, ct, cid, u["id"], now()))
    db.commit()
    flash("Discusión abierta.")
    return redirect(url_for("ls_view", sid=sid, tab="discusiones"))


@app.route("/ls/<int:sid>/discussion/post", methods=["POST"])
@login_required
def ls_discussion_post(sid):
    db, u = get_db(), current_user()
    _ls_session(sid)
    did = request.form.get("did")
    if not db.execute("SELECT 1 FROM ls_discussions WHERE id=? AND session_id=?", (did, sid)).fetchone():
        abort(404)
    body = request.form.get("body", "").strip()
    if body:
        db.execute("INSERT INTO ls_discussion_posts(discussion_id,author_id,body,created_at) VALUES(?,?,?,?)",
                   (did, u["id"], body, now()))
        db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="discusiones"))


@app.route("/ls/<int:sid>/discussion/del", methods=["POST"])
@login_required
def ls_discussion_del(sid):
    db, u = get_db(), current_user()
    s = _ls_session(sid)
    did = request.form.get("did")
    d = db.execute("SELECT * FROM ls_discussions WHERE id=? AND session_id=?", (did, sid)).fetchone()
    if not d:
        abort(404)
    g_owner = db.execute("SELECT owner_id FROM groups WHERE id=?", (s["group_id"],)).fetchone()["owner_id"]
    if d["created_by"] != u["id"] and s["owner_id"] != u["id"] and g_owner != u["id"]:
        abort(403)
    db.execute("DELETE FROM ls_discussions WHERE id=?", (did,))
    db.commit()
    flash("Discusión eliminada.")
    return redirect(url_for("ls_view", sid=sid, tab="discusiones"))


@app.route("/ls/<int:sid>/discussion/close", methods=["POST"])
@login_required
def ls_discussion_close(sid):
    db, u = get_db(), current_user()
    s = _ls_session(sid)
    did = request.form.get("did")
    d = db.execute("SELECT * FROM ls_discussions WHERE id=? AND session_id=?", (did, sid)).fetchone()
    if not d:
        abort(404)
    g_owner = db.execute("SELECT owner_id FROM groups WHERE id=?", (s["group_id"],)).fetchone()["owner_id"]
    if d["created_by"] != u["id"] and s["owner_id"] != u["id"] and g_owner != u["id"]:
        abort(403)
    if request.form.get("action") == "reopen":
        db.execute("UPDATE ls_discussions SET closed=0 WHERE id=?", (did,))
        flash("Discusión reabierta.")
    else:
        db.execute("UPDATE ls_discussions SET closed=1, conclusion=? WHERE id=?",
                   (request.form.get("conclusion", "").strip(), did))
        flash("Discusión cerrada con conclusión.")
    db.commit()
    return redirect(url_for("ls_view", sid=sid, tab="discusiones"))


@app.route("/ls/<int:sid>/delete", methods=["POST"])
@login_required
def ls_del(sid):
    db, u = get_db(), current_user()
    s = _ls_session(sid)
    g_owner = db.execute("SELECT owner_id FROM groups WHERE id=?", (s["group_id"],)).fetchone()["owner_id"]
    if s["owner_id"] != u["id"] and g_owner != u["id"]:
        abort(403)
    db.execute("DELETE FROM ls_sessions WHERE id=?", (sid,))
    db.commit()
    flash("Sesión de Lesson Study eliminada.")
    return redirect(url_for("group_view", gid=s["group_id"]))


# --------------------------------------------------------------------------- #
#  Mensajeria
# --------------------------------------------------------------------------- #
INBOX_TPL = """
<h1>Mensajes</h1>
<div class="row-flex" style="margin-bottom:14px">
 <a class="btn {{ '' if tab=='recibidos' else 'sec' }} sm" href="?tab=recibidos">Recibidos</a>
 <a class="btn {{ '' if tab=='enviados' else 'sec' }} sm" href="?tab=enviados">Enviados</a>
 <a class="btn {{ '' if tab=='conv' else 'sec' }} sm" href="?tab=conv">Conversaciones</a>
</div>
{% if tab=='conv' %}
 {% for c in convos %}<div class="card between">
  <div class="row-flex"><div class="avatar">{{ c['name'][0] }}</div>
   <div><b><a href="{{ url_for('thread', username=c['username']) }}">{{ c['name'] }}</a></b>
    {% if c['unread'] %}<span class="pill">{{ c['unread'] }} nuevo(s)</span>{% endif %}
    <div class="muted">{{ c['last'][:60] }}</div></div></div>
  <a class="btn sec sm" href="{{ url_for('thread', username=c['username']) }}">Abrir</a>
 </div>{% else %}<p class="muted">No tienes conversaciones.</p>{% endfor %}
{% else %}
 {% for m in msgs %}<div class="card between">
  <div><b><a href="{{ url_for('thread', username=m['other_username']) }}">{{ m['other_name'] }}</a></b>
   {% if tab=='recibidos' and not m['is_read'] %}<span class="pill">nuevo</span>{% endif %}
   <div class="muted">{{ m['body'][:80] }}</div></div>
  <span class="muted">{{ m['created_at'] }}</span>
 </div>{% else %}<p class="muted">{{ 'No has recibido mensajes.' if tab=='recibidos' else 'No has enviado mensajes.' }}</p>{% endfor %}
{% endif %}
"""


@app.route("/messages")
@login_required
def inbox():
    if not feature_on("stu_messages"):
        abort(403)
    db, u = get_db(), current_user()
    tab = request.args.get("tab", "recibidos")
    convos, msgs = [], []
    if tab == "conv":
        partners = db.execute("""
            SELECT CASE WHEN sender_id=? THEN recipient_id ELSE sender_id END pid, MAX(id) mid
            FROM messages WHERE sender_id=? OR recipient_id=? GROUP BY pid ORDER BY mid DESC""",
            (u["id"], u["id"], u["id"])).fetchall()
        for pr in partners:
            other = db.execute("SELECT * FROM users WHERE id=?", (pr["pid"],)).fetchone()
            if not other:
                continue
            last = db.execute("SELECT body FROM messages WHERE id=?", (pr["mid"],)).fetchone()["body"]
            unread = db.execute("SELECT COUNT(*) c FROM messages WHERE sender_id=? AND recipient_id=? AND is_read=0",
                                (other["id"], u["id"])).fetchone()["c"]
            convos.append({"name": other["name"], "username": other["username"], "last": last, "unread": unread})
    elif tab == "enviados":
        msgs = db.execute("""SELECT m.*, us.name other_name, us.username other_username
            FROM messages m JOIN users us ON us.id=m.recipient_id
            WHERE m.sender_id=? ORDER BY m.id DESC LIMIT 100""", (u["id"],)).fetchall()
    else:
        tab = "recibidos"
        msgs = db.execute("""SELECT m.*, us.name other_name, us.username other_username
            FROM messages m JOIN users us ON us.id=m.sender_id
            WHERE m.recipient_id=? ORDER BY m.id DESC LIMIT 100""", (u["id"],)).fetchall()
    return render(INBOX_TPL, title="Mensajes", tab=tab, convos=convos, msgs=msgs)


THREAD_TPL = """
<div class="between"><h1>{{ other['name'] }}</h1>
 <a class="btn sec sm" href="{{ url_for('profile', username=other['username']) }}">Ver perfil</a></div>
<p class="muted">@{{ other['username'] }} <span class="pill">{{ role_es(other['role']) }}</span>
 {% if status=='accepted' %}&middot; conocido{% endif %}</p>
<div class="card">
 {% for m in msgs %}
  <div class="bubble {{ 'me' if m['sender_id']==me else 'them' }}">{{ m['body'] }}
   <span class="t">{{ m['created_at'] }}</span></div>
 {% else %}<p class="muted">Aun no hay mensajes. Escribe el primero.</p>{% endfor %}
</div>
<div class="card"><form method="post" action="{{ url_for('send_message', username=other['username']) }}">
 <textarea name="body" placeholder="Escribe un mensaje a {{ other['name'].split()[0] }}..." required></textarea>
 <button class="btn">Enviar</button></form></div>
"""


@app.route("/messages/<username>")
@login_required
def thread(username):
    if not feature_on("stu_messages"):
        abort(403)
    db, u = get_db(), current_user()
    other = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not other or other["id"] == u["id"]:
        abort(404)
    msgs = db.execute("""SELECT * FROM messages
        WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)
        ORDER BY id""", (u["id"], other["id"], other["id"], u["id"])).fetchall()
    db.execute("UPDATE messages SET is_read=1 WHERE sender_id=? AND recipient_id=? AND is_read=0",
               (other["id"], u["id"]))
    db.commit()
    return render(THREAD_TPL, title=other["name"], other=other, msgs=msgs, me=u["id"],
                  status=contact_status(u["id"], other["id"]))


@app.route("/messages/<username>/send", methods=["POST"])
@login_required
def send_message(username):
    if not feature_on("stu_messages"):
        abort(403)
    db, u = get_db(), current_user()
    other = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not other or other["id"] == u["id"]:
        abort(404)
    body = request.form.get("body", "").strip()
    if body:
        db.execute("INSERT INTO messages(sender_id,recipient_id,body,created_at,is_read) VALUES(?,?,?,?,0)",
                   (u["id"], other["id"], body, now()))
        notify(other["id"], "message", "%s te ha enviado un mensaje." % u["name"],
               url_for("thread", username=u["username"]), {"actor": u["name"]}, in_app=False)
        db.commit()
    return redirect(url_for("thread", username=username))


# --------------------------------------------------------------------------- #
#  Preferencias del usuario (alumnado y cualquier rol)
# --------------------------------------------------------------------------- #
USER_EMAIL_EVENTS = [
    ("message", "Nuevos mensajes"),
    ("comment", "Comentarios y feedback en tus páginas"),
    ("contact_request", "Solicitudes de conocido"),
    ("group_request", "Solicitudes para unirse a tus grupos"),
    ("group_accepted", "Cuando te admiten en un grupo"),
]

PREFS_TPL = """
<div class="between"><h1>Mis preferencias</h1><a class="btn sec" href="{{ url_for('profile', username=user['username']) }}">Mi perfil</a></div>
<form method="post">
 <div class="card"><h2>Privacidad</h2>
  <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="show_online" style="width:auto" {{ 'checked' if prof['show_online'] or prof['show_online'] is none }}> Aparecer en línea (que otras personas vean cuándo estoy conectado/a)</label>
  <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="show_contacts" style="width:auto" {{ 'checked' if prof['show_contacts'] or prof['show_contacts'] is none }}> Mostrar mi lista de conocidos en mi perfil</label>
  {% if prof['role'] in ('teacher','admin') %}<label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="notify_changes" style="width:auto" {{ 'checked' if prof['notify_changes'] or prof['notify_changes'] is none }}> Recibir por email los cambios de mis estudiantes conocidos</label>{% endif %}
  <label style="margin-top:8px">Visibilidad por defecto de las páginas nuevas</label>
  <select name="default_vis" style="max-width:280px">
   {% for v,l in [('private','Privada (solo yo)'),('teachers','Docentes'),('public','Pública (toda la plataforma)')] %}
   <option value="{{ v }}" {{ 'selected' if (prof['default_vis'] or 'private')==v }}>{{ l }}</option>{% endfor %}</select>
 </div>

 <div class="card"><h2>Avisos por correo</h2>
  <p class="muted" style="margin-top:0;font-size:13px">Elige qué quieres recibir por email. Los avisos dentro de la app se muestran igualmente.</p>
  {% for ev,label in events %}
   <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="em_{{ ev }}" style="width:auto" {{ 'checked' if empref[ev] }}> {{ label }}</label>
  {% endfor %}
 </div>

 <div class="card"><h2>Accesibilidad</h2>
  <label>Tema</label>
  <select id="prefTheme" onchange="prefTheme(this.value)" style="max-width:240px">
   <option value="auto">Automático (según el sistema)</option>
   <option value="light">Claro</option>
   <option value="dark">Oscuro</option>
  </select>
  <label style="font-weight:400;display:block;padding:8px 0"><input type="checkbox" id="prefBig" onchange="prefFlag('evestigia-bigtext','data-bigtext',this.checked)" style="width:auto"> Texto más grande</label>
  <label style="font-weight:400;display:block;padding:2px 0"><input type="checkbox" id="prefReduce" onchange="prefFlag('evestigia-reduce','data-reduce',this.checked)" style="width:auto"> Reducir animaciones</label>
  <p class="muted" style="font-size:12px;margin:6px 0 0">Estos ajustes se guardan en este navegador.</p>
 </div>

 <button class="btn">Guardar preferencias</button>
</form>

<div class="card" style="margin-top:16px"><h2>Recorrido y ayuda</h2>
 <form method="post" style="display:inline"><input type="hidden" name="action" value="tour"><button class="btn sec sm">Volver a ver el recorrido guiado</button></form>
 <form method="post" style="display:inline;margin-left:6px"><input type="hidden" name="action" value="show_steps"><button class="btn sec sm">Volver a mostrar "Primeros pasos"</button></form>
</div>
<script>
function prefFlag(key,attr,on){ try{ if(on) localStorage.setItem(key,'1'); else localStorage.removeItem(key);
  if(on) document.documentElement.setAttribute(attr,'1'); else document.documentElement.removeAttribute(attr);}catch(e){} }
(function(){ try{
  var t=localStorage.getItem('evestigia-theme');
  document.getElementById('prefTheme').value = t||'auto';
  document.getElementById('prefBig').checked = localStorage.getItem('evestigia-bigtext')==='1';
  document.getElementById('prefReduce').checked = localStorage.getItem('evestigia-reduce')==='1';
}catch(e){} })();
</script>
"""


@app.route("/preferences", methods=["GET", "POST"])
@login_required
def preferences():
    db, u = get_db(), current_user()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "tour":
            db.execute("UPDATE users SET onboarded=0 WHERE id=?", (u["id"],))
            db.commit()
            flash("Se volverá a mostrar el recorrido guiado.")
            return redirect(url_for("dashboard"))
        if action == "show_steps":
            set_setting("onboarding_done_%d" % u["id"], "0")
            flash("Se volverá a mostrar 'Primeros pasos' en el inicio.")
            return redirect(url_for("dashboard"))
        dv = request.form.get("default_vis", "private")
        if dv not in ("private", "teachers", "public"):
            dv = "private"
        db.execute("UPDATE users SET show_online=?, show_contacts=?, default_vis=? WHERE id=?",
                   (1 if request.form.get("show_online") else 0,
                    1 if request.form.get("show_contacts") else 0, dv, u["id"]))
        if u["role"] in ("teacher", "admin"):
            db.execute("UPDATE users SET notify_changes=? WHERE id=?",
                       (1 if request.form.get("notify_changes") else 0, u["id"]))
        for ev, _l in USER_EMAIL_EVENTS:
            set_setting("emailpref_%d_%s" % (u["id"], ev), "1" if request.form.get("em_" + ev) else "0")
        set_setting("privacy_reviewed_%d" % u["id"], "1")
        db.commit()
        flash("Preferencias guardadas.")
        return redirect(url_for("profile", username=u["username"]) + "#ajustes")
    # Los ajustes viven dentro del perfil.
    return redirect(url_for("profile", username=u["username"]) + "#ajustes")


# --------------------------------------------------------------------------- #
#  Perfiles
# --------------------------------------------------------------------------- #
PROFILE_TPL = """
<div class="card"><div class="row-flex" style="align-items:flex-start">
 {% if prof['avatar'] %}<img src="{{ url_for('uploaded', fn=prof['avatar']) }}" style="width:72px;height:72px;border-radius:50%;object-fit:cover;flex-shrink:0">
 {% else %}<div class="avatar" style="width:72px;height:72px;font-size:28px">{{ prof['name'][0] }}</div>{% endif %}
 <div style="flex:1"><div class="between"><h1 style="margin:0">{{ prof['name'] }}</h1>
   {% if not is_me %}<div class="row-flex">
    {% if status=='accepted' %}<span class="pill">Conocido</span>
     <form method="post" action="{{ url_for('contact_action', username=prof['username']) }}" onsubmit="return confirm('Eliminar conocido?')"><input type="hidden" name="action" value="remove"><button class="btn sec sm">Eliminar</button></form>
    {% elif status=='pending_out' %}<span class="muted">Solicitud enviada</span>
    {% elif status=='pending_in' %}<form method="post" action="{{ url_for('contact_action', username=prof['username']) }}"><input type="hidden" name="action" value="accept"><button class="btn sm">Aceptar solicitud</button></form>
    {% else %}<form method="post" action="{{ url_for('contact_action', username=prof['username']) }}"><input type="hidden" name="action" value="request"><button class="btn sm">Añadir como conocido</button></form>{% endif %}
    <a class="btn sec sm" href="{{ url_for('thread', username=prof['username']) }}">Enviar mensaje</a>
   </div>{% endif %}</div>
  <div class="muted">@{{ prof['username'] }} <span class="pill">{{ role_es(prof['role']) }}</span>
   {% if online(prof) %}<span class="pill" style="background:#2e9e5b;color:#fff">● En línea</span>{% endif %}</div>
  {% if prof['bio'] %}<p>{{ prof['bio'] }}</p>{% endif %}
  <div class="muted">{{ n_contacts }} conocidos &middot; {{ pages|length }} páginas públicas</div>
  {% if grupos %}<div style="margin-top:8px;display:flex;flex-wrap:wrap;gap:6px">
   {% for g in grupos %}<a href="{{ url_for('group_view', gid=g['id']) }}" class="pill" style="text-decoration:none">&#128101; {{ g['name'] }}</a>{% endfor %}
  </div>{% endif %}
 </div></div></div>

{% set contacts_visible = prof['show_contacts'] or prof['show_contacts'] is none %}
{% if is_me or contacts_visible %}
<div class="card"><h2>Conocidos {% if n_contacts %}({{ n_contacts }}){% endif %}</h2>
 {% if is_me and not contacts_visible %}<p class="muted" style="font-size:12px;margin:-4px 0 10px">Esta lista está <b>oculta</b> para las demás personas (puedes cambiarlo en tu perfil).</p>{% endif %}
 {% if contactos %}
 <div class="row-flex" style="flex-wrap:wrap;gap:14px">
  {% for c in contactos %}<a href="{{ url_for('profile', username=c['username']) }}" style="display:flex;align-items:center;gap:8px;text-decoration:none;color:inherit">
   {{ avatar(c, 34) }}<span><b>{{ c['name'] }}</b><br><span class="muted" style="font-size:12px">@{{ c['username'] }}</span></span></a>{% endfor %}
 </div>
 {% if n_contacts > contactos|length %}<p class="muted" style="font-size:12px;margin:10px 0 0">Y {{ n_contacts - contactos|length }} más.</p>{% endif %}
 {% else %}<p class="muted" style="margin:0">{% if is_me %}Aún no tienes conocidos.{% else %}Todavía no tiene conocidos.{% endif %}</p>{% endif %}
</div>
{% endif %}

{% if bio_layout %}<div class="card"><h2>Biografia</h2>
 {% for R in bio_layout %}<div class="prow" style="grid-template-columns:{{ R['weights']|join('fr ') }}fr">
  {% for col in R['cols'] %}<div class="pcol">{% for b in col %}<div style="margin-bottom:12px">{{ render_block(b)|safe }}</div>{% endfor %}</div>{% endfor %}</div>
 {% endfor %}</div>{% endif %}

{% if is_me %}<div class="card"><h2>Editar mi perfil</h2>
 <form method="post" action="{{ url_for('edit_profile') }}" enctype="multipart/form-data">
  <label>Nombre</label><input name="name" value="{{ prof['name'] }}">
  <label>Email (para avisos)</label><input name="email" type="email" value="{{ prof['email'] or '' }}">
  <label>Foto de perfil</label><input type="file" name="avatar" accept="image/*">
  <label>Biografia corta (una linea)</label><textarea name="bio" style="min-height:50px">{{ prof['bio'] or '' }}</textarea>
  <button class="btn">Guardar perfil</button></form>
 <div class="row-flex" style="margin-top:10px">
  <a class="btn sec" href="{{ url_for('bio_edit') }}">Editar mi biografia con bloques</a>
  <a class="btn sec" href="{{ url_for('artefacts') }}">Mi almacenamiento</a>
 </div>
</div>
<div class="card"><h2>Cambiar contraseña</h2>
 <form method="post" action="{{ url_for('change_password') }}">
  <label>Contraseña actual</label><input type="password" name="current" required>
  <label>Nueva contraseña</label><input type="password" name="new" required>
  <label>Repite la nueva contraseña</label><input type="password" name="new2" required>
  <button class="btn">Cambiar contraseña</button></form>
</div>

<h2 id="ajustes" style="margin-top:24px">Ajustes y preferencias</h2>
<form method="post" action="{{ url_for('preferences') }}">
 <div class="card"><h2>Privacidad</h2>
  <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="show_online" style="width:auto" {{ 'checked' if prof['show_online'] or prof['show_online'] is none }}> Aparecer en línea (que otras personas vean cuándo estoy conectado/a)</label>
  <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="show_contacts" style="width:auto" {{ 'checked' if prof['show_contacts'] or prof['show_contacts'] is none }}> Mostrar mi lista de conocidos en mi perfil</label>
  {% if prof['role'] in ('teacher','admin') %}<label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="notify_changes" style="width:auto" {{ 'checked' if prof['notify_changes'] or prof['notify_changes'] is none }}> Recibir por email los cambios de mis estudiantes conocidos</label>{% endif %}
  <label style="margin-top:8px">Visibilidad por defecto de las páginas nuevas</label>
  <select name="default_vis" style="max-width:280px">
   {% for v,l in [('private','Privada (solo yo)'),('teachers','Docentes'),('public','Pública (toda la plataforma)')] %}
   <option value="{{ v }}" {{ 'selected' if (prof['default_vis'] or 'private')==v }}>{{ l }}</option>{% endfor %}</select>
 </div>
 <div class="card"><h2>Avisos por correo</h2>
  <p class="muted" style="margin-top:0;font-size:13px">Elige qué quieres recibir por email. Los avisos dentro de la app se muestran igualmente.</p>
  {% for ev,label in events %}
   <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="em_{{ ev }}" style="width:auto" {{ 'checked' if empref[ev] }}> {{ label }}</label>
  {% endfor %}
 </div>
 <div class="card"><h2>Accesibilidad</h2>
  <label>Tema</label>
  <select id="prefTheme" onchange="prefTheme(this.value)" style="max-width:240px">
   <option value="auto">Automático (según el sistema)</option>
   <option value="light">Claro</option>
   <option value="dark">Oscuro</option>
  </select>
  <label style="font-weight:400;display:block;padding:8px 0"><input type="checkbox" id="prefBig" onchange="prefFlag('evestigia-bigtext','data-bigtext',this.checked)" style="width:auto"> Texto más grande</label>
  <label style="font-weight:400;display:block;padding:2px 0"><input type="checkbox" id="prefReduce" onchange="prefFlag('evestigia-reduce','data-reduce',this.checked)" style="width:auto"> Reducir animaciones</label>
  <p class="muted" style="font-size:12px;margin:6px 0 0">Estos ajustes se guardan en este navegador.</p>
 </div>
 <button class="btn">Guardar preferencias</button>
</form>
<div class="card" style="margin-top:12px"><h2>Recorrido y ayuda</h2>
 <form method="post" action="{{ url_for('preferences') }}" style="display:inline"><input type="hidden" name="action" value="tour"><button class="btn sec sm">Volver a ver el recorrido guiado</button></form>
 <form method="post" action="{{ url_for('preferences') }}" style="display:inline;margin-left:6px"><input type="hidden" name="action" value="show_steps"><button class="btn sec sm">Volver a mostrar "Primeros pasos"</button></form>
</div>
<script>
function prefFlag(key,attr,on){ try{ if(on) localStorage.setItem(key,'1'); else localStorage.removeItem(key);
  if(on) document.documentElement.setAttribute(attr,'1'); else document.documentElement.removeAttribute(attr);}catch(e){} }
(function(){ try{
  var el=document.getElementById('prefTheme'); if(el) el.value=localStorage.getItem('evestigia-theme')||'auto';
  var b=document.getElementById('prefBig'); if(b) b.checked=localStorage.getItem('evestigia-bigtext')==='1';
  var r=document.getElementById('prefReduce'); if(r) r.checked=localStorage.getItem('evestigia-reduce')==='1';
}catch(e){} })();
</script>
{% endif %}

<h2>Páginas publicas</h2>
{% for p in pages %}<div class="card between">
 <b><a href="{{ url_for('page_view', pid=p['id']) }}">{{ p['title'] }}</a></b>
</div>
{% else %}<p class="muted">Sin páginas publicas.</p>{% endfor %}
"""


@app.route("/u/<username>")
@login_required
def profile(username):
    db, u = get_db(), current_user()
    prof = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not prof:
        abort(404)
    pages = db.execute("""SELECT p.*, (SELECT COUNT(*) FROM page_reads r WHERE r.page_id=p.id) reads
                          FROM pages p WHERE owner_id=? AND visibility='public' AND id IS NOT ?
                          ORDER BY id DESC""", (prof["id"], prof["profile_page_id"])).fetchall()
    n_contacts = db.execute("""SELECT COUNT(*) c FROM contacts WHERE status='accepted'
                               AND (requester_id=? OR addressee_id=?)""", (prof["id"], prof["id"])).fetchone()["c"]
    contactos = db.execute("""SELECT us.* FROM contacts c JOIN users us
          ON us.id = CASE WHEN c.requester_id=? THEN c.addressee_id ELSE c.requester_id END
        WHERE c.status='accepted' AND (c.requester_id=? OR c.addressee_id=?)
        ORDER BY us.name LIMIT 24""", (prof["id"], prof["id"], prof["id"])).fetchall()
    grupos = db.execute("""SELECT g.id, g.name FROM groups g JOIN group_members m ON m.group_id=g.id
                           WHERE m.user_id=? ORDER BY g.name""", (prof["id"],)).fetchall()
    bio_layout = page_rows(prof["profile_page_id"]) if prof["profile_page_id"] else None
    empref = {ev: (get_setting("emailpref_%d_%s" % (prof["id"], ev), "1") != "0") for ev, _l in USER_EMAIL_EVENTS}
    return render(PROFILE_TPL, title=prof["name"], prof=prof, pages=pages,
                  n_contacts=n_contacts, contactos=contactos, grupos=grupos,
                  is_me=(prof["id"] == u["id"]), status=contact_status(u["id"], prof["id"]),
                  bio_layout=bio_layout, empref=empref, events=USER_EMAIL_EVENTS,
                  render_block=lambda b: block_html(b))


@app.route("/profile/edit", methods=["POST"])
@login_required
def edit_profile():
    db, u = get_db(), current_user()
    avatar = u["avatar"]
    af = request.files.get("avatar")
    if af and af.filename:
        ext = af.filename.rsplit(".", 1)[-1].lower()
        if ext in IMAGE_EXT:
            avatar = "av_%s_%s" % (secrets.token_hex(6), secure_filename(af.filename))
            af.save(os.path.join(UPLOAD_DIR, avatar))
        else:
            flash("La foto debe ser una imagen (png, jpg, ...).", "error")
    db.execute("UPDATE users SET name=?,bio=?,email=?,avatar=? WHERE id=?",
               (request.form["name"].strip(), request.form.get("bio", "").strip(),
                request.form.get("email", "").strip(), avatar, u["id"]))
    db.commit()
    flash("Perfil actualizado.")
    return redirect(url_for("profile", username=u["username"]))


@app.route("/profile/password", methods=["POST"])
@login_required
def change_password():
    db, u = get_db(), current_user()
    full = db.execute("SELECT * FROM users WHERE id=?", (u["id"],)).fetchone()
    cur = request.form.get("current", "")
    new = request.form.get("new", "")
    new2 = request.form.get("new2", "")
    if not check_password_hash(full["password"], cur):
        flash("La contraseña actual no es correcta.", "error")
    elif len(new) < 6:
        flash("La nueva contraseña debe tener al menos 6 caracteres.", "error")
    elif new != new2:
        flash("Las contraseñas nuevas no coinciden.", "error")
    else:
        db.execute("UPDATE users SET password=? WHERE id=?",
                   (generate_password_hash(new, method=HASH), u["id"]))
        set_setting("pw_changed_%d" % u["id"], "1")
        db.commit()
        flash("Contraseña actualizada.")
    return redirect(url_for("profile", username=u["username"]))


@app.route("/profile/bio/edit")
@login_required
def bio_edit():
    db, u = get_db(), current_user()
    ppid = u["profile_page_id"]
    if not ppid:
        ppid = db.execute("""INSERT INTO pages(owner_id,title,description,visibility,created_at)
                             VALUES(?,?,?,?,?)""",
                          (u["id"], "Biografia de %s" % u["name"], "", "private", now())).lastrowid
        db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)", (ppid, 0, "1"))
        db.execute("UPDATE users SET profile_page_id=? WHERE id=?", (ppid, u["id"]))
        db.commit()
    return redirect(url_for("page_edit", pid=ppid))


# --------------------------------------------------------------------------- #
#  Colecciones
# --------------------------------------------------------------------------- #
COL_EDIT_TPL = """
<div class="between"><h1>Modificar colección</h1>
 <a class="btn sec" href="{{ url_for('pages') }}">Volver a Mis páginas</a></div>
<div class="card"><h2>Nombre y privacidad</h2>
 <form method="post" action="{{ url_for('collection_rename', cid=col['id']) }}">
  <label>Nombre</label><input name="title" value="{{ col['title'] }}" required>
  <label>Privacidad</label>
  <select name="visibility">
   <option value="private" {{ 'selected' if col['visibility']=='private' }}>Privada (solo tú)</option>
   <option value="teachers" {{ 'selected' if col['visibility']=='teachers' }}>Docentes</option>
   <option value="public" {{ 'selected' if col['visibility']=='public' }}>Pública (toda la plataforma)</option></select>
  <button class="btn sec sm">Guardar</button></form>
 {% if pages %}<div class="row-flex" style="margin-top:12px">
  <a class="btn sm" href="{{ url_for('collection_view', cid=col['id']) }}">Ver colección</a>
  {% if feat('stu_pdf') %}<a class="btn sec sm" href="{{ url_for('collection_pdf', cid=col['id']) }}">Descargar PDF</a>{% endif %}</div>{% endif %}
</div>

<div class="card"><h2>Páginas de la colección</h2>
 {% for pg in pages %}<div class="between" style="padding:6px 0">
  <div><b>{{ loop.index }}.</b> <a href="{{ url_for('page_view', pid=pg['id']) }}">{{ pg['title'] }}</a></div>
  <form method="post" action="{{ url_for('collection_remove_page', cid=col['id']) }}">
   <input type="hidden" name="page_id" value="{{ pg['id'] }}">
   <button class="btn sec sm">Quitar</button></form>
 </div>{% else %}<p class="muted">Esta colección aún no tiene páginas.</p>{% endfor %}
 {% if all_pages %}<form method="post" action="{{ url_for('collection_add', cid=col['id']) }}" class="row-flex" style="margin-top:10px">
  <select name="page_id" style="flex:1;margin:0">{% for pg in all_pages %}<option value="{{ pg['id'] }}">{{ pg['title'] }}</option>{% endfor %}</select>
  <button class="btn sec sm">Añadir página</button></form>{% endif %}
</div>

<div class="card"><h2>Eliminar colección</h2>
 <p class="muted">Se elimina la colección. Tus páginas no se borran.</p>
 <form method="post" action="{{ url_for('collection_del', cid=col['id']) }}" onsubmit="return confirm('¿Eliminar esta colección?')">
  <button class="btn danger sm">Eliminar colección</button></form>
</div>
"""


@app.route("/collections")
@login_required
def collections():
    # 'Colecciones' se gestiona ahora desde 'Mis páginas'.
    return redirect(url_for("pages"))


@app.route("/collections/new", methods=["POST"])
@login_required
def collection_new():
    if not feature_on("stu_collections"):
        abort(403)
    db, u = get_db(), current_user()
    cid = db.execute("INSERT INTO collections(owner_id,title,created_at) VALUES(?,?,?)",
                     (u["id"], request.form["title"].strip(), now())).lastrowid
    db.commit()
    flash("Colección creada. Añade páginas.")
    return redirect(url_for("collection_edit", cid=cid))


@app.route("/collections/<int:cid>/edit")
@login_required
def collection_edit(cid):
    db, u = get_db(), current_user()
    col = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
    if not col or col["owner_id"] != u["id"]:
        abort(403)
    pages = db.execute("""SELECT p.* FROM collection_pages cp JOIN pages p ON p.id=cp.page_id
                          WHERE cp.collection_id=? ORDER BY cp.position""", (cid,)).fetchall()
    in_ids = [p["id"] for p in pages]
    all_pages = [p for p in db.execute(
        "SELECT * FROM pages WHERE owner_id=? AND id IS NOT ? ORDER BY title",
        (u["id"], u["profile_page_id"])).fetchall() if p["id"] not in in_ids]
    return render(COL_EDIT_TPL, title="Modificar colección", col=col, pages=pages, all_pages=all_pages)


@app.route("/collections/<int:cid>/rename", methods=["POST"])
@login_required
def collection_rename(cid):
    db, u = get_db(), current_user()
    c = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
    if not c or c["owner_id"] != u["id"]:
        abort(403)
    title = request.form.get("title", "").strip()
    vis = request.form.get("visibility", c["visibility"])
    if vis not in VIS:
        vis = "private"
    if title:
        db.execute("UPDATE collections SET title=?, visibility=? WHERE id=?", (title, vis, cid))
        db.commit()
        flash("Colección actualizada.")
    return redirect(url_for("collection_edit", cid=cid))


@app.route("/collections/<int:cid>/pages/remove", methods=["POST"])
@login_required
def collection_remove_page(cid):
    db, u = get_db(), current_user()
    c = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
    if not c or c["owner_id"] != u["id"]:
        abort(403)
    db.execute("DELETE FROM collection_pages WHERE collection_id=? AND page_id=?",
               (cid, request.form.get("page_id")))
    db.commit()
    flash("Página quitada de la colección.")
    return redirect(url_for("collection_edit", cid=cid))


@app.route("/collections/<int:cid>/delete", methods=["POST"])
@login_required
def collection_del(cid):
    db, u = get_db(), current_user()
    c = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
    if not c or c["owner_id"] != u["id"]:
        abort(403)
    db.execute("DELETE FROM collections WHERE id=?", (cid,))
    db.commit()
    flash("Colección eliminada.")
    return redirect(url_for("pages"))


COL_VIEW_TPL = """
<div class="between"><h1>{{ col['title'] }}</h1>
 <a class="btn sec" href="{{ url_for('collection_edit', cid=col['id']) }}">Volver a la colección</a></div>
<div class="between" style="margin-bottom:10px">
 <span class="muted">Página {{ i+1 }} de {{ total }} &middot; <b>{{ page['title'] }}</b>
  <span class="pill">{{ vis[page['visibility']] }}</span></span>
 <span class="row-flex">
  {% if i>0 %}<a class="btn sec sm" href="?i={{ i-1 }}">&larr; Anterior</a>{% endif %}
  {% if i<total-1 %}<a class="btn sm" href="?i={{ i+1 }}">Siguiente &rarr;</a>{% endif %}
 </span></div>
{% if page['description'] %}<p class="muted">{{ page['description'] }}</p>{% endif %}
<div class="card">
 {% for R in layout %}<div class="prow" style="grid-template-columns:{{ R['weights']|join('fr ') }}fr">
  {% for col2 in R['cols'] %}<div class="pcol">
   {% for b in col2 %}<div style="margin-bottom:14px">{{ render_block(b)|safe }}</div>{% endfor %}
  </div>{% endfor %}</div>
 {% else %}<p class="muted">Esta página no tiene contenido.</p>{% endfor %}
</div>
<div class="between">
 <span>{% if i>0 %}<a class="btn sec" href="?i={{ i-1 }}">&larr; Anterior</a>{% endif %}</span>
 <div class="row-flex">{% for pg in pages %}
  <a class="btn {{ 'sec' if pg['id']!=page['id'] else '' }} sm" href="?i={{ loop.index0 }}" title="{{ pg['title'] }}">{{ loop.index }}</a>{% endfor %}</div>
 <span>{% if i<total-1 %}<a class="btn" href="?i={{ i+1 }}">Siguiente &rarr;</a>{% endif %}</span>
</div>
<div class="card"><h2>Comentarios y feedback</h2>
 {% set nxt = url_for('collection_view', cid=col['id']) ~ '?i=' ~ i %}
 {% for c in threads %}<div class="comment">
  <b>{{ c['name'] }}</b> <span class="pill">{{ role_es(c['role']) }}</span> <span class="muted">{{ c['created_at'] }}</span>
  <div>{{ c['body'] }}</div>
  {% for rp in c['replies'] %}<div class="comment" style="margin:8px 0 0 22px;background:#fff">
   <b>{{ rp['name'] }}</b> <span class="pill">{{ role_es(rp['role']) }}</span> <span class="muted">{{ rp['created_at'] }}</span>
   <div>{{ rp['body'] }}</div></div>{% endfor %}
  {% if can_comment %}<details class="add" style="margin-top:6px"><summary>Responder</summary>
   <form method="post" action="{{ url_for('add_comment', pid=page['id']) }}" style="margin-top:6px">
    <input type="hidden" name="parent_id" value="{{ c['id'] }}"><input type="hidden" name="next" value="{{ nxt }}">
    <textarea name="body" required></textarea><button class="btn sm">Responder</button></form></details>{% endif %}
 </div>{% else %}<p class="muted">Sin comentarios en esta página.</p>{% endfor %}
 {% if can_comment %}<form method="post" action="{{ url_for('add_comment', pid=page['id']) }}" style="margin-top:12px">
  <input type="hidden" name="next" value="{{ nxt }}">
  <textarea name="body" placeholder="Escribe un comentario para el estudiante..." required></textarea>
  <button class="btn">Públicar comentario</button></form>{% endif %}
</div>
<a class="btn sec sm" style="margin-top:12px" href="{{ url_for('page_view', pid=page['id']) }}">Abrir esta página (vista normal)</a>
"""


@app.route("/collections/<int:cid>/view")
@login_required
def collection_view(cid):
    db, u = get_db(), current_user()
    col = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
    if not col or not can_view_collection(col, u):
        abort(403)
    pages = db.execute("""SELECT p.* FROM collection_pages cp JOIN pages p ON p.id=cp.page_id
                          WHERE cp.collection_id=? ORDER BY cp.position""", (cid,)).fetchall()
    if not pages:
        flash("Esa colección no tiene páginas todavia.", "error")
        return redirect(url_for("collections"))
    try:
        i = int(request.args.get("i", 0))
    except ValueError:
        i = 0
    i = max(0, min(i, len(pages) - 1))
    page = pages[i]
    comments = db.execute("""SELECT c.*,us.name,us.role FROM comments c JOIN users us ON us.id=c.author_id
                             WHERE page_id=? ORDER BY c.id""", (page["id"],)).fetchall()
    return render(COL_VIEW_TPL, title=col["title"], col=col, page=page, pages=pages,
                  layout=page_rows(page["id"]), i=i, total=len(pages), vis=VIS,
                  threads=build_threads(comments),
                  can_comment=(u["role"] in ("teacher", "admin") or page["owner_id"] == u["id"]),
                  render_block=lambda b: block_html(b))


@app.route("/collections/<int:cid>/add", methods=["POST"])
@login_required
def collection_add(cid):
    db, u = get_db(), current_user()
    c = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
    if not c or c["owner_id"] != u["id"]:
        abort(403)
    pos = db.execute("SELECT COALESCE(MAX(position),-1)+1 n FROM collection_pages WHERE collection_id=?", (cid,)).fetchone()["n"]
    try:
        db.execute("INSERT INTO collection_pages(collection_id,page_id,position) VALUES(?,?,?)",
                   (cid, request.form["page_id"], pos))
        db.commit()
    except sqlite3.IntegrityError:
        flash("Esa página ya está en la colección.", "error")
    return redirect(url_for("collection_edit", cid=cid))


# --------------------------------------------------------------------------- #
#  Docente / admin
# --------------------------------------------------------------------------- #
REVIEW_TPL = """
<h1>Revisar portafolios</h1><p class="muted">Páginas compartidas con docentes o publicas.</p>
{% for s in students %}<div class="card">
 <b><a href="{{ url_for('profile', username=s['username']) }}">{{ s['name'] }}</a></b> <span class="muted">@{{ s['username'] }}</span>
 {% if s['pages'] %}<ul>{% for p in s['pages'] %}
  <li><a href="{{ url_for('page_view', pid=p['id']) }}">{{ p['title'] }}</a> <span class="pill">{{ vis[p['visibility']] }}</span>
   &middot; <a href="{{ url_for('page_pdf', pid=p['id']) }}">PDF</a></li>{% endfor %}</ul>
 {% else %}<div class="muted">Sin páginas compartidas.</div>{% endif %}
</div>{% else %}<p class="muted">No hay estudiantes.</p>{% endfor %}
"""


@app.route("/review")
@login_required
@role_required("teacher", "admin")
def review():
    db = get_db()
    students = []
    for s in db.execute("SELECT * FROM users WHERE role='student' ORDER BY name").fetchall():
        pgs = db.execute("""SELECT * FROM pages WHERE owner_id=? AND visibility IN ('teachers','public')
                            ORDER BY id DESC""", (s["id"],)).fetchall()
        students.append({"name": s["name"], "username": s["username"], "pages": pgs})
    return render(REVIEW_TPL, title="Revisar", students=students, vis=VIS)


ADMIN_TPL = """
<div class="between"><h1>Usuarios</h1><a class="btn sec" href="{{ url_for('admin_home') }}">Volver a Administración</a></div>
<div class="card"><h2>Crear usuario</h2>
 <form method="post" action="{{ url_for('admin_new') }}">
  <div class="row-flex"><div style="flex:1"><label>Nombre</label><input name="name" required></div>
   <div style="flex:1"><label>Usuario</label><input name="username" required></div></div>
  <div class="row-flex"><div style="flex:1"><label>Contraseña</label><input name="password" placeholder="Se genera automáticamente si lo dejas vacío"></div>
   <div style="flex:1"><label>Rol</label><select name="role">
    <option value="student">Estudiante</option><option value="teacher">Docente</option>
    <option value="admin">Admin</option></select></div></div>
  <label>Email (para avisos y envío de credenciales)</label><input name="email" type="email">
  <label style="font-weight:400;display:block;margin:8px 0"><input type="checkbox" name="sendmail" style="width:auto"> Enviar la contraseña por email al usuario</label>
  <button class="btn">Crear</button></form></div>
<div class="card"><h2>Importar usuarios (Excel o CSV)</h2>
 <p class="muted">Columnas: <code>nombre, usuario, contraseña, rol, email</code>. La contraseña es opcional: si la dejas vacía se genera automáticamente y (si hay email) se envía al usuario.
  <a href="{{ url_for('admin_users_template') }}">Descargar plantilla CSV</a></p>
 <form method="post" action="{{ url_for('admin_users_import') }}" enctype="multipart/form-data" class="row-flex">
  <input type="file" name="file" accept=".csv,.xlsx" style="flex:1;margin:0">
  <button class="btn">Importar</button></form></div>
<div class="card"><h2>Usuarios ({{ users|length }})</h2>
 <p class="muted">El correo {{ 'está activo: los envíos se mandan de verdad.' if email_on else 'está en modo demo: los envíos se registran en el historial pero no se mandan.' }}</p>
 <table><tr><th>Nombre</th><th>Usuario</th><th>Email</th><th>Rol</th><th>Contraseña</th></tr>
 {% for u in users %}<tr>
  <td>{{ u['name'] }}</td><td>@{{ u['username'] }}</td>
  <td><form method="post" action="{{ url_for('admin_set_email', uid=u['id']) }}" class="row-flex" style="gap:4px">
   <input name="email" type="email" value="{{ u['email'] or '' }}" placeholder="sin email" style="margin:0;padding:5px 8px;min-width:160px">
   <button class="btn sec sm">Guardar</button></form></td>
  <td>{% if u['id'] != user['id'] %}
   <form method="post" action="{{ url_for('admin_set_role', uid=u['id']) }}" class="row-flex" style="gap:4px">
    <select name="role" style="width:auto;margin:0;padding:5px 8px">
     <option value="student" {{ 'selected' if u['role']=='student' }}>Estudiante</option>
     <option value="teacher" {{ 'selected' if u['role']=='teacher' }}>Docente</option>
     <option value="admin" {{ 'selected' if u['role']=='admin' }}>Admin</option></select>
    <button class="btn sec sm">Cambiar</button></form>
   {% else %}<span class="pill">{{ role_es(u['role']) }}</span> <span class="muted">(tu cuenta)</span>{% endif %}</td>
  <td><form method="post" action="{{ url_for('admin_reset_pw', uid=u['id']) }}" onsubmit="return confirm('¿Restablecer la contraseña de @{{ u['username'] }}? Se generará una nueva.')">
    <button class="btn sec sm">Restablecer</button></form></td>
 </tr>{% endfor %}</table></div>
"""


def _temp_password(n=10):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    return "".join(secrets.choice(alphabet) for _ in range(n))


@app.route("/admin/users")
@login_required
@role_required("admin")
def admin_users():
    users = get_db().execute("SELECT * FROM users ORDER BY role,name").fetchall()
    return render(ADMIN_TPL, title="Usuarios", users=users, email_on=email_config()["enabled"])


@app.route("/admin/users/new", methods=["POST"])
@login_required
@role_required("admin")
def admin_new():
    db = get_db()
    username = request.form["username"].strip()
    pw = request.form.get("password", "").strip()
    generated = False
    if not pw:
        pw = _temp_password()
        generated = True
    name = request.form["name"].strip()
    role = request.form["role"]
    email = request.form.get("email", "").strip()
    try:
        db.execute("INSERT INTO users(username,password,name,role,email) VALUES(?,?,?,?,?)",
                   (username, generate_password_hash(pw, method=HASH), name, role, email))
        db.commit()
        parts = ["Usuario creado."]
        if generated:
            parts.append("Contraseña generada: %s" % pw)
        if request.form.get("sendmail") and email:
            ok, msg = send_email(email, "Tu cuenta en Vestigia",
                                 "Hola %s,\n\nSe ha creado tu cuenta en Vestigia.\n\n"
                                 "Usuario: %s\nContraseña: %s\n\n"
                                 "Te recomendamos cambiarla tras iniciar sesión.\n\n-- Vestigia"
                                 % (name or username, username, pw))
            parts.append("Email: " + msg)
        flash("  ·  ".join(parts))
    except sqlite3.IntegrityError:
        flash("Ese usuario ya existe.", "error")
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/role", methods=["POST"])
@login_required
@role_required("admin")
def admin_set_role(uid):
    db, me = get_db(), current_user()
    if uid == me["id"]:
        flash("No puedes cambiar tu propio rol.", "error")
        return redirect(url_for("admin_users"))
    role = request.form.get("role")
    if role not in ("student", "teacher", "admin"):
        abort(400)
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    db.commit()
    flash("Rol de @%s actualizado a %s." % (u["username"], role))
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/email", methods=["POST"])
@login_required
@role_required("admin")
def admin_set_email(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    email = request.form.get("email", "").strip()
    db.execute("UPDATE users SET email=? WHERE id=?", (email, uid))
    db.commit()
    flash("Email de @%s actualizado." % u["username"])
    return redirect(url_for("admin_users"))


@app.route("/admin/users/<int:uid>/reset", methods=["POST"])
@login_required
@role_required("admin")
def admin_reset_pw(uid):
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        abort(404)
    pw = _temp_password()
    db.execute("UPDATE users SET password=? WHERE id=?",
               (generate_password_hash(pw, method=HASH), uid))
    db.commit()
    if u["email"]:
        ok, msg = send_email(u["email"], "Restablecimiento de contraseña - Vestigia",
                             "Hola %s,\n\nUn administrador ha restablecido tu contraseña en Vestigia.\n\n"
                             "Nueva contraseña: %s\n\nTe recomendamos cambiarla tras iniciar sesión.\n\n-- Vestigia"
                             % (u["name"], pw))
        flash("Contraseña de @%s restablecida. Nueva: %s  ·  Email: %s" % (u["username"], pw, msg))
    else:
        flash("Contraseña de @%s restablecida. Nueva: %s (sin email registrado para enviarla)" % (u["username"], pw))
    return redirect(url_for("admin_users"))


@app.errorhandler(403)
def e403(e):
    return render("<div class='card'><h1>403</h1><p>Sin acceso.</p><a class='btn' href='/'>Inicio</a></div>", title="403"), 403


@app.errorhandler(404)
def e404(e):
    return render("<div class='card'><h1>404</h1><p>No encontrado.</p><a class='btn' href='/'>Inicio</a></div>", title="404"), 404


@app.errorhandler(413)
def e413(e):
    return render("<div class='card'><h1>Subida demasiado grande</h1>"
                  "<p>El conjunto de archivos supera el tamaño máximo permitido (1 GB). "
                  "Sube menos archivos a la vez o reduce el tamaño de los vídeos, y vuelve a intentarlo.</p>"
                  "<a class='btn' href='javascript:history.back()'>Volver</a></div>",
                  title="Demasiado grande"), 413


# =========================== v5: avisos, email, PDF, analiticas ============= #
EMAIL_LOG = os.path.join(BASE_DIR, "email_outbox.log")


def get_setting(key, default=None):
    r = get_db().execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    return r["value"] if r else default


def set_setting(key, value):
    db = get_db()
    db.execute("INSERT INTO settings(key,value) VALUES(?,?) "
               "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))
    db.commit()


# --------------------------------------------------------------------------- #
#  Tema personalizable por el administrador (para rebranding / open source)
# --------------------------------------------------------------------------- #
THEME_DEFAULTS = {"brand": "#7a1f3d", "brand2": "#c0325f", "accent": "#ff5c8a",
                  "bg": "#f2f0f5", "font": "Inter", "font_size": "16", "site_name": "eVestigia"}
THEME_FONTS = {
    "Inter": "Inter:wght@400;500;600;700;800",
    "Roboto": "Roboto:wght@400;500;700",
    "Poppins": "Poppins:wght@400;500;600;700",
    "Nunito": "Nunito:wght@400;600;700;800",
    "Merriweather": "Merriweather:wght@400;700",
    "Lora": "Lora:wght@400;500;600;700",
    "System": None,
}


def theme_settings():
    t = dict(THEME_DEFAULTS)
    for k in list(t.keys()):
        v = get_setting("theme_" + k)
        if v:
            t[k] = v
    t["logo"] = get_setting("theme_logo") or ""
    t["favicon"] = get_setting("theme_favicon") or ""
    return t


def theme_css():
    """Devuelve un <style> que sobrescribe las variables del tema con lo que fije el administrador."""
    t = theme_settings()
    font = t["font"] if t["font"] in THEME_FONTS else "Inter"
    try:
        fs = max(11, min(22, int(t["font_size"])))
    except Exception:
        fs = 16
    imp = ""
    if THEME_FONTS.get(font):
        imp = "@import url('https://fonts.googleapis.com/css2?family=%s&display=swap');" % THEME_FONTS[font]
    fam = ("-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,Helvetica,Arial,sans-serif"
           if font == "System" else "'%s',-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif" % font)
    return ("<style>%s:root{--brand:%s;--brand2:%s;--accent:%s;--bg:%s}"
            "body{font-family:%s;font-size:%dpx}"
            "header{background:linear-gradient(135deg,var(--brand),var(--brand2) 90%%)}"
            ".btn{background:linear-gradient(135deg,var(--brand),var(--brand2))}</style>") % (
        imp, t["brand"], t["brand2"], t["accent"], t["bg"], fam, fs)


# Funciones del alumnado que el administrador puede activar/ocultar (por defecto todas activas).
STUDENT_FEATURES = [
    ("stu_community", "Comunidad y portafolios públicos"),
    ("stu_contacts", "Buscar personas y añadir conocidos"),
    ("stu_messages", "Mensajería"),
    ("stu_groups", "Grupos (crear y unirse)"),
    ("stu_collections", "Colecciones"),
    ("stu_comment", "Comentar páginas de otros"),
    ("stu_public", "Públicar páginas como 'Pública'"),
    ("stu_pdf", "Descargar / exportar PDF"),
    ("stu_tour", "Mostrar el tour de bienvenida"),
]


def feature_on(key):
    """True si la función esta disponible para el usuario actual. El alumnado se limita por ajustes;
    docentes y admin siempre tienen todo."""
    u = current_user()
    if not u or u["role"] != "student":
        return True
    return get_setting(key, "1") != "0"


def storage_quota_bytes():
    try:
        return int(get_setting("storage_quota_mb", "600")) * 1024 * 1024
    except Exception:
        return STORAGE_QUOTA


app.jinja_env.globals["feat"] = feature_on

ROLE_ES = {"student": "Estudiante", "teacher": "Docente", "admin": "Admin"}
app.jinja_env.globals["role_es"] = lambda r: ROLE_ES.get(r, r)


def chat_enabled_dm():
    return get_setting("chat_dm", "1") != "0"


def chat_enabled_group():
    return get_setting("chat_group", "1") != "0"


def chat_retention_days():
    try:
        return int(get_setting("chat_retention_days", "120"))
    except Exception:
        return 120


def chat_encrypt(text):
    """Cifra el cuerpo del mensaje en reposo. enc=1 Fernet (AES); enc=2 alternativo (Python puro); enc=0 sin cifrar."""
    f = _fernet()
    if f:
        try:
            return f.encrypt((text or "").encode()).decode(), 1
        except Exception:
            pass
    tok = _std_encrypt(text)      # alternativo en Python puro (no necesita cryptography)
    if tok is not None:
        return tok, 2
    return (text or ""), 0


def chat_decrypt(body_enc, enc):
    if enc == 2:
        return _std_decrypt(body_enc or "")
    if enc:
        f = _fernet()
        if not f:
            return "[cifrado: falta la clave del administrador]"
        try:
            return f.decrypt((body_enc or "").encode()).decode()
        except Exception:
            return "[no se pudo descifrar]"
    return body_enc or ""


def chat_purge_old():
    """Borra mensajes de chat mas antiguos que la retencion (por defecto 4 meses)."""
    try:
        from datetime import timedelta
        cutoff = (datetime.now() - timedelta(days=chat_retention_days())).strftime("%Y-%m-%d %H:%M")
        db = get_db()
        db.execute("DELETE FROM chat_messages WHERE created_at < ?", (cutoff,))
        db.commit()
    except Exception:
        pass


Fernet = None
HAS_CRYPTO = False
CRYPTO_IMPORT_ERROR = ""


def _try_import_crypto():
    """Intenta importar cryptography y guarda el error real si falla."""
    global Fernet, HAS_CRYPTO, CRYPTO_IMPORT_ERROR
    try:
        from cryptography.fernet import Fernet as _F
        Fernet = _F
        HAS_CRYPTO = True
        CRYPTO_IMPORT_ERROR = ""
    except Exception as e:
        HAS_CRYPTO = False
        CRYPTO_IMPORT_ERROR = "%s: %s" % (type(e).__name__, e)
    return HAS_CRYPTO


CRYPTO_INSTALL_LOG = ""


def ensure_cryptography():
    """Si falta cryptography, intenta instalarla en el MISMO intérprete que ejecuta la app.
    El Python de las Command Line Tools de Apple no trae pip: primero se arranca con ensurepip."""
    global CRYPTO_INSTALL_LOG
    if _try_import_crypto():
        return True
    import sys as _sys
    import subprocess as _sp
    log = []

    def _run(args, timeout=300):
        try:
            r = _sp.run([_sys.executable] + args, capture_output=True, text=True, timeout=timeout)
            log.append("$ %s -> rc=%s\n%s%s" % (" ".join(args), r.returncode,
                                                (r.stdout or "")[-800:], (r.stderr or "")[-800:]))
            return r.returncode
        except Exception as e:
            log.append("$ %s -> EXCEPCIÓN: %s" % (" ".join(args), e))
            return -1

    print("[Vestigia] Falta 'cryptography' (%s). Intentando instalarla en %s ..."
          % (CRYPTO_IMPORT_ERROR, _sys.executable))
    # 1) Asegurar que pip existe para este intérprete (clave en el Python de Apple CLT).
    _run(["-m", "ensurepip", "--upgrade"])
    # 2) Actualizar pip para que reconozca las 'wheels' recientes (evita compilar desde fuente).
    _run(["-m", "pip", "install", "--upgrade", "pip", "--quiet", "--user"])
    # 3) Instalar cryptography con varias estrategias.
    for args in (["-m", "pip", "install", "cryptography", "--quiet", "--user"],
                 ["-m", "pip", "install", "cryptography", "--quiet"],
                 ["-m", "pip", "install", "cryptography", "--quiet", "--break-system-packages"]):
        _run(args)
        if _try_import_crypto():
            print("[Vestigia] 'cryptography' instalada y cargada correctamente.")
            return True
    CRYPTO_INSTALL_LOG = "\n".join(log)
    try:
        with open(os.path.join(BASE_DIR, "critical_alerts.log"), "a", encoding="utf-8") as f:
            f.write("[%s] No se pudo instalar cryptography automáticamente:\n%s\n%s\n"
                    % (datetime.now().strftime("%Y-%m-%d %H:%M"), CRYPTO_INSTALL_LOG, "-" * 54))
    except Exception:
        pass
    print("[Vestigia] No se pudo instalar 'cryptography' automáticamente. "
          "Revisa critical_alerts.log para el detalle.")
    _try_import_crypto()
    return HAS_CRYPTO


_try_import_crypto()


def _fernet():
    if not HAS_CRYPTO:
        return None
    k = os.environ.get("EVESTIGIA_SECRET_KEY")
    if not k:
        keyfile = os.path.join(BASE_DIR, "evestigia_secret.key")
        try:
            if os.path.exists(keyfile):
                k = open(keyfile).read().strip()
            else:
                k = Fernet.generate_key().decode()
                with open(keyfile, "w") as fh:
                    fh.write(k)
                try:
                    os.chmod(keyfile, 0o600)
                except Exception:
                    pass
        except Exception:
            return None
    try:
        return Fernet(k.encode() if isinstance(k, str) else k)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
#  Cifrado alternativo en Python puro (sin dependencias que haya que compilar).
#  Se usa SOLO cuando 'cryptography' (Fernet/AES) no está disponible, para que el
#  cifrado en reposo funcione siempre. Construcción: keystream con HMAC-SHA256 en
#  modo contador + autenticación encrypt-then-MAC (HMAC-SHA256). Clave del servidor.
# --------------------------------------------------------------------------- #
def _std_keys():
    import hashlib
    src = os.environ.get("EVESTIGIA_SECRET_KEY")
    if src:
        base = src.encode()
    else:
        kf = os.path.join(BASE_DIR, "evestigia_fallback.key")
        try:
            if os.path.exists(kf):
                base = open(kf, "rb").read()
            else:
                base = os.urandom(32)
                with open(kf, "wb") as fh:
                    fh.write(base)
                try:
                    os.chmod(kf, 0o600)
                except Exception:
                    pass
        except Exception:
            return None, None
    enc_key = hashlib.sha256(b"evestigia-enc\x00" + base).digest()
    mac_key = hashlib.sha256(b"evestigia-mac\x00" + base).digest()
    return enc_key, mac_key


def _std_keystream(enc_key, nonce, length):
    import hmac
    import hashlib
    import struct
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(enc_key, nonce + struct.pack(">I", counter), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def _std_encrypt(text):
    """Devuelve un token 'S1:...' o None si no se pudo."""
    import hmac
    import hashlib
    import base64
    enc_key, mac_key = _std_keys()
    if not enc_key:
        return None
    try:
        pt = (text or "").encode("utf-8")
        nonce = os.urandom(16)
        ct = bytes(a ^ b for a, b in zip(pt, _std_keystream(enc_key, nonce, len(pt))))
        tag = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
        return "S1:" + base64.urlsafe_b64encode(nonce + ct + tag).decode()
    except Exception:
        return None


def _std_decrypt(token):
    import hmac
    import hashlib
    import base64
    enc_key, mac_key = _std_keys()
    if not enc_key:
        return "[cifrado alternativo: falta la clave]"
    try:
        raw = base64.urlsafe_b64decode(token[3:].encode())
        nonce, rest = raw[:16], raw[16:]
        ct, tag = rest[:-32], rest[-32:]
        exp = hmac.new(mac_key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(exp, tag):
            return "[no se pudo descifrar]"
        pt = bytes(a ^ b for a, b in zip(ct, _std_keystream(enc_key, nonce, len(ct))))
        return pt.decode("utf-8", "replace")
    except Exception:
        return "[no se pudo descifrar]"


def crypto_status():
    """'fernet' (AES, ideal), 'std' (Python puro, alternativo) o 'none'."""
    if _fernet():
        return "fernet"
    if _std_keys()[0] is not None:
        return "std"
    return "none"


def security_report():
    """Lista de comprobaciones de seguridad/privacidad para el panel del administrador.
    Cada elemento: {'level': 'ok'|'warn'|'bad', 'title', 'detail'}."""
    import stat as _stat
    rep = []

    def add(level, title, detail, link=None, link_label=None):
        rep.append({"level": level, "title": title, "detail": detail, "link": link, "link_label": link_label})

    # Cifrado en reposo
    st = crypto_status()
    if st == "fernet":
        add("ok", "Cifrado en reposo", "AES/Fernet activo. Los mensajes del chat y los secretos se guardan cifrados.")
    elif st == "std":
        add("warn", "Cifrado en reposo", "Activo con el método alternativo (Python puro). Funciona; para AES "
            "estándar instala 'cryptography' en el intérprete de la app.")
    else:
        add("bad", "Cifrado en reposo", "INACTIVO: el contenido se guardaría sin cifrar. Revisa permisos de "
            "escritura de la carpeta o define EVESTIGIA_SECRET_KEY.")

    # Modo depuración
    if getattr(app, "debug", False):
        add("bad", "Modo depuración", "La app corre en modo DEBUG. Desactívalo en producción (no uses EVESTIGIA_DEBUG=1).")
    else:
        add("ok", "Modo depuración", "Desactivado (correcto para producción).")

    # HTTPS
    if app.config.get("SESSION_COOKIE_SECURE"):
        add("ok", "HTTPS / cookies seguras", "Activo.")
    else:
        add("warn", "HTTPS / cookies seguras", "Sin HTTPS forzado. En producción sirve tras HTTPS (nginx + certificado) "
            "y define EVESTIGIA_HTTPS=1.")

    # Envío de correo
    try:
        cfg = email_config()
        if not cfg["enabled"] or not cfg["host"]:
            add("warn", "Envío de correo (SMTP)", "No configurado: los avisos por correo no se envían (quedan en el registro).")
        elif cfg["user"] and not smtp_password():
            add("bad", "Envío de correo (SMTP)", "Hay usuario SMTP pero falta la contraseña: los envíos fallarán. "
                "Guárdala en Administración → Correo o define EVESTIGIA_SMTP_PASS.")
        else:
            add("ok", "Envío de correo (SMTP)", "Configurado correctamente.")
    except Exception:
        pass

    # Avisos críticos
    dests = admin_alert_emails()
    if dests:
        add("ok", "Avisos de fallos críticos", "Se avisará a: %s" % ", ".join(dests))
    else:
        add("warn", "Avisos de fallos críticos", "Sin destinatarios: configura un correo de avisos o pon email a un administrador.")

    # Permisos de archivos sensibles
    def _perm(path, label):
        try:
            if os.path.exists(path):
                mode = _stat.S_IMODE(os.stat(path).st_mode)
                if mode & 0o077:
                    add("warn", "Permisos: %s" % label,
                        "Accesible por otros usuarios del sistema (modo %o). Recomendado 600." % mode)
                else:
                    add("ok", "Permisos: %s" % label, "Correctos (solo el propietario).")
        except Exception:
            pass
    _perm(os.path.join(BASE_DIR, "evestigia_secret.key"), "clave de cifrado")
    _perm(os.path.join(BASE_DIR, "evestigia_fallback.key"), "clave alternativa")
    _perm(DB_PATH, "base de datos")

    # Contraseñas de ejemplo aún activas
    try:
        weak = []
        for uname, pw in (("admin", "admin123"), ("profesor", "profe123"), ("ana", "ana123")):
            r = get_db().execute("SELECT password FROM users WHERE username=?", (uname,)).fetchone()
            if r and check_password_hash(r["password"], pw):
                weak.append(uname)
        if weak:
            add("bad", "Contraseñas de ejemplo", "Estas cuentas mantienen la contraseña de demostración: %s. Cámbialas."
                % ", ".join(weak))
        else:
            add("ok", "Contraseñas de ejemplo", "Las cuentas principales no usan contraseñas de demostración.")
    except Exception:
        pass

    # Contenido público
    try:
        npub = get_db().execute("SELECT COUNT(*) c FROM pages WHERE visibility='public'").fetchone()["c"]
        if npub:
            add("warn", "Contenido público", "%d página(s) son públicas (visibles para cualquier persona "
                "registrada en la plataforma). Revisa que sea intencionado." % npub,
                link="admin_public", link_label="Revisar páginas públicas")
        else:
            add("ok", "Contenido público", "No hay páginas públicas.")
    except Exception:
        pass

    # Copias de seguridad
    lb = get_setting("last_backup")
    if lb:
        add("ok", "Copias de seguridad", "Última copia registrada: %s" % lb,
            link="admin_backup", link_label="Copias de seguridad")
    else:
        add("warn", "Copias de seguridad", "No hay copias registradas. Descarga una copia o automatízalas en el servidor.",
            link="admin_backup", link_label="Hacer copia de seguridad")

    return rep


def enc_secret(text):
    """Cifra un secreto (p. ej. la contraseña SMTP). Usa Fernet si está, o el método alternativo."""
    f = _fernet()
    if f:
        try:
            return f.encrypt(text.encode()).decode()
        except Exception:
            pass
    return _std_encrypt(text)  # 'S1:...' en Python puro; funciona sin cryptography


def dec_secret(token):
    """Descifra un secreto guardado por enc_secret (detecta el método automáticamente)."""
    if not token:
        return None
    if token.startswith("S1:"):
        v = _std_decrypt(token)
        return None if v.startswith("[") else v
    f = _fernet()
    if f:
        try:
            return f.decrypt(token.encode()).decode()
        except Exception:
            return None
    return None


def smtp_password():
    env = os.environ.get("EVESTIGIA_SMTP_PASS")
    if env:
        return env
    return dec_secret(get_setting("smtp_pass_enc"))


def email_config():
    g = get_setting
    return {"enabled": (g("smtp_enabled", os.environ.get("EVESTIGIA_SMTP_ENABLED", "0")) == "1"),
            "host": g("smtp_host", os.environ.get("EVESTIGIA_SMTP_HOST", "")),
            "port": int(g("smtp_port", os.environ.get("EVESTIGIA_SMTP_PORT", "587")) or 587),
            "user": g("smtp_user", os.environ.get("EVESTIGIA_SMTP_USER", "")),
            "from": g("smtp_from", os.environ.get("EVESTIGIA_SMTP_FROM", "noreply@evestigia.org")),
            "security": g("smtp_security", "starttls")}


def _log_email(to_addr, subject, status, detail):
    try:
        db = get_db()
        db.execute("INSERT INTO email_log(to_addr,subject,status,detail,created_at) VALUES(?,?,?,?,?)",
                   (to_addr, subject, status, detail, now()))
        db.commit()
    except Exception:
        pass


def _smtp_login(s, user, pwd):
    try:
        s.login(user, pwd)
    except UnicodeEncodeError:
        import base64
        s.ehlo_or_helo_if_needed()
        code, resp = s.docmd("AUTH", "LOGIN")
        if code != 334:
            raise smtplib.SMTPException("AUTH LOGIN no soportado (%s)" % resp)
        s.docmd(base64.b64encode(user.encode("utf-8")).decode())
        code, resp = s.docmd(base64.b64encode(pwd.encode("utf-8")).decode())
        if code not in (235, 503):
            raise smtplib.SMTPAuthenticationError(code, resp)


def _friendly_smtp_error(e, cfg):
    """Convierte un error técnico de SMTP en una explicación clara y accionable."""
    txt = str(e)
    low = txt.lower()
    host = cfg.get("host", "")
    if "client host rejected" in low or "access denied" in low or "relay" in low or "554" in txt:
        return ("El servidor de correo rechazó el envío (relay/acceso denegado). Casi siempre es porque se "
                "está intentando enviar sin un servidor de envío autenticado desde una IP doméstica. "
                "Solución: configura un servidor SMTP de envío con usuario y contraseña, por ejemplo "
                "smtp.gmail.com (puerto 587, STARTTLS) con una CONTRASEÑA DE APLICACIÓN de Gmail, "
                "o el servidor SMTP de tu institución con tus credenciales. Detalle: " + txt)
    if "authentication" in low or "535" in txt or "credentials" in low or "username and password" in low:
        return ("Autenticación rechazada: usuario o contraseña incorrectos. Si usas Gmail, necesitas una "
                "CONTRASEÑA DE APLICACIÓN (no tu contraseña normal) con la verificación en dos pasos activada. "
                "Detalle: " + txt)
    if "starttls" in low or "ssl" in low or "wrong version" in low or "tls" in low:
        return ("Error de cifrado del transporte. Prueba a cambiar la seguridad: usa STARTTLS con el puerto 587, "
                "o SSL/TLS con el puerto 465. Detalle: " + txt)
    if "name or service not known" in low or "getaddrinfo" in low or "connection refused" in low or "timed out" in low:
        return ("No se pudo conectar con el servidor SMTP '%s'. Revisa el nombre del servidor, el puerto y tu "
                "conexión a internet. Detalle: %s" % (host, txt))
    return "No se pudo enviar el correo. Detalle: " + txt


def _recipient_label(to_addr):
    """@usuario si el correo pertenece a un usuario; si no, el email enmascarado (a***@dominio).
    Nunca expone el email completo en el registro."""
    try:
        u = get_db().execute("SELECT username FROM users WHERE email=?", (to_addr,)).fetchone()
        if u and u["username"]:
            return "@" + u["username"]
    except Exception:
        pass
    a = to_addr or ""
    if "@" in a:
        local, dom = a.split("@", 1)
        return (local[:1] or "?") + "***@" + dom
    return "destinatario oculto"


def _outbox_note(status, subject, to_addr):
    """Anota SOLO el tipo de correo (asunto), el estado y el @usuario. Nunca el cuerpo ni el email."""
    try:
        with open(EMAIL_LOG, "a", encoding="utf-8") as f:
            f.write("[%s] %s · %s · %s\n" % (now(), status, subject, _recipient_label(to_addr)))
    except Exception:
        pass


def send_email(to_addr, subject, body):
    if not to_addr:
        return False, "sin destinatario"
    cfg = email_config()
    if not cfg["enabled"] or not cfg["host"]:
        _outbox_note("NO ENVIADO (SMTP inactivo)", subject, to_addr)
        _log_email(to_addr, subject, "demo", "SMTP no activado")
        return True, "registrado (SMTP no activado)"
    try:
        msg = EmailMessage()
        msg["From"] = cfg["from"]
        msg["To"] = to_addr
        msg["Subject"] = subject
        msg.set_content(body)
        if cfg["security"] == "ssl":
            s = smtplib.SMTP_SSL(cfg["host"], cfg["port"], timeout=20)
        else:
            s = smtplib.SMTP(cfg["host"], cfg["port"], timeout=20)
            if cfg["security"] == "starttls":
                s.starttls()
        pwd = smtp_password()
        if cfg["user"] and pwd:
            _smtp_login(s, cfg["user"], pwd)
        elif cfg["user"] and not pwd:
            s.quit()
            return False, ("Hay un usuario SMTP configurado pero la app no tiene la contraseña, así que se "
                           "enviaría SIN autenticación y el servidor lo rechaza. Vuelve a guardar la contraseña "
                           "en Administración → Correo (ahora ya puede almacenarse cifrada) o define la variable "
                           "de entorno EVESTIGIA_SMTP_PASS.")
        elif not cfg["user"]:
            s.quit()
            return False, ("El servidor SMTP no tiene usuario/contraseña configurados. "
                           "Para enviar correo debes usar un servidor de envío autenticado "
                           "(por ejemplo smtp.gmail.com con una contraseña de aplicación, o el servidor SMTP de tu institución).")
        s.send_message(msg)
        s.quit()
        _log_email(to_addr, subject, "enviado", "OK")
        return True, "enviado correctamente"
    except Exception as e:
        _outbox_note("FALLO AL ENVIAR", subject, to_addr)
        _log_email(to_addr, subject, "error", str(e))
        return False, _friendly_smtp_error(e, cfg)


ALERT_LOG = os.path.join(BASE_DIR, "critical_alerts.log")


def admin_alert_emails():
    """Correos a los que avisar de fallos críticos: variable de entorno + correos de los administradores."""
    emails = []
    env = os.environ.get("EVESTIGIA_ADMIN_ALERT_EMAIL", "").strip()
    if env:
        emails += [e.strip() for e in env.replace(";", ",").split(",") if e.strip()]
    try:
        extra = (get_setting("admin_alert_email", "") or "").strip()
        if extra:
            emails += [e.strip() for e in extra.replace(";", ",").split(",") if e.strip() and e.strip() not in emails]
    except Exception:
        pass
    try:
        for r in get_db().execute("SELECT email FROM users WHERE role='admin' AND email<>''").fetchall():
            if r["email"] and r["email"] not in emails:
                emails.append(r["email"])
    except Exception:
        pass
    return emails


def send_critical_alert(key, subject, body, throttle_hours=6):
    """Avisa por correo a la administración de un fallo crítico. Evita repetir el mismo aviso
    antes de `throttle_hours`. Siempre lo registra en critical_alerts.log."""
    try:
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n%s\n%s\n" % (now(), subject, body, "-" * 54))
    except Exception:
        pass
    # Antirrepetición: no reenviar el mismo aviso si se envió hace poco.
    try:
        last = get_setting("alert_ts_" + key)
        if last:
            from datetime import timedelta
            last_dt = datetime.strptime(last, "%Y-%m-%d %H:%M")
            if datetime.now() - last_dt < timedelta(hours=throttle_hours):
                return False, "silenciado (aviso reciente)"
    except Exception:
        pass
    recipients = admin_alert_emails()
    if not recipients:
        return False, "sin destinatarios de administración"
    sent_any = False
    for to in recipients:
        ok, _msg = send_email(to, subject, body)
        sent_any = sent_any or ok
    try:
        set_setting("alert_ts_" + key, now())
    except Exception:
        pass
    return sent_any, ("enviado a %d administrador(es)" % len(recipients))


def run_critical_checks(context="arranque"):
    """Comprueba fallos críticos y avisa a la administración. Devuelve la lista de problemas."""
    problems = []
    import sys as _sys
    status = crypto_status()
    # 1) Sin NINGÚN cifrado disponible -> crítico: el chat no se puede almacenar cifrado.
    if status == "none":
        problems.append(("cifrado_none",
                         "Vestigia: SIN CIFRADO EN REPOSO (crítico)",
                         "AVISO CRÍTICO (%s)\n\nNo hay ningún cifrado en reposo disponible (ni AES ni el alternativo). "
                         "Revisa los permisos de escritura de la carpeta de la app o define EVESTIGIA_SECRET_KEY.\n\n"
                         "-- Vestigia" % context))
    elif status == "std":
        # Funciona con el cifrado alternativo (Python puro); solo se recomienda instalar cryptography para AES.
        problems.append(("cifrado_std",
                         "Vestigia: usando cifrado alternativo (recomendado instalar cryptography)",
                         "AVISO (%s)\n\nEl chat SÍ se está cifrando en reposo, pero con el método alternativo en "
                         "Python puro porque no se pudo cargar 'cryptography' (AES/Fernet).\n\n"
                         "Error de importación: %s\nIntérprete: %s\n\n"
                         "Para usar AES estándar, instala la librería en ese intérprete:\n  %s -m pip install cryptography\n"
                         "No es urgente: el sistema funciona y los mensajes quedan cifrados.\n\n-- Vestigia"
                         % (context, CRYPTO_IMPORT_ERROR or "no disponible", _sys.executable, _sys.executable)))
    for key, subject, body in problems:
        # El aviso del método alternativo es informativo: no repetir más de una vez al día.
        send_critical_alert(key, subject, body, throttle_hours=(24 if key == "cifrado_std" else 6))
    return problems


@app.errorhandler(Exception)
def _handle_critical_exception(e):
    """Ante un error grave (500), avisa por correo a la administración de inmediato."""
    from werkzeug.exceptions import HTTPException
    if isinstance(e, HTTPException) and e.code and e.code < 500:
        return e  # 404, 403, 400... son errores normales, no críticos
    if app.debug:
        raise e
    import traceback
    tb = traceback.format_exc()
    try:
        path = request.path
    except Exception:
        path = "?"
    try:
        send_critical_alert("error_500",
                            "Vestigia: ERROR CRÍTICO en la aplicación",
                            "Se ha producido un error grave en la aplicación.\n\nRuta: %s\nFecha: %s\n\n%s\n\n-- Vestigia"
                            % (path, now(), tb), throttle_hours=1)
    except Exception:
        pass
    return ("<h1>Se ha producido un error</h1><p>El equipo de administración ha sido avisado. "
            "Vuelve a intentarlo en unos minutos.</p>"), 500


EVENT_LABELS = {"message": "Nuevo mensaje", "comment": "Nuevo comentario",
                "contact_request": "Solicitud de conocido",
                "group_request": "Solicitud de grupo",
                "group_accepted": "Admitido en un grupo",
                "mention": "Te han mencionado"}


def notify_mentions(actor, body, link, where, page=None):
    """Notifica (en la app) a las personas mencionadas con @usuario: conocidos aceptados
    o compañeros del grupo de la página."""
    import re
    db = get_db()
    unames = set(re.findall(r"@([\w.\-]{2,30})", body or ""))
    if not unames:
        return
    gid = page["group_id"] if (page is not None and "group_id" in page.keys()) else None
    for un in unames:
        target = db.execute("SELECT id FROM users WHERE username=?", (un,)).fetchone()
        if not target or target["id"] == actor["id"]:
            continue
        tid = target["id"]
        is_contact = db.execute("""SELECT 1 FROM contacts WHERE status='accepted'
            AND ((requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)) LIMIT 1""",
            (actor["id"], tid, tid, actor["id"])).fetchone()
        if is_contact or (gid and is_group_member(gid, tid)):
            notify(tid, "mention", "%s te ha mencionado en %s." % (actor["name"], where), link)
DEFAULT_TEMPLATES = {
    "message": ("Nuevo mensaje en Vestigia",
                "Hola {name},\n\n{actor} te ha enviado un mensaje en Vestigia.\n\nAbrelo aqui: {url}\n\n-- Vestigia"),
    "comment": ("Nuevo comentario en tu portafolio",
                "Hola {name},\n\n{actor} ha comentado en '{title}'.\n\nVelo aqui: {url}\n\n-- Vestigia"),
    "contact_request": ("Nueva solicitud de conocido",
                        "Hola {name},\n\n{actor} quiere añadirte como conocido en Vestigia.\n\nGestióna la solicitud aqui: {url}\n\n-- Vestigia"),
    "group_request": ("Nueva solicitud para unirse a tu grupo",
                      "Hola {name},\n\n{actor} ha solicitado unirse a tu grupo '{group}' en Vestigia.\n\n"
                      "Acepta o rechaza la solicitud aqui: {url}\n\n-- Vestigia"),
    "group_accepted": ("Te han admitido en un grupo",
                       "Hola {name},\n\nYa formas parte del grupo '{group}' en Vestigia.\n\nAbrelo aqui: {url}\n\n-- Vestigia"),
}


def seed_email_templates(db):
    """Inserta las plantillas que falten (también en bases de datos ya existentes)."""
    existing = {r["event"] for r in db.execute("SELECT event FROM email_templates").fetchall()}
    for ev, (subj, body) in DEFAULT_TEMPLATES.items():
        if ev not in existing:
            db.execute("INSERT INTO email_templates(event,subject,body,enabled) VALUES(?,?,?,1)",
                       (ev, subj, body))


def render_tpl(s, ctx):
    for k, v in (ctx or {}).items():
        s = s.replace("{%s}" % k, str(v))
    return s


def notify(user_id, event, text_default, link, ctx=None, in_app=True):
    db = get_db()
    if in_app:
        db.execute("INSERT INTO notifications(user_id,kind,text,link,created_at) VALUES(?,?,?,?,?)",
                   (user_id, EVENT_LABELS.get(event, event), text_default, link, now()))
    tpl = db.execute("SELECT * FROM email_templates WHERE event=?", (event,)).fetchone()
    if not tpl or not tpl["enabled"]:
        return
    # Preferencia por usuario: puede desactivar este tipo de aviso por correo.
    if get_setting("emailpref_%d_%s" % (user_id, event), "1") == "0":
        return
    row = db.execute("SELECT email,name FROM users WHERE id=?", (user_id,)).fetchone()
    if not row or not row["email"]:
        return
    ctx = dict(ctx or {})
    ctx.setdefault("name", row["name"])
    ctx.setdefault("url", (request.host_url.rstrip("/") + link) if link else "")
    send_email(row["email"], render_tpl(tpl["subject"], ctx), render_tpl(tpl["body"], ctx))


def record_student_change(actor_id, page_id, kind, detail):
    """Registra la actividad de un alumno (para analiticas) y avisa a sus profesores conocidos,
    pero SOLO si la página es compartida (Docentes o Pública); las privadas no generan avisos."""
    try:
        from datetime import timedelta
        db = get_db()
        actor = db.execute("SELECT id,name,role FROM users WHERE id=?", (actor_id,)).fetchone()
        if not actor or actor["role"] != "student":
            return
        p = db.execute("SELECT * FROM pages WHERE id=?", (page_id,)).fetchone() if page_id else None
        title = (p["title"] if p else "") or ""
        vis = (p["visibility"] if p else "private") or "private"
        # 1) Registro de actividad general (para analiticas): siempre, incluso privadas
        db.execute("""INSERT INTO student_activity(student_id,page_id,page_title,visibility,kind,detail,created_at)
                      VALUES(?,?,?,?,?,?,?)""", (actor_id, page_id, title, vis, kind, detail, now()))
        # 2) Avisos a profesores conocidos: solo si la página es compartida
        if vis not in ("teachers", "public"):
            db.commit()
            return
        teachers = db.execute("""
            SELECT us.* FROM contacts c JOIN users us
              ON us.id = CASE WHEN c.requester_id=? THEN c.addressee_id ELSE c.requester_id END
            WHERE c.status='accepted' AND (c.requester_id=? OR c.addressee_id=?)
              AND us.role IN ('teacher','admin')""", (actor_id, actor_id, actor_id)).fetchall()
        since = (datetime.now() - timedelta(minutes=10)).strftime("%Y-%m-%d %H:%M")
        for t in teachers:
            # No avisar de cambios si ese estudiante ya no es alumno del docente (o lo ha archivado).
            # (Los mensajes y comentarios directos sí siguen llegando; esto solo afecta a los avisos de cambios.)
            if not teacher_can_view_student(t, actor_id):
                continue
            db.execute("""INSERT INTO student_changes(teacher_id,student_id,page_id,page_title,kind,detail,created_at)
                          VALUES(?,?,?,?,?,?,?)""", (t["id"], actor_id, page_id, title, kind, detail, now()))
            wants = t["notify_changes"] if ("notify_changes" in t.keys()) else 1
            if t["email"] and wants:
                recent = db.execute("""SELECT COUNT(*) c FROM student_changes
                                       WHERE teacher_id=? AND page_id=? AND created_at>=?""",
                                    (t["id"], page_id, since)).fetchone()["c"]
                if recent <= 1:  # evita saturar: 1 email por página cada 10 min
                    link = url_for("page_view", pid=page_id) if page_id else url_for("feed")
                    url = request.host_url.rstrip("/") + link
                    send_email(t["email"], "Cambio de un estudiante en Vestigia",
                               "Hola %s,\n\n%s %s: \"%s\".\n\nVelo aqui: %s\n\n-- Vestigia"
                               % (t["name"], actor["name"], detail, title, url))
        db.commit()
    except Exception as e:
        try:
            with open(os.path.join(BASE_DIR, "changes_debug.log"), "a", encoding="utf-8") as f:
                f.write("[%s] record_student_change error: %r\n" % (now(), e))
        except Exception:
            pass


def notif_count(uid):
    return get_db().execute("SELECT COUNT(*) c FROM notifications WHERE user_id=? AND is_read=0 AND kind<>'Nuevo mensaje'",
                            (uid,)).fetchone()["c"]


NOTIF_TPL = """
<h1>Avisos</h1>
{% for n in items %}<div class="card between" style="margin-bottom:10px;{{ 'border-left:4px solid #b8365f' if not n['is_read'] else '' }}">
 <div><b>{{ n['kind'] }}</b><div class="muted">{{ n['text'] }} &middot; {{ n['created_at'] }}</div></div>
 {% if n['link'] %}<a class="btn sec sm" href="{{ n['link'] }}">Ver</a>{% endif %}
</div>{% else %}<p class="muted">No tienes avisos.</p>{% endfor %}
"""


@app.route("/notifications")
@login_required
def notifications():
    db, u = get_db(), current_user()
    items = db.execute("""SELECT * FROM notifications WHERE user_id=? AND kind<>'Nuevo mensaje'
                          ORDER BY id DESC LIMIT 100""", (u["id"],)).fetchall()
    return render(NOTIF_TPL, title="Avisos", items=items)


CHANGES_TPL = """
<div class="between"><h1>Cambios de estudiantes</h1></div>
<p class="muted" style="margin-top:0">Solo se avisa de páginas compartidas (Docentes o Pública); las privadas no generan aviso. Los cambios <b style="color:#d34">sin leer aparecen marcados en rojo</b>. El correo se activa o desactiva en tu perfil.</p>
{% for ch in items %}<div class="card between" style="{{ 'border-left:5px solid #d34;background:#fdf0f2' if not ch['is_read'] else '' }}">
 <div>{% if not ch['is_read'] %}<span class="pill" style="background:#d34;color:#fff">NUEVO</span> {% endif %}<b><a href="{{ url_for('profile', username=ch['student_username']) }}">{{ ch['student_name'] }}</a></b>
  <span class="muted">{{ ch['detail'] }}</span>
  <div class="muted">Página: <b>{{ ch['page_title'] or '(sin título)' }}</b> &middot; {{ ch['created_at'] }}</div></div>
 {% if ch['page_id'] and ch['page_vis'] in ('teachers','public') %}<a class="btn sec sm" href="{{ url_for('page_view', pid=ch['page_id']) }}">Ver</a>
 {% elif ch['page_id'] %}<span class="muted" style="font-size:12px">Ya no compartida</span>{% endif %}
</div>{% else %}<p class="muted">Aún no hay cambios registrados.</p>{% endfor %}
"""


@app.route("/changes")
@login_required
@role_required("teacher", "admin")
def changes():
    db, u = get_db(), current_user()
    items = db.execute("""SELECT sc.*, us.name student_name, us.username student_username,
        pg.visibility page_vis
        FROM student_changes sc JOIN users us ON us.id=sc.student_id
        LEFT JOIN pages pg ON pg.id=sc.page_id
        WHERE sc.teacher_id=? ORDER BY sc.id DESC LIMIT 200""", (u["id"],)).fetchall()
    db.execute("UPDATE student_changes SET is_read=1 WHERE teacher_id=? AND is_read=0", (u["id"],))
    db.commit()
    return render(CHANGES_TPL, title="Cambios", items=items)


@app.route("/n/<int:nid>")
@login_required
def notif_go(nid):
    db, u = get_db(), current_user()
    n = db.execute("SELECT * FROM notifications WHERE id=? AND user_id=?", (nid, u["id"])).fetchone()
    if not n:
        abort(404)
    db.execute("UPDATE notifications SET is_read=1 WHERE id=?", (nid,))
    db.commit()
    return redirect(n["link"] or url_for("dashboard"))


@app.route("/n/<int:nid>/dismiss", methods=["POST"])
@login_required
def notif_dismiss(nid):
    db, u = get_db(), current_user()
    db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?", (nid, u["id"]))
    db.commit()
    return redirect(url_for("dashboard"))


try:
    from xhtml2pdf import pisa
    HAS_PDF = True
except Exception:
    HAS_PDF = False


def _pdf_link_callback(uri, rel):
    if uri.startswith("/uploads/"):
        return os.path.join(UPLOAD_DIR, uri.split("/uploads/", 1)[1])
    return uri


def block_pdf_html(b):
    if b["block_type"] == "artefact":
        a = get_db().execute("SELECT * FROM artefacts WHERE id=?", (b["artefact_id"],)).fetchone()
        if not a:
            return ""
        t = '<p style="color:#7a1f3d"><b>%s</b></p>' % escape(a["title"])
        if a["kind"] == "text":
            return t + "<p>%s</p>" % escape(a["body"] or "")
        if a["kind"] == "image" and a["filename"]:
            return t + '<img src="/uploads/%s" style="max-width:420px"><br>' % a["filename"]
        if a["kind"] == "link":
            return t + "<p>Enlace: %s</p>" % escape(a["url"] or "")
        if a["kind"] == "video":
            return t + "<p>[Vídeo] %s</p>" % escape(a["url"] or a["filename"] or "")
        if a["kind"] == "audio":
            return t + "<p>[Audio] %s</p>" % escape(a["filename"] or a["url"] or "")
        return t + "<p>[Documento] %s</p>" % escape(a["filename"] or "")
    size = b["font_size"] or (24 if b["block_type"] == "heading" else 14)
    weight = "bold" if (b["bold"] or b["block_type"] == "heading") else "normal"
    style = "font-size:%spx;color:%s;text-align:%s;font-weight:%s" % (
        size, b["text_color"] or "#000", b["align"] or "left", weight)
    _c = b["text_content"] or ""
    _inner = sanitize_html(_c) if "<" in _c else escape(_c).replace("\n", "<br>")
    return '<p style="%s">%s</p>' % (style, _inner)


def page_pdf_html(p, author):
    parts = ['<h2 style="color:#7a1f3d">%s</h2>' % escape(p["title"]),
             '<p style="color:#666">Por %s</p>' % escape(author["name"])]
    if p["description"]:
        parts.append("<p><i>%s</i></p>" % escape(p["description"]))
    for R in page_rows(p["id"]):
        for col in R["cols"]:
            for b in col:
                parts.append(block_pdf_html(b))
    return "".join(parts)


def make_pdf(inner_html, filename):
    if not HAS_PDF:
        flash("Para descargar PDF instala la libreria:  pip install xhtml2pdf", "error")
        return redirect(request.referrer or url_for("dashboard"))
    from io import BytesIO
    from flask import Response
    html = ("<html><head><meta charset='utf-8'><style>"
            "body{font-family:Helvetica;font-size:13px;color:#222}"
            "h1{color:#7a1f3d}h2{margin:0 0 4px}p{line-height:1.4}</style></head><body>"
            + inner_html + "</body></html>")
    buf = BytesIO()
    pisa.CreatePDF(html, dest=buf, link_callback=_pdf_link_callback, encoding="utf-8")
    buf.seek(0)
    from flask import Response as _R
    return _R(buf.getvalue(), mimetype="application/pdf",
              headers={"Content-Disposition": "attachment; filename=" + filename})


def can_download(p, u):
    return u["role"] in ("teacher", "admin") or p["owner_id"] == u["id"]


@app.route("/pages/<int:pid>/pdf")
@login_required
def page_pdf(pid):
    if not feature_on("stu_pdf"):
        abort(403)
    db, u = get_db(), current_user()
    p = db.execute("SELECT * FROM pages WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    if not can_download(p, u):
        abort(403)
    if not HAS_PDF:
        return redirect(url_for("page_print", pid=pid))
    author = db.execute("SELECT * FROM users WHERE id=?", (p["owner_id"],)).fetchone()
    return make_pdf(page_pdf_html(p, author), "página_%s.pdf" % pid)


@app.route("/collections/<int:cid>/pdf")
@login_required
def collection_pdf(cid):
    if not feature_on("stu_pdf"):
        abort(403)
    db, u = get_db(), current_user()
    col = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
    if not col:
        abort(404)
    if not can_view_collection(col, u):
        abort(403)
    if not HAS_PDF:
        return redirect(url_for("collection_print", cid=cid))
    pages = db.execute("""SELECT p.* FROM collection_pages cp JOIN pages p ON p.id=cp.page_id
                          WHERE cp.collection_id=? ORDER BY cp.position""", (cid,)).fetchall()
    author = db.execute("SELECT * FROM users WHERE id=?", (col["owner_id"],)).fetchone()
    parts = ['<h1>%s</h1>' % escape(col["title"])]
    for idx, p in enumerate(pages):
        if idx:
            parts.append('<div style="page-break-before:always"></div>')
        parts.append(page_pdf_html(p, author))
    return make_pdf("".join(parts), "colección_%s.pdf" % cid)



PRINT_TPL = """<!doctype html><html lang="es"><head><meta charset="utf-8">
<title>{{ title }}</title><link rel="icon" type="image/svg+xml" href="/favicon.svg"><style>
 body{font-family:-apple-system,'Inter',Segoe UI,Roboto,Arial,sans-serif;color:#222;max-width:820px;margin:24px auto;padding:0 18px;line-height:1.5}
 h1{color:#7a1f3d}h2{color:#7a1f3d;margin:0 0 6px}img{max-width:100%;border-radius:8px}
 .pb{page-break-before:always}
 .toolbar{margin-bottom:18px}
 .toolbar button{background:#7a1f3d;color:#fff;border:0;padding:10px 18px;border-radius:8px;font-size:14px;cursor:pointer}
 @media print{.toolbar{display:none}}
</style></head><body>
<div class="toolbar"><button onclick="window.print()">Guardar como PDF / Imprimir</button>
 <span style="color:#888;font-size:13px;margin-left:8px">En el dialogo elige "Guardar como PDF".</span></div>
{{ inner|safe }}
<script>window.onload=function(){setTimeout(function(){window.print();},400);};</script>
</body></html>"""


@app.route("/pages/<int:pid>/print")
@login_required
def page_print(pid):
    db, u = get_db(), current_user()
    p = db.execute("SELECT * FROM pages WHERE id=?", (pid,)).fetchone()
    if not p:
        abort(404)
    if not can_download(p, u):
        abort(403)
    author = db.execute("SELECT * FROM users WHERE id=?", (p["owner_id"],)).fetchone()
    return render_template_string(PRINT_TPL, title=p["title"], inner=page_pdf_html(p, author))


@app.route("/collections/<int:cid>/print")
@login_required
def collection_print(cid):
    db, u = get_db(), current_user()
    col = db.execute("SELECT * FROM collections WHERE id=?", (cid,)).fetchone()
    if not col:
        abort(404)
    if not can_view_collection(col, u):
        abort(403)
    pages = db.execute("""SELECT p.* FROM collection_pages cp JOIN pages p ON p.id=cp.page_id
                          WHERE cp.collection_id=? ORDER BY cp.position""", (cid,)).fetchall()
    author = db.execute("SELECT * FROM users WHERE id=?", (col["owner_id"],)).fetchone()
    parts = ["<h1>%s</h1>" % escape(col["title"])]
    for idx, p in enumerate(pages):
        parts.append('<div class="pb">' if idx else '<div>')
        parts.append(page_pdf_html(p, author))
        parts.append('</div>')
    return render_template_string(PRINT_TPL, title=col["title"], inner="".join(parts))


def visible_student_ids(u):
    """IDs del alumnado que puede ver un usuario. None = todo. Admin: todo. Docente: el alumnado de sus
    asignaturas NO archivadas. Si NO hay asignaturas creadas (estructura académica sin usar), ve a todo el
    alumnado (comportamiento clásico)."""
    if u["role"] == "admin":
        return None
    db = get_db()
    if not db.execute("SELECT 1 FROM subjects LIMIT 1").fetchone():
        return None
    rows = db.execute("""SELECT DISTINCT ss.student_id FROM subject_students ss
        JOIN subject_teachers st ON st.subject_id=ss.subject_id
        WHERE st.teacher_id=? AND ss.subject_id NOT IN
              (SELECT subject_id FROM subject_archived WHERE teacher_id=?)""",
        (u["id"], u["id"])).fetchall()
    return {r["student_id"] for r in rows}


def teacher_can_view_student(u, student_id):
    vis = visible_student_ids(u)
    return vis is None or student_id in vis


ANALYTICS_TPL = """
<div class="between"><h1>Dashboard de aprendizaje</h1>
 <span class="muted">Solo profesorado &middot; datos en vivo</span></div>

{% if is_teacher %}
<div class="card"><div class="between"><h2 style="margin:0">Mis asignaturas</h2>
  <span class="muted" style="font-size:12px">Solo ves el alumnado de tus asignaturas no archivadas</span></div>
 {% if my_subjects %}
 <table style="width:100%;margin-top:6px"><tr><th style="text-align:left">Asignatura</th><th>Alumnado</th><th></th></tr>
 {% for s in my_subjects %}<tr style="border-top:1px solid var(--line){{ ';opacity:.55' if s['archived'] }}">
  <td style="padding:6px 0">{{ s['name'] }}{% if s['code'] %} <span class="muted">({{ s['code'] }})</span>{% endif %}{% if s['archived'] %} <span class="pill">archivada</span>{% endif %}</td>
  <td style="text-align:center">{{ s['nstud'] }}</td>
  <td style="text-align:right"><form method="post" action="{{ url_for('subject_archive_toggle', sid=s['id']) }}" style="margin:0"><button class="btn sec sm">{{ 'Recuperar' if s['archived'] else 'Archivar' }}</button></form></td>
 </tr>{% endfor %}</table>
 <p class="muted" style="font-size:12px;margin:8px 0 0">Archivar oculta ese alumnado <b>solo para ti</b> (no afecta a otros docentes ni borra datos).</p>
 {% else %}<p class="muted" style="margin:6px 0 0">Aún no tienes asignaturas asignadas. Pídele a la administración que te asigne a una para ver a tu alumnado.</p>{% endif %}
</div>
{% endif %}

{% if is_teacher and not rows %}
<div class="card"><p class="muted" style="margin:0">No hay alumnado que mostrar. Esto ocurre si aún no tienes asignaturas con estudiantes, o si has archivado todas tus asignaturas.</p></div>
{% else %}
<div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(150px,1fr))">
 <div class="tile"><div class="k">Estudiantes</div><div style="font-size:28px;font-weight:800">{{ kpi['students'] }}</div></div>
 <div class="tile"><div class="k">Páginas</div><div style="font-size:28px;font-weight:800">{{ kpi['pages'] }}</div></div>
 <div class="tile"><div class="k">% con página publica</div><div style="font-size:28px;font-weight:800">{{ kpi['pct_pub'] }}%</div></div>
 <div class="tile"><div class="k">Palabras (media)</div><div style="font-size:28px;font-weight:800">{{ kpi['avg_words'] }}</div></div>
 <div class="tile"><div class="k">Artefactos</div><div style="font-size:28px;font-weight:800">{{ kpi['artefacts'] }}</div></div>
 <div class="tile"><div class="k">Participación media</div><div style="font-size:28px;font-weight:800">{{ kpi['avg_part'] }}</div></div>
 <div class="tile"><div class="k">Riesgo alto</div><div style="font-size:28px;font-weight:800;color:#d34">{{ kpi['risk_high'] }}</div></div>
 <div class="tile"><div class="k">En seguimiento</div><div style="font-size:28px;font-weight:800;color:#e0a020">{{ kpi['watch'] }}</div></div>
 <div class="tile"><div class="k">Sin leer (tú)</div><div style="font-size:28px;font-weight:800;color:#c0325f">{{ kpi['pending'] }}</div></div>
</div>

<div class="prow" style="grid-template-columns:1.4fr 1fr">
 <div class="card"><h2>Actividad por semana</h2><canvas id="chActivity" height="150"></canvas></div>
 <div class="card"><h2>Tipos de evidencia</h2><canvas id="chKinds" height="150"></canvas></div>
</div>

<div class="card"><h2>Indice de completitud por estudiante</h2>
 <canvas id="chScore" height="120"></canvas>
 <p class="muted" style="margin-top:6px">Combina páginas, publicación, reflexion escrita, variedad de evidencias e interacción recibida (0-100).</p>
</div>

<div class="prow" style="grid-template-columns:1.4fr 1fr">
 <div class="card"><h2>Participación por estudiante</h2><canvas id="chPart" height="150"></canvas>
  <p class="muted" style="margin-top:6px">Interacción aportada: comentarios a otros, lecturas, mensajes, evidencias LS y pertenencia a grupos (0-100).</p></div>
 <div class="card"><h2>Riesgo de abandono</h2><canvas id="chRisk" height="150"></canvas></div>
</div>

{% if watch %}<div class="card" style="border-left:4px solid #d34">
 <h2>Riesgo de abandono</h2>
 <p class="muted">Estudiantes a vigilar, ordenados por nivel de riesgo.</p>
 {% for r in watch %}<div class="between" style="padding:8px 0;border-bottom:1px solid var(--line)">
  <div><b><a href="{{ url_for('profile', username=r['username']) }}">{{ r['name'] }}</a></b>
   <span class="pill" style="background:{{ r['rcolor'] }};color:#fff">{{ r['level'] }} &middot; {{ r['risk'] }}%</span>
   <div class="muted">{{ r['reason'] }}</div></div>
  <a class="btn sec sm" href="{{ url_for('assistant', username=r['username']) }}">Revisar</a>
 </div>{% endfor %}
</div>{% endif %}

{% if pending %}<div class="card" style="border-left:4px solid #c0325f">
 <h2>Pendientes de leer (tú)</h2>
 <p class="muted">Páginas compartidas contigo que aun no has marcado como leidas.</p>
 {% for p in pending %}<div class="between" style="padding:6px 0;border-bottom:1px solid var(--line)">
  <div><b><a href="{{ url_for('page_view', pid=p['id']) }}">{{ p['title'] }}</a></b> <span class="muted">&middot; {{ p['name'] }}</span></div>
  <a class="btn sec sm" href="{{ url_for('page_view', pid=p['id']) }}">Abrir</a></div>{% endfor %}
</div>{% endif %}
<div class="card"><h2>Detalle por estudiante</h2>
 <div style="overflow-x:auto">
 <table style="min-width:1040px"><tr><th>Estudiante</th><th>Completitud</th><th>Particip.</th><th>Riesgo</th><th>Tend.</th><th>Reacción</th><th>Inicios</th><th>Pag.</th><th>Publ.</th><th>Artef.</th>
  <th>Palabras</th><th>Feedback</th><th>Lecturas</th><th>Sin leer</th><th>Ult. actividad</th><th></th></tr>
 {% for r in rows %}<tr>
  <td><a href="{{ url_for('profile', username=r['username']) }}">{{ r['name'] }}</a></td>
  <td><div style="display:flex;align-items:center;gap:8px">
   <div style="background:#efeaed;border-radius:6px;height:10px;width:90px">
    <div style="height:10px;border-radius:6px;width:{{ r['score'] }}%;background:{{ r['color'] }}"></div></div>
   <span class="muted">{{ r['score'] }}</span></div></td>
  <td><div style="display:flex;align-items:center;gap:8px">
   <div style="background:#efeaed;border-radius:6px;height:10px;width:70px">
    <div style="height:10px;border-radius:6px;width:{{ r['participation'] }}%;background:{{ r['pcolor'] }}"></div></div>
   <span class="muted">{{ r['participation'] }} <span title="acciones de participación (sin tope)">· {{ r['part_raw'] }} acc.</span></span></div></td>
  <td><span class="pill" style="background:{{ r['rcolor'] }};color:#fff">{{ r['level'] }}</span></td>
  <td style="color:{{ '#2e9e5b' if r['trend']=='sube' else ('#d34' if r['trend'] in ('baja','en pausa') else '#8b8492') }}" title="{{ r['trend'] }}">{{ r['trend_arrow'] }}</td>
  <td>{{ r['reacts'] }}</td>
  <td>{{ r['logins'] }}</td>
  <td>{{ r['pages'] }}</td><td>{{ r['public'] }}</td><td>{{ r['artefacts'] }}</td>
  <td>{{ r['words'] }}</td><td>{{ r['comments'] }}</td><td>{{ r['reads'] }}</td><td>{{ r['pend'] }}</td>
  <td class="muted">{{ ('hace ' ~ r['days'] ~ ' d') if r['days'] is not none else '-' }}</td>
  <td><a class="btn sec sm" href="{{ url_for('assistant', username=r['username']) }}">Ver ficha</a></td>
 </tr>{% endfor %}</table></div></div>

<div class="card"><h2>Analíticas de grupo</h2>
 <p class="muted" style="margin-top:0">Actividad, reparto de la carga entre miembros y cobertura de los ciclos de Lesson Study.</p>
 {% for gd in groups_data %}<div style="padding:10px 0;border-bottom:1px solid var(--line)">
  <div class="between"><b><a href="{{ url_for('group_view', gid=gd['id']) }}">{{ gd['name'] }}</a></b>
   <span class="muted">{{ gd['nmembers'] }} miembros &middot; {{ gd['npages'] }} páginas &middot; {{ gd['nsess'] }} sesiones LS &middot; {{ gd['nevid'] }} evidencias</span></div>
  {% if gd['uneven'] %}<div style="color:#d34;font-size:13px;margin-top:2px">⚠ Reparto desigual: hay miembros que aún no han aportado páginas ni evidencias.</div>{% endif %}
  <div class="muted" style="font-size:13px;margin-top:2px">Cobertura LS: objetivos {{ gd['cov_obj'] }}/{{ gd['tot_obj'] }} &middot; ítems {{ gd['cov_item'] }}/{{ gd['tot_item'] }} con evidencia.</div>
  <div class="muted" style="font-size:13px">Discusiones: {{ gd['ndisc_closed'] }}/{{ gd['ndisc'] }} cerradas con conclusión{% if gd['avg_lat'] is not none %} &middot; latencia media al compartir evidencias: {{ gd['avg_lat'] }} día(s) tras la lección{% endif %}.</div>
  <div style="font-size:13px;margin-top:2px">Equidad de participación (Gini):
   <b style="color:{{ '#2e9e5b' if gd['gini']<0.3 else ('#e0a020' if gd['gini']<0.5 else '#d34') }}">{{ gd['gini'] }}</b>
   <span class="muted">— {{ 'reparto equilibrado' if gd['gini']<0.3 else ('cierta desigualdad' if gd['gini']<0.5 else 'reparto muy desigual') }} (0 = todos aportan igual, 1 = uno solo aporta todo)</span></div>
  {% if gd['contrib'] %}<table style="margin-top:6px"><tr><th>Miembro</th><th>Visitas</th><th>Páginas</th><th>Palabras</th><th>Evidencias</th><th>Reflexión</th></tr>
   {% for c in gd['contrib'] %}<tr><td>{{ c['name'] }}</td><td>{{ c['visits'] }}</td><td>{{ c['pages'] }}</td><td>{{ c['words'] }}</td><td>{{ c['evid'] }}</td><td>{{ c['refl'] }}</td></tr>{% endfor %}
  </table>{% endif %}
 </div>{% else %}<p class="muted">No hay grupos todavía.</p>{% endfor %}
</div>

<div class="card"><h2>Grafo de colaboración</h2>
 <p class="muted" style="margin-top:0;font-size:13px">Quién comenta el portafolio de quién. La flecha va de quien comenta hacia el autor; a mayor grosor, más comentarios.</p>
 {% if collab.nodes %}
 <div style="overflow-x:auto"><svg viewBox="0 0 520 300" style="width:100%;max-width:600px">
  <defs><marker id="arr" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" fill="#c0325f"/></marker></defs>
  {% for e in collab.edges %}<line x1="{{ e.x1 }}" y1="{{ e.y1 }}" x2="{{ e.x2 }}" y2="{{ e.y2 }}" stroke="#c0325f" stroke-opacity=".45" stroke-width="{{ e.w }}" marker-end="url(#arr)"/>{% endfor %}
  {% for nd in collab.nodes %}<circle cx="{{ nd.x }}" cy="{{ nd.y }}" r="6" fill="#7a1f3d"/><text x="{{ nd.x }}" y="{{ nd.y - 9 }}" font-size="11" text-anchor="middle" fill="#25202a">{{ nd.name }}</text>{% endfor %}
 </svg></div>
 {% else %}<p class="muted">Aún no hay comentarios entre personas para dibujar el grafo.</p>{% endif %}
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<script>
var DATA = {{ charts|safe }};
var mk = '#7a1f3d', pk = '#c0325f', ac = '#ff5c8a';
if(window.Chart){
 new Chart(document.getElementById('chActivity'),{type:'line',
  data:{labels:DATA.weeks,datasets:[
   {label:'Páginas',data:DATA.pages,borderColor:mk,backgroundColor:mk,tension:.3},
   {label:'Artefactos',data:DATA.artefacts,borderColor:pk,backgroundColor:pk,tension:.3},
   {label:'Comentarios',data:DATA.comments,borderColor:ac,backgroundColor:ac,tension:.3}]},
  options:{plugins:{legend:{position:'bottom'}},scales:{y:{beginAtZero:true,ticks:{precision:0}}}}});
 new Chart(document.getElementById('chKinds'),{type:'doughnut',
  data:{labels:DATA.kind_labels,datasets:[{data:DATA.kind_counts,
   backgroundColor:['#7a1f3d','#c0325f','#ff5c8a','#e0a020','#2e9e5b','#3a7bd5']}]},
  options:{plugins:{legend:{position:'bottom'}}}});
 new Chart(document.getElementById('chScore'),{type:'bar',
  data:{labels:DATA.student_names,datasets:[{label:'Completitud',data:DATA.student_scores,
   backgroundColor:DATA.student_colors}]},
  options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,max:100}}}});
 if(document.getElementById('chPart')) new Chart(document.getElementById('chPart'),{type:'bar',
  data:{labels:DATA.student_names,datasets:[{label:'Participación',data:DATA.student_part,backgroundColor:'#3a7bd5'}]},
  options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,max:100}}}});
 if(document.getElementById('chRisk')) new Chart(document.getElementById('chRisk'),{type:'doughnut',
  data:{labels:DATA.risk_names,datasets:[{data:DATA.risk_data,backgroundColor:['#d34','#e0a020','#2e9e5b']}]},
  options:{plugins:{legend:{position:'bottom'}}}});
}
</script>
{% endif %}
"""


def student_overview(db, s, me, today):
    """Fila de resumen de un estudiante (los mismos datos de la tabla 'Detalle por
    estudiante'). Se usa tanto en la tabla de /analytics como en el asistente individual."""
    from datetime import datetime, timedelta
    sid = s["id"]
    pages = db.execute("SELECT COUNT(*) c FROM pages WHERE owner_id=? AND id IS NOT ?", (sid, s["profile_page_id"])).fetchone()["c"]
    public = db.execute("SELECT COUNT(*) c FROM pages WHERE owner_id=? AND visibility='public' AND id IS NOT ?", (sid, s["profile_page_id"])).fetchone()["c"]
    arte = db.execute("SELECT COUNT(*) c FROM artefacts WHERE owner_id=?", (sid,)).fetchone()["c"]
    kinds = set(r["kind"] for r in db.execute("SELECT DISTINCT kind FROM artefacts WHERE owner_id=?", (sid,)))
    words = 0
    last = None
    for p in db.execute("SELECT * FROM pages WHERE owner_id=? AND id IS NOT ?", (sid, s["profile_page_id"])):
        if p["created_at"] and (last is None or p["created_at"] > last):
            last = p["created_at"]
        for R in page_rows(p["id"]):
            for col in R["cols"]:
                for b in col:
                    if b["block_type"] in ("text", "heading") and b["text_content"]:
                        words += len(_strip_tags(b["text_content"]).split())
    comments = db.execute("""SELECT COUNT(*) c FROM comments c JOIN pages p ON p.id=c.page_id
                             WHERE p.owner_id=? AND c.author_id<>?""", (sid, sid)).fetchone()["c"]
    reads = db.execute("""SELECT COUNT(*) c FROM page_reads r JOIN pages p ON p.id=r.page_id
                          WHERE p.owner_id=?""", (sid,)).fetchone()["c"]
    pend_s = db.execute("""SELECT COUNT(*) c FROM pages p WHERE p.owner_id=? AND p.visibility IN ('teachers','public')
                           AND p.id NOT IN (SELECT page_id FROM page_reads WHERE user_id=?)""",
                        (sid, me["id"])).fetchone()["c"]
    # Participacion = interacción aportada por el estudiante (no recibida)
    given = db.execute("""SELECT COUNT(*) c FROM comments c JOIN pages p ON p.id=c.page_id
                          WHERE c.author_id=? AND p.owner_id<>?""", (sid, sid)).fetchone()["c"]
    reads_given = db.execute("SELECT COUNT(*) c FROM page_reads WHERE user_id=?", (sid,)).fetchone()["c"]
    msgs = db.execute("SELECT COUNT(*) c FROM messages WHERE sender_id=?", (sid,)).fetchone()["c"]
    ls_ev = db.execute("SELECT COUNT(*) c FROM ls_evidences WHERE author_id=?", (sid,)).fetchone()["c"]
    ngroups = db.execute("SELECT COUNT(*) c FROM group_members WHERE user_id=?", (sid,)).fetchone()["c"]
    # Saturación SUAVE x/(x+k) con k = umbral/4: da 0,8 en el umbral de referencia y sigue
    # creciendo hacia 1 sin techo duro, de modo que quien hace más puntúa algo más (sin ranking).
    def _sat(x, thr):
        return x / (x + thr / 4.0) if x else 0.0
    participation = int(round(_sat(given, 5) * 30 + _sat(reads_given, 5) * 20 +
                              _sat(msgs, 10) * 15 + _sat(ls_ev, 3) * 20 +
                              _sat(ngroups, 1) * 15))
    # Contador bruto (sin tope): distingue a los muy participativos aunque todos lleguen a 100.
    part_raw = given + reads_given + msgs + ls_ev + ngroups
    pcolor = "#2e9e5b" if participation >= 60 else ("#e0a020" if participation >= 30 else "#d34")

    score = 0
    score += 20 if pages else 0
    score += 15 if public else 0
    score += _sat(words, 300) * 25
    score += _sat(len(kinds), 4) * 20
    score += _sat(comments + reads, 5) * 20
    score = int(round(score))
    color = "#2e9e5b" if score >= 70 else ("#e0a020" if score >= 40 else "#d34")
    days = None
    if last:
        try:
            days = (today - datetime.strptime(last[:10], "%Y-%m-%d").date()).days
        except Exception:
            days = None

    # Riesgo de abandono (0-100, mayor = mas riesgo)
    risk = 0
    if days is None:
        risk += 35
    elif days > 30:
        risk += 40
    elif days > 21:
        risk += 28
    elif days > 14:
        risk += 15
    if pages == 0:
        risk += 25
    elif public == 0:
        risk += 8
    if score < 25:
        risk += 20
    elif score < 40:
        risk += 10
    if participation < 20:
        risk += 15
    elif participation < 40:
        risk += 7
    risk = min(100, risk)
    level = "Alto" if risk >= 55 else ("Medio" if risk >= 30 else "Bajo")
    rcolor = "#d34" if level == "Alto" else ("#e0a020" if level == "Medio" else "#2e9e5b")

    reasons = []
    if pages == 0:
        reasons.append("sin páginas")
    elif public == 0:
        reasons.append("sin publicar")
    if days is None:
        reasons.append("nunca ha creado")
    elif days > 21:
        reasons.append("inactivo %d d" % days)
    if score < 40:
        reasons.append("completitud baja")
    if participation < 25:
        reasons.append("baja participación")

    # Tendencia = momentum reciente: últimos 7 días frente a los 7 anteriores.
    # Ventana corta (1 semana) para que un parón de unos días se refleje enseguida:
    # una subida de hace 8-14 días ya NO cuenta como reciente.
    d7 = (today - timedelta(days=7)).strftime("%Y-%m-%d")
    d14 = (today - timedelta(days=14)).strftime("%Y-%m-%d")
    d28 = (today - timedelta(days=28)).strftime("%Y-%m-%d")

    def _act(a, b):
        n = 0
        for tbl in ("pages", "artefacts", "ls_evidences"):
            col = "author_id" if tbl == "ls_evidences" else "owner_id"
            n += db.execute("SELECT COUNT(*) c FROM %s WHERE %s=? AND created_at>=? AND created_at<?"
                            % (tbl, col), (sid, a, b)).fetchone()["c"]
        n += db.execute("SELECT COUNT(*) c FROM comments WHERE author_id=? AND created_at>=? AND created_at<?",
                        (sid, a, b)).fetchone()["c"]
        # las ediciones de páginas cuentan como actividad reciente (created_at de la página es antiguo)
        n += db.execute("SELECT COUNT(*) c FROM student_activity WHERE student_id=? AND created_at>=? AND created_at<?",
                        (sid, a, b)).fetchone()["c"]
        return n
    r7 = _act(d7, "9999")   # última semana
    p7 = _act(d14, d7)      # semana anterior
    if r7 == 0 and p7 == 0:
        trend, trend_arrow = "sin actividad", "—"
    elif r7 == 0:           # estuvo activo pero nada en la última semana
        trend, trend_arrow = "en pausa", "⏸"
    elif r7 > p7:
        trend, trend_arrow = "sube", "▲"
    elif r7 < p7:
        trend, trend_arrow = "baja", "▼"
    else:
        trend, trend_arrow = "estable", "—"
    # Parada reciente (para el riesgo): activo antes y 0 en las últimas 2 semanas.
    recent_act = _act(d14, "9999")
    prev_act = _act(d28, d14)
    if recent_act == 0 and prev_act > 0:
        risk = min(100, risk + 25)
        reasons.append("ha dejado de trabajar")
        level = "Alto" if risk >= 55 else ("Medio" if risk >= 30 else "Bajo")
        rcolor = "#d34" if level == "Alto" else ("#e0a020" if level == "Medio" else "#2e9e5b")

    # Reacciona al feedback: ¿hace algo tras el ultimo comentario docente en sus páginas?
    lastfb = db.execute("""SELECT MAX(c.created_at) m FROM comments c JOIN pages p ON p.id=c.page_id
                           JOIN users au ON au.id=c.author_id
                           WHERE p.owner_id=? AND au.role IN ('teacher','admin')""", (sid,)).fetchone()["m"]
    if not lastfb:
        reacts = "—"
    else:
        aft = db.execute("SELECT COUNT(*) c FROM artefacts WHERE owner_id=? AND created_at>?", (sid, lastfb)).fetchone()["c"]
        aft += db.execute("SELECT COUNT(*) c FROM comments WHERE author_id=? AND created_at>?", (sid, lastfb)).fetchone()["c"]
        aft += db.execute("SELECT COUNT(*) c FROM pages WHERE owner_id=? AND created_at>?", (sid, lastfb)).fetchone()["c"]
        reacts = "sí" if aft > 0 else "no"

    return {"name": s["name"], "username": s["username"], "pages": pages, "public": public,
            "artefacts": arte, "words": words, "comments": comments, "reads": reads, "pend": pend_s,
            "score": score, "color": color, "days": days, "logins": (s["login_count"] or 0),
            "participation": participation, "pcolor": pcolor, "part_raw": part_raw,
            "risk": risk, "level": level, "rcolor": rcolor,
            "trend": trend, "trend_arrow": trend_arrow, "reacts": reacts,
            "at_risk": level in ("Alto", "Medio"), "reason": ", ".join(reasons)}


@app.route("/analytics")
@login_required
@role_required("teacher", "admin")
def analytics():
    from datetime import datetime, date
    db = get_db()
    me = current_user()
    vis_ids = visible_student_ids(me)  # None = admin ve a todos
    studs = [s for s in db.execute("SELECT * FROM users WHERE role='student' ORDER BY name").fetchall()
             if vis_ids is None or s["id"] in vis_ids]
    # Asignaturas del docente (para archivar/desarchivar); admin gestiona en su panel.
    my_subjects = []
    if me["role"] == "teacher":
        my_subjects = db.execute("""SELECT s.id, s.name, s.code,
            (SELECT COUNT(*) FROM subject_students ss WHERE ss.subject_id=s.id) nstud,
            EXISTS(SELECT 1 FROM subject_archived a WHERE a.subject_id=s.id AND a.teacher_id=?) archived
            FROM subjects s JOIN subject_teachers st ON st.subject_id=s.id
            WHERE st.teacher_id=? ORDER BY s.name""", (me["id"], me["id"])).fetchall()

    def wk(v):
        try:
            d = datetime.strptime((v or "")[:10], "%Y-%m-%d").date()
        except Exception:
            return None
        y, w, _ = d.isocalendar()
        return "%04d-S%02d" % (y, w)

    counts = {}
    for tbl, key in (("pages", "pages"), ("artefacts", "artefacts"), ("comments", "comments")):
        for r in db.execute("SELECT created_at FROM %s" % tbl):
            k = wk(r["created_at"])
            if not k:
                continue
            counts.setdefault(k, {"pages": 0, "artefacts": 0, "comments": 0})
            counts[k][key] += 1
    weeks = sorted(counts.keys())[-12:]

    kc = db.execute("SELECT kind, COUNT(*) c FROM artefacts GROUP BY kind ORDER BY c DESC").fetchall()
    kind_labels = [KIND_LABELS.get(r["kind"], r["kind"]) for r in kc]
    kind_counts = [r["c"] for r in kc]

    today = date.today()
    rows = [student_overview(db, s, me, today) for s in studs]

    n = len(rows) or 1
    pending = db.execute("""SELECT p.id, p.title, us.name, p.owner_id oid FROM pages p JOIN users us ON us.id=p.owner_id
        WHERE us.role='student' AND p.visibility IN ('teachers','public')
        AND p.id NOT IN (SELECT page_id FROM page_reads WHERE user_id=?) ORDER BY p.id DESC""",
        (me["id"],)).fetchall()
    if vis_ids is not None:
        pending = [p for p in pending if p["oid"] in vis_ids]
    risk_counts = {"Alto": sum(1 for r in rows if r["level"] == "Alto"),
                   "Medio": sum(1 for r in rows if r["level"] == "Medio"),
                   "Bajo": sum(1 for r in rows if r["level"] == "Bajo")}
    kpi = {"students": len(studs), "pages": sum(r["pages"] for r in rows),
           "artefacts": sum(r["artefacts"] for r in rows),
           "avg_words": int(round(sum(r["words"] for r in rows) / n)),
           "avg_part": int(round(sum(r["participation"] for r in rows) / n)),
           "pct_pub": int(round(100 * sum(1 for r in rows if r["public"] > 0) / n)),
           "risk_high": risk_counts["Alto"], "watch": sum(1 for r in rows if r["at_risk"]),
           "pending": len(pending)}
    watch = sorted([r for r in rows if r["at_risk"]], key=lambda r: -r["risk"])

    # Analiticas de grupo
    groups_data = []
    for grp in db.execute("SELECT * FROM groups ORDER BY name").fetchall():
        gid = grp["id"]
        members = db.execute("""SELECT u.id,u.name,u.username FROM group_members gm JOIN users u ON u.id=gm.user_id
                                WHERE gm.group_id=? ORDER BY u.name""", (gid,)).fetchall()
        if vis_ids is not None and not any(mm["id"] in vis_ids for mm in members):
            continue  # el docente no tiene alumnado en este grupo
        npages = db.execute("SELECT COUNT(*) c FROM pages WHERE group_id=?", (gid,)).fetchone()["c"]
        nsess = db.execute("SELECT COUNT(*) c FROM ls_sessions WHERE group_id=?", (gid,)).fetchone()["c"]
        nevid = db.execute("""SELECT COUNT(*) c FROM ls_evidences e JOIN ls_sessions s ON s.id=e.session_id
                              WHERE s.group_id=?""", (gid,)).fetchone()["c"]
        contrib = []
        for m in members:
            mp = db.execute("SELECT COUNT(*) c FROM pages WHERE group_id=? AND owner_id=?",
                            (gid, m["id"])).fetchone()["c"]
            mev = db.execute("""SELECT COUNT(*) c FROM ls_evidences e JOIN ls_sessions s ON s.id=e.session_id
                                WHERE s.group_id=? AND e.author_id=?""", (gid, m["id"])).fetchone()["c"]
            mwords = 0
            for p in db.execute("SELECT id FROM pages WHERE group_id=? AND owner_id=?", (gid, m["id"])):
                for R in page_rows(p["id"]):
                    for col in R["cols"]:
                        for b in col:
                            if b["block_type"] in ("text", "heading") and b["text_content"]:
                                mwords += len(_strip_tags(b["text_content"]).split())
            mcom = db.execute("""SELECT COUNT(*) c FROM comments c JOIN pages p ON p.id=c.page_id
                                 WHERE p.group_id=? AND c.author_id=?""", (gid, m["id"])).fetchone()["c"]
            mrefl = db.execute("""SELECT COUNT(*) c FROM ls_evidence_comments ec
                                  JOIN ls_evidences e ON e.id=ec.evidence_id
                                  JOIN ls_sessions s ON s.id=e.session_id
                                  WHERE s.group_id=? AND ec.author_id=?""", (gid, m["id"])).fetchone()["c"]
            vrow = db.execute("SELECT visits FROM group_visits WHERE group_id=? AND user_id=?",
                              (gid, m["id"])).fetchone()
            mvis = vrow["visits"] if vrow else 0
            contrib.append({"name": m["name"], "username": m["username"], "pages": mp, "evid": mev,
                            "words": mwords, "refl": mcom + mrefl, "visits": mvis,
                            "total": mp + mev + mcom + mrefl + mwords})
        tot_obj = db.execute("""SELECT COUNT(*) c FROM ls_objectives o JOIN ls_sessions s ON s.id=o.session_id
                                WHERE s.group_id=?""", (gid,)).fetchone()["c"]
        cov_obj = db.execute("""SELECT COUNT(*) c FROM ls_objectives o JOIN ls_sessions s ON s.id=o.session_id
                                WHERE s.group_id=? AND EXISTS(SELECT 1 FROM ls_evidence_links l
                                WHERE l.target_type='objective' AND l.target_id=o.id)""", (gid,)).fetchone()["c"]
        tot_item = db.execute("""SELECT COUNT(*) c FROM ls_items i JOIN ls_sessions s ON s.id=i.session_id
                                 WHERE s.group_id=?""", (gid,)).fetchone()["c"]
        cov_item = db.execute("""SELECT COUNT(*) c FROM ls_items i JOIN ls_sessions s ON s.id=i.session_id
                                 WHERE s.group_id=? AND EXISTS(SELECT 1 FROM ls_evidence_links l
                                 WHERE l.target_type='item' AND l.target_id=i.id)""", (gid,)).fetchone()["c"]
        totals = [c["total"] for c in contrib]
        uneven = bool(totals) and min(totals) == 0 and max(totals) >= 2
        # Índice de Gini de la participación (0 = reparto equitativo; →1 = muy desigual)
        _sv = sorted(totals)
        _n, _s = len(_sv), sum(_sv)
        if _n and _s:
            gini = round((2 * sum((i + 1) * v for i, v in enumerate(_sv))) / (_n * _s) - (_n + 1) / _n, 2)
        else:
            gini = 0.0
        gini = max(0.0, gini)
        ndisc = db.execute("""SELECT COUNT(*) c FROM ls_discussions d JOIN ls_sessions s ON s.id=d.session_id
                              WHERE s.group_id=?""", (gid,)).fetchone()["c"]
        ndisc_closed = db.execute("""SELECT COUNT(*) c FROM ls_discussions d JOIN ls_sessions s ON s.id=d.session_id
                                     WHERE s.group_id=? AND d.closed=1""", (gid,)).fetchone()["c"]
        # Latencia media: dias entre la fecha de la leccion y la subida de la evidencia
        lats = []
        for lr in db.execute("""SELECT s.lesson_date ld, e.created_at ca FROM ls_evidences e
                                JOIN ls_sessions s ON s.id=e.session_id
                                WHERE s.group_id=? AND s.lesson_date IS NOT NULL AND s.lesson_date<>''""",
                             (gid,)).fetchall():
            try:
                dd = (datetime.strptime(lr["ca"][:10], "%Y-%m-%d").date()
                      - datetime.strptime(lr["ld"][:10], "%Y-%m-%d").date()).days
                if dd >= 0:
                    lats.append(dd)
            except Exception:
                pass
        avg_lat = round(sum(lats) / len(lats), 1) if lats else None
        groups_data.append({"name": grp["name"], "id": gid, "nmembers": len(members), "npages": npages,
                            "nsess": nsess, "nevid": nevid, "contrib": contrib, "uneven": uneven,
                            "cov_obj": cov_obj, "tot_obj": tot_obj, "cov_item": cov_item, "tot_item": tot_item,
                            "ndisc": ndisc, "ndisc_closed": ndisc_closed, "avg_lat": avg_lat, "gini": gini})
    # Grafo de colaboración: quién comenta el portafolio de quién
    import math
    names_all = {r["id"]: (r["name"].split()[0] if r["name"] else "?")
                 for r in db.execute("SELECT id, name FROM users").fetchall()}
    edge_rows = db.execute("""SELECT c.author_id a, p.owner_id o, COUNT(*) n
        FROM comments c JOIN pages p ON p.id=c.page_id
        WHERE c.author_id<>p.owner_id GROUP BY c.author_id, p.owner_id""").fetchall()
    if vis_ids is not None:  # docente: solo entre su alumnado visible
        edge_rows = [e for e in edge_rows if e["a"] in vis_ids and e["o"] in vis_ids]
    nid = sorted({e["a"] for e in edge_rows} | {e["o"] for e in edge_rows})
    pos = {}
    cnodes = []
    N = len(nid)
    cx, cy, R = 260, 150, 118
    for i, uid in enumerate(nid):
        ang = (2 * math.pi * i / N - math.pi / 2) if N else 0
        x, y = cx + R * math.cos(ang), cy + R * math.sin(ang)
        pos[uid] = (x, y)
        cnodes.append({"name": names_all.get(uid, "?"), "x": round(x, 1), "y": round(y, 1)})
    maxn = max((e["n"] for e in edge_rows), default=1)
    cedges = []
    for e in edge_rows:
        x1, y1 = pos[e["a"]]
        x2, y2 = pos[e["o"]]
        dx, dy = x2 - x1, y2 - y1
        L = math.hypot(dx, dy) or 1
        ux, uy = dx / L, dy / L
        cedges.append({"x1": round(x1 + ux * 10, 1), "y1": round(y1 + uy * 10, 1),
                       "x2": round(x2 - ux * 11, 1), "y2": round(y2 - uy * 11, 1),
                       "w": round(1 + 3 * e["n"] / maxn, 1)})
    collab = {"nodes": cnodes, "edges": cedges}

    charts = json.dumps({
        "weeks": weeks,
        "pages": [counts[w]["pages"] for w in weeks],
        "artefacts": [counts[w]["artefacts"] for w in weeks],
        "comments": [counts[w]["comments"] for w in weeks],
        "kind_labels": kind_labels, "kind_counts": kind_counts,
        "student_names": [r["name"].split()[0] for r in rows],
        "student_scores": [r["score"] for r in rows],
        "student_colors": [r["color"] for r in rows],
        "student_part": [r["participation"] for r in rows],
        "risk_names": ["Alto", "Medio", "Bajo"],
        "risk_data": [risk_counts["Alto"], risk_counts["Medio"], risk_counts["Bajo"]]})
    return render(ANALYTICS_TPL, title="Dashboard", kpi=kpi, rows=rows, watch=watch, pending=pending,
                  charts=charts, groups_data=groups_data, risk_counts=risk_counts, collab=collab,
                  my_subjects=my_subjects, is_teacher=(me["role"] == "teacher"))


@app.route("/subjects/<int:sid>/archive", methods=["POST"])
@login_required
@role_required("teacher", "admin")
def subject_archive_toggle(sid):
    db, u = get_db(), current_user()
    if u["role"] != "admin" and not db.execute(
            "SELECT 1 FROM subject_teachers WHERE subject_id=? AND teacher_id=?", (sid, u["id"])).fetchone():
        abort(403)
    if db.execute("SELECT 1 FROM subject_archived WHERE subject_id=? AND teacher_id=?", (sid, u["id"])).fetchone():
        db.execute("DELETE FROM subject_archived WHERE subject_id=? AND teacher_id=?", (sid, u["id"]))
    else:
        db.execute("INSERT INTO subject_archived(subject_id,teacher_id) VALUES(?,?)", (sid, u["id"]))
    db.commit()
    return redirect(url_for("analytics"))


STUDENT_ACTIVITY_TPL = """
<div class="between"><h1>Cambios de {{ stud['name'] }}</h1>
 <a class="btn sec" href="{{ url_for('analytics') }}">Volver a analíticas</a></div>
<p class="muted" style="margin-top:0">Todas las entradas y ediciones registradas, con su fecha. Las páginas privadas se muestran sin título por privacidad.</p>
{% for a in items %}<div class="card between" style="padding:12px 16px">
 <div><span class="muted">{{ a['created_at'] }}</span> &middot; {{ a['detail'] }}
  <div style="margin-top:2px"><b>{% if a['visibility'] in ('teachers','public') %}{{ a['page_title'] or '(sin título)' }}{% else %}(página privada){% endif %}</b>
   {% if a['visibility'] %}<span class="pill">{{ vis[a['visibility']] }}</span>{% endif %}</div></div>
 {% if a['page_id'] and a['visibility'] in ('teachers','public') %}<a class="btn sec sm" href="{{ url_for('page_view', pid=a['page_id']) }}">Ver</a>{% endif %}
</div>{% else %}<p class="muted">Sin cambios registrados para este estudiante.</p>{% endfor %}

<div class="card" style="border:2px solid #d33;background:#fff6f6;margin-top:20px">
 <h2 style="margin-top:0;color:#b3261e">&#128721; Evidencia: comentarios del profesorado ({{ ev_comments|length }})</h2>
 <p class="muted" style="margin-top:0;font-size:13px">Comentarios publicados por <b>docentes o administración</b>. Se conservan <b>aunque el estudiante borre la página o el comentario</b>. No se registran los mensajes ni los comentarios entre estudiantes.</p>
 {% for c in ev_comments %}<div style="border-top:1px solid #f0cfcf;padding:8px 0">
  <div style="font-size:13px"><b>{{ c['author_name'] }}</b> <span class="muted">en «{{ c['page_title'] or '(página eliminada)' }}» &middot; {{ c['created_at'] }}</span></div>
  <div>{{ c['body'] }}</div></div>
 {% else %}<p class="muted" style="margin:0">Sin comentarios del profesorado registrados.</p>{% endfor %}
</div>
"""


@app.route("/analytics/student/<username>")
@login_required
@role_required("teacher", "admin")
def student_activity(username):
    db = get_db()
    stud = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not stud:
        abort(404)
    if not teacher_can_view_student(current_user(), stud["id"]):
        abort(403)
    items = db.execute("SELECT * FROM student_activity WHERE student_id=? ORDER BY id DESC LIMIT 500",
                       (stud["id"],)).fetchall()
    # Evidencia: comentarios del profesorado/admin, que se conservan aunque el alumno borre la página.
    ev_comments = db.execute("""SELECT * FROM comment_log WHERE owner_id=?
        AND author_role IN ('teacher','admin') ORDER BY id DESC LIMIT 500""", (stud["id"],)).fetchall()
    return render(STUDENT_ACTIVITY_TPL, title="Cambios de " + stud["name"], stud=stud, items=items, vis=VIS,
                  ev_comments=ev_comments)


def individual_metrics(db, s, nweeks=8):
    """Métricas individualizadas de un estudiante para su dashboard en el asistente."""
    from datetime import datetime, date, timedelta
    if nweeks not in (8, 12, 26, 52):
        nweeks = 8
    sid, ppid = s["id"], s["profile_page_id"]
    today = date.today()

    def c1(sql, args):
        return db.execute(sql, args).fetchone()["c"]

    def wk(v):
        try:
            d = datetime.strptime((v or "")[:10], "%Y-%m-%d").date()
            y, w, _ = d.isocalendar()
            return "%04d-S%02d" % (y, w)
        except Exception:
            return None

    pages = c1("SELECT COUNT(*) c FROM pages WHERE owner_id=? AND id IS NOT ?", (sid, ppid))
    public = c1("SELECT COUNT(*) c FROM pages WHERE owner_id=? AND visibility='public' AND id IS NOT ?", (sid, ppid))
    shared = c1("SELECT COUNT(*) c FROM pages WHERE owner_id=? AND visibility IN ('teachers','public') AND id IS NOT ?", (sid, ppid))
    arte = c1("SELECT COUNT(*) c FROM artefacts WHERE owner_id=?", (sid,))
    kinds = set(r["kind"] for r in db.execute("SELECT DISTINCT kind FROM artefacts WHERE owner_id=?", (sid,)))
    words = n_text = 0
    last = None
    for p in db.execute("SELECT id, created_at FROM pages WHERE owner_id=? AND id IS NOT ?", (sid, ppid)):
        if p["created_at"] and (last is None or p["created_at"] > last):
            last = p["created_at"]
        for R in page_rows(p["id"]):
            for col in R["cols"]:
                for b in col:
                    if b["block_type"] in ("text", "heading") and b["text_content"]:
                        words += len(_strip_tags(b["text_content"]).split())
                        n_text += 1
    received = c1("SELECT COUNT(*) c FROM comments c JOIN pages p ON p.id=c.page_id WHERE p.owner_id=? AND c.author_id<>?", (sid, sid))
    given = c1("SELECT COUNT(*) c FROM comments c JOIN pages p ON p.id=c.page_id WHERE c.author_id=? AND p.owner_id<>?", (sid, sid))
    reads = c1("SELECT COUNT(*) c FROM page_reads r JOIN pages p ON p.id=r.page_id WHERE p.owner_id=?", (sid,))
    g_contrib = (c1("SELECT COUNT(*) c FROM pages WHERE group_id IS NOT NULL AND owner_id=?", (sid,))
                 + c1("SELECT COUNT(*) c FROM ls_evidences WHERE author_id=?", (sid,))
                 + c1("SELECT COUNT(*) c FROM ls_evidence_comments WHERE author_id=?", (sid,))
                 + c1("SELECT COUNT(*) c FROM ls_discussion_posts WHERE author_id=?", (sid,)))
    days = None
    if last:
        try:
            days = (today - datetime.strptime(last[:10], "%Y-%m-%d").date()).days
        except Exception:
            days = None
    weekset = []
    for i in range(nweeks - 1, -1, -1):
        d = today - timedelta(weeks=i)
        y, w, _ = d.isocalendar()
        weekset.append("%04d-S%02d" % (y, w))
    wkc = {lab: 0 for lab in weekset}
    for tbl, col in (("pages", "owner_id"), ("artefacts", "owner_id"), ("ls_evidences", "author_id")):
        for r in db.execute("SELECT created_at FROM %s WHERE %s=?" % (tbl, col), (sid,)):
            k = wk(r["created_at"])
            if k in wkc:
                wkc[k] += 1
    for r in db.execute("SELECT created_at FROM comments WHERE author_id=?", (sid,)):
        k = wk(r["created_at"])
        if k in wkc:
            wkc[k] += 1
    weekly = [wkc[lab] for lab in weekset]
    constancia = sum(1 for v in weekly[-8:] if v > 0)  # semanas activas de las últimas 8
    # Reacción al feedback: para CADA comentario docente en sus páginas, ¿respondió en ≤7 días,
    # ya sea comentando en esa misma página o editándola (registro en student_activity)?
    fbs = db.execute("""SELECT c.page_id pid, c.created_at ca FROM comments c
        JOIN pages p ON p.id=c.page_id JOIN users au ON au.id=c.author_id
        WHERE p.owner_id=? AND au.role IN ('teacher','admin')""", (sid,)).fetchall()
    reacts_m = len(fbs)
    reacts_resp = 0
    for fb in fbs:
        T, P = fb["ca"], fb["pid"]
        try:
            tlim = (datetime.strptime(T[:16], "%Y-%m-%d %H:%M") + timedelta(days=7)).strftime("%Y-%m-%d %H:%M")
        except Exception:
            tlim = "9999"
        replied = c1("SELECT COUNT(*) c FROM comments WHERE page_id=? AND author_id=? AND created_at>? AND created_at<=?",
                     (P, sid, T, tlim))
        edited = c1("SELECT COUNT(*) c FROM student_activity WHERE page_id=? AND student_id=? AND created_at>? AND created_at<=?",
                    (P, sid, T, tlim))
        if replied or edited:
            reacts_resp += 1
    reacts_pct = round(100 * reacts_resp / reacts_m) if reacts_m else None
    reacts = ("%d de %d" % (reacts_resp, reacts_m)) if reacts_m else "—"

    # Tiempo hasta la primera publicación (días entre la 1ª página y la 1ª pública)
    first_page = db.execute("SELECT MIN(created_at) m FROM pages WHERE owner_id=? AND id IS NOT ?", (sid, ppid)).fetchone()["m"]
    first_pub = db.execute("SELECT MIN(created_at) m FROM pages WHERE owner_id=? AND visibility='public' AND id IS NOT ?", (sid, ppid)).fetchone()["m"]
    pub_status = "—"
    if first_pub and first_page:
        try:
            dd = (datetime.strptime(first_pub[:10], "%Y-%m-%d").date()
                  - datetime.strptime(first_page[:10], "%Y-%m-%d").date()).days
            pub_status = "%d d" % max(0, dd)
        except Exception:
            pass
    elif first_page:
        pub_status = "sin publicar"

    # Evolución: actividad acumulada dentro del periodo
    cum = []
    run = 0
    for v in weekly:
        run += v
        cum.append(run)

    # Mapa de calor de actividad por día (L-D) y hora (0-23)
    heat = [[0] * 24 for _ in range(7)]

    def _heat(ts):
        try:
            dt = datetime.strptime(ts[:16], "%Y-%m-%d %H:%M")
            heat[dt.weekday()][dt.hour] += 1
        except Exception:
            pass
    for tbl, col in (("pages", "owner_id"), ("artefacts", "owner_id"), ("ls_evidences", "author_id")):
        for r in db.execute("SELECT created_at FROM %s WHERE %s=?" % (tbl, col), (sid,)):
            if r["created_at"]:
                _heat(r["created_at"])
    for r in db.execute("SELECT created_at FROM comments WHERE author_id=?", (sid,)):
        if r["created_at"]:
            _heat(r["created_at"])
    hmax = max((max(row) for row in heat), default=0)
    heat_css = [["rgba(192,50,95,%.2f)" % (v / hmax) if (v and hmax) else "#f0eaef" for v in row] for row in heat]

    # Volumen de trabajo (NO se satura): total de entradas productivas. Distingue a quien hace mucho
    # de quien solo cumple el mínimo, aunque ambos estén "verdes" en completitud.
    n_comments_all = c1("SELECT COUNT(*) c FROM comments WHERE author_id=?", (sid,))
    ls_ev_auth = c1("SELECT COUNT(*) c FROM ls_evidences WHERE author_id=?", (sid,))
    volume = pages + arte + ls_ev_auth + n_comments_all

    # Inactividad y parada (detecta si "de nuevo" deja de entrar/crear/publicar)
    ls_seen = s["last_seen"] if ("last_seen" in s.keys()) else None
    seen_days = None
    if ls_seen:
        try:
            seen_days = (today - datetime.strptime(ls_seen[:10], "%Y-%m-%d").date()).days
        except Exception:
            seen_days = None
    last8 = weekly[-8:]
    inactive_weeks = sum(1 for v in last8 if v == 0)
    # Parada: hubo actividad en semanas anteriores pero las 2 últimas están a cero.
    stalled = (sum(last8[:-2]) > 0) and (sum(last8[-2:]) == 0)

    return {
        "pages": pages, "public": public, "shared": shared, "artefacts": arte, "words": words,
        "kinds": len(kinds), "received": received, "given": given, "reads": reads,
        "logins": s["login_count"] or 0, "group_contrib": g_contrib, "days": days,
        "constancia": constancia, "pub_rate": (round(public * 100 / pages) if pages else 0),
        "depth": (round(words / n_text) if n_text else 0),
        "refl_ratio": (round(words / arte, 1) if arte else 0),
        "reciprocity": ("%d dados / %d recibidos" % (given, received)),
        "reacts": reacts, "reacts_pct": reacts_pct,
        "weeks": weekset, "weekly": weekly, "nweeks": nweeks,
        "pub_status": pub_status, "cum": cum, "heat_css": heat_css,
        "volume": volume, "seen_days": seen_days, "inactive_weeks": inactive_weeks, "stalled": stalled,
    }


ASSIST_TPL = """
<div class="between"><h1>Asistente de revision</h1>
 <a class="btn sec" href="{{ url_for('analytics') }}">Volver a analiticas</a></div>
<p class="muted">Portafolio de <b>{{ stud['name'] }}</b> &middot; IA:
 {% if ai_on %}<span class="pill">conectada ({{ ai_provider }})</span>{% else %}<span class="pill">no configurada</span>{% endif %}</p>

<div class="card"><h2>Dashboard individual</h2>
 {% if m.stalled %}<div style="background:#fdecea;color:#8a1c1c;border:1px solid #f3b8b1;border-radius:10px;padding:10px 12px;margin-bottom:10px;font-size:13px">
  <b>&#9888; Parece que ha dejado de trabajar.</b> Sin actividad en las últimas 2 semanas tras haber estado activo/a{% if m.seen_days is not none %} · última conexión hace {{ m.seen_days }} día(s){% endif %}. Buen momento para escribirle.</div>{% endif %}
 <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:12px">
  <div class="tile"><div class="k">Volumen de trabajo</div><div style="font-size:26px;font-weight:800">{{ m.volume }}</div><div class="muted" style="font-size:12px">entradas totales (no se satura)</div></div>
  <div class="tile"><div class="k">Semanas sin actividad</div><div style="font-size:26px;font-weight:800;color:{{ '#d34' if m.inactive_weeks>=4 else ('#e0a020' if m.inactive_weeks>=2 else '#2e9e5b') }}">{{ m.inactive_weeks }}/8</div><div class="muted" style="font-size:12px">de las últimas 8</div></div>
  <div class="tile"><div class="k">Última conexión</div><div style="font-size:22px;font-weight:800">{% if m.seen_days is none %}—{% else %}hace {{ m.seen_days }} d{% endif %}</div><div class="muted" style="font-size:12px">entrar en la plataforma</div></div>
  <div class="tile"><div class="k">Páginas</div><div style="font-size:26px;font-weight:800">{{ m.pages }}</div><div class="muted" style="font-size:12px">{{ m.public }} públicas · {{ m.shared }} compartidas</div></div>
  <div class="tile"><div class="k">Palabras de reflexión</div><div style="font-size:26px;font-weight:800">{{ m.words }}</div><div class="muted" style="font-size:12px">{{ m.depth }} por bloque</div></div>
  <div class="tile"><div class="k">Artefactos</div><div style="font-size:26px;font-weight:800">{{ m.artefacts }}</div><div class="muted" style="font-size:12px">{{ m.kinds }} tipo(s)</div></div>
  <div class="tile"><div class="k">Constancia</div><div style="font-size:26px;font-weight:800">{{ m.constancia }}/8</div><div class="muted" style="font-size:12px">semanas activas</div></div>
  <div class="tile"><div class="k">Publicación</div><div style="font-size:26px;font-weight:800">{{ m.pub_rate }}%</div><div class="muted" style="font-size:12px">páginas públicas</div></div>
  <div class="tile"><div class="k">Reflexión / evidencia</div><div style="font-size:26px;font-weight:800">{{ m.refl_ratio }}</div><div class="muted" style="font-size:12px">palabras por artefacto</div></div>
  <div class="tile"><div class="k">Interacción</div><div style="font-size:16px;font-weight:800;margin-top:6px">{{ m.reciprocity }}</div><div class="muted" style="font-size:12px">comentarios</div></div>
  <div class="tile"><div class="k">Aportación en grupo</div><div style="font-size:26px;font-weight:800">{{ m.group_contrib }}</div><div class="muted" style="font-size:12px">páginas, evidencias, discusiones</div></div>
  <div class="tile"><div class="k">Responde al feedback</div><div style="font-size:22px;font-weight:800">{% if m.reacts_pct is none %}—{% else %}{{ m.reacts_pct }}%{% endif %}</div><div class="muted" style="font-size:12px">responde a {{ m.reacts }} comentarios docentes (≤7 días: edita la página o responde)</div></div>
  <div class="tile"><div class="k">Última actividad</div><div style="font-size:22px;font-weight:800">{% if m.days is none %}—{% else %}hace {{ m.days }} d{% endif %}</div><div class="muted" style="font-size:12px">{{ m.logins }} inicios de sesión</div></div>
  <div class="tile"><div class="k">Tiempo hasta publicar</div><div style="font-size:22px;font-weight:800">{{ m.pub_status }}</div><div class="muted" style="font-size:12px">desde la 1ª página a la 1ª pública</div></div>
 </div>
 <div class="between" style="margin-top:16px;align-items:center">
  <b class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.05em">Actividad por semanas</b>
  <select onchange="location.href='{{ url_for('assistant', username=stud['username']) }}?w='+this.value" style="max-width:180px;margin:0">
   {% for wv,wl in [(8,'Últimas 8 semanas'),(12,'Últimas 12 semanas'),(26,'Últimos 6 meses'),(52,'Último año')] %}
   <option value="{{ wv }}" {{ 'selected' if m.nweeks==wv }}>{{ wl }}</option>{% endfor %}</select>
 </div>
 <canvas id="wkChart" height="90" style="margin-top:6px"></canvas>

 <div class="between" style="margin-top:18px;align-items:center">
  <b class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.05em">Mapa de calor · cuándo trabaja (día × hora)</b>
  <span class="muted" style="font-size:11px">Menos <span style="display:inline-block;width:12px;height:12px;background:#f0eaef;vertical-align:middle"></span> <span style="display:inline-block;width:12px;height:12px;background:rgba(192,50,95,.5);vertical-align:middle"></span> <span style="display:inline-block;width:12px;height:12px;background:rgba(192,50,95,1);vertical-align:middle"></span> Más</span>
 </div>
 <div style="overflow-x:auto;margin-top:6px"><table style="border-collapse:collapse;font-size:9px">
  <tr><th></th>{% for h in range(24) %}<th style="font-weight:400;color:var(--muted);padding:0 1px">{{ h }}</th>{% endfor %}</tr>
  {% for di in range(7) %}<tr>
   <td style="color:var(--muted);padding-right:5px;text-align:right">{{ ['Lun','Mar','Mié','Jue','Vie','Sáb','Dom'][di] }}</td>
   {% for h in range(24) %}<td style="width:13px;height:13px;background:{{ m.heat_css[di][h] }};border:1px solid #fff"></td>{% endfor %}
  </tr>{% endfor %}
 </table></div>
</div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.0/chart.umd.min.js"></script>
<script>
(function(){ var el=document.getElementById('wkChart'); if(!el||!window.Chart) return;
 new Chart(el,{type:'bar',data:{labels:{{ m.weeks|tojson }},datasets:[
   {label:'Actividad por semana',data:{{ m.weekly|tojson }},backgroundColor:'#c0325f',borderRadius:5}
  ]},
  options:{plugins:{legend:{display:false}},scales:{y:{beginAtZero:true,ticks:{precision:0}}}}});
})();
</script>

<div class="card"><h2>Indicadores de seguimiento</h2>
 <p class="muted" style="margin-top:0;font-size:13px">Los mismos datos de la fila de la tabla de analíticas, aquí explicados uno a uno. Son orientativos (individuales y formativos), no una nota ni una comparación con el resto.</p>
 <div class="grid" style="grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:12px">
  <div class="tile"><div class="k">Completitud del portafolio</div>
   <div style="display:flex;align-items:center;gap:8px;margin-top:4px">
    <div style="background:#efeaed;border-radius:6px;height:10px;flex:1"><div style="height:10px;border-radius:6px;width:{{ ov.score }}%;background:{{ ov.color }}"></div></div>
    <b>{{ ov.score }}</b></div>
   <div class="muted" style="font-size:12px;margin-top:4px">0–100. Combina tener páginas, publicar, reflexión escrita, variedad de evidencias e interacción recibida. Verde ≥70, ámbar 40–69, rojo &lt;40. <b>Se satura</b>: por eso mira también el volumen de arriba.</div></div>

  <div class="tile"><div class="k">Participación</div>
   <div style="display:flex;align-items:center;gap:8px;margin-top:4px">
    <div style="background:#efeaed;border-radius:6px;height:10px;flex:1"><div style="height:10px;border-radius:6px;width:{{ ov.participation }}%;background:{{ ov.pcolor }}"></div></div>
    <b>{{ ov.participation }}</b></div>
   <div class="muted" style="font-size:12px;margin-top:4px">0–100. Lo que <b>aporta</b> (no lo que recibe): comentarios a otros, lecturas, mensajes, evidencias LS y grupos. Sin tope: <b>{{ ov.part_raw }} acciones</b> en total.</div></div>

  <div class="tile"><div class="k">Riesgo de abandono</div>
   <div style="margin-top:4px"><span class="pill" style="background:{{ ov.rcolor }};color:#fff">{{ ov.level }} · {{ ov.risk }}%</span></div>
   <div class="muted" style="font-size:12px;margin-top:4px">Heurístico de inactividad, baja producción y parada reciente.{% if ov.reason %} Señales: {{ ov.reason }}.{% endif %}</div></div>

  <div class="tile"><div class="k">Tendencia</div>
   <div style="font-size:22px;font-weight:800;color:{{ '#2e9e5b' if ov.trend=='sube' else ('#d34' if ov.trend in ('baja','en pausa') else '#8b8492') }};margin-top:2px">{{ ov.trend_arrow }} {{ ov.trend }}</div>
   <div class="muted" style="font-size:12px">Momentum reciente: últimos 7 días frente a los 7 anteriores. Si no hay nada en la última semana aparece «en pausa».</div></div>

  <div class="tile"><div class="k">Feedback recibido</div><div style="font-size:26px;font-weight:800">{{ ov.comments }}</div>
   <div class="muted" style="font-size:12px">Comentarios de otras personas en sus páginas.</div></div>

  <div class="tile"><div class="k">Lecturas recibidas</div><div style="font-size:26px;font-weight:800">{{ ov.reads }}</div>
   <div class="muted" style="font-size:12px">Veces que sus páginas han sido leídas.</div></div>

  <div class="tile"><div class="k">Sin leer (por ti)</div><div style="font-size:26px;font-weight:800;color:{{ '#c0325f' if ov.pend else '#25202a' }}">{{ ov.pend }}</div>
   <div class="muted" style="font-size:12px">Páginas suyas compartidas contigo que aún no has marcado como leídas.</div></div>
 </div>
</div>

<div class="card"><h2>Asistentes de IA</h2>
 {% if ai_on %}
 <p class="muted" style="margin-top:0;font-size:13px">Dos asistentes distintos: <b>Feedback</b> redacta una devolución formativa para el estudiante; <b>Analizar entradas</b> hace un análisis rápido (estadístico y cualitativo) de sus páginas, temas, profundidad y frecuencia, cita fragmentos y sugiere preguntas para seguir ayudándole a reflexionar.</p>
 <form method="post">
  <label>Instrucción para la IA (opcional, se aplica al asistente que pulses)</label>
  <textarea name="instruction" placeholder="Ej.: evalua la claridad de las reflexiones y sugiere mejoras de accesibilidad">{{ instruction or '' }}</textarea>
  <div class="row-flex" style="gap:8px;margin-top:4px">
   <button class="btn" name="mode" value="feedback">✍ Generar feedback</button>
   <button class="btn sec" name="mode" value="analisis">🔍 Analizar entradas</button>
  </div>
  <span class="muted" style="font-size:12px;display:block;margin-top:6px">Se genera en segundo plano; puedes seguir trabajando y te avisaremos al terminar.</span>
 </form>
 <div style="margin-top:10px;font-size:12px;background:#fff7e6;color:#7a4a00;border:1px solid #f0d9a8;border-radius:8px;padding:7px 10px">&#9888; Esto es una IA: puede cometer errores. Revisa y <b>verifica siempre</b> sus respuestas antes de usarlas.</div>
 {% if jobs %}<div style="margin-top:14px">
  <b class="muted" style="font-size:12px;text-transform:uppercase;letter-spacing:.05em">Resultados generados</b>
  {% for j in jobs %}
  <div class="job" data-id="{{ j['id'] }}" data-status="{{ j['status'] }}" style="border:1px solid var(--line);border-radius:12px;padding:12px;margin-top:8px">
   <div class="between"><span class="muted" style="font-size:12px"><span class="pill" style="background:{{ '#3a7bd5' if j['mode']=='analisis' else '#7a1f3d' }};color:#fff">{{ 'Análisis' if j['mode']=='analisis' else 'Feedback' }}</span> {{ j['created_at'] }}{% if j['instruction'] %} · {{ j['instruction'] }}{% endif %}</span>
    <span class="pill job-badge" style="background:{{ '#2e9e5b' if j['status']=='done' else ('#d34' if j['status']=='error' else '#e0a020') }};color:#fff">{{ {'pending':'en cola','running':'generando','done':'listo','error':'error'}[j['status']] }}</span></div>
   <div class="job-body" style="margin-top:8px;white-space:pre-wrap">{% if j['status']=='done' %}{{ j['result'] }}{% elif j['status']=='error' %}<span style="color:#d34">Error: {{ j['error'] }}</span>{% else %}<span class="muted">Generando… puedes salir de esta página; recibirás un aviso.</span>{% endif %}</div>
  </div>
  {% endfor %}
 </div>
 <script>
 (function(){ document.querySelectorAll('.job').forEach(function(el){
   var st=el.getAttribute('data-status');
   if(st==='pending'||st==='running'){ var id=el.getAttribute('data-id');
     var t=setInterval(function(){ fetch('/api/aijob/'+id).then(function(r){return r.json();}).then(function(d){
       if(d.status==='done'||d.status==='error'){ clearInterval(t);
         var b=el.querySelector('.job-badge'); b.textContent=(d.status==='done'?'listo':'error'); b.style.background=(d.status==='done'?'#2e9e5b':'#d34');
         el.querySelector('.job-body').textContent=(d.status==='done'? d.result : ('Error: '+(d.error||'')));
       } }).catch(function(){}); }, 3000);
   } }); })();
 </script>{% endif %}
 {% else %}
 <p class="muted"><b>Opciones GRATIS</b> para activar la IA (define la variable antes de arrancar la app):</p>
 <ul class="muted" style="line-height:1.7">
  <li><b>Ollama</b> (local, gratis y privado): instala Ollama, ejecuta <code>ollama pull llama3.2</code> y arranca con <code>OLLAMA_MODEL=llama3.2 python3 app.py</code>.</li>
  <li><b>Google Gemini</b> (nube, capa gratuita): clave gratis en Google AI Studio y <code>export GEMINI_API_KEY=...</code></li>
  <li><b>Groq</b> (nube, gratis): clave en groq.com y <code>export GROQ_API_KEY=...</code></li>
 </ul>
 <p class="muted">Tambien sirven <code>ANTHROPIC_API_KEY</code> u <code>OPENAI_API_KEY</code> (de pago). Sin nada configurado, tienes el análisis automatico de abajo.</p>
 {% endif %}
</div>

<div class="card"><h2>Resumen automatico</h2>
 <ul>{% for k,v in stats.items() %}<li><b>{{ k }}:</b> {{ v }}</li>{% endfor %}</ul></div>
<div class="card"><h2>Sugerencias automáticas</h2>
 {% if tips %}<ul>{% for t in tips %}<li>{{ t }}</li>{% endfor %}</ul>
 {% else %}<p class="muted">El portafolio parece bastante completo.</p>{% endif %}</div>
<div class="card"><h2>Borrador automatico</h2>
 <p style="white-space:pre-wrap">{{ draft }}</p></div>

<div class="card"><h2>Registro de cambios ({{ items|length }})</h2>
 <p class="muted" style="margin-top:0;font-size:13px">Todas las entradas y ediciones registradas, con su fecha. Las páginas privadas se muestran sin título por privacidad.</p>
 {% for a in items %}<div class="between" style="padding:8px 0;border-bottom:1px solid var(--line)">
  <div><span class="muted">{{ a['created_at'] }}</span> &middot; {{ a['detail'] }}
   <div style="margin-top:2px"><b>{% if a['visibility'] in ('teachers','public') %}{{ a['page_title'] or '(sin título)' }}{% else %}(página privada){% endif %}</b>
    {% if a['visibility'] %}<span class="pill">{{ vis[a['visibility']] }}</span>{% endif %}</div></div>
  {% if a['page_id'] and a['visibility'] in ('teachers','public') %}<a class="btn sec sm" href="{{ url_for('page_view', pid=a['page_id']) }}">Ver</a>{% endif %}
 </div>{% else %}<p class="muted">Sin cambios registrados para este estudiante.</p>{% endfor %}
</div>

<div class="card" style="border:2px solid #d33;background:#fff6f6">
 <h2 style="margin-top:0;color:#b3261e">&#128721; Evidencia: comentarios del profesorado ({{ ev_comments|length }})</h2>
 <p class="muted" style="margin-top:0;font-size:13px">Comentarios publicados por <b>docentes o administración</b>. Se conservan <b>aunque el estudiante borre la página o el comentario</b>. No se registran los mensajes ni los comentarios entre estudiantes.</p>
 {% for c in ev_comments %}<div style="border-top:1px solid #f0cfcf;padding:8px 0">
  <div style="font-size:13px"><b>{{ c['author_name'] }}</b> <span class="muted">en «{{ c['page_title'] or '(página eliminada)' }}» &middot; {{ c['created_at'] }}</span></div>
  <div>{{ c['body'] }}</div></div>
 {% else %}<p class="muted" style="margin:0">Sin comentarios del profesorado registrados.</p>{% endfor %}
</div>
"""


# --------------------------- Conexion con IA ------------------------------- #
def ai_config():
    """Devuelve (proveedor, clave_o_host, modelo) segun el entorno, o (None, None, None).
    Soporta opciones GRATIS: Ollama (local) y Google Gemini / Groq (capa gratuita)."""
    m = os.environ.get("EVESTIGIA_AI_MODEL")
    prov = os.environ.get("EVESTIGIA_AI_PROVIDER")
    # Ollama: local, gratis y privado (no requiere clave)
    if prov == "ollama" or (not prov and os.environ.get("OLLAMA_MODEL")):
        return ("ollama", os.environ.get("OLLAMA_HOST", "http://localhost:11434"),
                m or os.environ.get("OLLAMA_MODEL", "llama3.2"))
    if os.environ.get("ANTHROPIC_API_KEY"):
        return ("anthropic", os.environ["ANTHROPIC_API_KEY"], m or "claude-3-5-sonnet-latest")
    if os.environ.get("OPENAI_API_KEY"):
        return ("openai", os.environ["OPENAI_API_KEY"], m or "gpt-4o-mini")
    if os.environ.get("GROQ_API_KEY"):
        return ("groq", os.environ["GROQ_API_KEY"], m or "llama-3.1-8b-instant")
    if os.environ.get("GEMINI_API_KEY"):
        return ("gemini", os.environ["GEMINI_API_KEY"], m or "gemini-1.5-flash")
    return (None, None, None)


def _ai_build_request(provider, key, model, system, user):
    system = system or ""   # vacio -> deja mandar al SYSTEM del modelo (Modelfile/fine-tuning)
    if provider == "anthropic":
        url = "https://api.anthropic.com/v1/messages"
        headers = {"x-api-key": key, "anthropic-versión": "2023-06-01", "content-type": "application/json"}
        data = {"model": model, "max_tokens": 900, "messages": [{"role": "user", "content": user}]}
        if system:
            data["system"] = system
    elif provider == "gemini":
        url = ("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s"
               % (model, key))
        headers = {"content-type": "application/json"}
        data = {"contents": [{"role": "user", "parts": [{"text": user}]}]}
        if system:
            data["system_instruction"] = {"parts": [{"text": system}]}
    elif provider == "ollama":
        url = key.rstrip("/") + "/api/chat"   # 'key' aqui es el host local
        headers = {"content-type": "application/json"}
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": user}]
        # keep_alive mantiene el modelo cargado (evita recargarlo en cada petición);
        # num_ctx amplía la ventana para no truncar prompts largos (análisis con ejemplos).
        data = {"model": model, "stream": False, "messages": msgs,
                "keep_alive": os.environ.get("OLLAMA_KEEP_ALIVE", "30m"),
                "options": {"num_ctx": int(os.environ.get("OLLAMA_NUM_CTX", "8192"))}}
    else:  # openai o groq (API compatible con OpenAI)
        url = ("https://api.groq.com/openai/v1/chat/completions" if provider == "groq"
               else "https://api.openai.com/v1/chat/completions")
        headers = {"Authorization": "Bearer " + key, "content-type": "application/json"}
        msgs = ([{"role": "system", "content": system}] if system else []) + [{"role": "user", "content": user}]
        data = {"model": model, "messages": msgs}
    return url, headers, json.dumps(data).encode("utf-8")


def _ai_parse_response(provider, raw):
    d = json.loads(raw)
    if provider == "anthropic":
        return d["content"][0]["text"]
    if provider == "gemini":
        return d["candidates"][0]["content"]["parts"][0]["text"]
    if provider == "ollama":
        return d["message"]["content"]
    return d["choices"][0]["message"]["content"]


def ai_generate_ex(system, user, timeout=None):
    """Devuelve (texto, error). error=None si todo fue bien."""
    provider, key, model = ai_config()
    if not provider:
        return None, "IA no configurada"
    if timeout is None:
        # Ollama en local puede ser lento (y la 1ª petición carga el modelo): margen amplio.
        default = "600" if provider == "ollama" else "180"
        try:
            timeout = int(os.environ.get("EVESTIGIA_AI_TIMEOUT", default))
        except Exception:
            timeout = int(default)
    import urllib.request, urllib.error
    url, headers, body = _ai_build_request(provider, key, model, system, user)
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return _ai_parse_response(provider, r.read().decode("utf-8")), None
    except urllib.error.HTTPError as e:
        try:
            detail = e.read().decode("utf-8", "ignore")[:300]
        except Exception:
            detail = ""
        return None, "HTTP %s. %s" % (e.code, detail)
    except urllib.error.URLError as e:
        return None, ("No hay conexion con el proveedor (%s). Si usas Ollama, revisa que este "
                      "arrancado y el modelo descargado." % getattr(e, "reason", e))
    except Exception as e:
        return None, str(e)


def ai_generate(system, user, timeout=120):
    text, _err = ai_generate_ex(system, user, timeout)
    return text


# --------- Cola de tareas de IA (segundo plano, sin dependencias externas) --------- #
import queue as _queue
import threading as _threading

AI_QUEUE = _queue.Queue()


def _ai_worker():
    while True:
        try:
            jid, system, user_prompt = AI_QUEUE.get()
        except Exception:
            continue
        conn = None
        try:
            conn = sqlite3.connect(DB_PATH, timeout=30)
            conn.execute("UPDATE ai_jobs SET status='running' WHERE id=?", (jid,))
            conn.commit()
            text, err = ai_generate_ex(system, user_prompt)
            job = conn.execute("SELECT requester_id, student_name, student_username FROM ai_jobs WHERE id=?",
                               (jid,)).fetchone()
            if text is not None:
                conn.execute("UPDATE ai_jobs SET status='done', result=?, done_at=? WHERE id=?",
                             (text, now(), jid))
                if job and job[2]:  # solo avisa en el asistente de alumno; en LS se ve en el panel
                    conn.execute("INSERT INTO notifications(user_id,kind,text,link,is_read,created_at) "
                                 "VALUES(?,?,?,?,0,?)",
                                 (job[0], "Feedback de IA listo",
                                  "El feedback de IA para %s ya está disponible." % (job[1] or "el estudiante"),
                                  "/assistant/%s" % job[2], now()))
            else:
                conn.execute("UPDATE ai_jobs SET status='error', error=?, done_at=? WHERE id=?",
                             (err or "error desconocido", now(), jid))
            conn.commit()
        except Exception as e:
            try:
                conn.execute("UPDATE ai_jobs SET status='error', error=?, done_at=? WHERE id=?",
                             (str(e), now(), jid))
                conn.commit()
            except Exception:
                pass
        finally:
            if conn:
                conn.close()
            AI_QUEUE.task_done()


_threading.Thread(target=_ai_worker, daemon=True).start()


def enqueue_ai_job(requester_id, stud, system, user_prompt, instruction, mode="feedback"):
    db = get_db()
    jid = db.execute("""INSERT INTO ai_jobs(requester_id,student_id,student_name,student_username,
                        instruction,mode,status,created_at) VALUES(?,?,?,?,?,?, 'pending', ?)""",
                     (requester_id, stud["id"], stud["name"], stud["username"], instruction, mode, now())).lastrowid
    db.commit()
    AI_QUEUE.put((jid, system, user_prompt))
    return jid


def ai_examples_block(db, kind, limit=3):
    """Ejemplos anonimizados subidos por el admin, en texto, para guiar el estilo (few-shot).
    Se añaden al 'system' del modelo. Devuelve '' si no hay ejemplos."""
    try:
        rows = db.execute("""SELECT title, portfolio, feedback FROM ai_examples
            WHERE active=1 AND kind=? ORDER BY id DESC LIMIT ?""", (kind, limit)).fetchall()
    except Exception:
        return ""
    if not rows:
        return ""
    parts = ["\n\nEJEMPLOS DE REFERENCIA (anonimizados) — imita su estilo, tono y criterios, NO los copies literalmente:"]
    for i, r in enumerate(rows, 1):
        parts.append("\n--- Ejemplo %d%s ---\nPORTAFOLIO:\n%s\n\n%s:\n%s"
                      % (i, (" (" + r["title"] + ")") if r["title"] else "",
                         (r["portfolio"] or "")[:2500],
                         "FEEDBACK" if kind == "feedback" else "ANÁLISIS",
                         (r["feedback"] or "")[:2500]))
    return "".join(parts)


def _strip_tags(s):
    return re.sub(r"<[^>]+>", " ", s or "")


def portfolio_text(stud_id):
    db = get_db()
    pages = db.execute("SELECT * FROM pages WHERE owner_id=?", (stud_id,)).fetchall()
    chunks = []
    for p in pages:
        chunks.append("PAGINA: %s (%s)" % (p["title"], p["visibility"]))
        if p["description"]:
            chunks.append("Descripción: " + p["description"])
        for R in page_rows(p["id"]):
            for col in R["cols"]:
                for b in col:
                    if b["block_type"] in ("text", "heading") and b["text_content"]:
                        chunks.append(_strip_tags(b["text_content"]))
                    elif b["block_type"] == "artefact":
                        a = db.execute("SELECT kind,title FROM artefacts WHERE id=?", (b["artefact_id"],)).fetchone()
                        if a:
                            chunks.append("[%s] %s" % (a["kind"], a["title"]))
    return "\n".join(chunks)[:6000]


def _entries_stats_text(db, stud):
    """Datos cuantitativos de las entradas: nº, fechas, frecuencia y ritmo de publicación.
    Se pasa al modo 'análisis' para que combine estadística con lo cualitativo."""
    from datetime import datetime
    sid = stud["id"]
    pages = db.execute("""SELECT title, visibility, created_at FROM pages
                          WHERE owner_id=? AND id IS NOT ? ORDER BY created_at""",
                       (sid, stud["profile_page_id"])).fetchall()
    if not pages:
        return "Sin páginas de portafolio todavía."
    lines, dates = [], []
    for p in pages:
        d = (p["created_at"] or "")[:10]
        lines.append("- %s · «%s» (%s)" % (d or "s/f", p["title"] or "(sin título)", p["visibility"]))
        try:
            dates.append(datetime.strptime(d, "%Y-%m-%d").date())
        except Exception:
            pass
    txt = "Nº de entradas: %d\nFecha de cada entrada:\n%s" % (len(pages), "\n".join(lines))
    if len(dates) >= 2:
        dates.sort()
        span = (dates[-1] - dates[0]).days or 1
        gaps = [(dates[i + 1] - dates[i]).days for i in range(len(dates) - 1)]
        avg_gap = round(sum(gaps) / len(gaps), 1)
        txt += ("\nPrimera entrada: %s · última: %s (periodo de %d días).\n"
                "Intervalo medio entre entradas: %s días. Mayor parón sin publicar: %d días."
                % (dates[0], dates[-1], span, avg_gap, max(gaps)))
    return txt


@app.route("/assistant/<username>", methods=["GET", "POST"])
@login_required
@role_required("teacher", "admin")
def assistant(username):
    db = get_db()
    stud = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not stud:
        abort(404)
    if not teacher_can_view_student(current_user(), stud["id"]):
        abort(403)
    pages = db.execute("SELECT * FROM pages WHERE owner_id=?", (stud["id"],)).fetchall()
    n_pages = len(pages)
    n_public = sum(1 for p in pages if p["visibility"] == "public")
    arts = db.execute("SELECT kind, COUNT(*) c FROM artefacts WHERE owner_id=? GROUP BY kind", (stud["id"],)).fetchall()
    kinds = {a["kind"]: a["c"] for a in arts}
    words = n_text = n_media = 0
    for p in pages:
        for R in page_rows(p["id"]):
            for col in R["cols"]:
                for b in col:
                    if b["block_type"] in ("text", "heading") and b["text_content"]:
                        words += len(_strip_tags(b["text_content"]).split())
                        n_text += 1
                    elif b["block_type"] == "artefact":
                        n_media += 1
    stats = {"Páginas": n_pages, "Páginas publicas": n_public,
             "Palabras de reflexion": words, "Bloques de texto": n_text,
             "Artefactos en páginas": n_media,
             "Tipos de artefacto": ", ".join("%s (%s)" % (k, v) for k, v in kinds.items()) or "ninguno"}
    tips = []
    if n_pages == 0:
        tips.append("Aun no ha creado ninguna página de portafolio.")
    if n_public == 0 and n_pages:
        tips.append("No ha publicado ninguna página; anima a compartir al menos una.")
    if words < 100:
        tips.append("Hay poca reflexion escrita (menos de 100 palabras); pide que argumente su aprendizaje.")
    if len(kinds) < 2:
        tips.append("Usa pocos tipos de evidencia; sugiere añadir imagenes, video o documentos.")
    if "video" not in kinds and "image" not in kinds:
        tips.append("No incluye evidencias multimedia (imagen o video).")
    draft = ("Hola %s, he revisado tu portafolio. Has creado %d página(s) con unas %d palabras de reflexion. "
             % (stud["name"].split()[0], n_pages, words))
    if tips:
        draft += "Para mejorarlo te sugiero: " + " ".join(t.lower() for t in tips)
    else:
        draft += "Esta muy completo: buena combinacion de reflexion y evidencias. Sigue asi."

    provider, _key, _model = ai_config()
    ai_on = provider is not None
    instruction = request.form.get("instruction", "")
    mode = request.form.get("mode", "feedback")
    if mode not in ("feedback", "analisis"):
        mode = "feedback"
    if request.method == "POST" and ai_on:
        if mode == "analisis":
            system = ("Eres un asistente docente que analiza rápidamente el portafolio de un estudiante para "
                      "ayudar al profesorado a hacerse una idea del contenido. Combina datos CUANTITATIVOS "
                      "(estadística y los indicadores de analítica que se te facilitan) y CUALITATIVOS. Responde "
                      "en español, de forma concisa, y NO inventes: usa solo el texto y los datos proporcionados. "
                      "Estructura la respuesta en tres partes:\n"
                      "1) RESUMEN ESTADÍSTICO: nº de entradas, frecuencia y ritmo de publicación (regular o "
                      "irregular, rachas y parones), extensión media, variedad de evidencias e interpretación de "
                      "los indicadores de analítica (completitud, participación, constancia, tendencia, riesgo…).\n"
                      "2) ANÁLISIS POR ENTRADA: para CADA página indica el título, los temas o conceptos que "
                      "trata (lista breve), el nivel de profundidad (superficial / intermedio / profundo) con "
                      "una frase que lo justifique, y 1-2 fragmentos textuales entrecomillados representativos.\n"
                      "3) LISTADO GLOBAL de todos los temas detectados en el portafolio.\n"
                      "4) PREGUNTAS PARA SEGUIR REFLEXIONANDO: a partir de los temas y del nivel de profundidad "
                      "de cada uno, propón 3-5 preguntas abiertas y socráticas (no de respuesta sí/no) que "
                      "inviten al estudiante a profundizar; en los temas ya profundos, pide relacionar con la "
                      "práctica o la teoría, y en los superficiales, pide concretar, ejemplificar o justificar. "
                      "Indica a qué tema o entrada se refiere cada pregunta.")
            from datetime import date as _d
            im = individual_metrics(db, stud, 8)
            av = student_overview(db, stud, current_user(), _d.today())
            stats_block = (
                "INDICADORES DE ANALÍTICA (individuales y formativos, no comparativos):\n"
                "- Completitud del portafolio: %d/100\n"
                "- Participación: %d/100 (%d acciones, sin tope)\n"
                "- Volumen de trabajo (sin tope): %d entradas\n"
                "- Constancia: %d/8 semanas activas · Semanas sin actividad: %d/8\n"
                "- Tendencia reciente (última semana vs. anterior): %s\n"
                "- Riesgo de abandono: %s (%d%%)%s\n"
                "- Publicación: %d%% de páginas públicas\n"
                "- Profundidad de reflexión: %d palabras/bloque · Reflexión por evidencia: %s palabras/artefacto\n"
                "- Interacción (comentarios): %s · Responde al feedback: %s%s\n"
                "- Última conexión: %s"
            ) % (av["score"], av["participation"], av["part_raw"], im["volume"], im["constancia"],
                 im["inactive_weeks"], av["trend"], av["level"], av["risk"],
                 ((" — señales: " + av["reason"]) if av["reason"] else ""),
                 im["pub_rate"], im["depth"], im["refl_ratio"], im["reciprocity"], im["reacts"],
                 ((" (%d%%)" % im["reacts_pct"]) if im["reacts_pct"] is not None else ""),
                 (("hace %d d" % im["seen_days"]) if im["seen_days"] is not None else "—"))
            user = ("Datos de actividad del estudiante %s:\n%s\n\n%s\n\nContenido del portafolio:\n\n%s"
                    % (stud["name"], stats_block, _entries_stats_text(db, stud), portfolio_text(stud["id"])))
        else:
            default_system = ("Eres un docente universitario que da feedback formativo a estudiantes sobre su "
                      "portafolio de aprendizaje. Responde en español, en 150-220 palabras, con un tono "
                      "amable y constructivo, incluyendo 3 puntos de mejora concretos y accionables.")
            _ov = os.environ.get("EVESTIGIA_AI_SYSTEM")
            system = _ov if _ov is not None else default_system
            user = "Portafolio del estudiante %s:\n\n%s" % (stud["name"], portfolio_text(stud["id"]))
        # Ejemplos anonimizados del admin (few-shot): guían el estilo con cualquier proveedor, incl. Ollama.
        system += ai_examples_block(db, mode)
        if instruction.strip():
            user += "\n\nInstrucción adicional del docente: " + instruction.strip()
        enqueue_ai_job(current_user()["id"], stud, system, user, instruction.strip(), mode)
        flash("La IA está generando el %s en segundo plano. Puedes seguir trabajando: "
              "te avisaremos y aparecerá aquí abajo al terminar."
              % ("análisis" if mode == "analisis" else "feedback"))
        return redirect(url_for("assistant", username=username))
    jobs = db.execute("SELECT * FROM ai_jobs WHERE student_id=? ORDER BY id DESC LIMIT 6",
                      (stud["id"],)).fetchall()
    try:
        nweeks = int(request.args.get("w", 8))
    except Exception:
        nweeks = 8
    from datetime import date as _date
    ov = student_overview(db, stud, current_user(), _date.today())
    items = db.execute("SELECT * FROM student_activity WHERE student_id=? ORDER BY id DESC LIMIT 500",
                       (stud["id"],)).fetchall()
    ev_comments = db.execute("""SELECT * FROM comment_log WHERE owner_id=?
        AND author_role IN ('teacher','admin') ORDER BY id DESC LIMIT 500""", (stud["id"],)).fetchall()
    return render(ASSIST_TPL, title="Asistente", stud=stud, stats=stats, tips=tips, draft=draft,
                  ai_on=ai_on, ai_provider=provider, instruction=instruction, jobs=jobs,
                  m=individual_metrics(db, stud, nweeks), ov=ov, vis=VIS,
                  items=items, ev_comments=ev_comments)


@app.route("/api/aijob/<int:jid>")
@login_required
def api_ai_job(jid):
    u = current_user()
    r = get_db().execute("SELECT status, result, error, requester_id FROM ai_jobs WHERE id=?", (jid,)).fetchone()
    if not r:
        abort(404)
    if r["requester_id"] != u["id"] and u["role"] not in ("teacher", "admin"):
        abort(403)
    return jsonify({"status": r["status"], "result": r["result"], "error": r["error"]})




EMAIL_ADMIN_TPL = """
<h1>Correo (SMTP)</h1>
<p class="muted">Configura el envio de avisos por email. El transporte va cifrado (STARTTLS/SSL).</p>
<div class="card"><h2>Servidor de correo</h2>
 <form method="post">
  <input type="hidden" name="action" value="save">
  <label style="font-weight:400"><input type="checkbox" name="enabled" style="width:auto" {{ 'checked' if cfg['enabled'] }}> Activar el envio de correos</label>
  <div class="row-flex"><div style="flex:2"><label>Servidor SMTP</label><input name="host" value="{{ cfg['host'] }}" placeholder="smtp.tu-institucion.org"></div>
   <div style="flex:1"><label>Puerto</label><input name="port" value="{{ cfg['port'] }}"></div></div>
  <div class="row-flex"><div style="flex:1"><label>Usuario</label><input name="user" value="{{ cfg['user'] }}"></div>
   <div style="flex:1"><label>Seguridad</label><select name="security">
    {% for v,l in [('starttls','STARTTLS (puerto 587)'),('ssl','SSL/TLS (puerto 465)'),('none','Sin cifrado (no recomendado)')] %}
    <option value="{{ v }}" {{ 'selected' if cfg['security']==v }}>{{ l }}</option>{% endfor %}</select></div></div>
  <label>Remitente (From)</label><input name="from" value="{{ cfg['from'] }}">
  <label>Contraseña SMTP</label><input type="password" name="password" placeholder="(dejar vacío para no cambiarla)">
  <p style="font-size:13px;margin:6px 0">Estado de la contrase&ntilde;a:
   {% if pass_usable %}<b style="color:#2e7d32">&#10003; guardada y utilizable</b> ({{ pass_source }}){% else %}<b style="color:#b3261e">&#10007; la app no tiene contrase&ntilde;a</b> &mdash; gu&aacute;rdala aqu&iacute; o define EVESTIGIA_SMTP_PASS{% endif %}</p>
  <p class="muted" style="font-size:12px">{{ crypto_note|safe }}</p>
  <button class="btn">Guardar configuración</button>
 </form>
</div>
<div class="card"><h2>Enviar correo de prueba</h2>
 <form method="post" class="row-flex">
  <input type="hidden" name="action" value="test">
  <input name="to" placeholder="tu-email@ejemplo.org" style="flex:1;margin:0">
  <button class="btn sec">Enviar prueba</button></form>
</div>
<div class="card"><h2>Avisos de fallos cr&iacute;ticos</h2>
 <p class="muted" style="margin-top:0">Si ocurre un fallo cr&iacute;tico (por ejemplo, el cifrado en reposo deja de estar disponible o hay un error grave en la app), se avisa <b>de inmediato</b> por correo.</p>
 <form method="post">
  <input type="hidden" name="action" value="save_alert">
  <label>Correo(s) para avisos cr&iacute;ticos <span class="muted" style="font-weight:400">(separa varios con comas; adem&aacute;s siempre se avisa a los administradores)</span></label>
  <input name="admin_alert_email" value="{{ alert_email }}" placeholder="admin-personal@ejemplo.org">
  <button class="btn">Guardar</button>
 </form>
 <p class="muted" style="font-size:13px">Destinatarios actuales: {{ alert_recipients or 'ninguno (configura un correo o pon email a un administrador)' }}</p>
 <form method="post" style="margin-top:6px"><input type="hidden" name="action" value="test_alert">
  <button class="btn sec">Enviar aviso cr&iacute;tico de prueba</button></form>
</div>
<a class="btn" href="{{ url_for('admin_email_templates') }}">Editar plantillas de los correos</a>
<a class="btn sec" href="{{ url_for('admin_email_log') }}">Ver correos enviados</a>
"""


@app.route("/admin/email", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_email():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save":
            set_setting("smtp_enabled", "1" if request.form.get("enabled") else "0")
            for fld in ("host", "port", "user", "from", "security"):
                set_setting("smtp_" + fld, request.form.get(fld, "").strip())
            pw = request.form.get("password", "").strip()
            if pw:
                enc = enc_secret(pw)
                if enc:
                    set_setting("smtp_pass_enc", enc)
                    flash("Configuracion guardada (contraseña cifrada en la base de datos).")
                else:
                    flash("Configuracion guardada. La contraseña NO se guardo por seguridad: "
                          "define la variable de entorno EVESTIGIA_SMTP_PASS.", "error")
            else:
                flash("Configuracion guardada.")
        elif action == "test":
            to = request.form.get("to", "").strip()
            ok, msg = send_email(to, "Prueba de Vestigia",
                                 "Este es un correo de prueba de Vestigia. Si lo recibes, la configuración es correcta.")
            flash(("Prueba: " + msg) if ok else ("Fallo en la prueba: " + msg), "" if ok else "error")
        elif action == "save_alert":
            set_setting("admin_alert_email", request.form.get("admin_alert_email", "").strip())
            flash("Correo de avisos críticos guardado.")
        elif action == "test_alert":
            set_setting("alert_ts_prueba", "")  # sin silenciar la prueba
            ok, msg = send_critical_alert("prueba",
                                          "Vestigia: aviso crítico de PRUEBA",
                                          "Esto es una PRUEBA del sistema de avisos críticos. Si lo recibes, "
                                          "los avisos ante fallos graves llegarán correctamente.\n\n-- Vestigia",
                                          throttle_hours=0)
            flash(("Aviso de prueba: " + msg) if ok else ("No se pudo enviar el aviso: " + msg),
                  "" if ok else "error")
        return redirect(url_for("admin_email"))
    cfg = email_config()
    if os.environ.get("EVESTIGIA_SMTP_PASS"):
        note = ("La contrase&ntilde;a se toma de la variable de entorno <code>EVESTIGIA_SMTP_PASS</code> "
                "(no se guarda en la base de datos). Es la opción mas segura.")
    elif _fernet():
        note = "La contrase&ntilde;a se guarda <b>cifrada</b> en la base de datos (AES/Fernet)."
    elif crypto_status() == "std":
        note = ("La contrase&ntilde;a se guarda <b>cifrada</b> con el m&eacute;todo alternativo (Python puro), "
                "porque no est&aacute; disponible <code>cryptography</code>. Funciona correctamente; para usar "
                "AES est&aacute;ndar, instala <code>cryptography</code> en el int&eacute;rprete de la app y reinicia.")
    elif not HAS_CRYPTO:
        import sys as _sys
        note = ("El cifrado en reposo no esta disponible: no se pudo cargar la libreria <code>cryptography</code> "
                "en el intérprete que ejecuta la app (<code>%s</code>). Error: <code>%s</code>. "
                "Instálala en <b>ese mismo</b> intérprete con <code>%s -m pip install cryptography</code> y reinicia."
                % (_sys.executable, (CRYPTO_IMPORT_ERROR or "no disponible"), _sys.executable))
    else:
        note = ("No se pudo preparar la clave de cifrado (revisa permisos de escritura de la carpeta de la app) "
                "o define <code>EVESTIGIA_SECRET_KEY</code>. Tambien puedes usar la variable de entorno "
                "<code>EVESTIGIA_SMTP_PASS</code>, que es la opción mas segura y sencilla.")
    _pw = smtp_password()
    _src = ("variable de entorno" if os.environ.get("EVESTIGIA_SMTP_PASS")
            else ("guardada cifrada" if get_setting("smtp_pass_enc") else ""))
    return render(EMAIL_ADMIN_TPL, title="Correo", cfg=cfg, crypto_note=note,
                  alert_email=(get_setting("admin_alert_email", "") or ""),
                  alert_recipients=", ".join(admin_alert_emails()),
                  pass_usable=bool(_pw), pass_source=_src)


EMAIL_TPLS_TPL = """
<div class="between"><h1>Plantillas de correo</h1><a class="btn sec" href="{{ url_for('admin_email') }}">Volver</a></div>
<p class="muted">Variables disponibles: <code>{name}</code> (destinatario), <code>{actor}</code> (quien lo origina),
 <code>{title}</code> (título de la página), <code>{url}</code> (enlace).</p>
{% for t in tpls %}<div class="card">
 <form method="post" action="{{ url_for('admin_email_template_save', event=t['event']) }}">
  <div class="between"><h2 style="margin:0">{{ labels.get(t['event'], t['event']) }}</h2>
   <label style="font-weight:400"><input type="checkbox" name="enabled" style="width:auto" {{ 'checked' if t['enabled'] }}> Enviar este aviso</label></div>
  <label>Asunto</label><input name="subject" value="{{ t['subject'] }}">
  <label>Cuerpo</label><textarea name="body" style="min-height:130px">{{ t['body'] }}</textarea>
  <button class="btn sm">Guardar plantilla</button></form>
</div>{% endfor %}
"""


@app.route("/admin/email/templates")
@login_required
@role_required("admin")
def admin_email_templates():
    tpls = get_db().execute("SELECT * FROM email_templates ORDER BY event").fetchall()
    return render(EMAIL_TPLS_TPL, title="Plantillas", tpls=tpls, labels=EVENT_LABELS)


@app.route("/admin/email/templates/<event>", methods=["POST"])
@login_required
@role_required("admin")
def admin_email_template_save(event):
    db = get_db()
    db.execute("UPDATE email_templates SET subject=?, body=?, enabled=? WHERE event=?",
               (request.form.get("subject", "").strip(), request.form.get("body", "").strip(),
                1 if request.form.get("enabled") else 0, event))
    db.commit()
    flash("Plantilla actualizada.")
    return redirect(url_for("admin_email_templates"))



EMAIL_LOG_TPL = """
<div class="between"><h1>Correos enviados</h1><a class="btn sec" href="{{ url_for('admin_email') }}">Volver</a></div>
<div class="card"><table>
 <tr><th>Fecha</th><th>Para</th><th>Asunto</th><th>Estado</th><th>Detalle</th></tr>
 {% for e in items %}<tr>
  <td class="muted">{{ e['created_at'] }}</td><td>{{ e['to_addr'] }}</td><td>{{ e['subject'] }}</td>
  <td><span class="pill">{{ e['status'] }}</span></td><td class="muted">{{ e['detail'] }}</td></tr>
 {% else %}<tr><td colspan="5" class="muted">Aun no se ha enviado ningun correo.</td></tr>{% endfor %}
</table></div>
"""


@app.route("/admin/email/log")
@login_required
@role_required("admin")
def admin_email_log():
    items = get_db().execute("SELECT * FROM email_log ORDER BY id DESC LIMIT 300").fetchall()
    return render(EMAIL_LOG_TPL, title="Correos enviados", items=items)


ADMIN_HOME_TPL = """
<h1>Administración</h1>
<p class="muted">Panel de control de Vestigia.</p>
<div class="grid">
 <a class="tile" href="{{ url_for('admin_users') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Usuarios</div><div style="font-size:28px;font-weight:800">{{ n_users }}</div>
  <div class="muted">Alta manual, importar Excel/CSV</div></a>
 <a class="tile" href="{{ url_for('admin_email') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Correo (SMTP)</div><div style="font-size:22px;font-weight:800;color:{{ '#2e9e5b' if email_on else '#d34' }}">{{ 'Activo' if email_on else 'Inactivo' }}</div>
  <div class="muted">Servidor, seguridad y plantillas</div></a>
 <a class="tile" href="{{ url_for('admin_email_templates') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Plantillas de correo</div><div style="font-size:22px;font-weight:800">Editar</div>
  <div class="muted">Mensaje, comentario, solicitud</div></a>
 <a class="tile" href="{{ url_for('admin_email_log') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Correos enviados</div><div style="font-size:28px;font-weight:800">{{ n_mail }}</div>
  <div class="muted">Historial de envios</div></a>
 <a class="tile" href="{{ url_for('analytics') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Analiticas</div><div style="font-size:28px;font-weight:800">&#128202;</div>
  <div class="muted">Dashboard de aprendizaje</div></a>
 <a class="tile" href="{{ url_for('admin_students') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Alumnado</div><div style="font-size:22px;font-weight:800">Ajustes</div>
  <div class="muted">Qué funciones ve el alumnado y cuota</div></a>
 <a class="tile" href="{{ url_for('admin_backup') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Copias de seguridad</div><div style="font-size:22px;font-weight:800">&#128190;</div>
  <div class="muted">Descargar copia de todo el sistema</div></a>
 <a class="tile" href="{{ url_for('admin_theme') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Apariencia (tema)</div><div style="font-size:22px;font-weight:800">&#127912;</div>
  <div class="muted">Colores, fuente, logo y favicon</div></a>
 <a class="tile" href="{{ url_for('admin_subjects') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Asignaturas</div><div style="font-size:22px;font-weight:800">&#127891;</div>
  <div class="muted">Alumnado y profesorado por asignatura</div></a>
 <a class="tile" href="{{ url_for('admin_aiex') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Ejemplos para la IA</div><div style="font-size:22px;font-weight:800">&#129302;</div>
  <div class="muted">Portafolios y feedbacks (few-shot / JSONL){% if n_aiex %} · {{ n_aiex }}{% endif %}</div></a>
 <a class="tile" href="{{ url_for('admin_group_quotas') }}" style="display:block;text-decoration:none;color:inherit">
  <div class="k">Cuotas de grupos</div><div style="font-size:22px;font-weight:800">&#128190;</div>
  <div class="muted">Espacio de evidencias por grupo</div></a>
</div>
"""


STU_SETTINGS_TPL = """
<div class="between"><h1>Ajustes del alumnado</h1><a class="btn sec" href="{{ url_for('admin_home') }}">Volver a Administración</a></div>
<p class="muted" style="margin-top:0">Activa u oculta funciones para el <b>alumnado</b>. Docentes y administradores siempre tienen acceso completo.</p>
<form method="post">
 <div class="card"><h2>Funciones disponibles para el alumnado</h2>
  {% for key,label in features %}
   <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="{{ key }}" style="width:auto" {{ 'checked' if flags[key] }}> {{ label }}</label>
  {% endfor %}
 </div>
 <div class="card"><h2>Almacenamiento</h2>
  <label>Cuota por persona (MB)</label>
  <input type="number" name="storage_quota_mb" min="50" step="50" value="{{ quota_mb }}" style="max-width:200px">
 </div>
 <div class="card"><h2>Página de inicio</h2>
  <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="onboarding_on" style="width:auto" {{ 'checked' if onboarding_on }}> Mostrar el recuadro <b>"Primeros pasos"</b> en el inicio de cada persona</label>
  <div class="muted" style="font-size:12px">Guía de tareas iniciales con barra de progreso. Cada persona puede cerrarlo cuando completa lo esencial.</div>
 </div>
 <div class="card"><h2>Chat</h2>
  {% if chat_crypto == 'none' %}<div style="background:#fdecea;color:#8a1c1c;border:1px solid #f3b8b1;border-radius:10px;padding:10px 12px;margin-bottom:10px;font-size:13px">
   <b>&#9888; El cifrado en reposo no est&aacute; activo.</b> Los mensajes del chat se guardar&iacute;an <b>sin cifrar</b>.
   Revisa los permisos de escritura de la carpeta de la app o define <code>EVESTIGIA_SECRET_KEY</code>.</div>
  {% elif chat_crypto == 'std' %}<div style="background:#fff7e6;color:#7a4a00;border:1px solid #f0d9a8;border-radius:10px;padding:10px 12px;margin-bottom:10px;font-size:13px">
   <b>&#8505; Chat cifrado con el m&eacute;todo alternativo</b> (Python puro). Funciona correctamente. Para usar AES est&aacute;ndar, instala <code>cryptography</code> en el int&eacute;rprete de la app y reinicia.</div>{% endif %}
  <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="chat_dm" style="width:auto" {{ 'checked' if chat_dm }}> Chat individual (mensajes directos entre personas en l&iacute;nea)</label>
  <label style="font-weight:400;display:block;padding:5px 0"><input type="checkbox" name="chat_group" style="width:auto" {{ 'checked' if chat_group }}> Chat grupal (dentro de cada grupo)</label>
  <label style="margin-top:8px">Retenci&oacute;n de mensajes (d&iacute;as)</label>
  <input type="number" name="chat_retention_days" min="1" step="1" value="{{ chat_ret }}" style="max-width:200px">
  <div class="muted" style="font-size:12px;margin-top:4px">Los mensajes se guardan <b>cifrados</b> y se eliminan autom&aacute;ticamente pasado este plazo. Solo la administraci&oacute;n puede descifrarlos.</div>
  <div style="margin-top:10px"><a class="btn sec sm" href="{{ url_for('admin_chat') }}">Supervisar chats</a></div>
 </div>
 <button class="btn">Guardar ajustes</button>
</form>
"""


@app.route("/admin/students", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_students():
    if request.method == "POST":
        for key, _label in STUDENT_FEATURES:
            set_setting(key, "1" if request.form.get(key) else "0")
        try:
            q = max(50, int(request.form.get("storage_quota_mb", "600")))
        except Exception:
            q = 600
        set_setting("storage_quota_mb", str(q))
        set_setting("onboarding_on", "1" if request.form.get("onboarding_on") else "0")
        set_setting("chat_dm", "1" if request.form.get("chat_dm") else "0")
        set_setting("chat_group", "1" if request.form.get("chat_group") else "0")
        try:
            r = max(1, int(request.form.get("chat_retention_days", "120")))
        except Exception:
            r = 120
        set_setting("chat_retention_days", str(r))
        flash("Ajustes del alumnado guardados.")
        return redirect(url_for("admin_students"))
    flags = {key: (get_setting(key, "1") != "0") for key, _l in STUDENT_FEATURES}
    return render(STU_SETTINGS_TPL, title="Ajustes del alumnado", features=STUDENT_FEATURES,
                  flags=flags, quota_mb=get_setting("storage_quota_mb", "600"),
                  chat_dm=chat_enabled_dm(), chat_group=chat_enabled_group(),
                  chat_ret=chat_retention_days(), chat_crypto=crypto_status(),
                  onboarding_on=(get_setting("onboarding_on", "1") != "0"))


ADMIN_CHAT_TPL = """
<div class="between"><h1>Supervisi&oacute;n de chats</h1><a class="btn sec" href="{{ url_for('admin_students') }}">Volver a Ajustes</a></div>
<p class="muted" style="margin-top:0">Los mensajes se almacenan cifrados. Aqu&iacute; se descifran &uacute;nicamente para la administraci&oacute;n. Se conservan {{ retention }} d&iacute;as.</p>
{% if thread is none %}
<div class="card"><h2>Conversaciones individuales</h2>
 {% if dms %}<table style="width:100%"><tr><th style="text-align:left">Participantes</th><th>Mensajes</th><th>&Uacute;ltimo</th><th></th></tr>
 {% for d in dms %}<tr><td>{{ d.a_name }} &harr; {{ d.b_name }}</td><td style="text-align:center">{{ d.c }}</td><td style="text-align:center">{{ d.last }}</td>
  <td style="text-align:right"><a class="btn sec sm" href="{{ url_for('admin_chat', kind='dm', a=d.a, b=d.b) }}">Ver</a></td></tr>{% endfor %}</table>
 {% else %}<p class="muted">No hay mensajes individuales.</p>{% endif %}
</div>
<div class="card"><h2>Conversaciones de grupo</h2>
 {% if groups %}<table style="width:100%"><tr><th style="text-align:left">Grupo</th><th>Mensajes</th><th>&Uacute;ltimo</th><th></th></tr>
 {% for g in groups %}<tr><td>{{ g.name }}</td><td style="text-align:center">{{ g.c }}</td><td style="text-align:center">{{ g.last }}</td>
  <td style="text-align:right"><a class="btn sec sm" href="{{ url_for('admin_chat', kind='group', gid=g.id) }}">Ver</a></td></tr>{% endfor %}</table>
 {% else %}<p class="muted">No hay mensajes de grupo.</p>{% endif %}
</div>
{% else %}
<div class="between"><h2 style="margin:0">{{ thread_title }}</h2><a class="btn sec sm" href="{{ url_for('admin_chat') }}">&larr; Todas</a></div>
<div class="card" style="max-height:60vh;overflow:auto">
 {% for m in thread %}<div style="padding:6px 0;border-bottom:1px solid var(--line)">
  <b>{{ m.sender }}</b> <span class="muted" style="font-size:12px">{{ m.at }}</span><br>{{ m.body }}</div>{% endfor %}
 {% if not thread %}<p class="muted">Sin mensajes.</p>{% endif %}
</div>
{% endif %}
"""


@app.route("/admin/chat")
@login_required
@role_required("admin")
def admin_chat():
    db = get_db()
    chat_purge_old()
    names = {r["id"]: (r["name"] or r["username"])
             for r in db.execute("SELECT id, username, name FROM users").fetchall()}
    kind = request.args.get("kind")
    if kind == "dm" and request.args.get("a") and request.args.get("b"):
        a = int(request.args["a"]); b = int(request.args["b"])
        rows = db.execute(
            "SELECT * FROM chat_messages WHERE kind='dm' AND "
            "((sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?)) "
            "ORDER BY created_at", (a, b, b, a)).fetchall()
        thread = [{"sender": names.get(r["sender_id"], "?"),
                   "body": chat_decrypt(r["body_enc"], r["enc"]), "at": r["created_at"]} for r in rows]
        return render(ADMIN_CHAT_TPL, title="Supervisión de chats",
                      retention=chat_retention_days(), thread=thread,
                      thread_title="%s ↔ %s" % (names.get(a, "?"), names.get(b, "?")),
                      dms=None, groups=None)
    if kind == "group" and request.args.get("gid"):
        gid = int(request.args["gid"])
        g = db.execute("SELECT name FROM groups WHERE id=?", (gid,)).fetchone()
        rows = db.execute("SELECT * FROM chat_messages WHERE kind='group' AND group_id=? ORDER BY created_at",
                          (gid,)).fetchall()
        thread = [{"sender": names.get(r["sender_id"], "?"),
                   "body": chat_decrypt(r["body_enc"], r["enc"]), "at": r["created_at"]} for r in rows]
        return render(ADMIN_CHAT_TPL, title="Supervisión de chats",
                      retention=chat_retention_days(), thread=thread,
                      thread_title=g["name"] if g else "Grupo", dms=None, groups=None)
    dm_rows = db.execute(
        "SELECT MIN(sender_id,recipient_id) a, MAX(sender_id,recipient_id) b, "
        "COUNT(*) c, MAX(created_at) last FROM chat_messages "
        "WHERE kind='dm' AND recipient_id IS NOT NULL GROUP BY a,b ORDER BY last DESC").fetchall()
    dms = [{"a": r["a"], "b": r["b"], "a_name": names.get(r["a"], "?"),
            "b_name": names.get(r["b"], "?"), "c": r["c"], "last": r["last"]} for r in dm_rows]
    gr_rows = db.execute(
        "SELECT c.group_id gid, COUNT(*) c, MAX(c.created_at) last, g.name name "
        "FROM chat_messages c JOIN groups g ON g.id=c.group_id "
        "WHERE c.kind='group' GROUP BY c.group_id ORDER BY last DESC").fetchall()
    groups = [{"id": r["gid"], "name": r["name"], "c": r["c"], "last": r["last"]} for r in gr_rows]
    return render(ADMIN_CHAT_TPL, title="Supervisión de chats",
                  retention=chat_retention_days(), thread=None, thread_title="",
                  dms=dms, groups=groups)


ADMIN_PUBLIC_TPL = """
<div class="between"><h1>Páginas públicas</h1><a class="btn sec" href="{{ url_for('dashboard') }}">Volver a Inicio</a></div>
<p class="muted" style="margin-top:0">Estas páginas son visibles para <b>cualquier persona registrada</b> en la plataforma (ya no existen enlaces anónimos).
 Revisa que cada una deba serlo. Para cambiar la privacidad, abre la página y usa su configuración (o el autor puede hacerlo).</p>
{% if pages %}
<div class="card"><table style="width:100%;border-collapse:collapse">
 <tr><th style="text-align:left">Página</th><th style="text-align:left">Autor</th><th></th></tr>
 {% for p in pages %}<tr style="border-top:1px solid var(--line)">
  <td style="padding:8px 0">{{ p['title'] }}</td>
  <td>{{ p['owner_name'] }} <span class="muted">@{{ p['owner_username'] }}</span></td>
  <td style="text-align:right"><a class="btn sec sm" href="{{ url_for('page_view', pid=p['id']) }}">Abrir</a></td>
 </tr>{% endfor %}
</table></div>
{% else %}<div class="card"><p class="muted" style="margin:0">No hay páginas públicas.</p></div>{% endif %}
"""


@app.route("/admin/public")
@login_required
@role_required("admin")
def admin_public():
    rows = get_db().execute("""SELECT p.id, p.title, u.name owner_name, u.username owner_username
        FROM pages p JOIN users u ON u.id=p.owner_id
        WHERE p.visibility='public' ORDER BY u.name, p.title""").fetchall()
    return render(ADMIN_PUBLIC_TPL, title="Páginas públicas", pages=rows)


def _dir_size(path):
    total = 0
    try:
        for root, _d, files in os.walk(path):
            for fn in files:
                try:
                    total += os.path.getsize(os.path.join(root, fn))
                except Exception:
                    pass
    except Exception:
        pass
    return total


def _human_size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%.0f %s" % (n, unit) if unit == "B" else "%.1f %s" % (n, unit)
        n /= 1024
    return "%.1f TB" % n


def _backup_zip(include_keys):
    """Genera un ZIP en memoria con la base de datos (copia consistente) y los archivos subidos."""
    import io
    import zipfile
    import sqlite3 as _sq
    import tempfile
    from flask import send_file
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        # Copia consistente de la base de datos (aunque la app esté en uso).
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".db")
        tmp.close()
        try:
            src = _sq.connect(DB_PATH)
            dst = _sq.connect(tmp.name)
            with dst:
                src.backup(dst)
            src.close()
            dst.close()
            z.write(tmp.name, "evestigia.db")
        finally:
            try:
                os.remove(tmp.name)
            except Exception:
                pass
        # Archivos subidos (evidencias, imágenes...).
        for root, _d, files in os.walk(UPLOAD_DIR):
            for fn in files:
                fp = os.path.join(root, fn)
                z.write(fp, os.path.join("uploads", os.path.relpath(fp, UPLOAD_DIR)))
        if include_keys:
            for kf in ("evestigia_secret.key", "evestigia_fallback.key"):
                p = os.path.join(BASE_DIR, kf)
                if os.path.exists(p):
                    z.write(p, kf)
    buf.seek(0)
    set_setting("last_backup", now())
    fname = "evestigia_backup_%s.zip" % datetime.now().strftime("%Y%m%d_%H%M")
    return send_file(buf, mimetype="application/zip", as_attachment=True, download_name=fname)


def _keys_zip():
    import io
    import zipfile
    from flask import send_file
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for kf in ("evestigia_secret.key", "evestigia_fallback.key"):
            p = os.path.join(BASE_DIR, kf)
            if os.path.exists(p):
                z.write(p, kf)
    buf.seek(0)
    return send_file(buf, mimetype="application/zip", as_attachment=True,
                     download_name="evestigia_claves.zip")


def _backup_code_valid(code):
    """Comprueba el código de verificación de descarga (10 min de validez)."""
    saved = session.get("backup_code")
    ts = session.get("backup_code_ts")
    if not saved or not ts:
        return False
    try:
        from datetime import timedelta
        if datetime.now() - datetime.strptime(ts, "%Y-%m-%d %H:%M:%S") > timedelta(minutes=10):
            return False
    except Exception:
        return False
    return bool(code) and str(code).strip() == saved


# ---- TOTP (app de autenticación), en Python puro (RFC 6238) ----
def _b32_decode(s):
    import base64
    s = (s or "").strip().replace(" ", "").upper()
    return base64.b32decode(s + "=" * ((-len(s)) % 8))


def _totp_at(secret_b32, for_time, step=30, digits=6):
    import hmac
    import hashlib
    import struct
    counter = int(for_time // step)
    h = hmac.new(_b32_decode(secret_b32), struct.pack(">Q", counter), hashlib.sha1).digest()
    o = h[-1] & 0x0F
    val = (struct.unpack(">I", h[o:o + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(val).zfill(digits)


def _totp_check(secret_b32, code):
    if not secret_b32 or not code:
        return False
    import time
    code = str(code).strip()
    now = time.time()
    for drift in (-1, 0, 1):  # tolera ±30 s de desfase de reloj
        try:
            if _totp_at(secret_b32, now + drift * 30) == code:
                return True
        except Exception:
            return False
    return False


def _gen_totp_secret():
    import base64
    return base64.b32encode(os.urandom(20)).decode().rstrip("=")


def _totp_secret():
    return dec_secret(get_setting("backup_totp_secret"))


def _totp_enabled():
    return bool(_totp_secret())


def _totp_valid(code):
    return _totp_check(_totp_secret(), code)


ADMIN_BACKUP_TPL = """
<div class="between"><h1>Copias de seguridad</h1><a class="btn sec" href="{{ url_for('admin_home') }}">Volver a Administración</a></div>
<p class="muted" style="margin-top:0">Descarga una copia de todo el sistema. Por seguridad, la descarga requiere un <b>segundo paso de verificación</b>:
 un código enviado a tu correo <b>o</b> el código de tu app de autenticación. Consulta <code>SEGURIDAD_cifrado_y_copias.md</code> para automatizar las copias en el servidor.</p>
<div class="card">
 <p style="margin-top:0">Estado: {% if last %}<b style="color:#2e7d32">última copia {{ last }}</b>{% else %}<b style="color:#b3261e">sin copias registradas</b>{% endif %}</p>
 <p class="muted" style="font-size:13px">Base de datos: {{ db_h }} &middot; Archivos subidos: {{ up_h }}</p>
</div>

<div class="card">
 <h2>Verificación en dos pasos</h2>
 <p style="margin-top:0;font-size:14px">App de autenticación (TOTP):
  {% if totp_enabled %}<b style="color:#2e7d32">activada</b>{% else %}<b style="color:#b3261e">no configurada</b>{% endif %}</p>
 {% if setup_secret %}
  <div style="background:#f7f4fa;border:1px solid var(--line);border-radius:10px;padding:12px">
   <p style="margin:0 0 6px">Añade esta cuenta a Google Authenticator, Authy, etc. Escanea el enlace o introduce la clave manualmente:</p>
   <p style="font-size:13px;margin:4px 0">Clave (formato base32): <code style="font-size:15px;letter-spacing:1px">{{ setup_secret }}</code></p>
   <p style="font-size:12px;margin:4px 0;word-break:break-all">Enlace de configuración (otpauth): <code>{{ otpauth }}</code></p>
   <form method="post" style="margin-top:8px"><input type="hidden" name="action" value="totp_confirm">
    <label>Introduce el código de 6 dígitos que muestra la app para confirmar</label>
    <input name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="6 dígitos" style="max-width:200px">
    <button class="btn sm">Activar</button></form>
  </div>
 {% elif totp_enabled %}
  <form method="post" onsubmit="return confirm('¿Desactivar la app de autenticación para las copias?')">
   <input type="hidden" name="action" value="totp_disable">
   <button class="btn sec sm">Desactivar app de autenticación</button></form>
 {% else %}
  <form method="post"><input type="hidden" name="action" value="totp_setup">
   <button class="btn sec sm">Configurar app de autenticación</button></form>
 {% endif %}
</div>

<div class="card">
 <h2>Descargar</h2>
 <p class="muted" style="margin-top:0;font-size:13px">Correo para el código: <b>{{ dest or 'ninguno configurado' }}</b></p>
 <form method="post" style="margin-bottom:10px"><input type="hidden" name="action" value="send_code">
  <button class="btn sec sm" {{ 'disabled' if not dest }}>Enviar código al correo</button></form>
 <form method="post">
  <label>Código de verificación (del correo o de la app de autenticación)</label>
  <input name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="6 dígitos" style="max-width:200px">
  <div style="margin-top:10px">
   <button class="btn" name="action" value="data">Descargar copia (datos)</button>
   <button class="btn sec" name="action" value="keys">Descargar solo las claves</button>
  </div>
 </form>
 <p class="muted" style="font-size:12px;margin:8px 0 0">"Datos" incluye la base de datos y los archivos subidos (no las claves). Las claves de cifrado se descargan aparte y deben guardarse <b>por separado</b>.</p>
</div>
<div class="card" style="border:2px solid #d33;background:#fff6f6">
 <h2 style="margin-top:0;color:#b3261e">Restaurar una copia previa</h2>
 <p class="muted" style="margin-top:0;font-size:13px">Sube el archivo <b>.zip</b> de una copia de datos (el que contiene <code>evestigia.db</code> y <code>uploads/</code>).
  <b>Sustituye por completo</b> la base de datos y los archivos actuales por los de la copia. Antes de sustituir, la app guarda automáticamente una copia de seguridad de la base actual (<code>evestigia.db.pre-restore-…</code>).</p>
 <form method="post" enctype="multipart/form-data">
  <input type="hidden" name="action" value="restore">
  <label>Archivo de copia (.zip)</label>
  <input type="file" name="backup" accept=".zip" required>
  <label style="margin-top:8px">Código de verificación (del correo o de la app de autenticación)</label>
  <input name="code" inputmode="numeric" autocomplete="one-time-code" placeholder="6 dígitos" style="max-width:200px">
  <label style="font-weight:400;display:block;margin-top:8px"><input type="checkbox" name="confirm" value="si" style="width:auto"> Entiendo que esto <b>reemplazará</b> los datos actuales por los de la copia.</label>
  <button class="btn" style="margin-top:10px;background:#b3261e" onclick="return confirm('¿Restaurar la copia y reemplazar los datos actuales?')">Restaurar copia</button>
 </form>
</div>

<div class="card" style="border-color:#f0d9a8;background:#fffdf7">
 <p style="margin:0;font-size:13px">&#9888; La copia contiene datos personales del alumnado. Trátala como información confidencial y cífrala en su almacenamiento fuera de la app (por ejemplo con <code>age</code> o un repositorio cifrado tipo <code>restic</code>).</p>
</div>
"""


@app.route("/admin/backup", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_backup():
    dests = admin_alert_emails()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "send_code":
            if not dests:
                flash("No hay ningún correo de administración configurado. Añádelo en Administración → Correo.", "error")
                return redirect(url_for("admin_backup"))
            import secrets as _sec
            code = "%06d" % _sec.randbelow(1000000)
            session["backup_code"] = code
            session["backup_code_ts"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ok_any = False
            for to in dests:
                ok, _m = send_email(to, "Vestigia: código para descargar la copia de seguridad",
                                    "Tu código de verificación para descargar la copia de seguridad es: %s\n\n"
                                    "Es válido durante 10 minutos. Si no has solicitado esta descarga, "
                                    "cambia tu contraseña y avisa al equipo.\n\n-- Vestigia" % code)
                ok_any = ok_any or ok
            flash("Código enviado a %s. Revísalo e introdúcelo abajo." % ", ".join(dests) if ok_any
                  else "No se pudo enviar el código (revisa la configuración de correo).",
                  "" if ok_any else "error")
            return redirect(url_for("admin_backup"))
        if action == "totp_setup":
            session["totp_setup_secret"] = _gen_totp_secret()
            flash("Escanea o introduce la clave en tu app de autenticación y confirma con un código.")
            return redirect(url_for("admin_backup"))
        if action == "totp_confirm":
            sec = session.get("totp_setup_secret")
            if sec and _totp_check(sec, request.form.get("code")):
                enc = enc_secret(sec)
                if enc:
                    set_setting("backup_totp_secret", enc)
                    session.pop("totp_setup_secret", None)
                    flash("App de autenticación activada para las descargas.")
                else:
                    flash("No se pudo guardar el secreto de forma segura.", "error")
            else:
                flash("Código incorrecto. Vuelve a intentarlo.", "error")
            return redirect(url_for("admin_backup"))
        if action == "totp_disable":
            set_setting("backup_totp_secret", "")
            flash("App de autenticación desactivada.")
            return redirect(url_for("admin_backup"))
        if action in ("data", "keys"):
            code = request.form.get("code")
            if not (_backup_code_valid(code) or _totp_valid(code)):
                flash("Código incorrecto o caducado. Usa el código del correo o el de tu app de autenticación.", "error")
                return redirect(url_for("admin_backup"))
            # El código por correo es de un solo uso (el de la app cambia solo cada 30 s).
            session.pop("backup_code", None)
            session.pop("backup_code_ts", None)
            return _keys_zip() if action == "keys" else _backup_zip(include_keys=False)
        if action == "restore":
            code = request.form.get("code")
            if not (_backup_code_valid(code) or _totp_valid(code)):
                flash("Código incorrecto o caducado. Usa el código del correo o el de tu app de autenticación.", "error")
                return redirect(url_for("admin_backup"))
            if request.form.get("confirm") != "si":
                flash("Marca la casilla de confirmación para restaurar.", "error")
                return redirect(url_for("admin_backup"))
            f = request.files.get("backup")
            if not f or not (f.filename or "").lower().endswith(".zip"):
                flash("Sube el archivo .zip de una copia de seguridad.", "error")
                return redirect(url_for("admin_backup"))
            import io as _io, zipfile as _zip, tempfile as _tmp, sqlite3 as _sq, shutil as _sh
            try:
                zf = _zip.ZipFile(_io.BytesIO(f.read()))
            except Exception:
                flash("El archivo no es un ZIP válido.", "error")
                return redirect(url_for("admin_backup"))
            names = zf.namelist()
            if "evestigia.db" not in names:
                flash("El ZIP no contiene 'evestigia.db'. ¿Es una copia de datos de eVestigia?", "error")
                return redirect(url_for("admin_backup"))
            # Validar que la BD del ZIP es una base SQLite correcta de la app.
            tf = _tmp.NamedTemporaryFile(delete=False, suffix=".db")
            tf.write(zf.read("evestigia.db"))
            tf.close()
            try:
                t = _sq.connect(tf.name)
                t.execute("SELECT COUNT(*) FROM users").fetchone()
                t.close()
            except Exception:
                try: os.remove(tf.name)
                except Exception: pass
                flash("La base de datos del ZIP no es válida o no es de eVestigia.", "error")
                return redirect(url_for("admin_backup"))
            # Copia de seguridad de la base actual antes de sustituir.
            try:
                ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                _sh.copy(DB_PATH, DB_PATH + ".pre-restore-" + ts)
            except Exception:
                pass
            for sfx in ("-wal", "-shm"):
                try: os.remove(DB_PATH + sfx)
                except Exception: pass
            _sh.move(tf.name, DB_PATH)
            # Restaurar archivos subidos (con protección frente a rutas maliciosas del ZIP).
            base = os.path.abspath(UPLOAD_DIR)
            restored = 0
            for n in names:
                if not n.startswith("uploads/") or n.endswith("/"):
                    continue
                target = os.path.abspath(os.path.join(UPLOAD_DIR, os.path.relpath(n, "uploads")))
                if not target.startswith(base + os.sep):
                    continue
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, "wb") as out:
                    out.write(zf.read(n))
                restored += 1
            session.pop("backup_code", None)
            session.pop("backup_code_ts", None)
            try: harden_file_perms()
            except Exception: pass
            flash("Copia restaurada (base de datos y %d archivo(s)). Cierra sesión y vuelve a entrar; "
                  "si algo no se ve al momento, recarga la app." % restored)
            return redirect(url_for("admin_backup"))
        return redirect(url_for("admin_backup"))
    setup_secret = session.get("totp_setup_secret")
    otpauth = ""
    if setup_secret:
        from urllib.parse import quote
        u = current_user()
        otpauth = "otpauth://totp/Vestigia:%s?secret=%s&issuer=Vestigia" % (quote(u["username"]), setup_secret)
    return render(ADMIN_BACKUP_TPL, title="Copias de seguridad",
                  last=get_setting("last_backup"), dest=", ".join(dests),
                  totp_enabled=_totp_enabled(), setup_secret=setup_secret, otpauth=otpauth,
                  db_h=_human_size(os.path.getsize(DB_PATH) if os.path.exists(DB_PATH) else 0),
                  up_h=_human_size(_dir_size(UPLOAD_DIR)))


ADMIN_THEME_TPL = """
<div class="between"><h1>Apariencia (tema)</h1><a class="btn sec" href="{{ url_for('admin_home') }}">Volver a Administración</a></div>
<p class="muted" style="margin-top:0">Personaliza la marca de la plataforma. Pensado para adaptarla a otra institución (proyecto open source).</p>
<form method="post" enctype="multipart/form-data">
 <div class="card"><h2>Identidad</h2>
  <label>Nombre del sitio</label><input name="site_name" value="{{ t['site_name'] }}" maxlength="40">
  <label style="margin-top:8px">Logo de cabecera (imagen o SVG; opcional)</label><input type="file" name="logo" accept="image/*,.svg">
  {% if t['logo'] %}<div class="muted" style="font-size:12px;margin-top:4px">Actual: <img src="{{ url_for('brand_logo') }}" style="height:22px;vertical-align:middle;background:#7a1f3d;border-radius:4px;padding:2px"></div>{% endif %}
  <label style="margin-top:8px">Favicon (imagen o SVG; opcional)</label><input type="file" name="favicon" accept="image/*,.svg">
  {% if t['favicon'] %}<div class="muted" style="font-size:12px;margin-top:4px">Actual: <img src="{{ url_for('brand_favicon') }}" style="height:20px;vertical-align:middle"></div>{% endif %}
 </div>
 <div class="card"><h2>Colores</h2>
  <div class="row-flex" style="flex-wrap:wrap;gap:16px">
   <div><label>Marca (principal)</label><br><input type="color" name="brand" value="{{ t['brand'] }}" style="width:70px;height:40px;padding:2px"></div>
   <div><label>Marca (secundario)</label><br><input type="color" name="brand2" value="{{ t['brand2'] }}" style="width:70px;height:40px;padding:2px"></div>
   <div><label>Acento</label><br><input type="color" name="accent" value="{{ t['accent'] }}" style="width:70px;height:40px;padding:2px"></div>
   <div><label>Fondo</label><br><input type="color" name="bg" value="{{ t['bg'] }}" style="width:70px;height:40px;padding:2px"></div>
  </div>
 </div>
 <div class="card"><h2>Tipografía</h2>
  <label>Fuente</label>
  <select name="font">{% for f in fonts %}<option value="{{ f }}" {{ 'selected' if t['font']==f }}>{{ f }}</option>{% endfor %}</select>
  <label style="margin-top:8px">Tamaño base del texto (px)</label>
  <input type="number" name="font_size" min="11" max="22" value="{{ t['font_size'] }}" style="max-width:120px">
 </div>
 <button class="btn">Guardar tema</button>
</form>
<form method="post" style="margin-top:10px" onsubmit="return confirm('¿Restablecer el tema por defecto?')">
 <input type="hidden" name="action" value="reset"><button class="btn sec">Restablecer valores por defecto</button>
</form>
"""


@app.route("/admin/theme", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_theme():
    if request.method == "POST":
        if request.form.get("action") == "reset":
            for k in THEME_DEFAULTS:
                set_setting("theme_" + k, "")
            set_setting("theme_logo", "")
            set_setting("theme_favicon", "")
            flash("Tema restablecido a los valores por defecto.")
            return redirect(url_for("admin_theme"))
        for k in ("brand", "brand2", "accent", "bg", "font", "site_name"):
            set_setting("theme_" + k, request.form.get(k, "").strip())
        set_setting("theme_font_size", request.form.get("font_size", "16").strip())
        for field, key in (("logo", "theme_logo"), ("favicon", "theme_favicon")):
            f = request.files.get(field)
            if f and f.filename:
                ext = os.path.splitext(f.filename)[1].lower().lstrip(".")
                if ext in IMAGE_EXT or ext == "svg":  # el logo/favicon del tema admite SVG
                    fn = "theme_%s_%s.%s" % (field, secrets.token_hex(5), ext)
                    f.save(os.path.join(UPLOAD_DIR, fn))
                    set_setting(key, fn)
                else:
                    flash("El %s debe ser una imagen (png, jpg, svg...)." % field, "error")
        flash("Tema guardado.")
        return redirect(url_for("admin_theme"))
    return render(ADMIN_THEME_TPL, title="Tema", t=theme_settings(), fonts=list(THEME_FONTS.keys()))


ADMIN_SUBJECTS_TPL = """
<div class="between"><h1>Asignaturas</h1><a class="btn sec" href="{{ url_for('admin_home') }}">Volver a Administración</a></div>
<p class="muted" style="margin-top:0">Estructura académica: <b>Asignatura → Alumnado → Profesorado</b>. Cada docente solo ve el alumnado de sus asignaturas.</p>
<div class="card"><h2>Nueva asignatura</h2>
 <form method="post" class="row-flex">
  <input name="name" placeholder="Nombre de la asignatura" required style="flex:2;min-width:180px;margin:0">
  <input name="code" placeholder="Código (opcional)" style="flex:1;min-width:120px;margin:0">
  <button class="btn">Crear</button></form>
</div>
{% for s in subjects %}<div class="card between">
 <div><b>{{ s['name'] }}</b>{% if s['code'] %} <span class="muted">({{ s['code'] }})</span>{% endif %}
  <div class="muted" style="font-size:13px">{{ s['nteach'] }} docente(s) · {{ s['nstud'] }} estudiante(s)</div></div>
 <div class="row-flex"><a class="btn sec sm" href="{{ url_for('admin_subject', sid=s['id']) }}">Gestionar</a>
  <form method="post" action="{{ url_for('admin_subject_del', sid=s['id']) }}" onsubmit="return confirm('¿Eliminar la asignatura? No borra usuarios.')" style="margin:0"><button class="btn sec sm">Eliminar</button></form></div>
</div>{% else %}<p class="muted">No hay asignaturas todavía.</p>{% endfor %}
"""

ADMIN_SUBJECT_TPL = """
<div class="between"><h1>{{ s['name'] }}{% if s['code'] %} <span class="muted" style="font-size:16px">({{ s['code'] }})</span>{% endif %}</h1>
 <a class="btn sec" href="{{ url_for('admin_subjects') }}">Volver</a></div>
<div class="card"><h2>Nombre y código</h2>
 <form method="post" action="{{ url_for('admin_subject_rename', sid=s['id']) }}" class="row-flex">
  <input name="name" value="{{ s['name'] }}" required style="flex:2;min-width:180px;margin:0">
  <input name="code" value="{{ s['code'] or '' }}" placeholder="Código (opcional)" style="flex:1;min-width:120px;margin:0">
  <button class="btn sec sm">Guardar cambios</button></form>
</div>
<div class="card"><h2>Profesorado</h2>
 {% for t in teachers %}<div class="between" style="padding:5px 0;border-top:1px solid var(--line)"><div>{{ t['name'] }} <span class="muted">@{{ t['username'] }}</span></div>
  <form method="post" action="{{ url_for('admin_subject_teacher', sid=s['id']) }}" style="margin:0"><input type="hidden" name="action" value="remove"><input type="hidden" name="uid" value="{{ t['id'] }}"><button class="btn sec sm">Quitar</button></form></div>
 {% else %}<p class="muted" style="margin:6px 0">Sin docentes asignados.</p>{% endfor %}
 {% if all_teachers %}<form method="post" action="{{ url_for('admin_subject_teacher', sid=s['id']) }}" class="row-flex" style="margin-top:10px"><input type="hidden" name="action" value="add">
  <select name="uid" style="flex:1;margin:0">{% for t in all_teachers %}<option value="{{ t['id'] }}">{{ t['name'] }} (@{{ t['username'] }})</option>{% endfor %}</select>
  <button class="btn sec sm">Añadir docente</button></form>{% endif %}
</div>
<div class="card"><h2>Alumnado</h2>
 {% for st in students %}<div class="between" style="padding:5px 0;border-top:1px solid var(--line)"><div>{{ st['name'] }} <span class="muted">@{{ st['username'] }}</span></div>
  <form method="post" action="{{ url_for('admin_subject_student', sid=s['id']) }}" style="margin:0"><input type="hidden" name="action" value="remove"><input type="hidden" name="uid" value="{{ st['id'] }}"><button class="btn sec sm">Quitar</button></form></div>
 {% else %}<p class="muted" style="margin:6px 0">Sin alumnado.</p>{% endfor %}
 {% if all_students %}<form method="post" action="{{ url_for('admin_subject_student', sid=s['id']) }}" class="row-flex" style="margin-top:10px"><input type="hidden" name="action" value="add">
  <select name="uid" style="flex:1;margin:0">{% for st in all_students %}<option value="{{ st['id'] }}">{{ st['name'] }} (@{{ st['username'] }})</option>{% endfor %}</select>
  <button class="btn sec sm">Añadir</button></form>{% endif %}
</div>
"""


@app.route("/admin/subjects", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_subjects():
    db = get_db()
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        if name:
            db.execute("INSERT INTO subjects(name,code,created_at) VALUES(?,?,?)",
                       (name, request.form.get("code", "").strip(), now()))
            db.commit()
            flash("Asignatura creada.")
        return redirect(url_for("admin_subjects"))
    subjects = db.execute("""SELECT s.*,
        (SELECT COUNT(*) FROM subject_teachers t WHERE t.subject_id=s.id) nteach,
        (SELECT COUNT(*) FROM subject_students ss WHERE ss.subject_id=s.id) nstud
        FROM subjects s ORDER BY s.name""").fetchall()
    return render(ADMIN_SUBJECTS_TPL, title="Asignaturas", subjects=subjects)


@app.route("/admin/subjects/<int:sid>/delete", methods=["POST"])
@login_required
@role_required("admin")
def admin_subject_del(sid):
    db = get_db()
    db.execute("DELETE FROM subjects WHERE id=?", (sid,))
    db.commit()
    flash("Asignatura eliminada.")
    return redirect(url_for("admin_subjects"))


@app.route("/admin/subjects/<int:sid>")
@login_required
@role_required("admin")
def admin_subject(sid):
    db = get_db()
    s = db.execute("SELECT * FROM subjects WHERE id=?", (sid,)).fetchone()
    if not s:
        abort(404)
    teachers = db.execute("""SELECT u.id,u.name,u.username FROM subject_teachers t JOIN users u ON u.id=t.teacher_id
                             WHERE t.subject_id=? ORDER BY u.name""", (sid,)).fetchall()
    students = db.execute("""SELECT u.id,u.name,u.username FROM subject_students ss JOIN users u ON u.id=ss.student_id
                             WHERE ss.subject_id=? ORDER BY u.name""", (sid,)).fetchall()
    tids = {t["id"] for t in teachers}
    sids = {st["id"] for st in students}
    all_teachers = [u for u in db.execute("SELECT id,name,username FROM users WHERE role IN ('teacher','admin') ORDER BY name")
                    if u["id"] not in tids]
    all_students = [u for u in db.execute("SELECT id,name,username FROM users WHERE role='student' ORDER BY name")
                    if u["id"] not in sids]
    return render(ADMIN_SUBJECT_TPL, title=s["name"], s=s, teachers=teachers, students=students,
                  all_teachers=all_teachers, all_students=all_students)


@app.route("/admin/subjects/<int:sid>/rename", methods=["POST"])
@login_required
@role_required("admin")
def admin_subject_rename(sid):
    db = get_db()
    name = request.form.get("name", "").strip()
    if name:
        db.execute("UPDATE subjects SET name=?, code=? WHERE id=?",
                   (name, request.form.get("code", "").strip(), sid))
        db.commit()
        flash("Asignatura actualizada.")
    return redirect(url_for("admin_subject", sid=sid))


@app.route("/admin/subjects/<int:sid>/teacher", methods=["POST"])
@login_required
@role_required("admin")
def admin_subject_teacher(sid):
    db = get_db()
    uid = request.form.get("uid")
    if request.form.get("action") == "add" and uid:
        db.execute("INSERT OR IGNORE INTO subject_teachers(subject_id,teacher_id) VALUES(?,?)", (sid, uid))
    elif request.form.get("action") == "remove" and uid:
        db.execute("DELETE FROM subject_teachers WHERE subject_id=? AND teacher_id=?", (sid, uid))
    db.commit()
    return redirect(url_for("admin_subject", sid=sid))


@app.route("/admin/subjects/<int:sid>/student", methods=["POST"])
@login_required
@role_required("admin")
def admin_subject_student(sid):
    db = get_db()
    uid = request.form.get("uid")
    if request.form.get("action") == "add" and uid:
        db.execute("INSERT OR IGNORE INTO subject_students(subject_id,student_id) VALUES(?,?)", (sid, uid))
    elif request.form.get("action") == "remove" and uid:
        db.execute("DELETE FROM subject_students WHERE subject_id=? AND student_id=?", (sid, uid))
    db.commit()
    return redirect(url_for("admin_subject", sid=sid))


ADMIN_AIEX_TPL = """
<div class="between"><h1>Ejemplos para la IA (Ollama)</h1><a class="btn sec" href="{{ url_for('admin_home') }}">Volver a Administración</a></div>
<p class="muted" style="margin-top:0">Sube pares <b>portafolio anonimizado → feedback/análisis modelo</b>. Sirven de dos formas: <b>(1) ahora mismo</b> como ejemplos que guían el estilo de la IA (few-shot, funciona con Ollama local sin sacar datos); <b>(2) más adelante</b>, cuando tengas muchos, puedes <b>exportarlos a JSONL</b> para afinar un modelo con un LoRA en local.</p>

<div class="card" style="border:2px solid #d33;background:#fff6f6">
 <b style="color:#b3261e">&#9888; Anonimización</b>
 <p class="muted" style="margin:4px 0 0;font-size:13px">Es responsabilidad de quien sube el documento: elimina nombres, correos y datos personales antes de pegarlos. eVestigia no los comparte con terceros; con Ollama todo el procesamiento es local.</p>
</div>

<div class="card"><h2>Añadir ejemplo</h2>
 <form method="post">
  <div class="row-flex" style="gap:10px">
   <div style="flex:1"><label>Tipo</label>
    <select name="kind">
     <option value="feedback">Feedback (devolución al estudiante)</option>
     <option value="analisis">Análisis de entradas</option>
    </select></div>
   <div style="flex:2"><label>Título / etiqueta (opcional)</label>
    <input name="title" placeholder="Ej.: portafolio bien reflexionado, nivel alto"></div>
  </div>
  <label>Portafolio anonimizado (entrada del alumno)</label>
  <textarea name="portfolio" rows="6" required placeholder="Pega aquí el texto del portafolio, ya anonimizado."></textarea>
  <label>Feedback / análisis modelo (la respuesta que consideras buena)</label>
  <textarea name="feedback" rows="6" required placeholder="Pega aquí el feedback o análisis ejemplar."></textarea>
  <label>Nota interna (opcional)</label>
  <input name="note" placeholder="Por qué es un buen ejemplo, curso, etc.">
  <button class="btn" style="margin-top:8px">Guardar ejemplo</button>
 </form>
</div>

<div class="card"><h2>Ejemplos guardados ({{ rows|length }})</h2>
 <p class="muted" style="margin-top:0;font-size:13px">Se usan como few-shot los <b>{{ nshot }} más recientes por tipo</b>. Puedes activarlos/desactivarlos o borrarlos.</p>
 <div style="margin-bottom:10px">
  <a class="btn sec sm" href="{{ url_for('admin_aiex_export', kind='feedback') }}">Exportar feedback (JSONL)</a>
  <a class="btn sec sm" href="{{ url_for('admin_aiex_export', kind='analisis') }}">Exportar análisis (JSONL)</a>
 </div>
 {% for r in rows %}<div style="border-top:1px solid var(--line);padding:8px 0">
  <div class="between">
   <div><span class="pill" style="background:{{ '#3a7bd5' if r['kind']=='analisis' else '#7a1f3d' }};color:#fff">{{ 'Análisis' if r['kind']=='analisis' else 'Feedback' }}</span>
    <b>{{ r['title'] or '(sin título)' }}</b> <span class="muted" style="font-size:12px">· {{ r['created_at'] }}{% if not r['active'] %} · desactivado{% endif %}</span></div>
   <div class="row-flex" style="gap:6px">
    <form method="post" action="{{ url_for('admin_aiex_toggle', eid=r['id']) }}"><button class="btn sec sm">{{ 'Desactivar' if r['active'] else 'Activar' }}</button></form>
    <form method="post" action="{{ url_for('admin_aiex_del', eid=r['id']) }}" onsubmit="return confirm('¿Borrar este ejemplo?')"><button class="btn sec sm" style="color:#d33">Borrar</button></form>
   </div>
  </div>
  <div class="muted" style="font-size:12px;margin-top:4px;white-space:pre-wrap">{{ (r['portfolio'] or '')[:160] }}…</div>
 </div>{% else %}<p class="muted">Aún no hay ejemplos.</p>{% endfor %}
</div>
"""


@app.route("/admin/ai-examples", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_aiex():
    db = get_db()
    if request.method == "POST":
        kind = request.form.get("kind", "feedback")
        if kind not in ("feedback", "analisis"):
            kind = "feedback"
        portfolio = (request.form.get("portfolio") or "").strip()
        feedback = (request.form.get("feedback") or "").strip()
        if portfolio and feedback:
            db.execute("""INSERT INTO ai_examples(kind,title,portfolio,feedback,note,active,created_by,created_at)
                          VALUES(?,?,?,?,?,1,?,?)""",
                       (kind, (request.form.get("title") or "").strip(), portfolio, feedback,
                        (request.form.get("note") or "").strip(), current_user()["id"], now()))
            db.commit()
            flash("Ejemplo guardado.")
        else:
            flash("Necesito el portafolio y el feedback/análisis.")
        return redirect(url_for("admin_aiex"))
    rows = db.execute("SELECT * FROM ai_examples ORDER BY id DESC").fetchall()
    return render(ADMIN_AIEX_TPL, title="Ejemplos para la IA", rows=rows, nshot=3)


@app.route("/admin/ai-examples/<int:eid>/toggle", methods=["POST"])
@login_required
@role_required("admin")
def admin_aiex_toggle(eid):
    db = get_db()
    db.execute("UPDATE ai_examples SET active = 1 - COALESCE(active,0) WHERE id=?", (eid,))
    db.commit()
    return redirect(url_for("admin_aiex"))


@app.route("/admin/ai-examples/<int:eid>/del", methods=["POST"])
@login_required
@role_required("admin")
def admin_aiex_del(eid):
    db = get_db()
    db.execute("DELETE FROM ai_examples WHERE id=?", (eid,))
    db.commit()
    flash("Ejemplo borrado.")
    return redirect(url_for("admin_aiex"))


@app.route("/admin/ai-examples/export/<kind>.jsonl")
@login_required
@role_required("admin")
def admin_aiex_export(kind):
    from flask import Response
    if kind not in ("feedback", "analisis"):
        abort(404)
    db = get_db()
    if kind == "feedback":
        sysmsg = ("Eres un docente universitario que da feedback formativo a estudiantes sobre su portafolio "
                  "de aprendizaje. Responde en español, en 150-220 palabras, con un tono amable y constructivo, "
                  "incluyendo 3 puntos de mejora concretos y accionables.")
    else:
        sysmsg = ("Eres un asistente docente que analiza rápidamente el portafolio de un estudiante, combinando "
                  "datos cuantitativos y cualitativos: temas, nivel de profundidad, frecuencia y preguntas para "
                  "seguir reflexionando. Responde en español y sin inventar.")
    rows = db.execute("SELECT portfolio, feedback FROM ai_examples WHERE kind=? AND active=1 ORDER BY id",
                      (kind,)).fetchall()
    lines = []
    for r in rows:
        obj = {"messages": [
            {"role": "system", "content": sysmsg},
            {"role": "user", "content": "Portafolio del estudiante:\n\n" + (r["portfolio"] or "")},
            {"role": "assistant", "content": r["feedback"] or ""},
        ]}
        lines.append(json.dumps(obj, ensure_ascii=False))
    body = "\n".join(lines) + ("\n" if lines else "")
    return Response(body, mimetype="application/jsonl",
                    headers={"Content-Disposition": "attachment; filename=ejemplos_%s.jsonl" % kind})


ADMIN_GROUPQ_TPL = """
<div class="between"><h1>Cuotas de evidencias por grupo</h1><a class="btn sec" href="{{ url_for('admin_home') }}">Volver a Administración</a></div>
<p class="muted" style="margin-top:0">Espacio de archivos de evidencia (Lesson Study) de cada grupo. Déjalo vacío para usar el valor por defecto ({{ default_mb }} MB). Solo la administración ajusta estas cuotas.</p>
<form method="post">
 <div class="card">
 {% if groups %}
 <div style="overflow-x:auto"><table style="min-width:560px;width:100%">
  <tr><th>Grupo</th><th>Uso actual</th><th>Cuota (MB)</th></tr>
  {% for g in groups %}<tr>
   <td><b>{{ g['name'] }}</b> <span class="muted">&middot; {{ g['nmembers'] }} miembros</span></td>
   <td><span style="color:{{ '#d34' if g['pct']>=90 else 'inherit' }}">{{ g['used_h'] }}</span> <span class="muted">de {{ g['quota_h'] }} ({{ g['pct'] }}%)</span></td>
   <td><input type="number" name="q_{{ g['id'] }}" min="100" step="100" value="{{ g['evidence_quota_mb'] or '' }}" placeholder="{{ default_mb }}" style="max-width:140px;margin:0"></td>
  </tr>{% endfor %}
 </table></div>
 <button class="btn" style="margin-top:12px">Guardar cuotas</button>
 {% else %}<p class="muted">No hay grupos todavía.</p>{% endif %}
 </div>
</form>
"""


@app.route("/admin/group-quotas", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin_group_quotas():
    db = get_db()
    if request.method == "POST":
        for gr in db.execute("SELECT id FROM groups").fetchall():
            raw = (request.form.get("q_%d" % gr["id"], "") or "").strip()
            val = int(raw) if raw.isdigit() else None
            db.execute("UPDATE groups SET evidence_quota_mb=? WHERE id=?", (val, gr["id"]))
        db.commit()
        flash("Cuotas de grupos guardadas.")
        return redirect(url_for("admin_group_quotas"))
    default_mb = LS_GROUP_QUOTA // (1024 * 1024)
    rows = []
    for gr in db.execute("SELECT * FROM groups ORDER BY name").fetchall():
        used = _group_evidence_bytes(gr["id"])
        quota = _group_quota(gr["id"])
        nmembers = db.execute("SELECT COUNT(*) c FROM group_members WHERE group_id=?", (gr["id"],)).fetchone()["c"]
        rows.append({"id": gr["id"], "name": gr["name"], "evidence_quota_mb": gr["evidence_quota_mb"],
                     "nmembers": nmembers, "used_h": human_size(used), "quota_h": human_size(quota),
                     "pct": min(100, int(round(used * 100.0 / quota))) if quota else 0})
    return render(ADMIN_GROUPQ_TPL, title="Cuotas de grupos", groups=rows, default_mb=default_mb)


@app.route("/admin")
@login_required
@role_required("admin")
def admin_home():
    db = get_db()
    n_users = db.execute("SELECT COUNT(*) c FROM users").fetchone()["c"]
    n_mail = db.execute("SELECT COUNT(*) c FROM email_log").fetchone()["c"]
    n_aiex = db.execute("SELECT COUNT(*) c FROM ai_examples").fetchone()["c"]
    return render(ADMIN_HOME_TPL, title="Administración", n_users=n_users, n_mail=n_mail,
                  email_on=email_config()["enabled"], n_aiex=n_aiex)


@app.route("/admin/users/template.csv")
@login_required
@role_required("admin")
def admin_users_template():
    from flask import Response
    csv_text = ("nombre,usuario,contraseña,rol,email\n"
                "Ana Ejemplo,ana.ejemplo,cambiar123,student,ana.ejemplo@ejemplo.org\n"
                "Prof Ejemplo,prof.ejemplo,cambiar123,teacher,prof.ejemplo@ejemplo.org\n")
    return Response(csv_text, mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=plantilla_usuarios.csv"})


def _parse_user_rows(storage):
    fn = (storage.filename or "").lower()
    if fn.endswith(".csv"):
        import csv, io
        data = storage.read().decode("utf-8-sig", "ignore")
        return [list(r) for r in csv.reader(io.StringIO(data))]
    if fn.endswith(".xlsx"):
        try:
            import openpyxl, io
        except Exception:
            return None
        wb = openpyxl.load_workbook(io.BytesIO(storage.read()), read_only=True, data_only=True)
        ws = wb.active
        return [["" if c is None else str(c) for c in row] for row in ws.iter_rows(values_only=True)]
    return []


@app.route("/admin/users/import", methods=["POST"])
@login_required
@role_required("admin")
def admin_users_import():
    db = get_db()
    f = request.files.get("file")
    if not f or not f.filename:
        flash("Selecciona un archivo .csv o .xlsx.", "error")
        return redirect(url_for("admin_users"))
    rows = _parse_user_rows(f)
    if rows is None:
        flash("Para archivos .xlsx necesitas instalar openpyxl (pip install openpyxl), o sube un .csv.", "error")
        return redirect(url_for("admin_users"))
    created = skipped = mailed = 0
    for r in rows:
        if len(r) < 2:
            continue
        name = r[0].strip() if len(r) > 0 else ""
        username = r[1].strip() if len(r) > 1 else ""
        pwd = r[2].strip() if len(r) > 2 else ""
        role = (r[3].strip().lower() if len(r) > 3 and r[3].strip() else "student")
        email = (r[4].strip() if len(r) > 4 else "")
        if not username or username.lower() in ("usuario", "username"):
            continue
        if not pwd:  # contraseña automática si la celda viene vacia
            pwd = _temp_password()
        if role not in ("student", "teacher", "admin"):
            role = "student"
        try:
            db.execute("INSERT INTO users(username,password,name,role,email) VALUES(?,?,?,?,?)",
                       (username, generate_password_hash(pwd, method=HASH), name or username, role, email))
            created += 1
            if email:
                ok, _ = send_email(email, "Tu cuenta en Vestigia",
                                   "Hola %s,\n\nSe ha creado tu cuenta en Vestigia.\n\n"
                                   "Usuario: %s\nContraseña: %s\n\n"
                                   "Te recomendamos cambiarla tras iniciar sesión.\n\n-- Vestigia"
                                   % (name or username, username, pwd))
                if ok:
                    mailed += 1
        except sqlite3.IntegrityError:
            skipped += 1
    db.commit()
    flash("Importacion completada: %d creados, %d omitidos (ya existian), %d con credenciales enviadas por email."
          % (created, skipped, mailed))
    return redirect(url_for("admin_users"))


FAVICON_SVG = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
               "<rect width='32' height='32' rx='7' fill='#7a1f3d'/>"
               "<g fill='none' stroke='#fff' stroke-width='2.2' stroke-linecap='round'>"
               "<path d='M8 22 Q16 9 24 22'/>"
               "<path d='M11 22.4 Q16 12 21 22.4'/>"
               "<path d='M13.5 22 Q16 15 18.5 22'/></g>"
               "<circle cx='16' cy='19' r='1.6' fill='#ff5c8a'/></svg>")


@app.route("/favicon.svg")
def favicon_svg():
    from flask import Response
    return Response(FAVICON_SVG, mimetype="image/svg+xml",
                    headers={"Cache-Control": "public, max-age=86400"})


@app.route("/favicon.ico")
def favicon_ico():
    from flask import Response
    data = _favicon_png_bytes()
    if data:
        return Response(data, mimetype="image/png", headers={"Cache-Control": "public, max-age=86400"})
    return Response(FAVICON_SVG, mimetype="image/svg+xml")


_FAVICON_PNG = None


# Icono (PNG 64x64) incrustado en base64: no depende de Pillow ni de nada externo.
FAVICON_PNG_B64 = ("iVBORw0KGgoAAAANSUhEUgAAAEAAAABACAYAAACqaXHeAAABsUlEQVR4nO1byXHDMAxccdxH0khSmPO2"
                   "C7MbsStxXspoGJoUSBwjAvuUaQp7ELoXEHD++HpRxlvh+rwve8c2Bx6F9Du0xEi1H49OHmhzKKozA/"
                   "ESSmn4l4BZyQNlbqk1YDbkHKs9wAP+BPDg/oot15Rv8IKVcywB6wKssXiM/xbuExACWBdgjRDAugBrs"
                   "Apwedw4p1PZz/BhsFTMz+f3yJSq+ztxFWGJbT1UMbqWQGsnUgK15u1JQjTB3j9qp0DCfSASMCaAVgqk"
                   "3AciAeMCSKdA0n0gEsAjgFQKpN0HIgF8AnCnQMN9IBLAKwBXCrTcBwwS0CKnfaXJLoDkvQCJ+UUS0Ls"
                   "UNKO/Ipqg1MTUFFi4D0QCZAXYmwIr94FIgM7T4ZFju/Rh1X0CVATodVHafSASoCcA1U0N94FIgK4Ae1"
                   "3Vch+IBNi8JXZ53Iouv9suiXhNzroAa3S9IMGJ/DRZewkkygdG3ChdI2jeE7w+74vZEqgR1RTBfQ9IA"
                   "O07u1mwck75Bg/YcjVbArVub3YqrJ2CElFp8jlH9x9OVh2fRYhasqs9YIbG2OJAIniURFCM+wV3vLgu"
                   "XLRJoAAAAABJRU5ErkJggg==")


def _favicon_png_bytes():
    global _FAVICON_PNG
    if _FAVICON_PNG is not None:
        return _FAVICON_PNG
    try:
        import base64
        _FAVICON_PNG = base64.b64decode(FAVICON_PNG_B64)
    except Exception:
        _FAVICON_PNG = b""
    return _FAVICON_PNG


@app.route("/favicon.png")
def favicon_png():
    from flask import Response
    data = _favicon_png_bytes()
    if not data:  # sin Pillow: servimos el SVG para que el enlace nunca falle
        return Response(FAVICON_SVG, mimetype="image/svg+xml",
                        headers={"Cache-Control": "public, max-age=86400"})
    return Response(data, mimetype="image/png", headers={"Cache-Control": "public, max-age=86400"})


@app.route("/api/mentionable")
@login_required
def api_mentionable():
    db, u = get_db(), current_user()
    rows = db.execute("""SELECT us.username, us.name FROM contacts c JOIN users us
          ON us.id = CASE WHEN c.requester_id=? THEN c.addressee_id ELSE c.requester_id END
        WHERE c.status='accepted' AND (c.requester_id=? OR c.addressee_id=?)
        ORDER BY us.name""", (u["id"], u["id"], u["id"])).fetchall()
    return jsonify({"people": [{"username": r["username"], "name": r["name"]} for r in rows]})


@app.route("/api/notifications")
@login_required
def api_notifications():
    u = current_user()
    rows = get_db().execute("""SELECT id,kind,text,link,is_read,created_at FROM notifications
                               WHERE user_id=? AND kind<>'Nuevo mensaje' ORDER BY id DESC LIMIT 10""", (u["id"],)).fetchall()
    convos = recent_convos(u["id"])
    return jsonify({"count": notif_count(u["id"]), "items": [dict(r) for r in rows],
                    "msg_count": unread_count(u["id"]),
                    "msg_items": [{"name": c["name"], "username": c["username"],
                                   "last": (c["last"] or "")[:60], "unread": c["unread"]} for c in convos]})


# --------------------------------------------------------------------------- #
#  Chat (cifrado en reposo, supervisable por el administrador)
# --------------------------------------------------------------------------- #
@app.route("/api/chat/peers")
@login_required
def api_chat_peers():
    db, u = get_db(), current_user()
    chat_purge_old()
    from datetime import timedelta
    threshold = (datetime.now() - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M")
    people, groups, pending = [], [], []
    if chat_enabled_dm():
        online_ids = set()
        for o in db.execute("""SELECT id,name,username FROM users
                WHERE show_online=1 AND last_seen>=? AND id<>? ORDER BY name LIMIT 60""",
                (threshold, u["id"])).fetchall():
            people.append({"id": o["id"], "name": o["name"], "username": o["username"]})
            online_ids.add(o["id"])
        # Conversaciones pendientes: personas desconectadas que te han escrito y aún no has leído.
        for o in db.execute("""SELECT u.id,u.name,u.username, COUNT(*) n
                FROM chat_messages c JOIN users u ON u.id=c.sender_id
                LEFT JOIN chat_reads r ON r.user_id=? AND r.conv_key='dm:'||c.sender_id
                WHERE c.kind='dm' AND c.recipient_id=? AND c.id>COALESCE(r.last_read_id,0)
                GROUP BY u.id ORDER BY u.name""", (u["id"], u["id"])).fetchall():
            if o["id"] not in online_ids:
                pending.append({"id": o["id"], "name": o["name"], "username": o["username"], "n": o["n"]})
    if chat_enabled_group():
        for g in db.execute("""SELECT g.id,g.name FROM groups g JOIN group_members m ON m.group_id=g.id
                WHERE m.user_id=? ORDER BY g.name""", (u["id"],)).fetchall():
            groups.append({"id": g["id"], "name": g["name"]})
    return jsonify({"dm_on": chat_enabled_dm(), "group_on": chat_enabled_group(),
                    "people": people, "groups": groups, "pending": pending})


@app.route("/api/chat/history")
@login_required
def api_chat_history():
    db, u = get_db(), current_user()
    kind = request.args.get("kind")
    rows = []
    if kind == "dm" and chat_enabled_dm():
        other = request.args.get("with")
        rows = db.execute("""SELECT c.*, us.name sender_name FROM chat_messages c JOIN users us ON us.id=c.sender_id
            WHERE c.kind='dm' AND ((c.sender_id=? AND c.recipient_id=?) OR (c.sender_id=? AND c.recipient_id=?))
            ORDER BY c.id DESC LIMIT 100""", (u["id"], other, other, u["id"])).fetchall()
    elif kind == "group" and chat_enabled_group():
        gid = request.args.get("gid")
        if not is_group_member(gid, u["id"]):
            abort(403)
        rows = db.execute("""SELECT c.*, us.name sender_name FROM chat_messages c JOIN users us ON us.id=c.sender_id
            WHERE c.kind='group' AND c.group_id=? ORDER BY c.id DESC LIMIT 100""", (gid,)).fetchall()
    out = []
    for r in reversed(rows):
        out.append({"id": r["id"], "sender": r["sender_name"], "me": r["sender_id"] == u["id"],
                    "body": chat_decrypt(r["body_enc"], r["enc"]), "at": r["created_at"]})
    if rows:
        maxid = max(r["id"] for r in rows)
        if kind == "dm":
            chat_mark_read(u["id"], "dm:%s" % request.args.get("with"), maxid)
        elif kind == "group":
            chat_mark_read(u["id"], "grp:%s" % request.args.get("gid"), maxid)
    return jsonify({"messages": out})


@app.route("/api/chat/send", methods=["POST"])
@login_required
def api_chat_send():
    db, u = get_db(), current_user()
    kind = request.form.get("kind")
    body = (request.form.get("body", "") or "").strip()[:4000]
    if not body:
        return jsonify({"error": "vacío"}), 400
    # Solo se rechaza si NO hay ningún cifrado posible (ni Fernet ni el alternativo).
    if crypto_status() == "none":
        import sys as _sys
        send_critical_alert("chat_sin_cifrado",
                            "Vestigia: MENSAJE DE CHAT RECHAZADO (cifrado inactivo)",
                            "Un usuario (%s) intentó enviar un mensaje de chat pero no hay cifrado en reposo "
                            "disponible, así que se rechazó para no almacenarlo sin cifrar.\n\n"
                            "Error de cryptography: %s\nIntérprete: %s\n\nRevisa los permisos de escritura de la "
                            "carpeta de la app o define EVESTIGIA_SECRET_KEY.\n\n-- eVestigia"
                            % (u["username"], (CRYPTO_IMPORT_ERROR or "no disponible"), _sys.executable))
        return jsonify({"error": "El chat no está disponible temporalmente (cifrado inactivo). "
                                 "Se ha avisado a la administración."}), 503
    try:
        enc_body, enc = chat_encrypt(body)
        if kind == "dm" and chat_enabled_dm():
            db.execute("""INSERT INTO chat_messages(kind,sender_id,recipient_id,body_enc,enc,created_at)
                          VALUES('dm',?,?,?,?,?)""", (u["id"], request.form.get("to"), enc_body, enc, now()))
        elif kind == "group" and chat_enabled_group():
            gid = request.form.get("gid")
            if not is_group_member(gid, u["id"]):
                abort(403)
            db.execute("""INSERT INTO chat_messages(kind,sender_id,group_id,body_enc,enc,created_at)
                          VALUES('group',?,?,?,?,?)""", (u["id"], gid, enc_body, enc, now()))
        else:
            return jsonify({"error": "no disponible"}), 403
        db.commit()
    except Exception as e:
        from werkzeug.exceptions import HTTPException
        if isinstance(e, HTTPException):
            raise
        import traceback
        send_critical_alert("chat_error",
                            "Vestigia: FALLO AL ENVIAR UN MENSAJE DE CHAT",
                            "No se pudo guardar un mensaje de chat de %s.\n\n%s\n\n-- Vestigia"
                            % (u["username"], traceback.format_exc()), throttle_hours=1)
        return jsonify({"error": "No se pudo enviar el mensaje. Se ha avisado a la administración."}), 500
    return jsonify({"ok": True})


def chat_mark_read(user_id, conv_key, upto_id):
    """Marca como leídos los mensajes de una conversación hasta upto_id."""
    if not upto_id:
        return
    db = get_db()
    db.execute("""INSERT INTO chat_reads(user_id,conv_key,last_read_id) VALUES(?,?,?)
                  ON CONFLICT(user_id,conv_key) DO UPDATE SET last_read_id=MAX(last_read_id,excluded.last_read_id)""",
               (user_id, conv_key, upto_id))
    db.commit()


@app.route("/api/chat/unread")
@login_required
def api_chat_unread():
    db, u = get_db(), current_user()
    convs, total = {}, 0
    if chat_enabled_dm():
        for r in db.execute("""SELECT c.sender_id peer, COUNT(*) n FROM chat_messages c
                LEFT JOIN chat_reads r ON r.user_id=? AND r.conv_key='dm:'||c.sender_id
                WHERE c.kind='dm' AND c.recipient_id=? AND c.id>COALESCE(r.last_read_id,0)
                GROUP BY c.sender_id""", (u["id"], u["id"])).fetchall():
            convs["dm:%d" % r["peer"]] = r["n"]; total += r["n"]
    if chat_enabled_group():
        for r in db.execute("""SELECT c.group_id gid, COUNT(*) n FROM chat_messages c
                JOIN group_members m ON m.group_id=c.group_id AND m.user_id=?
                LEFT JOIN chat_reads r ON r.user_id=? AND r.conv_key='grp:'||c.group_id
                WHERE c.kind='group' AND c.sender_id<>? AND c.id>COALESCE(r.last_read_id,0)
                GROUP BY c.group_id""", (u["id"], u["id"], u["id"])).fetchall():
            convs["grp:%d" % r["gid"]] = r["n"]; total += r["n"]
    return jsonify({"total": total, "convs": convs})


# =========================== API JSON (para el front-end Next.js) ========== #
FRONTEND_ORIGIN = os.environ.get("VESTIGIA_FRONTEND_ORIGIN", "http://localhost:3000")


def _serializer():
    return URLSafeTimedSerializer(app.config["SECRET_KEY"], salt="vestigia-api")


def make_token(uid):
    return _serializer().dumps({"uid": uid})


def user_from_token():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return None
    try:
        data = _serializer().loads(auth[7:], max_age=7 * 24 * 3600)
    except (BadSignature, SignatureExpired, Exception):
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (data.get("uid"),)).fetchone()


def api_login_required(f):
    @wraps(f)
    def w(*a, **k):
        u = user_from_token()
        if not u:
            return jsonify({"error": "no autorizado"}), 401
        g.api_user = u
        return f(*a, **k)
    return w


@app.after_request
def _cors(resp):
    if request.path.startswith("/api/"):
        origin = request.headers.get("Origin", "")
        if origin and (origin == FRONTEND_ORIGIN or
                       re.match(r"^https?://(localhost|127\.0\.0\.1)(:\d+)?$", origin)):
            allow = origin
        else:
            allow = FRONTEND_ORIGIN
        resp.headers["Access-Control-Allow-Origin"] = allow
        resp.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        resp.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        resp.headers["Vary"] = "Origin"
    return resp


@app.before_request
def _preflight():
    if request.method == "OPTIONS" and request.path.startswith("/api/"):
        return ("", 204)


def _user_public(u):
    return {"id": u["id"], "username": u["username"], "name": u["name"],
            "role": u["role"], "bio": u["bio"], "avatar": u["avatar"] or None}


@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json(force=True, silent=True) or {}
    u = get_db().execute("SELECT * FROM users WHERE username=?", (str(d.get("username", "")).strip(),)).fetchone()
    if not u or not check_password_hash(u["password"], str(d.get("password", ""))):
        return jsonify({"error": "Credenciales incorrectas"}), 401
    return jsonify({"token": make_token(u["id"]), "user": _user_public(u)})


@app.route("/api/me")
@api_login_required
def api_me():
    return jsonify({"user": _user_public(g.api_user)})


@app.route("/api/feed")
@api_login_required
def api_feed():
    rows = get_db().execute("""
        SELECT p.id, p.title, p.description, p.created_at, us.name, us.username,
          (SELECT COUNT(*) FROM page_reads r WHERE r.page_id=p.id) reads,
          (SELECT COUNT(*) FROM comments c WHERE c.page_id=p.id) comments
        FROM pages p JOIN users us ON us.id=p.owner_id
        WHERE p.visibility='public' ORDER BY p.id DESC LIMIT 50""").fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/my/pages")
@api_login_required
def api_my_pages():
    u = g.api_user
    rows = get_db().execute("""SELECT id,title,description,visibility,created_at FROM pages
                               WHERE owner_id=? AND id IS NOT ? ORDER BY id DESC""",
                            (u["id"], u["profile_page_id"])).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


def _blocks_json(page_id):
    out = []
    for R in page_rows(page_id):
        out.append({"layout": R["row"]["layout"], "weights": R["weights"],
                    "cols": [[{"type": b["block_type"], "html": block_html(b)} for b in col] for col in R["cols"]]})
    return out


@app.route("/api/profile/<username>")
@api_login_required
def api_profile(username):
    db = get_db()
    prof = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not prof:
        return jsonify({"error": "no encontrado"}), 404
    pages = db.execute("""SELECT id,title,(SELECT COUNT(*) FROM page_reads r WHERE r.page_id=p.id) reads
                          FROM pages p WHERE owner_id=? AND visibility='public' AND id IS NOT ?
                          ORDER BY id DESC""", (prof["id"], prof["profile_page_id"])).fetchall()
    bio = _blocks_json(prof["profile_page_id"]) if prof["profile_page_id"] else None
    return jsonify({"user": _user_public(prof), "pages": [dict(p) for p in pages], "bio": bio})


def _owned_api_page(pid):
    p = get_db().execute("SELECT * FROM pages WHERE id=?", (pid,)).fetchone()
    if not p or p["owner_id"] != g.api_user["id"]:
        abort(403)
    return p


@app.route("/api/artefacts")
@api_login_required
def api_artefacts():
    rows = get_db().execute("SELECT id,title,kind FROM artefacts WHERE owner_id=? ORDER BY id DESC",
                            (g.api_user["id"],)).fetchall()
    return jsonify({"items": [dict(r) for r in rows]})


@app.route("/api/pages", methods=["POST"])
@api_login_required
def api_create_page():
    u = g.api_user
    db = get_db()
    d = request.get_json(force=True, silent=True) or {}
    title = (d.get("title") or "Nueva página").strip()
    pid = db.execute("INSERT INTO pages(owner_id,title,description,created_at) VALUES(?,?,?,?)",
                     (u["id"], title, "", now())).lastrowid
    db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)", (pid, 0, "1"))
    db.commit()
    return jsonify({"id": pid})


@app.route("/api/pages/<int:pid>/edit")
@api_login_required
def api_page_edit(pid):
    p = _owned_api_page(pid)
    db = get_db()
    arts = db.execute("SELECT id,title,kind FROM artefacts WHERE owner_id=? ORDER BY id DESC", (g.api_user["id"],)).fetchall()
    rows = []
    for R in page_rows(pid):
        cols = []
        for col in R["cols"]:
            cols.append([{"id": b["id"], "type": b["block_type"], "artefact_id": b["artefact_id"],
                          "text": b["text_content"], "font_family": b["font_family"], "font_size": b["font_size"],
                          "color": b["text_color"], "align": b["align"], "html": block_html(b)} for b in col])
        rows.append({"id": R["row"]["id"], "layout": R["row"]["layout"], "weights": R["weights"], "cols": cols})
    return jsonify({"title": p["title"], "description": p["description"], "visibility": p["visibility"],
                    "rows": rows, "artefacts": [dict(a) for a in arts], "layouts": list(LAYOUTS.keys()),
                    "layout_labels": LAYOUT_LABELS})


@app.route("/api/pages/<int:pid>/meta", methods=["POST"])
@api_login_required
def api_page_meta(pid):
    p = _owned_api_page(pid)
    db = get_db()
    d = request.get_json(force=True, silent=True) or {}
    vis = d.get("visibility", p["visibility"])
    token = p["share_token"] or (secrets.token_urlsafe(10) if vis == "public" else None)
    db.execute("UPDATE pages SET title=?,description=?,visibility=?,share_token=? WHERE id=?",
               ((d.get("title") or p["title"]).strip(), d.get("description", ""), vis, token, pid))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/pages/<int:pid>/rows", methods=["POST"])
@api_login_required
def api_add_row(pid):
    _owned_api_page(pid)
    db = get_db()
    layout = (request.get_json(force=True, silent=True) or {}).get("layout", "1")
    if layout not in LAYOUTS:
        layout = "1"
    pos = db.execute("SELECT COALESCE(MAX(position),-1)+1 n FROM rows WHERE page_id=?", (pid,)).fetchone()["n"]
    rid = db.execute("INSERT INTO rows(page_id,position,layout) VALUES(?,?,?)", (pid, pos, layout)).lastrowid
    db.commit()
    return jsonify({"id": rid})


@app.route("/api/rows/<int:rid>", methods=["DELETE"])
@api_login_required
def api_del_row(rid):
    db = get_db()
    r = db.execute("SELECT r.id, p.owner_id FROM rows r JOIN pages p ON p.id=r.page_id WHERE r.id=?", (rid,)).fetchone()
    if not r or r["owner_id"] != g.api_user["id"]:
        abort(403)
    db.execute("DELETE FROM rows WHERE id=?", (rid,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/rows/<int:rid>/blocks", methods=["POST"])
@api_login_required
def api_add_block(rid):
    db = get_db()
    u = g.api_user
    r = db.execute("SELECT r.id, p.owner_id FROM rows r JOIN pages p ON p.id=r.page_id WHERE r.id=?", (rid,)).fetchone()
    if not r or r["owner_id"] != u["id"]:
        abort(403)
    is_form = bool(request.form) or bool(request.files)
    f = request.form if is_form else (request.get_json(force=True, silent=True) or {})
    ci = int(f.get("col_index", 0) or 0)
    bt = f.get("block_type")
    pos = db.execute("SELECT COALESCE(MAX(position),-1)+1 n FROM blocks WHERE row_id=? AND col_index=?", (rid, ci)).fetchone()["n"]
    if bt in ("text", "heading"):
        bid = db.execute("INSERT INTO blocks(row_id,col_index,position,block_type,text_content) VALUES(?,?,?,?,?)",
                         (rid, ci, pos, bt, (f.get("text") or "").strip())).lastrowid
    elif bt == "artefact":
        bid = db.execute("INSERT INTO blocks(row_id,col_index,position,block_type,artefact_id) VALUES(?,?,?,?,?)",
                         (rid, ci, pos, "artefact", f.get("artefact_id"))).lastrowid
    else:
        kind = bt
        title = (f.get("title") or KIND_LABELS.get(kind, "Artefacto")).strip()
        url = (f.get("url") or "").strip()
        fn = None
        if kind in ("image", "audio", "file") or (kind == "video" and not url):
            fn, ext = save_upload()
            if ext == "bad":
                return jsonify({"error": "tipo de archivo no permitido"}), 400
            if not fn:
                return jsonify({"error": "falta archivo o URL"}), 400
            if ext in IMAGE_EXT:
                kind = "image"
        aid = db.execute("INSERT INTO artefacts(owner_id,kind,title,body,url,filename,created_at) VALUES(?,?,?,?,?,?,?)",
                         (u["id"], kind, title, "", url, fn, now())).lastrowid
        bid = db.execute("INSERT INTO blocks(row_id,col_index,position,block_type,artefact_id) VALUES(?,?,?,?,?)",
                         (rid, ci, pos, "artefact", aid)).lastrowid
    db.commit()
    b = db.execute("SELECT * FROM blocks WHERE id=?", (bid,)).fetchone()
    return jsonify({"id": bid, "html": block_html(b)})


@app.route("/api/blocks/<int:bid>", methods=["POST", "DELETE"])
@api_login_required
def api_block(bid):
    db = get_db()
    b = db.execute("""SELECT b.*, p.owner_id FROM blocks b JOIN rows r ON r.id=b.row_id
                      JOIN pages p ON p.id=r.page_id WHERE b.id=?""", (bid,)).fetchone()
    if not b or b["owner_id"] != g.api_user["id"]:
        abort(403)
    if request.method == "DELETE":
        db.execute("DELETE FROM blocks WHERE id=?", (bid,))
        db.commit()
        return jsonify({"ok": True})
    d = request.get_json(force=True, silent=True) or {}
    db.execute("UPDATE blocks SET text_content=?,font_family=?,font_size=?,text_color=?,align=? WHERE id=?",
               ((d.get("text") or "").strip(), d.get("font_family", "sans"), int(d.get("font_size", 16) or 16),
                d.get("color", "#1c1922"), d.get("align", "left"), bid))
    db.commit()
    b2 = db.execute("SELECT * FROM blocks WHERE id=?", (bid,)).fetchone()
    return jsonify({"html": block_html(b2)})


@app.route("/api/pages/<int:pid>/reorder", methods=["POST"])
@api_login_required
def api_reorder(pid):
    _owned_api_page(pid)
    db = get_db()
    data = request.get_json(force=True, silent=True) or {}
    valid = {x["id"] for x in db.execute("SELECT b.id FROM blocks b JOIN rows r ON r.id=b.row_id WHERE r.page_id=?", (pid,)).fetchall()}
    validrows = {x["id"] for x in db.execute("SELECT id FROM rows WHERE page_id=?", (pid,)).fetchall()}
    for col in data.get("columns", []):
        rid, ci = int(col["row_id"]), int(col["col_index"])
        if rid not in validrows:
            continue
        for i, bid in enumerate(col.get("block_ids", [])):
            if int(bid) in valid:
                db.execute("UPDATE blocks SET row_id=?,col_index=?,position=? WHERE id=?", (rid, ci, i, int(bid)))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/pages/<int:pid>", methods=["DELETE"])
@api_login_required
def api_del_page(pid):
    _owned_api_page(pid)
    db = get_db()
    db.execute("DELETE FROM pages WHERE id=?", (pid,))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/people")
@api_login_required
def api_people():
    u = g.api_user
    q = request.args.get("q", "").strip()
    db = get_db()
    if q:
        rows = db.execute("SELECT * FROM users WHERE id<>? AND (name LIKE ? OR username LIKE ?) ORDER BY name LIMIT 50",
                          (u["id"], "%" + q + "%", "%" + q + "%")).fetchall()
    else:
        rows = db.execute("SELECT * FROM users WHERE id<>? ORDER BY name LIMIT 50", (u["id"],)).fetchall()
    return jsonify({"items": [dict(_user_public(r), status=contact_status(u["id"], r["id"])) for r in rows]})


@app.route("/api/contacts")
@api_login_required
def api_contacts_list():
    u = g.api_user
    db = get_db()
    friends = db.execute("""SELECT us.* FROM contacts c JOIN users us
        ON us.id = CASE WHEN c.requester_id=? THEN c.addressee_id ELSE c.requester_id END
        WHERE c.status='accepted' AND (c.requester_id=? OR c.addressee_id=?) ORDER BY us.name""",
        (u["id"], u["id"], u["id"])).fetchall()
    incoming = db.execute("""SELECT us.* FROM contacts c JOIN users us ON us.id=c.requester_id
        WHERE c.addressee_id=? AND c.status='pending' ORDER BY us.name""", (u["id"],)).fetchall()
    outgoing = db.execute("""SELECT us.* FROM contacts c JOIN users us ON us.id=c.addressee_id
        WHERE c.requester_id=? AND c.status='pending' ORDER BY us.name""", (u["id"],)).fetchall()
    return jsonify({"friends": [_user_public(x) for x in friends],
                    "incoming": [_user_public(x) for x in incoming],
                    "outgoing": [_user_public(x) for x in outgoing]})


@app.route("/api/contacts/<username>", methods=["POST"])
@api_login_required
def api_contact_action(username):
    u = g.api_user
    db = get_db()
    other = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not other or other["id"] == u["id"]:
        return jsonify({"error": "invalido"}), 400
    action = (request.get_json(force=True, silent=True) or {}).get("action")
    me, ot = u["id"], other["id"]
    if action == "request" and contact_status(me, ot) == "none":
        db.execute("INSERT INTO contacts(requester_id,addressee_id,status,created_at) VALUES(?,?,?,?)",
                   (me, ot, "pending", now()))
        notify(ot, "contact_request", "%s quiere añadirte como conocido." % u["name"],
               url_for("contacts"), {"actor": u["name"]})
    elif action == "accept":
        db.execute("UPDATE contacts SET status='accepted' WHERE requester_id=? AND addressee_id=? AND status='pending'", (ot, me))
    elif action == "remove":
        db.execute("DELETE FROM contacts WHERE (requester_id=? AND addressee_id=?) OR (requester_id=? AND addressee_id=?)", (me, ot, ot, me))
    db.commit()
    return jsonify({"status": contact_status(me, ot)})


@app.route("/api/conversations")
@api_login_required
def api_conversations():
    return jsonify({"items": recent_convos(g.api_user["id"], 50)})


@app.route("/api/conversations/<username>", methods=["GET", "POST"])
@api_login_required
def api_conversation(username):
    u = g.api_user
    db = get_db()
    other = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not other or other["id"] == u["id"]:
        return jsonify({"error": "no encontrado"}), 404
    if request.method == "POST":
        body = (request.get_json(force=True, silent=True) or {}).get("body", "").strip()
        if body:
            db.execute("INSERT INTO messages(sender_id,recipient_id,body,created_at,is_read) VALUES(?,?,?,?,0)",
                       (u["id"], other["id"], body, now()))
            notify(other["id"], "message", "%s te ha enviado un mensaje." % u["name"],
                   url_for("thread", username=u["username"]), {"actor": u["name"]}, in_app=False)
            db.commit()
    msgs = db.execute("""SELECT id,sender_id,body,created_at FROM messages
        WHERE (sender_id=? AND recipient_id=?) OR (sender_id=? AND recipient_id=?) ORDER BY id""",
        (u["id"], other["id"], other["id"], u["id"])).fetchall()
    db.execute("UPDATE messages SET is_read=1 WHERE sender_id=? AND recipient_id=? AND is_read=0", (other["id"], u["id"]))
    db.commit()
    return jsonify({"other": _user_public(other), "me": u["id"], "messages": [dict(m) for m in msgs]})


@app.route("/api/notifs")
@api_login_required
def api_notifs():
    u = g.api_user
    rows = get_db().execute("""SELECT id,kind,text,link,is_read,created_at FROM notifications
        WHERE user_id=? AND kind<>'Nuevo mensaje' ORDER BY id DESC LIMIT 30""", (u["id"],)).fetchall()
    return jsonify({"count": notif_count(u["id"]), "msg_count": unread_count(u["id"]),
                    "items": [dict(r) for r in rows]})


@app.route("/api/notifs/<int:nid>/read", methods=["POST"])
@api_login_required
def api_notif_read(nid):
    u = g.api_user
    db = get_db()
    db.execute("UPDATE notifications SET is_read=1 WHERE id=? AND user_id=?", (nid, u["id"]))
    db.commit()
    return jsonify({"ok": True})


@app.route("/api/pages/<int:pid>")
@api_login_required
def api_page(pid):
    db = get_db()
    p = db.execute("SELECT * FROM pages WHERE id=?", (pid,)).fetchone()
    if not p or not can_view(p, g.api_user):
        return jsonify({"error": "no encontrado"}), 404
    author = db.execute("SELECT * FROM users WHERE id=?", (p["owner_id"],)).fetchone()
    return jsonify({"title": p["title"], "description": p["description"],
                    "visibility": p["visibility"], "author": _user_public(author),
                    "rows": _blocks_json(pid)})


if __name__ == "__main__":
    # Asegura la librería de cifrado en el mismo intérprete (si falta, intenta instalarla).
    ensure_cryptography()
    init_db()
    # Autocomprobación de fallos críticos (p. ej. cifrado en reposo inactivo): avisa por correo a la administración.
    try:
        with app.app_context():
            _probs = run_critical_checks("arranque")
            if _probs:
                print("[AVISO CRÍTICO] " + "; ".join(p[1] for p in _probs))
    except Exception as _e:
        print("No se pudo ejecutar la autocomprobación:", _e)
    print("Vestigia v4 en http://127.0.0.1:5000  (ana/ana123, luis/luis123, maria/maria123, profesor/profe123, admin/admin123)")
    # Por seguridad: enlazado solo a localhost y sin depurador (activa con EVESTIGIA_DEBUG=1 si lo necesitas).
    _debug = os.environ.get("EVESTIGIA_DEBUG") == "1"
    _host = os.environ.get("EVESTIGIA_HOST", "127.0.0.1")
    # threaded=True: atiende varias peticiones a la vez, para que una tarea lenta (IA) no congele a los demás.
    app.run(debug=_debug, host=_host, port=int(os.environ.get("EVESTIGIA_PORT", "5000")), threaded=True)
