import os
import re
import io
import hmac
import hashlib
import sqlite3
import secrets
import ssl
import time
from datetime import date, datetime, timedelta
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit

from flask import (
    Flask, render_template, request, redirect, url_for, flash,
    session, abort, send_file, g,
)
from werkzeug.middleware.proxy_fix import ProxyFix

import crypto_utils
import mailer
from crypto_utils import pack, unpack, hmac_index, hash_password, verify_password
from validators import (
    ValidationError, validate_login, validate_user, validate_client,
    validate_contact, validate_address, validate_process, validate_associate,
    validate_precedent, validate_receipt, validate_preferences, validate_password,
    PROCESS_STATUS, PROCESS_TYPES, ASSOCIATE_ROLES,
)

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("DATA_DIR", BASE_DIR / "data"))
DB_PATH = DATA_DIR / "advocacia.sqlite"
KEY_PATH = DATA_DIR / "encryption.key"
SCHEMA_PATH = BASE_DIR / "database" / "schema.sqlite.sql"
ALLOWED_MIME = {"application/pdf", "image/jpeg", "image/png", "image/webp"}
MAX_FILE_SIZE = 10 * 1024 * 1024


# --- Configuração (variáveis de ambiente) ---

def _load_env_file(path):
    # data/smtp.env é criado por "python manage.py smtp"; variáveis já definidas têm prioridade.
    if path.exists():
        for line in path.read_text().splitlines():
            key, sep, value = line.partition("=")
            if sep and key.strip() and not key.startswith("#"):
                os.environ.setdefault(key.strip(), value.strip())


def _int_env(name, default, low, high):
    raw = os.environ.get(name, str(default))
    if not raw.isdigit() or not low <= int(raw) <= high:
        raise SystemExit(f"{name} deve ser um número inteiro entre {low} e {high}.")
    return int(raw)


_load_env_file(DATA_DIR / "smtp.env")
PRODUCTION = os.environ.get("APP_ENV") == "production"
PORT = _int_env("PORT", 5000, 1, 65535)
HOST = os.environ.get("HOST", "127.0.0.1")
SESSION_HOURS = _int_env("SESSION_HOURS", 8, 1, 24)

TLS_CERT = Path(os.environ.get("TLS_CERT_FILE", DATA_DIR / "tls" / "localhost-cert.pem"))
TLS_KEY = Path(os.environ.get("TLS_KEY_FILE", DATA_DIR / "tls" / "localhost-key.pem"))
TLS_MODE = os.environ.get("TLS_MODE", "auto")
if TLS_MODE not in ("auto", "on", "off"):
    raise SystemExit("TLS_MODE deve ser auto, on ou off.")
if TLS_CERT.exists() != TLS_KEY.exists():
    raise SystemExit("TLS incompleto: certificado e chave privada devem existir juntos.")
if TLS_MODE == "on" and not TLS_CERT.exists():
    raise SystemExit("TLS_MODE=on exige certificado e chave. Execute: python manage.py tls")
DIRECT_TLS = TLS_MODE == "on" or (TLS_MODE == "auto" and TLS_CERT.exists())

APP_ORIGIN = os.environ.get("APP_ORIGIN", "")
_origin = urlsplit(APP_ORIGIN or f"{'https' if DIRECT_TLS else 'http'}://localhost:{PORT}")
if (_origin.scheme not in ("http", "https") or not _origin.hostname or _origin.username
        or _origin.password or _origin.path or _origin.query or _origin.fragment):
    raise SystemExit("APP_ORIGIN deve conter só a origem, por exemplo https://gestao.exemplo.com (sem barra final).")
SECURE = _origin.scheme == "https"
EXPECTED_HOST = _origin.netloc.lower()
if APP_ORIGIN:
    ALLOWED_ORIGINS = {APP_ORIGIN.lower()}
else:
    ALLOWED_ORIGINS = {f"{_origin.scheme}://{h}:{PORT}" for h in ("localhost", "127.0.0.1", "[::1]")}
if DIRECT_TLS and not SECURE:
    raise SystemExit("APP_ORIGIN deve usar HTTPS quando o TLS local está ativo.")
if PRODUCTION and not SECURE:
    raise SystemExit("Em produção, APP_ORIGIN deve usar HTTPS.")

TRUST_PROXY = _int_env("TRUST_PROXY", 0, 0, 5)
if DIRECT_TLS and TRUST_PROXY:
    raise SystemExit("Não combine TLS direto com TRUST_PROXY; termine o TLS no Python ou no proxy.")

MFA_MODE = os.environ.get("MFA_MODE") or ("smtp" if PRODUCTION else "console")
if MFA_MODE not in ("smtp", "console", "test"):
    raise SystemExit("MFA_MODE deve ser smtp, console ou test.")
if PRODUCTION and MFA_MODE != "smtp":
    raise SystemExit("Em produção, MFA_MODE deve ser smtp.")
mailer.configure(MFA_MODE, os.environ)

app = Flask(__name__, static_folder="static", template_folder="templates")
if TRUST_PROXY:
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=TRUST_PROXY, x_proto=TRUST_PROXY, x_host=TRUST_PROXY)
app.config.update(
    MAX_CONTENT_LENGTH=MAX_FILE_SIZE + 512 * 1024,
    SESSION_COOKIE_NAME="__Host-sessao" if SECURE else "sessao",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=SECURE,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=SESSION_HOURS),
)

if not KEY_PATH.exists():
    raise SystemExit("Execute primeiro: python manage.py setup")

crypto_utils.load_key(str(KEY_PATH))
# Chave do cookie derivada da chave de cifragem: as sessões sobrevivem a reinícios sem outro segredo.
app.secret_key = hmac.new(KEY_PATH.read_bytes(), b"flask-session-cookie", hashlib.sha256).digest()


# --- Database ---

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(str(DB_PATH))
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.execute("PRAGMA busy_timeout=5000")
    return g.db


@app.teardown_appcontext
def close_db(exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db = sqlite3.connect(str(DB_PATH))
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA foreign_keys=ON")
    with open(SCHEMA_PATH) as f:
        db.executescript(f.read())
    db.execute("PRAGMA trusted_schema=OFF")
    db.execute("PRAGMA secure_delete=ON")
    db.close()


if DB_PATH.exists():
    init_db()


def audit(user_id, action, table, record_id):
    get_db().execute(
        "INSERT INTO logs_auditoria(id_usuario,acao,tabela_afetada,id_registro) VALUES(?,?,?,?)",
        (user_id, action, table, record_id),
    )


def public_user(row):
    data = unpack(bytes(row["dados"]), "usuario")
    return {
        "id_usuario": row["id_usuario"],
        "nome": data["nome"],
        "email": data["email"],
        "preferencias": data.get("preferencias", {"tema": "SISTEMA", "fonte": "NORMAL", "alto_contraste": False}),
        "perfil": row["perfil"],
        "ativo": bool(row["ativo"]),
    }


# --- Proteções de rede ---

@app.before_request
def network_guard():
    if request.method not in ("GET", "HEAD", "POST"):
        return "Método não permitido.", 405, {"Allow": "GET, HEAD, POST"}
    if SECURE:
        if request.host.lower() != EXPECTED_HOST:
            return "Destino HTTP inválido.", 421, {"Content-Type": "text/plain; charset=utf-8"}
        if not request.is_secure:
            if request.method in ("GET", "HEAD"):
                return redirect(f"https://{EXPECTED_HOST}{request.full_path.rstrip('?')}", 308)
            return "Use uma conexão HTTPS.", 400
    if request.method == "POST":
        # Bloqueia envios de formulário vindos de outros sites (além do token CSRF).
        origin = request.headers.get("Origin")
        if origin and origin.lower() not in ALLOWED_ORIGINS:
            abort(403)
        if request.headers.get("Sec-Fetch-Site", "same-origin") not in ("same-origin", "none"):
            abort(403)
        if request.content_length and request.mimetype not in (
                "application/x-www-form-urlencoded", "multipart/form-data"):
            return "Tipo de conteúdo não aceito.", 415


# --- Rate Limiting ---

_rate_windows = {}

@app.before_request
def rate_limit():
    now = time.time()
    ip = request.remote_addr or "unknown"
    window = _rate_windows.get(ip)
    if not window or window["expires"] <= now:
        window = {"total": 0, "expires": now + 300}
        _rate_windows[ip] = window
    window["total"] += 1
    if window["total"] > 600:
        abort(429)
    if len(_rate_windows) > 10000:
        expired = [k for k, v in _rate_windows.items() if v["expires"] <= now]
        for k in expired:
            del _rate_windows[k]


# --- Security Headers ---

@app.after_request
def security_headers(response):
    h = response.headers
    h["X-Content-Type-Options"] = "nosniff"
    h["X-Frame-Options"] = "DENY"
    h["Referrer-Policy"] = "no-referrer"
    h["X-Robots-Tag"] = "noindex, nofollow, noarchive, nosnippet"
    h["Cross-Origin-Opener-Policy"] = "same-origin"
    h["Cross-Origin-Embedder-Policy"] = "require-corp"
    h["Cross-Origin-Resource-Policy"] = "same-origin"
    h["Content-Security-Policy"] = (
        "default-src 'none'; script-src 'self'; script-src-attr 'none'; style-src 'self'; "
        "style-src-attr 'none'; img-src 'self'; font-src 'self'; connect-src 'self'; "
        "form-action 'self'; frame-ancestors 'none'; base-uri 'none'; object-src 'none'"
        + ("; upgrade-insecure-requests" if SECURE else "")
    )
    h["Permissions-Policy"] = (
        "accelerometer=(), autoplay=(), camera=(), display-capture=(), geolocation=(), "
        "gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()"
    )
    if SECURE:
        h["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains; preload"
    if request.endpoint != "static":
        h["Cache-Control"] = "no-store"
    return response


# --- Session / Auth ---

def current_user():
    user_id = session.get("user_id")
    session_id = session.get("session_id")
    if not user_id or not session_id:
        return None
    db = get_db()
    row = db.execute(
        "SELECT s.id_sessao, s.expira, s.csrf, u.* FROM sessoes s "
        "JOIN usuarios u ON u.id_usuario = s.id_usuario "
        "WHERE s.id_sessao = ? AND s.id_usuario = ? AND s.expira > ? AND u.ativo = 1",
        (session_id, user_id, int(time.time() * 1000)),
    ).fetchone()
    if not row:
        session.clear()
        return None
    return public_user(row)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Entre novamente para continuar.", "error")
            return redirect(url_for("login"))
        g.user = user
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    @login_required
    def decorated(*args, **kwargs):
        if g.user["perfil"] != "ADMINISTRADOR":
            flash("Acesso exclusivo de administradores.", "error")
            return redirect(url_for("dashboard_page"))
        return f(*args, **kwargs)
    return decorated


def csrf_protect():
    if request.method == "POST":
        token = request.form.get("_csrf") or request.headers.get("X-CSRF-Token", "")
        expected = session.get("csrf", "")
        if not token or not expected or not secrets.compare_digest(token, expected):
            abort(403)


@app.before_request
def enforce_csrf():
    if request.method == "POST" and request.endpoint and request.endpoint != "static":
        csrf_protect()


@app.context_processor
def inject_globals():
    user = current_user() if session.get("user_id") else None
    return {
        "current_user": user,
        "csrf_token": session.get("csrf", ""),
        "is_admin": user and user["perfil"] == "ADMINISTRADOR",
        "page_url": page_url,
        "today": date.today().isoformat(),
    }


def page_url(page):
    args = request.args.to_dict()
    args["page"] = page
    return url_for(request.endpoint, **request.view_args, **args)


def int_arg(name, default=0, low=0, high=10**9):
    try:
        return max(low, min(high, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


def cents_arg(name):
    try:
        value = float(request.args.get(name, "").replace(",", "."))
        return round(value * 100) if value >= 0 else None
    except ValueError:
        return None


# --- Template Helpers ---

@app.template_filter("date_br")
def date_br_filter(value):
    if not value:
        return ""
    try:
        if " " in str(value):
            dt = datetime.fromisoformat(str(value).replace(" ", "T") + ("+00:00" if "+" not in str(value) and "Z" not in str(value) else ""))
            return dt.strftime("%d/%m/%Y %H:%M")
        return date.fromisoformat(str(value)).strftime("%d/%m/%Y")
    except Exception:
        return str(value)


@app.template_filter("money")
def money_filter(cents):
    try:
        value = int(cents or 0) / 100
        return f"R$ {value:,.2f}".replace(",", "X").replace(".", ",").replace("X", ".")
    except (TypeError, ValueError):
        return "R$ 0,00"


@app.template_filter("code_label")
def code_label_filter(value):
    if not value:
        return ""
    return " ".join(w.capitalize() for w in str(value).lower().split("_"))


@app.template_filter("step5")
def step5_filter(pct):
    # As barras dos gráficos usam classes CSS de 5 em 5% (w-0 … w-100), já que a CSP proíbe style="".
    try:
        return max(0, min(100, 5 * round(float(pct) / 5)))
    except (TypeError, ValueError):
        return 0


@app.template_filter("mask_doc")
def mask_doc_filter(value):
    if not value:
        return ""
    d = re.sub(r"\D", "", str(value))
    if len(d) == 11:
        return f"{d[:3]}.{d[3:6]}.{d[6:9]}-{d[9:]}"
    elif len(d) == 14:
        return f"{d[:2]}.{d[2:5]}.{d[5:8]}/{d[8:12]}-{d[12:]}"
    return d


@app.template_filter("mask_cnj")
def mask_cnj_filter(value):
    if not value:
        return ""
    d = re.sub(r"\D", "", str(value))[:20]
    if len(d) == 20:
        return f"{d[:7]}-{d[7:9]}.{d[9:13]}.{d[13]}.{d[14:16]}.{d[16:]}"
    return d


def business_deadline(start_date, days):
    from datetime import timedelta
    d = date.fromisoformat(start_date)
    remaining = days
    while remaining > 0:
        d += timedelta(days=1)
        if d.weekday() < 5:
            remaining -= 1
    return d.isoformat()


# --- Routes: Auth ---

@app.route("/")
def index():
    if current_user():
        return redirect(url_for("dashboard_page"))
    return redirect(url_for("login"))


MFA_LIFETIME_MS = 10 * 60 * 1000
MFA_RESEND_MS = 60 * 1000
LOCK_MS = 15 * 60 * 1000
_DUMMY_HASH = hash_password(secrets.token_hex(16))


def _now_ms():
    return int(time.time() * 1000)


def _mask_email(email):
    local, _, domain = email.partition("@")
    return local[:1] + "*" * min(6, max(2, len(local) - 1)) + "@" + domain


def _bump(db, key):
    db.execute(
        "INSERT INTO tentativas(chave,total,expira) VALUES(?,1,?) "
        "ON CONFLICT(chave) DO UPDATE SET total=total+1, expira=excluded.expira",
        (key, _now_ms() + LOCK_MS),
    )


def _blocked(db, key, limit):
    row = db.execute("SELECT total FROM tentativas WHERE chave=?", (key,)).fetchone()
    return bool(row and row["total"] >= limit)


def _mfa_token_hash(challenge):
    return hmac_index("mfa-token:" + challenge)


def _mfa_code_hash(challenge, code):
    return hmac_index(f"mfa-code:{challenge}:{code}")


def _new_code():
    return f"{secrets.randbelow(1_000_000):06d}"


def _create_session(db, user_row):
    now = _now_ms()
    email = unpack(bytes(user_row["dados"]), "usuario")["email"]
    db.execute("DELETE FROM desafios_mfa WHERE id_usuario=?", (user_row["id_usuario"],))
    for key in (hmac_index("ip:" + (request.remote_addr or "")), hmac_index("login:" + email),
                hmac_index("mfa-send:" + str(user_row["id_usuario"]))):
        db.execute("DELETE FROM tentativas WHERE chave=?", (key,))
    session_id = secrets.token_urlsafe(24)
    csrf = secrets.token_hex(32)
    db.execute(
        "INSERT INTO sessoes(id_sessao,id_usuario,refresh_hash,csrf,expira,criado) VALUES(?,?,?,?,?,?)",
        (session_id, user_row["id_usuario"], hmac_index("refresh:" + secrets.token_urlsafe(32)),
         csrf, now + SESSION_HOURS * 3600 * 1000, now),
    )
    db.execute(
        "DELETE FROM sessoes WHERE id_usuario = ? AND id_sessao NOT IN "
        "(SELECT id_sessao FROM sessoes WHERE id_usuario = ? ORDER BY criado DESC LIMIT 5)",
        (user_row["id_usuario"], user_row["id_usuario"]),
    )
    audit(user_row["id_usuario"], "LOGIN", "usuarios", user_row["id_usuario"])
    db.commit()
    session.clear()
    session.update(user_id=user_row["id_usuario"], session_id=session_id, csrf=csrf)
    session.permanent = True


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user():
        return redirect(url_for("dashboard_page"))
    if request.method == "GET":
        # Limpa a sessão anterior, mas preserva os avisos (ex.: "código expirado") para aparecerem na tela.
        flashes = session.get("_flashes")
        session.clear()
        if flashes:
            session["_flashes"] = flashes
        session["csrf"] = secrets.token_hex(32)
        return render_template("login.html")

    db = get_db()
    now = _now_ms()
    for table in ("tentativas", "sessoes", "desafios_mfa"):
        db.execute(f"DELETE FROM {table} WHERE expira < ?", (now,))
    db.commit()

    try:
        v = validate_login(request.form)
    except ValidationError as e:
        flash(str(e), "error")
        return render_template("login.html"), 400

    keys = (hmac_index("ip:" + (request.remote_addr or "")), hmac_index("login:" + v["email"]))
    if any(_blocked(db, k, 10) for k in keys):
        flash("Muitas tentativas. Aguarde 15 minutos.", "error")
        return render_template("login.html"), 429
    for k in keys:
        _bump(db, k)
    db.commit()

    user = db.execute("SELECT * FROM usuarios WHERE email_indice = ?", (hmac_index(v["email"]),)).fetchone()
    # Mesmo sem usuário, calcula um hash para não revelar pelo tempo de resposta se o e-mail existe.
    valid = verify_password(v["senha"], user["senha_hash"] if user else _DUMMY_HASH)
    if not user or not valid or not user["ativo"]:
        flash("E-mail ou senha inválidos.", "error")
        return render_template("login.html"), 401

    send_key = hmac_index("mfa-send:" + str(user["id_usuario"]))
    if _blocked(db, send_key, 5):
        flash("Muitos códigos solicitados. Aguarde 15 minutos.", "error")
        return render_template("login.html"), 429
    challenge = secrets.token_urlsafe(32)
    code = _new_code()
    email = unpack(bytes(user["dados"]), "usuario")["email"]
    db.execute("DELETE FROM desafios_mfa WHERE id_usuario=?", (user["id_usuario"],))
    db.execute(
        "INSERT INTO desafios_mfa(token_hash,id_usuario,codigo_hash,ip_indice,senha_indice,proximo_envio,expira,criado) "
        "VALUES(?,?,?,?,?,?,?,?)",
        (_mfa_token_hash(challenge), user["id_usuario"], _mfa_code_hash(challenge, code),
         hmac_index("mfa-ip:" + (request.remote_addr or "")), hmac_index("mfa-password:" + user["senha_hash"]),
         now + MFA_RESEND_MS, now + MFA_LIFETIME_MS, now),
    )
    _bump(db, send_key)
    db.commit()
    try:
        mailer.send_mfa_code(email, code)
    except Exception:
        db.execute("DELETE FROM desafios_mfa WHERE token_hash=?", (_mfa_token_hash(challenge),))
        db.commit()
        flash("Não foi possível enviar o código de acesso. Tente novamente.", "error")
        return render_template("login.html"), 503
    session["mfa"] = challenge
    session["mfa_destino"] = _mask_email(email)
    return redirect(url_for("login_mfa"))


def _usable_challenge(db, challenge):
    if not challenge:
        return None
    row = db.execute(
        "SELECT d.*, u.dados, u.senha_hash, u.ativo, u.id_usuario FROM desafios_mfa d "
        "JOIN usuarios u ON u.id_usuario=d.id_usuario WHERE d.token_hash=?",
        (_mfa_token_hash(challenge),),
    ).fetchone()
    usable = (
        row and row["ativo"] and row["expira"] > _now_ms() and row["tentativas"] < 5
        and row["ip_indice"] == hmac_index("mfa-ip:" + (request.remote_addr or ""))
        and row["senha_indice"] == hmac_index("mfa-password:" + row["senha_hash"])
    )
    if row and not usable:
        db.execute("DELETE FROM desafios_mfa WHERE token_hash=?", (row["token_hash"],))
        db.commit()
    return row if usable else None


def _restart_login(message):
    session.pop("mfa", None)
    session.pop("mfa_destino", None)
    flash(message, "error")
    return redirect(url_for("login"))


@app.route("/login/codigo", methods=["GET", "POST"])
def login_mfa():
    challenge = session.get("mfa")
    if not challenge:
        return redirect(url_for("login"))
    if request.method == "GET":
        return render_template("login_mfa.html", destino=session.get("mfa_destino", ""))
    db = get_db()
    row = _usable_challenge(db, challenge)
    if not row:
        return _restart_login("Código expirado. Entre novamente.")
    code = request.form.get("codigo", "").strip()
    if not re.fullmatch(r"\d{6}", code) or not hmac.compare_digest(row["codigo_hash"], _mfa_code_hash(challenge, code)):
        attempts = row["tentativas"] + 1
        if attempts >= 5:
            db.execute("DELETE FROM desafios_mfa WHERE token_hash=?", (row["token_hash"],))
            db.commit()
            return _restart_login("Limite de tentativas atingido. Entre novamente.")
        db.execute("UPDATE desafios_mfa SET tentativas=? WHERE token_hash=?", (attempts, row["token_hash"]))
        db.commit()
        flash(f"Código inválido. Restam {5 - attempts} tentativa{'s' if 5 - attempts > 1 else ''}.", "error")
        return render_template("login_mfa.html", destino=session.get("mfa_destino", "")), 401
    user_row = db.execute("SELECT * FROM usuarios WHERE id_usuario=?", (row["id_usuario"],)).fetchone()
    _create_session(db, user_row)
    return redirect(url_for("dashboard_page"))


@app.route("/login/codigo/reenviar", methods=["POST"])
def login_mfa_resend():
    challenge = session.get("mfa")
    db = get_db()
    row = _usable_challenge(db, challenge)
    if not row:
        return _restart_login("Código expirado. Entre novamente.")
    now = _now_ms()
    if row["proximo_envio"] > now:
        flash(f"Aguarde {-(-(row['proximo_envio'] - now) // 1000)} segundos antes de pedir outro código.", "error")
        return redirect(url_for("login_mfa"))
    send_key = hmac_index("mfa-send:" + str(row["id_usuario"]))
    if _blocked(db, send_key, 5):
        return _restart_login("Muitos códigos solicitados. Aguarde 15 minutos.")
    code = _new_code()
    db.execute(
        "UPDATE desafios_mfa SET codigo_hash=?, proximo_envio=?, expira=? WHERE token_hash=?",
        (_mfa_code_hash(challenge, code), now + MFA_RESEND_MS, now + MFA_LIFETIME_MS, row["token_hash"]),
    )
    _bump(db, send_key)
    db.commit()
    try:
        mailer.send_mfa_code(unpack(bytes(row["dados"]), "usuario")["email"], code)
    except Exception:
        db.execute("DELETE FROM desafios_mfa WHERE token_hash=?", (row["token_hash"],))
        db.commit()
        return _restart_login("Não foi possível reenviar o código. Entre novamente.")
    flash("Enviamos um novo código.", "success")
    return redirect(url_for("login_mfa"))


@app.route("/health")
def health():
    get_db().execute("SELECT 1").fetchone()
    return {"status": "ok"}


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    db = get_db()
    db.execute("DELETE FROM sessoes WHERE id_sessao = ?", (session.get("session_id"),))
    audit(g.user["id_usuario"], "LOGOUT", "usuarios", g.user["id_usuario"])
    db.commit()
    session.clear()
    flash("Sessão encerrada.", "info")
    return redirect(url_for("login"))


# --- Routes: Dashboard ---

@app.route("/dashboard")
@login_required
def dashboard_page():
    db = get_db()
    stats = {
        "clientes": db.execute("SELECT count(*) n FROM clientes").fetchone()["n"],
        "ativos": db.execute("SELECT count(*) n FROM clientes WHERE ativo=1").fetchone()["n"],
        "documentos": db.execute("SELECT count(*) n FROM documentos").fetchone()["n"],
        "processos": db.execute("SELECT count(*) n FROM processos").fetchone()["n"],
        "processos_ativos": db.execute("SELECT count(*) n FROM processos WHERE situacao='ATIVO'").fetchone()["n"],
        "sem_atualizacao": db.execute(
            "SELECT count(*) n FROM processos WHERE situacao='ATIVO' AND data_atualizacao < datetime('now','-30 days')"
        ).fetchone()["n"],
        "novos_30_dias": db.execute(
            "SELECT count(*) n FROM processos WHERE data_cadastro >= datetime('now','-30 days')"
        ).fetchone()["n"],
    }
    if g.user["perfil"] == "ADMINISTRADOR":
        stats["estimado"] = db.execute(
            "SELECT coalesce(sum(valor_estimado_centavos),0) t FROM processos"
        ).fetchone()["t"]
        stats["recebido"] = db.execute(
            "SELECT coalesce(sum(valor_centavos),0) t FROM recebimentos"
        ).fetchone()["t"]
    por_status = db.execute("SELECT status, count(*) total FROM processos GROUP BY status").fetchall()
    por_ramo = db.execute(
        "SELECT ramo, count(*) total FROM processos GROUP BY ramo ORDER BY total DESC LIMIT 6"
    ).fetchall()
    aberturas_mensais = db.execute(
        "SELECT substr(data_abertura,1,7) mes, count(*) total FROM processos "
        "WHERE data_abertura >= date('now','start of month','-5 months') GROUP BY mes ORDER BY mes"
    ).fetchall()

    today = date.today().isoformat()
    today_ms = int(datetime.fromisoformat(today + "T12:00:00+00:00").timestamp() * 1000)
    prazos = []
    recentes = []
    rows = db.execute(
        "SELECT p.id_processo, p.dados, p.status, p.data_atualizacao, c.dados as cliente_dados "
        "FROM processos p JOIN clientes c ON c.id_cliente=p.id_cliente "
        "WHERE p.situacao='ATIVO' ORDER BY p.data_atualizacao DESC"
    ).fetchall()
    for row in rows:
        pdata = unpack(bytes(row["dados"]), "processo")
        cliente = unpack(bytes(row["cliente_dados"]), "cliente")["nome"]
        if len(recentes) < 6:
            recentes.append({
                "id_processo": row["id_processo"], "titulo": pdata["titulo"],
                "cliente": cliente, "status": row["status"],
                "data_atualizacao": row["data_atualizacao"],
            })
        notice = pdata.get("intimacao", {})
        if notice.get("data") and notice.get("prazo_dias", 0) > 0:
            final = business_deadline(notice["data"], notice["prazo_dias"])
            final_ms = int(datetime.fromisoformat(final + "T12:00:00+00:00").timestamp() * 1000)
            dias = round((final_ms - today_ms) / 86400000)
            prazos.append({
                "id_processo": row["id_processo"], "titulo": pdata["titulo"],
                "cliente": cliente, "orgao": pdata.get("orgao", ""),
                "prazo_final": final, "dias_restantes": dias,
            })
    prazos.sort(key=lambda x: x["prazo_final"])
    prazos = prazos[:8]

    hour = datetime.now().hour
    saudacao = "Bom dia" if hour < 12 else "Boa tarde" if hour < 18 else "Boa noite"

    nomes = ["jan", "fev", "mar", "abr", "mai", "jun", "jul", "ago", "set", "out", "nov", "dez"]
    por_mes = {r["mes"]: r["total"] for r in aberturas_mensais}
    meses = []
    ano, mes = date.today().year, date.today().month
    for i in range(5, -1, -1):
        m, a = mes - i, ano
        while m < 1:
            m, a = m + 12, a - 1
        meses.append({"label": nomes[m - 1], "total": por_mes.get(f"{a}-{m:02d}", 0)})
    mes_max = max([1] + [m["total"] for m in meses])
    for m in meses:
        m["pct"] = max(3, round(m["total"] / mes_max * 100)) if m["total"] else 0
    ramo_max = max([1] + [r["total"] for r in por_ramo])
    ramos = [{"ramo": r["ramo"], "total": r["total"], "pct": max(4, round(r["total"] / ramo_max * 100))} for r in por_ramo]

    return render_template("dashboard.html",
        stats=stats, por_status=por_status, ramos=ramos,
        prazos=prazos, recentes=recentes, saudacao=saudacao, meses=meses,
    )


# --- Routes: Clients ---

@app.route("/clients")
@login_required
def clients_page():
    db = get_db()
    q = request.args.get("q", "").strip().lower()[:180]
    situacao = request.args.get("situacao", "")
    page = int_arg("page", 1, 1, 100000)
    sql = "SELECT * FROM clientes"
    if situacao in ("ativo", "inativo"):
        sql += " WHERE ativo=" + ("1" if situacao == "ativo" else "0")
    rows = db.execute(sql + " ORDER BY id_cliente DESC").fetchall()
    n_proc = dict(db.execute("SELECT id_cliente, count(*) FROM processos GROUP BY id_cliente").fetchall())
    q_digits = re.sub(r"\D", "", q)
    items = []
    for row in rows:
        c = unpack(bytes(row["dados"]), "cliente")
        c["id_cliente"] = row["id_cliente"]
        c["ativo"] = bool(row["ativo"])
        c["versao"] = row["versao"]
        c["data_atualizacao"] = row["data_atualizacao"]
        c["processos"] = n_proc.get(row["id_cliente"], 0)
        if q and q not in c["nome"].lower() and not (q_digits and q_digits in (c.get("cpf_cnpj") or "")):
            continue
        items.append(c)
    total = len(items)
    items = items[(page - 1) * 25: page * 25]
    return render_template("clients.html", items=items, total=total, page=page, q=q, situacao=situacao)


CONTACT_FIELDS = ("tipo", "valor", "principal")
ADDRESS_FIELDS = ("tipo", "cep", "logradouro", "numero", "complemento", "bairro", "cidade", "uf", "principal")
ASSOC_FIELDS = ("nome", "papel", "oab")
JURIS_FIELDS = ("tribunal", "referencia", "url", "resumo")


def form_rows(prefix, fields):
    # Lê campos repetidos como contato_tipo_0, contato_valor_0, aceitando índices com buracos.
    first = f"{prefix}_{fields[0]}_"
    indexes = sorted({int(k[len(first):]) for k in request.form if k.startswith(first) and k[len(first):].isdigit()})
    return [{f: request.form.get(f"{prefix}_{f}_{i}", "") for f in fields} for i in indexes[:50]]


def apply_row_op(lists):
    # Botões "+ Adicionar" (op=add:contato) e "Remover" (op=remove:contato:2).
    parts = request.form.get("op", "").split(":")
    if len(parts) < 2 or parts[1] not in lists:
        return
    rows = lists[parts[1]]
    if parts[0] == "add" and len(rows) < 50:
        rows.append({})
    elif parts[0] == "remove" and len(parts) == 3 and parts[2].isdigit() and int(parts[2]) < len(rows):
        rows.pop(int(parts[2]))


def confirm_first(message, back_url):
    # Exclusões passam por uma página "Tem certeza?" antes de executar.
    if request.form.get("confirmado") == "1":
        return None
    return render_template("confirm.html", message=message, back_url=back_url)


def _load_client(db, client_id):
    row = db.execute("SELECT * FROM clientes WHERE id_cliente=?", (client_id,)).fetchone()
    if not row:
        return None
    client = unpack(bytes(row["dados"]), "cliente")
    client.update(id_cliente=row["id_cliente"], ativo=bool(row["ativo"]), versao=row["versao"])
    return client


def _render_client(client, form, contatos, enderecos, status=200):
    db = get_db()
    docs, procs = [], []
    if client:
        for d in db.execute(
            "SELECT id_documento,dados,tamanho_bytes,data_envio FROM documentos WHERE id_cliente=? ORDER BY id_documento DESC",
            (client["id_cliente"],),
        ).fetchall():
            dd = unpack(bytes(d["dados"]), "documento")
            dd.update(id_documento=d["id_documento"], tamanho_bytes=d["tamanho_bytes"], data_envio=d["data_envio"])
            docs.append(dd)
        for p in db.execute(
            "SELECT id_processo,dados,status,situacao FROM processos WHERE id_cliente=? ORDER BY id_processo DESC",
            (client["id_cliente"],),
        ).fetchall():
            pd = unpack(bytes(p["dados"]), "processo")
            pd.update(id_processo=p["id_processo"], status=p["status"], situacao=p["situacao"])
            procs.append(pd)
    return render_template("client_form.html", client=client, form=form, contatos=contatos,
                           enderecos=enderecos, documentos=docs, processos=procs), status


@app.route("/clients/new", methods=["GET", "POST"])
@login_required
def client_new():
    if request.method == "POST":
        return _save_client(None)
    return _render_client(None, {"tipo_pessoa": "PF", "ativo": True}, [], [])


@app.route("/clients/<int:client_id>", methods=["GET", "POST"])
@login_required
def client_edit(client_id):
    if request.method == "POST":
        return _save_client(client_id)
    db = get_db()
    client = _load_client(db, client_id)
    if not client:
        flash("Cliente não encontrado.", "error")
        return redirect(url_for("clients_page"))
    contatos = []
    for c in db.execute("SELECT * FROM contatos WHERE id_cliente=?", (client_id,)).fetchall():
        cd = unpack(bytes(c["dados"]), "contato")
        cd.update(tipo=c["tipo"], principal=bool(c["principal"]))
        contatos.append(cd)
    enderecos = []
    for e in db.execute("SELECT * FROM enderecos WHERE id_cliente=?", (client_id,)).fetchall():
        ed = unpack(bytes(e["dados"]), "endereco")
        ed["principal"] = bool(e["principal"])
        enderecos.append(ed)
    audit(g.user["id_usuario"], "LEITURA", "clientes", client_id)
    db.commit()
    return _render_client(client, client, contatos, enderecos)


def _save_client(client_id):
    db = get_db()
    client = None
    if client_id:
        client = _load_client(db, client_id)
        if not client:
            flash("Cliente não encontrado.", "error")
            return redirect(url_for("clients_page"))
    form = request.form.to_dict()
    form["ativo"] = form.get("ativo") == "on"
    contatos = form_rows("contato", CONTACT_FIELDS)
    enderecos = form_rows("endereco", ADDRESS_FIELDS)
    if request.form.get("op"):
        apply_row_op({"contato": contatos, "endereco": enderecos})
        return _render_client(client, form, contatos, enderecos)
    try:
        v = validate_client(request.form)
        contatos_ok = [validate_contact(c) for c in contatos]
        enderecos_ok = [validate_address(a) for a in enderecos]
    except ValidationError as e:
        flash(str(e), "error")
        return _render_client(client, form, contatos, enderecos, 400)

    data = {k: v[k] for k in ("tipo_pessoa", "nome", "cpf_cnpj", "data_nascimento", "observacoes")}
    doc_index = hmac_index(v["cpf_cnpj"]) if v["cpf_cnpj"] else None
    try:
        if client:
            if str(client["versao"]) != request.form.get("versao"):
                flash("Cadastro alterado por outra pessoa enquanto você editava. Confira e salve de novo.", "error")
                return redirect(url_for("client_edit", client_id=client_id))
            db.execute(
                "UPDATE clientes SET dados=?,documento_indice=?,ativo=?,versao=versao+1,data_atualizacao=CURRENT_TIMESTAMP WHERE id_cliente=?",
                (pack(data, "cliente"), doc_index, int(v["ativo"]), client_id),
            )
            db.execute("DELETE FROM contatos WHERE id_cliente=?", (client_id,))
            db.execute("DELETE FROM enderecos WHERE id_cliente=?", (client_id,))
        else:
            cur = db.execute(
                "INSERT INTO clientes(dados,documento_indice,ativo) VALUES(?,?,?)",
                (pack(data, "cliente"), doc_index, int(v["ativo"])),
            )
            client_id = cur.lastrowid
        for c in contatos_ok:
            db.execute(
                "INSERT INTO contatos(id_cliente,tipo,dados,valor_indice,principal) VALUES(?,?,?,?,?)",
                (client_id, c["tipo"], pack({"valor": c["valor"]}, "contato"), hmac_index(c["valor"]), int(c["principal"])),
            )
        for a in enderecos_ok:
            principal = a.pop("principal")
            db.execute(
                "INSERT INTO enderecos(id_cliente,dados,principal) VALUES(?,?,?)",
                (client_id, pack(a, "endereco"), int(principal)),
            )
        audit(g.user["id_usuario"], "ALTERACAO" if client else "CADASTRO", "clientes", client_id)
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        flash("CPF/CNPJ ou contato já cadastrado em outro cliente.", "error")
        return _render_client(client, form, contatos, enderecos, 400)

    flash("Cadastro salvo.", "success")
    return redirect(url_for("client_edit", client_id=client_id))


@app.route("/clients/<int:client_id>/delete", methods=["POST"])
@admin_required
def client_delete(client_id):
    db = get_db()
    row = db.execute("SELECT versao FROM clientes WHERE id_cliente=?", (client_id,)).fetchone()
    if not row:
        flash("Cliente não encontrado.", "error")
        return redirect(url_for("clients_page"))
    if db.execute("SELECT count(*) n FROM documentos WHERE id_cliente=?", (client_id,)).fetchone()["n"]:
        flash("Remova os documentos antes de excluir.", "error")
        return redirect(url_for("client_edit", client_id=client_id))
    if db.execute("SELECT count(*) n FROM processos WHERE id_cliente=?", (client_id,)).fetchone()["n"]:
        flash("O cliente possui processos vinculados.", "error")
        return redirect(url_for("client_edit", client_id=client_id))
    nome = _load_client(db, client_id)["nome"]
    page = confirm_first(f"Excluir permanentemente o cadastro de {nome}?", url_for("client_edit", client_id=client_id))
    if page:
        return page
    db.execute("DELETE FROM contatos WHERE id_cliente=?", (client_id,))
    db.execute("DELETE FROM enderecos WHERE id_cliente=?", (client_id,))
    db.execute("DELETE FROM clientes WHERE id_cliente=?", (client_id,))
    audit(g.user["id_usuario"], "EXCLUSAO", "clientes", client_id)
    db.commit()
    flash("Cadastro excluído.", "success")
    return redirect(url_for("clients_page"))


# --- Routes: Documents ---

@app.route("/clients/<int:client_id>/documents", methods=["POST"])
@login_required
def document_upload(client_id):
    db = get_db()
    if not db.execute("SELECT 1 FROM clientes WHERE id_cliente=?", (client_id,)).fetchone():
        flash("Cliente não encontrado.", "error")
        return redirect(url_for("clients_page"))
    titulo = request.form.get("titulo", "").strip()
    tipo_doc = request.form.get("tipo_documento", "OUTRO")
    if not titulo:
        flash("Informe o título.", "error")
        return redirect(url_for("client_edit", client_id=client_id))
    f = request.files.get("arquivo")
    if not f or not f.filename:
        flash("Selecione um arquivo.", "error")
        return redirect(url_for("client_edit", client_id=client_id))
    content = f.read()
    if len(content) > MAX_FILE_SIZE:
        flash("Arquivo excede 10 MB.", "error")
        return redirect(url_for("client_edit", client_id=client_id))
    mime = _detect_mime(content, f.filename)
    if mime not in ("application/pdf", "image/jpeg", "image/png"):
        flash("Envie um PDF, JPEG ou PNG.", "error")
        return redirect(url_for("client_edit", client_id=client_id))
    ext = {"application/pdf": "pdf", "image/jpeg": "jpg", "image/png": "png"}[mime]
    original = _safe_filename(f.filename, ext)
    metadata = {"titulo": titulo, "tipo_documento": tipo_doc, "nome_original": original, "tipo_mime": mime, "ext": ext}
    encrypted = crypto_utils.encrypt(content, f"arquivo:{client_id}")
    cur = db.execute(
        "INSERT INTO documentos(id_cliente,id_usuario_envio,dados,conteudo,tamanho_bytes) VALUES(?,?,?,?,?)",
        (client_id, g.user["id_usuario"], pack(metadata, "documento"), encrypted, len(content)),
    )
    audit(g.user["id_usuario"], "CADASTRO", "documentos", cur.lastrowid)
    db.commit()
    flash("Documento armazenado.", "success")
    return redirect(url_for("client_edit", client_id=client_id))


@app.route("/documents/<int:doc_id>/download")
@login_required
def document_download(doc_id):
    db = get_db()
    row = db.execute("SELECT * FROM documentos WHERE id_documento=?", (doc_id,)).fetchone()
    if not row:
        abort(404)
    meta = unpack(bytes(row["dados"]), "documento")
    content = crypto_utils.decrypt(bytes(row["conteudo"]), f"arquivo:{row['id_cliente']}")
    audit(g.user["id_usuario"], "LEITURA", "documentos", doc_id)
    db.commit()
    return send_file(io.BytesIO(content), mimetype=meta["tipo_mime"],
                     as_attachment=True, download_name=f"documento-{doc_id}.{meta['ext']}")


@app.route("/documents/<int:doc_id>/delete", methods=["POST"])
@admin_required
def document_delete(doc_id):
    db = get_db()
    row = db.execute("SELECT id_cliente, dados FROM documentos WHERE id_documento=?", (doc_id,)).fetchone()
    if not row:
        flash("Documento não encontrado.", "error")
        return redirect(url_for("clients_page"))
    client_id = row["id_cliente"]
    titulo = unpack(bytes(row["dados"]), "documento")["titulo"]
    page = confirm_first(f"Excluir permanentemente o documento “{titulo}”?", url_for("client_edit", client_id=client_id))
    if page:
        return page
    db.execute("DELETE FROM documentos WHERE id_documento=?", (doc_id,))
    audit(g.user["id_usuario"], "EXCLUSAO", "documentos", doc_id)
    db.commit()
    flash("Documento excluído.", "success")
    return redirect(url_for("client_edit", client_id=client_id))


# --- Routes: Processes ---

@app.route("/processes")
@login_required
def processes_page():
    db = get_db()
    page = int_arg("page", 1, 1, 100000)
    q = request.args.get("q", "").strip().lower()[:180]
    where = []
    params = []
    for name, col in [("status", "p.status"), ("ramo", "p.ramo"), ("tipificacao", "p.tipificacao"), ("situacao", "p.situacao")]:
        val = request.args.get(name, "")
        if val:
            where.append(f"{col}=?")
            params.append(val)
    if int_arg("id_cliente"):
        where.append("p.id_cliente=?")
        params.append(int_arg("id_cliente"))
    for name, col, op in [
        ("abertura_de", "p.data_abertura", ">="), ("abertura_ate", "p.data_abertura", "<="),
        ("atualizacao_de", "date(p.data_atualizacao)", ">="), ("atualizacao_ate", "date(p.data_atualizacao)", "<="),
    ]:
        val = request.args.get(name, "")
        if val and re.match(r"^\d{4}-\d{2}-\d{2}$", val):
            where.append(f"{col}{op}?")
            params.append(val)
    is_admin = g.user["perfil"] == "ADMINISTRADOR"
    recebido_sql = "(SELECT coalesce(sum(r.valor_centavos),0) FROM recebimentos r WHERE r.id_processo=p.id_processo)"
    for name, col, op in [
        ("valor_min", "p.valor_estimado_centavos", ">="), ("valor_max", "p.valor_estimado_centavos", "<="),
        ("recebido_min", recebido_sql, ">="), ("recebido_max", recebido_sql, "<="),
    ]:
        val = cents_arg(name)
        if val is not None and is_admin:
            where.append(f"{col}{op}?")
            params.append(val)
    com_anexos = request.args.get("com_anexos", "")
    if com_anexos == "1":
        where.append("EXISTS (SELECT 1 FROM arquivos_processos a WHERE a.id_processo=p.id_processo)")
    elif com_anexos == "0":
        where.append("NOT EXISTS (SELECT 1 FROM arquivos_processos a WHERE a.id_processo=p.id_processo)")
    elif com_anexos in ("FOTO", "DOCUMENTO"):
        where.append("EXISTS (SELECT 1 FROM arquivos_processos a WHERE a.id_processo=p.id_processo AND a.categoria=?)")
        params.append(com_anexos)
    sql = "SELECT p.*, c.dados as cliente_dados FROM processos p JOIN clientes c ON c.id_cliente=p.id_cliente"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY p.id_processo DESC"
    rows = db.execute(sql, params).fetchall()
    items = []
    for row in rows:
        pdata = unpack(bytes(row["dados"]), "processo")
        cliente = unpack(bytes(row["cliente_dados"]), "cliente")["nome"]
        item = {
            "id_processo": row["id_processo"], "titulo": pdata["titulo"],
            "numero_cnj": pdata["numero_cnj"], "cliente": cliente,
            "status": row["status"], "ramo": row["ramo"], "situacao": row["situacao"],
            "tipificacao": row["tipificacao"], "orgao": pdata.get("orgao", ""),
            "data_atualizacao": row["data_atualizacao"],
            "valor_estimado_centavos": row["valor_estimado_centavos"],
            "ultima_movimentacao": pdata.get("ultima_movimentacao", ""),
        }
        if q:
            digits = re.sub(r"\D", "", q)
            if not (str(item["id_processo"]) == q or q in item["titulo"].lower()
                    or q in item["cliente"].lower() or (digits and digits in item["numero_cnj"])):
                continue
        items.append(item)
    total = len(items)
    items = items[(page - 1) * 25: page * 25]
    client_options = _client_options(db)
    all_tipificacoes = sorted(set(t for types in PROCESS_TYPES.values() for t in types))
    active_filters = sum(1 for k, v in request.args.items() if v and k not in ("q", "page"))
    return render_template("processes.html", items=items, total=total, page=page, q=q,
                           PROCESS_STATUS=PROCESS_STATUS, PROCESS_TYPES=PROCESS_TYPES,
                           all_tipificacoes=all_tipificacoes, active_filters=active_filters,
                           client_options=client_options, filters=request.args)


def _client_options(db):
    rows = db.execute("SELECT id_cliente, dados FROM clientes WHERE ativo=1 ORDER BY id_cliente").fetchall()
    opts = []
    for r in rows:
        d = unpack(bytes(r["dados"]), "cliente")
        opts.append({"id_cliente": r["id_cliente"], "nome": d["nome"]})
    opts.sort(key=lambda x: x["nome"])
    return opts


def deadline_info(start, prazo):
    try:
        prazo = int(prazo or 0)
        date.fromisoformat(start)
    except (TypeError, ValueError):
        return None
    if prazo <= 0:
        return None
    final = business_deadline(start, prazo)
    return {"final": final, "dias": (date.fromisoformat(final) - date.today()).days}


def _load_process(db, process_id):
    row = db.execute(
        "SELECT p.*, c.dados as cliente_dados FROM processos p "
        "JOIN clientes c ON c.id_cliente=p.id_cliente WHERE p.id_processo=?",
        (process_id,),
    ).fetchone()
    if not row:
        return None
    return {
        **unpack(bytes(row["dados"]), "processo"),
        "id_processo": row["id_processo"], "id_cliente": row["id_cliente"],
        "status": row["status"], "ramo": row["ramo"], "tipificacao": row["tipificacao"],
        "situacao": row["situacao"], "data_abertura": row["data_abertura"],
        "valor_estimado_centavos": row["valor_estimado_centavos"], "versao": row["versao"],
        "data_cadastro": row["data_cadastro"], "data_atualizacao": row["data_atualizacao"],
        "cliente": unpack(bytes(row["cliente_dados"]), "cliente")["nome"],
    }


def _process_form_from_record(p):
    n = p.get("intimacao") or {}
    return {
        **p, "id_cliente": str(p["id_cliente"]),
        "intimacao_data": n.get("data", ""), "intimacao_prazo": n.get("prazo_dias") or "",
        "intimacao_descricao": n.get("descricao", ""),
        "valor_estimado": f"{p['valor_estimado_centavos'] / 100:.2f}",
    }


def _render_process(process, form, associados, jurisprudencia, status=200):
    db = get_db()
    historico, arquivos, recebimentos = [], [], []
    if process:
        pid = process["id_processo"]
        if g.user["perfil"] == "ADMINISTRADOR":
            recebido = db.execute(
                "SELECT coalesce(sum(valor_centavos),0) t FROM recebimentos WHERE id_processo=?", (pid,)
            ).fetchone()["t"]
            est = process["valor_estimado_centavos"]
            process.update(
                valor_recebido_centavos=recebido, saldo_centavos=est - recebido,
                pct_recebido=min(100, round(recebido / est * 100)) if est else 0,
                status_pagamento="SEM_VALOR" if est == 0 else "PENDENTE" if recebido == 0
                else "PARCIAL" if recebido < est else "QUITADO",
            )
            for r in db.execute(
                "SELECT * FROM recebimentos WHERE id_processo=? ORDER BY data_recebimento DESC", (pid,)
            ).fetchall():
                rd = unpack(bytes(r["dados"]), f"recebimento:{pid}")
                rd.update(id_recebimento=r["id_recebimento"], valor_centavos=r["valor_centavos"],
                          data_recebimento=r["data_recebimento"])
                recebimentos.append(rd)
        for h in db.execute(
            "SELECT h.*, u.dados as usuario_dados FROM historico_processos h "
            "JOIN usuarios u ON u.id_usuario=h.id_usuario WHERE h.id_processo=? ORDER BY h.id_historico DESC LIMIT 100",
            (pid,),
        ).fetchall():
            hd = unpack(bytes(h["dados"]), f"historico:{pid}")
            hd.update(usuario=unpack(bytes(h["usuario_dados"]), "usuario")["nome"], data_hora=h["data_hora"])
            historico.append(hd)
        for a in db.execute(
            "SELECT id_arquivo,categoria,dados,tamanho_bytes,data_envio FROM arquivos_processos WHERE id_processo=? ORDER BY id_arquivo DESC",
            (pid,),
        ).fetchall():
            ad = unpack(bytes(a["dados"]), "processo-arquivo")
            ad.update(id_arquivo=a["id_arquivo"], categoria=a["categoria"],
                      tamanho_bytes=a["tamanho_bytes"], data_envio=a["data_envio"])
            arquivos.append(ad)
    return render_template(
        "process_form.html", process=process, form=form,
        associados=associados, jurisprudencia=jurisprudencia,
        client_options=_client_options(db), PROCESS_STATUS=PROCESS_STATUS, PROCESS_TYPES=PROCESS_TYPES,
        deadline=deadline_info(form.get("intimacao_data"), form.get("intimacao_prazo")),
        historico=historico, arquivos=arquivos, recebimentos=recebimentos,
    ), status


@app.route("/processes/new", methods=["GET", "POST"])
@login_required
def process_new():
    if request.method == "POST":
        return _save_process(None)
    form = {"id_cliente": request.args.get("client_id", ""), "ramo": "CIVEL", "status": "EM_ANALISE",
            "data_abertura": date.today().isoformat(), "valor_estimado": "0.00"}
    return _render_process(None, form, [], [])


@app.route("/processes/<int:process_id>", methods=["GET", "POST"])
@login_required
def process_edit(process_id):
    if request.method == "POST":
        return _save_process(process_id)
    db = get_db()
    process = _load_process(db, process_id)
    if not process:
        flash("Processo não encontrado.", "error")
        return redirect(url_for("processes_page"))
    audit(g.user["id_usuario"], "LEITURA", "processos", process_id)
    db.commit()
    return _render_process(process, _process_form_from_record(process),
                           process.get("associados") or [], process.get("jurisprudencia") or [])


def _save_process(process_id):
    db = get_db()
    process = None
    if process_id:
        process = _load_process(db, process_id)
        if not process:
            flash("Processo não encontrado.", "error")
            return redirect(url_for("processes_page"))
    form = request.form.to_dict()
    form["ramo"], _, form["tipificacao"] = form.get("classificacao", "").partition(":")
    # A situação acompanha o status: Encerrado/Arquivado fecham o processo, o resto o mantém ativo.
    form["situacao"] = form.get("status") if form.get("status") in ("ENCERRADO", "ARQUIVADO") else "ATIVO"
    associados = form_rows("assoc", ASSOC_FIELDS)
    jurisprudencia = form_rows("juris", JURIS_FIELDS)
    if request.form.get("op"):
        apply_row_op({"assoc": associados, "juris": jurisprudencia})
        return _render_process(process, form, associados, jurisprudencia)
    is_admin = g.user["perfil"] == "ADMINISTRADOR"
    try:
        v = validate_process(form, is_admin=is_admin, old=process)
        associados_ok = [validate_associate(a) for a in associados]
        jurisprudencia_ok = [validate_precedent(j) for j in jurisprudencia]
        client_row = db.execute("SELECT ativo FROM clientes WHERE id_cliente=?", (v["id_cliente"],)).fetchone()
        if not client_row or not client_row["ativo"]:
            raise ValidationError("O cliente selecionado está inativo. Ative o cadastro dele primeiro.")
    except ValidationError as e:
        flash(str(e), "error")
        return _render_process(process, form, associados, jurisprudencia, 400)

    encrypted_data = {
        "numero_cnj": v["numero_cnj"], "titulo": v["titulo"],
        "observacoes": v["observacoes"], "previsao_recebimento": v["previsao_recebimento"],
        "orgao": v["orgao"], "numero_oab": v["numero_oab"],
        "data_publicacao": v["data_publicacao"], "data_disponibilizacao": v["data_disponibilizacao"],
        "ultima_movimentacao": v["ultima_movimentacao"], "intimacao": v["intimacao"],
        "associados": associados_ok, "jurisprudencia": jurisprudencia_ok,
    }
    try:
        if process:
            if str(process["versao"]) != request.form.get("versao"):
                flash("Processo alterado por outra pessoa enquanto você editava. Confira e salve de novo.", "error")
                return redirect(url_for("process_edit", process_id=process_id))
            db.execute(
                "UPDATE processos SET id_cliente=?,numero_indice=?,dados=?,status=?,ramo=?,tipificacao=?,"
                "situacao=?,data_abertura=?,valor_estimado_centavos=?,versao=versao+1,"
                "data_atualizacao=CURRENT_TIMESTAMP WHERE id_processo=?",
                (v["id_cliente"], hmac_index(v["numero_cnj"]), pack(encrypted_data, "processo"),
                 v["status"], v["ramo"], v["tipificacao"], v["situacao"], v["data_abertura"],
                 v["valor_estimado_centavos"], process_id),
            )
            db.execute(
                "INSERT INTO historico_processos(id_processo,id_usuario,dados) VALUES(?,?,?)",
                (process_id, g.user["id_usuario"],
                 pack({"evento": "PROCESSO_ATUALIZADO", "status_anterior": process["status"], "status_atual": v["status"]},
                      f"historico:{process_id}")),
            )
            audit(g.user["id_usuario"], "ALTERACAO", "processos", process_id)
        else:
            cur = db.execute(
                "INSERT INTO processos(id_cliente,numero_indice,dados,status,ramo,tipificacao,situacao,data_abertura,valor_estimado_centavos) "
                "VALUES(?,?,?,?,?,?,?,?,?)",
                (v["id_cliente"], hmac_index(v["numero_cnj"]), pack(encrypted_data, "processo"),
                 v["status"], v["ramo"], v["tipificacao"], v["situacao"], v["data_abertura"],
                 v["valor_estimado_centavos"]),
            )
            process_id = cur.lastrowid
            db.execute(
                "INSERT INTO historico_processos(id_processo,id_usuario,dados) VALUES(?,?,?)",
                (process_id, g.user["id_usuario"],
                 pack({"evento": "PROCESSO_CADASTRADO", "status_atual": v["status"]}, f"historico:{process_id}")),
            )
            audit(g.user["id_usuario"], "CADASTRO", "processos", process_id)
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        flash("Já existe um processo com esse número CNJ.", "error")
        return _render_process(process, form, associados, jurisprudencia, 400)

    flash("Processo salvo.", "success")
    return redirect(url_for("process_edit", process_id=process_id))


@app.route("/processes/<int:process_id>/delete", methods=["POST"])
@admin_required
def process_delete(process_id):
    db = get_db()
    row = db.execute("SELECT versao FROM processos WHERE id_processo=?", (process_id,)).fetchone()
    if not row:
        flash("Processo não encontrado.", "error")
        return redirect(url_for("processes_page"))
    has_deps = db.execute(
        "SELECT (SELECT count(*) FROM recebimentos WHERE id_processo=?) r, "
        "(SELECT count(*) FROM arquivos_processos WHERE id_processo=?) a",
        (process_id, process_id)
    ).fetchone()
    if has_deps["r"] or has_deps["a"]:
        flash("Remova recebimentos e anexos antes de excluir.", "error")
        return redirect(url_for("process_edit", process_id=process_id))
    titulo = _load_process(db, process_id)["titulo"]
    page = confirm_first(f"Excluir permanentemente o processo “{titulo}”?", url_for("process_edit", process_id=process_id))
    if page:
        return page
    db.execute("DELETE FROM processos WHERE id_processo=?", (process_id,))
    audit(g.user["id_usuario"], "EXCLUSAO", "processos", process_id)
    db.commit()
    flash("Processo excluído.", "success")
    return redirect(url_for("processes_page"))


# --- Routes: Process Files ---

@app.route("/processes/<int:process_id>/files", methods=["POST"])
@login_required
def process_file_upload(process_id):
    db = get_db()
    if not db.execute("SELECT 1 FROM processos WHERE id_processo=?", (process_id,)).fetchone():
        abort(404)
    titulo = request.form.get("titulo", "").strip()
    if not titulo:
        flash("Informe o título.", "error")
        return redirect(url_for("process_edit", process_id=process_id))
    f = request.files.get("arquivo")
    if not f or not f.filename:
        flash("Selecione um arquivo.", "error")
        return redirect(url_for("process_edit", process_id=process_id))
    content = f.read()
    if len(content) > MAX_FILE_SIZE:
        flash("Arquivo excede 10 MB.", "error")
        return redirect(url_for("process_edit", process_id=process_id))
    mime = _detect_mime(content, f.filename)
    if mime not in ALLOWED_MIME:
        flash("Envie um PDF, JPEG, PNG ou WebP.", "error")
        return redirect(url_for("process_edit", process_id=process_id))
    photo = mime.startswith("image/")
    ext = {"application/pdf": "pdf", "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"}[mime]
    thumbnail = None
    if photo:
        try:
            from PIL import Image, ImageOps
            Image.MAX_IMAGE_PIXELS = 40_000_000  # recusa "bombas de descompressão"
            img = Image.open(io.BytesIO(content))
            if img.width * img.height > Image.MAX_IMAGE_PIXELS:
                raise ValueError("imagem grande demais")
            img = ImageOps.exif_transpose(img)
            img.thumbnail((2400, 2400))
            buf = io.BytesIO()
            img.convert("RGB").save(buf, "JPEG", quality=86)
            content = buf.getvalue()
            img.thumbnail((480, 360))
            tbuf = io.BytesIO()
            img.convert("RGB").save(tbuf, "JPEG", quality=78)
            thumbnail = tbuf.getvalue()
            mime = "image/jpeg"
            ext = "jpg"
        except Exception:
            flash("Imagem corrompida ou não suportada.", "error")
            return redirect(url_for("process_edit", process_id=process_id))
    original = _safe_filename(f.filename, ext)
    metadata = {"titulo": titulo, "nome_original": original, "tipo_mime": mime, "ext": ext}
    cur = db.execute(
        "INSERT INTO arquivos_processos(id_processo,id_usuario_envio,categoria,dados,conteudo,miniatura,tamanho_bytes) VALUES(?,?,?,?,?,?,?)",
        (process_id, g.user["id_usuario"], "FOTO" if photo else "DOCUMENTO",
         pack(metadata, "processo-arquivo"),
         crypto_utils.encrypt(content, f"processo-arquivo:{process_id}"),
         crypto_utils.encrypt(thumbnail, f"processo-miniatura:{process_id}") if thumbnail else None,
         len(content)),
    )
    db.execute("UPDATE processos SET data_atualizacao=CURRENT_TIMESTAMP, versao=versao+1 WHERE id_processo=?", (process_id,))
    db.execute(
        "INSERT INTO historico_processos(id_processo,id_usuario,dados) VALUES(?,?,?)",
        (process_id, g.user["id_usuario"],
         pack({"evento": "ANEXO_INCLUIDO", "categoria": "FOTO" if photo else "DOCUMENTO"}, f"historico:{process_id}")),
    )
    audit(g.user["id_usuario"], "CADASTRO", "arquivos_processos", cur.lastrowid)
    db.commit()
    flash("Anexo armazenado.", "success")
    return redirect(url_for("process_edit", process_id=process_id))


@app.route("/process-files/<int:file_id>/download")
@login_required
def process_file_download(file_id):
    db = get_db()
    row = db.execute("SELECT * FROM arquivos_processos WHERE id_arquivo=?", (file_id,)).fetchone()
    if not row:
        abort(404)
    meta = unpack(bytes(row["dados"]), "processo-arquivo")
    content = crypto_utils.decrypt(bytes(row["conteudo"]), f"processo-arquivo:{row['id_processo']}")
    audit(g.user["id_usuario"], "LEITURA", "arquivos_processos", file_id)
    db.commit()
    return send_file(io.BytesIO(content), mimetype=meta["tipo_mime"],
                     as_attachment=True, download_name=f"processo-{row['id_processo']}-{file_id}.{meta['ext']}")


@app.route("/process-files/<int:file_id>/preview")
@login_required
def process_file_preview(file_id):
    db = get_db()
    row = db.execute("SELECT * FROM arquivos_processos WHERE id_arquivo=?", (file_id,)).fetchone()
    if not row or row["categoria"] != "FOTO" or not row["miniatura"]:
        abort(404)
    content = crypto_utils.decrypt(bytes(row["miniatura"]), f"processo-miniatura:{row['id_processo']}")
    return send_file(io.BytesIO(content), mimetype="image/jpeg")


@app.route("/process-files/<int:file_id>/delete", methods=["POST"])
@admin_required
def process_file_delete(file_id):
    db = get_db()
    row = db.execute("SELECT id_processo, dados FROM arquivos_processos WHERE id_arquivo=?", (file_id,)).fetchone()
    if not row:
        flash("Anexo não encontrado.", "error")
        return redirect(url_for("processes_page"))
    pid = row["id_processo"]
    titulo = unpack(bytes(row["dados"]), "processo-arquivo")["titulo"]
    page = confirm_first(f"Excluir o anexo “{titulo}”?", url_for("process_edit", process_id=pid) + "#anexos")
    if page:
        return page
    db.execute("DELETE FROM arquivos_processos WHERE id_arquivo=?", (file_id,))
    db.execute("UPDATE processos SET data_atualizacao=CURRENT_TIMESTAMP, versao=versao+1 WHERE id_processo=?", (pid,))
    db.execute(
        "INSERT INTO historico_processos(id_processo,id_usuario,dados) VALUES(?,?,?)",
        (pid, g.user["id_usuario"], pack({"evento": "ANEXO_REMOVIDO"}, f"historico:{pid}")),
    )
    audit(g.user["id_usuario"], "EXCLUSAO", "arquivos_processos", file_id)
    db.commit()
    flash("Anexo excluído.", "success")
    return redirect(url_for("process_edit", process_id=pid))


# --- Routes: Receipts ---

@app.route("/processes/<int:process_id>/receipts", methods=["POST"])
@admin_required
def receipt_new(process_id):
    db = get_db()
    if not db.execute("SELECT 1 FROM processos WHERE id_processo=?", (process_id,)).fetchone():
        abort(404)
    try:
        v = validate_receipt(request.form)
    except ValidationError as e:
        flash(str(e), "error")
        return redirect(url_for("process_edit", process_id=process_id))
    cur = db.execute(
        "INSERT INTO recebimentos(id_processo,id_usuario,dados,valor_centavos,data_recebimento) VALUES(?,?,?,?,?)",
        (process_id, g.user["id_usuario"], pack({"observacao": v["observacao"]}, f"recebimento:{process_id}"),
         v["valor_centavos"], v["data_recebimento"]),
    )
    db.execute("UPDATE processos SET data_atualizacao=CURRENT_TIMESTAMP, versao=versao+1 WHERE id_processo=?", (process_id,))
    db.execute(
        "INSERT INTO historico_processos(id_processo,id_usuario,dados) VALUES(?,?,?)",
        (process_id, g.user["id_usuario"],
         pack({"evento": "RECEBIMENTO_REGISTRADO"}, f"historico:{process_id}")),
    )
    audit(g.user["id_usuario"], "CADASTRO", "recebimentos", cur.lastrowid)
    db.commit()
    flash("Recebimento registrado.", "success")
    return redirect(url_for("process_edit", process_id=process_id))


@app.route("/receipts/<int:receipt_id>/delete", methods=["POST"])
@admin_required
def receipt_delete(receipt_id):
    db = get_db()
    row = db.execute("SELECT id_processo, valor_centavos FROM recebimentos WHERE id_recebimento=?", (receipt_id,)).fetchone()
    if not row:
        flash("Recebimento não encontrado.", "error")
        return redirect(url_for("processes_page"))
    pid = row["id_processo"]
    page = confirm_first(f"Excluir o recebimento de {money_filter(row['valor_centavos'])}?",
                         url_for("process_edit", process_id=pid) + "#financeiro")
    if page:
        return page
    db.execute("DELETE FROM recebimentos WHERE id_recebimento=?", (receipt_id,))
    db.execute("UPDATE processos SET data_atualizacao=CURRENT_TIMESTAMP, versao=versao+1 WHERE id_processo=?", (pid,))
    db.execute(
        "INSERT INTO historico_processos(id_processo,id_usuario,dados) VALUES(?,?,?)",
        (pid, g.user["id_usuario"], pack({"evento": "RECEBIMENTO_REMOVIDO"}, f"historico:{pid}")),
    )
    audit(g.user["id_usuario"], "EXCLUSAO", "recebimentos", receipt_id)
    db.commit()
    flash("Recebimento excluído.", "success")
    return redirect(url_for("process_edit", process_id=pid))


# --- Routes: Users ---

@app.route("/users")
@admin_required
def users_page():
    db = get_db()
    rows = db.execute("SELECT * FROM usuarios ORDER BY id_usuario").fetchall()
    users = [public_user(r) for r in rows]
    return render_template("users.html", users=users)


@app.route("/users/new", methods=["GET", "POST"])
@admin_required
def user_new():
    if request.method == "GET":
        return render_template("user_form.html", user=None)
    return _save_user(None)


@app.route("/users/<int:user_id>/edit", methods=["GET", "POST"])
@admin_required
def user_edit(user_id):
    if request.method == "POST":
        return _save_user(user_id)
    db = get_db()
    row = db.execute("SELECT * FROM usuarios WHERE id_usuario=?", (user_id,)).fetchone()
    if not row:
        flash("Usuário não encontrado.", "error")
        return redirect(url_for("users_page"))
    return render_template("user_form.html", user=public_user(row))


def _save_user(user_id):
    db = get_db()
    try:
        v = validate_user(request.form, is_edit=bool(user_id))
    except ValidationError as e:
        flash(str(e), "error")
        return redirect(request.url)
    if user_id == g.user["id_usuario"] and (not v["ativo"] or v["perfil"] != "ADMINISTRADOR"):
        flash("Você não pode remover seu próprio acesso de administrador.", "error")
        return redirect(request.url)
    try:
        if user_id:
            old = db.execute("SELECT * FROM usuarios WHERE id_usuario=?", (user_id,)).fetchone()
            if not old:
                flash("Usuário não encontrado.", "error")
                return redirect(url_for("users_page"))
            old_data = unpack(bytes(old["dados"]), "usuario")
            if old["ativo"] and old["perfil"] == "ADMINISTRADOR" and (not v["ativo"] or v["perfil"] != "ADMINISTRADOR"):
                count = db.execute("SELECT count(*) n FROM usuarios WHERE ativo=1 AND perfil='ADMINISTRADOR'").fetchone()["n"]
                if count <= 1:
                    flash("Mantenha ao menos um administrador ativo.", "error")
                    return redirect(request.url)
            user_data = {"nome": v["nome"], "email": v["email"]}
            if old_data.get("preferencias"):
                user_data["preferencias"] = old_data["preferencias"]
            db.execute(
                "UPDATE usuarios SET dados=?,email_indice=?,senha_hash=?,perfil=?,ativo=?,data_atualizacao=CURRENT_TIMESTAMP WHERE id_usuario=?",
                (pack(user_data, "usuario"), hmac_index(v["email"]),
                 hash_password(v["senha"]) if v["senha"] else old["senha_hash"],
                 v["perfil"], int(v["ativo"]), user_id),
            )
            db.execute("DELETE FROM sessoes WHERE id_usuario=?", (user_id,))
            db.execute("DELETE FROM desafios_mfa WHERE id_usuario=?", (user_id,))
            audit(g.user["id_usuario"], "ALTERACAO", "usuarios", user_id)
        else:
            cur = db.execute(
                "INSERT INTO usuarios(dados,email_indice,senha_hash,perfil,ativo) VALUES(?,?,?,?,?)",
                (pack({"nome": v["nome"], "email": v["email"]}, "usuario"),
                 hmac_index(v["email"]), hash_password(v["senha"]),
                 v["perfil"], int(v["ativo"])),
            )
            user_id = cur.lastrowid
            audit(g.user["id_usuario"], "CADASTRO", "usuarios", user_id)
        db.commit()
    except sqlite3.IntegrityError:
        db.rollback()
        flash("E-mail já cadastrado.", "error")
        return redirect(request.url)
    flash("Usuário salvo.", "success")
    if user_id == g.user["id_usuario"] and v.get("senha"):
        session.clear()
        return redirect(url_for("login"))
    return redirect(url_for("users_page"))


# --- Routes: Audit ---

@app.route("/audit")
@admin_required
def audit_page():
    db = get_db()
    page = int_arg("page", 1, 1, 100000)
    total = db.execute("SELECT count(*) n FROM logs_auditoria").fetchone()["n"]
    rows = db.execute(
        "SELECT l.*, u.dados FROM logs_auditoria l JOIN usuarios u ON u.id_usuario=l.id_usuario "
        "ORDER BY id_log DESC LIMIT 50 OFFSET ?",
        ((page - 1) * 50,)
    ).fetchall()
    items = []
    for r in rows:
        items.append({
            "id_log": r["id_log"], "acao": r["acao"],
            "tabela_afetada": r["tabela_afetada"], "id_registro": r["id_registro"],
            "data_hora": r["data_hora"],
            "usuario": unpack(bytes(r["dados"]), "usuario")["nome"],
        })
    return render_template("audit.html", items=items, total=total, page=page)


# --- Routes: Account ---

@app.route("/account", methods=["GET", "POST"])
@login_required
def account_page():
    if request.method == "GET":
        return render_template("account.html")
    action = request.form.get("action")
    db = get_db()
    if action == "preferences":
        prefs = validate_preferences(request.form)
        row = db.execute("SELECT dados FROM usuarios WHERE id_usuario=?", (g.user["id_usuario"],)).fetchone()
        current = unpack(bytes(row["dados"]), "usuario")
        current["preferencias"] = prefs
        db.execute(
            "UPDATE usuarios SET dados=?,data_atualizacao=CURRENT_TIMESTAMP WHERE id_usuario=?",
            (pack(current, "usuario"), g.user["id_usuario"]),
        )
        audit(g.user["id_usuario"], "ALTERACAO", "usuarios", g.user["id_usuario"])
        db.commit()
        flash("Preferências salvas.", "success")
    elif action == "password":
        atual = request.form.get("atual", "")
        nova = request.form.get("nova", "")
        confirmacao = request.form.get("confirmacao", "")
        if nova != confirmacao:
            flash("A confirmação não corresponde à nova senha.", "error")
            return redirect(url_for("account_page"))
        try:
            validate_password(nova)
        except ValidationError as e:
            flash(str(e), "error")
            return redirect(url_for("account_page"))
        row = db.execute("SELECT senha_hash FROM usuarios WHERE id_usuario=?", (g.user["id_usuario"],)).fetchone()
        if not verify_password(atual, row["senha_hash"]):
            flash("Senha atual incorreta.", "error")
            return redirect(url_for("account_page"))
        db.execute(
            "UPDATE usuarios SET senha_hash=?,data_atualizacao=CURRENT_TIMESTAMP WHERE id_usuario=?",
            (hash_password(nova), g.user["id_usuario"]),
        )
        db.execute("DELETE FROM sessoes WHERE id_usuario=?", (g.user["id_usuario"],))
        db.execute("DELETE FROM desafios_mfa WHERE id_usuario=?", (g.user["id_usuario"],))
        audit(g.user["id_usuario"], "ALTERACAO", "usuarios", g.user["id_usuario"])
        db.commit()
        session.clear()
        flash("Senha alterada. Entre com a nova senha.", "success")
        return redirect(url_for("login"))
    return redirect(url_for("account_page"))


@app.route("/account/toggle", methods=["POST"])
@login_required
def toggle_preference():
    db = get_db()
    row = db.execute("SELECT dados FROM usuarios WHERE id_usuario=?", (g.user["id_usuario"],)).fetchone()
    data = unpack(bytes(row["dados"]), "usuario")
    p = {"tema": "SISTEMA", "fonte": "NORMAL", "alto_contraste": False, **data.get("preferencias", {})}
    kind = request.form.get("kind")
    if kind == "theme":
        p["tema"] = {"SISTEMA": "CLARO", "CLARO": "ESCURO", "ESCURO": "SISTEMA"}.get(p["tema"], "SISTEMA")
    elif kind == "font":
        p["fonte"] = {"NORMAL": "GRANDE", "GRANDE": "MUITO_GRANDE", "MUITO_GRANDE": "NORMAL"}.get(p["fonte"], "NORMAL")
    elif kind == "contrast":
        p["alto_contraste"] = not p["alto_contraste"]
    data["preferencias"] = p
    db.execute("UPDATE usuarios SET dados=? WHERE id_usuario=?", (pack(data, "usuario"), g.user["id_usuario"]))
    db.commit()
    nxt = request.form.get("next", "")
    if not nxt.startswith("/") or nxt.startswith("//"):
        nxt = url_for("dashboard_page")
    return redirect(nxt)


# --- Helpers ---

def _detect_mime(content, filename):
    if content[:4] == b"%PDF":
        return "application/pdf"
    if content[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    if content[:8] == b"\x89PNG\r\n\x1a\n":
        return "image/png"
    if content[:4] == b"RIFF" and content[8:12] == b"WEBP":
        return "image/webp"
    # Nunca confiar na extensão do nome: um executável renomeado para .pdf é recusado.
    return "application/octet-stream"


def _safe_filename(original, default_ext):
    import unicodedata
    name = unicodedata.normalize("NFKC", original or "")
    name = re.sub(r"[\x00-\x1f\x7f/\\]", "_", name)[:200]
    return name or f"arquivo.{default_ext}"


# --- Error Handlers ---

@app.errorhandler(404)
def not_found(e):
    return render_template("base.html", error="Página não encontrada."), 404


@app.errorhandler(403)
def forbidden(e):
    flash("O formulário expirou ou veio de outra página. Tente de novo.", "error")
    return redirect(url_for("login"))


@app.errorhandler(413)
def too_large(e):
    flash("O arquivo passa do limite de 10 MB.", "error")
    back = request.path.rsplit("/", 1)[0]
    return redirect(back if back.startswith("/") and not back.startswith("//") else url_for("dashboard_page"))


@app.errorhandler(429)
def too_many(e):
    return "Muitas requisições. Aguarde.", 429


def main():
    os.umask(0o077)
    with sqlite3.connect(str(DB_PATH)) as db:
        admins = db.execute("SELECT count(*) FROM usuarios WHERE ativo=1 AND perfil='ADMINISTRADOR'").fetchone()[0]
    if not admins:
        raise SystemExit("Cadastre ao menos um administrador ativo: python manage.py setup")
    try:
        mailer.verify()
    except Exception as error:
        if PRODUCTION:
            raise SystemExit(f"Não foi possível validar o servidor SMTP: {error}")
        print(f"Aviso: SMTP indisponível ({error}). Novos logins falharão até a conexão voltar; "
              "nenhum código será mostrado no terminal.")
    context = None
    if DIRECT_TLS:
        if os.name != "nt" and TLS_KEY.stat().st_mode & 0o077:
            raise SystemExit("A chave privada TLS não pode ter permissão para grupo ou outros usuários.")
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(TLS_CERT, TLS_KEY)
    if MFA_MODE == "console":
        print("MFA em modo console: o código de acesso aparece neste terminal (só para desenvolvimento).")
    print(f"Marquezi disponível em {APP_ORIGIN or _origin.geturl()}")
    app.run(host=HOST, port=PORT, ssl_context=context, threaded=True, debug=False)


if __name__ == "__main__":
    main()
