#!/usr/bin/env python3
"""
OLUNE ACCESS — serviço de convites, cotas mensais e suspensão do Olune Remote.
Somente biblioteca padrão (Python 3.10+). Banco: sqlite (mesma pasta persistente do servidor).
Fica atrás do Caddy (TLS). Escuta em 127.0.0.1:21121.

Endpoints públicos (aparelho convidado):
  POST /v1/enroll   {code, device_name, platform}  -> {token, server{id,relay,key}, name, quota}
  GET  /v1/status   Authorization: Bearer <token>   -> {status, remaining_minutes, monthly_minutes, allowed_ids, server, name}
  POST /v1/usage    Bearer; {session_id, target_id, minutes, kind} -> {status, remaining_minutes}
Administração (Authorization: Bearer <admin token>, ou cookie de sessão emitido por /admin/login):
  POST /admin/login {password} -> {session}      GET /admin/invites   POST /admin/invites {name, monthly_hours, allowed_ids[]}
  PATCH /admin/invites/<id> {status|name|monthly_hours|allowed_ids}   DELETE /admin/invites/<id>
  POST /admin/invites/<id>/regenerate-code       GET /admin/usage?month=YYYY-MM   GET /admin/devices
  DELETE /admin/devices/<id>                      GET /admin/audit
O hbbs (fork) lê as tabelas invites/devices deste banco para recusar conexões de tokens inválidos/suspensos/sem horas.
"""
import base64, hashlib, hmac, json, os, secrets, sqlite3, sys, time, threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

DATA_DIR = os.environ.get("OLUNE_DATA_DIR", "/opt/olune-server/data")
DB_PATH = os.path.join(DATA_DIR, "olune-access.sqlite3")
PUBKEY_PATH = os.path.join(DATA_DIR, "id_ed25519.pub")
ADMIN_TOKEN_PATH = os.path.join(DATA_DIR, "olune-admin.token")
ENV_PATH = os.environ.get("OLUNE_ENV", "/opt/olune-server/.env")
LISTEN = ("127.0.0.1", int(os.environ.get("OLUNE_ACCESS_PORT", "21121")))
ALLOWED_ORIGINS = [o for o in os.environ.get("OLUNE_CORS_ORIGINS", "").split(",") if o]

_lock = threading.Lock()
_rate = {}  # ip -> [timestamps] para /v1/enroll e /admin/login

def now(): return int(time.time())
def month_key(ts=None): return datetime.fromtimestamp(ts or now(), timezone.utc).strftime("%Y-%m")
def gen_code(): return "-".join(secrets.token_hex(2).upper() for _ in range(3))  # ex.: A1B2-C3D4-E5F6
def gen_token(): return secrets.token_urlsafe(32)
def sha(s): return hashlib.sha256(s.encode()).hexdigest()

def db():
    c = sqlite3.connect(DB_PATH, timeout=10, isolation_level=None)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL"); c.execute("PRAGMA busy_timeout=10000")
    return c

def init_db():
    os.makedirs(DATA_DIR, exist_ok=True)
    c = db()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS invites(
      id INTEGER PRIMARY KEY, name TEXT NOT NULL, code TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',        -- active | suspended | removed
      monthly_minutes INTEGER NOT NULL DEFAULT 600,  -- 0 = ilimitado
      used_minutes INTEGER NOT NULL DEFAULT 0, month_key TEXT NOT NULL,
      allowed_ids TEXT NOT NULL DEFAULT '*',         -- '*' ou JSON de IDs permitidos
      max_devices INTEGER NOT NULL DEFAULT 3, note TEXT DEFAULT '',
      created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS devices(
      id INTEGER PRIMARY KEY, invite_id INTEGER NOT NULL REFERENCES invites(id),
      token TEXT UNIQUE NOT NULL, device_name TEXT, platform TEXT,
      created_at INTEGER NOT NULL, last_seen INTEGER, revoked INTEGER NOT NULL DEFAULT 0);
    CREATE INDEX IF NOT EXISTS idx_devices_token ON devices(token);
    CREATE TABLE IF NOT EXISTS usage(
      id INTEGER PRIMARY KEY, device_id INTEGER NOT NULL, invite_id INTEGER NOT NULL,
      session_id TEXT, target_id TEXT, minutes INTEGER NOT NULL, kind TEXT, ts INTEGER NOT NULL);
    CREATE INDEX IF NOT EXISTS idx_usage_ts ON usage(ts);
    CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, actor TEXT, action TEXT, details TEXT);
    CREATE TABLE IF NOT EXISTS admin_sessions(token TEXT PRIMARY KEY, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL);
    """)
    c.close()
    if not os.path.exists(ADMIN_TOKEN_PATH):
        with open(ADMIN_TOKEN_PATH, "w") as f: f.write(gen_token())
        os.chmod(ADMIN_TOKEN_PATH, 0o600)

def admin_token():
    return open(ADMIN_TOKEN_PATH).read().strip()

def server_config():
    host = ""
    try:
        for line in open(ENV_PATH):
            if line.startswith("OLUNE_PUBLIC_HOST="): host = line.split("=", 1)[1].strip()
    except FileNotFoundError: pass
    host = os.environ.get("OLUNE_PUBLIC_HOST", host)
    key = open(PUBKEY_PATH).read().strip() if os.path.exists(PUBKEY_PATH) else ""
    return {"id": host, "relay": f"{host}:21117", "key": key}

def audit(c, actor, action, details=""):
    c.execute("INSERT INTO audit(ts, actor, action, details) VALUES(?,?,?,?)", (now(), actor, action, details))

def rollover(c, inv):
    """Zera o uso quando vira o mês (cota mensal renovável)."""
    mk = month_key()
    if inv["month_key"] != mk:
        c.execute("UPDATE invites SET used_minutes=0, month_key=?, updated_at=? WHERE id=?", (mk, now(), inv["id"]))
        inv = c.execute("SELECT * FROM invites WHERE id=?", (inv["id"],)).fetchone()
    return inv

def remaining(inv):
    if inv["monthly_minutes"] == 0: return None  # ilimitado
    return max(0, inv["monthly_minutes"] - inv["used_minutes"])

def effective_status(inv):
    if inv["status"] != "active": return inv["status"]
    r = remaining(inv)
    return "exhausted" if (r is not None and r <= 0) else "active"

def inv_public(inv):
    return {"id": inv["id"], "name": inv["name"], "status": effective_status(inv),
            "monthly_minutes": inv["monthly_minutes"], "used_minutes": inv["used_minutes"],
            "remaining_minutes": remaining(inv), "month": inv["month_key"],
            "allowed_ids": json.loads(inv["allowed_ids"]) if inv["allowed_ids"] != "*" else "*",
            "max_devices": inv["max_devices"], "note": inv["note"], "created_at": inv["created_at"]}

def rate_ok(ip, limit=8, window=60):
    with _lock:
        ts = [t for t in _rate.get(ip, []) if t > now() - window]
        if len(ts) >= limit: _rate[ip] = ts; return False
        ts.append(now()); _rate[ip] = ts; return True

class H(BaseHTTPRequestHandler):
    server_version = "OluneAccess/1"
    def log_message(self, fmt, *a): sys.stderr.write("%s %s\n" % (self.address_string(), fmt % a))

    # ---------- utilidades ----------
    def _cors(self):
        origin = self.headers.get("Origin", "")
        if origin and (origin in ALLOWED_ORIGINS or origin.endswith(".vercel.app")):
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
            self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
            self.send_header("Vary", "Origin")
    def _json(self, code, obj, cookie=None):
        body = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body))); self._cors()
        if cookie: self.send_header("Set-Cookie", cookie)
        self.end_headers(); self.wfile.write(body)
    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        if n > 65536: raise ValueError("body too large")
        return json.loads(self.rfile.read(n) or b"{}") if n else {}
    def _ip(self):
        return self.headers.get("X-Forwarded-For", self.client_address[0]).split(",")[0].strip()
    def _bearer(self):
        a = self.headers.get("Authorization", "")
        return a[7:].strip() if a.startswith("Bearer ") else ""
    def _cookie(self, name):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == name: return v
        return ""
    def _is_admin(self, c):
        t = self._bearer()
        if t and hmac.compare_digest(t, admin_token()): return True
        s = self._cookie("olune_admin") or t
        if s:
            row = c.execute("SELECT expires_at FROM admin_sessions WHERE token=?", (s,)).fetchone()
            if row and row["expires_at"] > now(): return True
        return False
    def _device(self, c):
        t = self._bearer()
        if not t: return None, None
        d = c.execute("SELECT * FROM devices WHERE token=? AND revoked=0", (t,)).fetchone()
        if not d: return None, None
        inv = c.execute("SELECT * FROM invites WHERE id=?", (d["invite_id"],)).fetchone()
        if not inv or inv["status"] == "removed": return None, None
        c.execute("UPDATE devices SET last_seen=? WHERE id=?", (now(), d["id"]))
        return d, rollover(c, inv)

    def do_OPTIONS(self):
        self.send_response(204); self._cors(); self.send_header("Content-Length", "0"); self.end_headers()

    # ---------- rotas ----------
    def do_GET(self):
        u = urlparse(self.path); p = u.path; q = parse_qs(u.query)
        c = db()
        try:
            if p == "/v1/health": return self._json(200, {"ok": True, "time": now()})
            if p == "/v1/status":
                d, inv = self._device(c)
                if not d: return self._json(401, {"error": "token inválido"})
                return self._json(200, {"status": effective_status(inv), "name": inv["name"],
                    "remaining_minutes": remaining(inv), "monthly_minutes": inv["monthly_minutes"],
                    "allowed_ids": inv_public(inv)["allowed_ids"], "server": server_config()})
            if not self._is_admin(c): return self._json(401, {"error": "não autorizado"})
            if p == "/admin/invites":
                rows = [inv_public(rollover(c, r)) for r in c.execute("SELECT * FROM invites WHERE status!='removed' ORDER BY id").fetchall()]
                for r in rows:
                    r["devices"] = c.execute("SELECT COUNT(*) FROM devices WHERE invite_id=? AND revoked=0", (r["id"],)).fetchone()[0]
                    r["code"] = c.execute("SELECT code FROM invites WHERE id=?", (r["id"],)).fetchone()[0]
                return self._json(200, {"invites": rows, "server": server_config()})
            if p == "/admin/devices":
                rows = [dict(r) for r in c.execute("SELECT d.id, d.invite_id, i.name, d.device_name, d.platform, d.created_at, d.last_seen FROM devices d JOIN invites i ON i.id=d.invite_id WHERE d.revoked=0 ORDER BY d.id").fetchall()]
                return self._json(200, {"devices": rows})
            if p == "/admin/usage":
                mk = (q.get("month") or [month_key()])[0]
                start = int(datetime.strptime(mk, "%Y-%m").replace(tzinfo=timezone.utc).timestamp())
                y, m = map(int, mk.split("-")); end = int(datetime(y + (m // 12), (m % 12) + 1, 1, tzinfo=timezone.utc).timestamp())
                rows = [dict(r) for r in c.execute("""SELECT i.id AS invite_id, i.name, SUM(u.minutes) AS minutes, COUNT(DISTINCT u.session_id) AS sessions,
                    SUM(CASE WHEN u.kind='relay' THEN u.minutes ELSE 0 END) AS relay_minutes
                    FROM usage u JOIN invites i ON i.id=u.invite_id WHERE u.ts>=? AND u.ts<? GROUP BY i.id ORDER BY minutes DESC""", (start, end)).fetchall()]
                return self._json(200, {"month": mk, "usage": rows})
            if p == "/admin/audit":
                rows = [dict(r) for r in c.execute("SELECT * FROM audit ORDER BY id DESC LIMIT 200").fetchall()]
                return self._json(200, {"audit": rows})
            return self._json(404, {"error": "rota"})
        except Exception as e:
            return self._json(500, {"error": str(e)})
        finally: c.close()

    def do_POST(self):
        p = urlparse(self.path).path; c = db()
        try:
            body = self._body()
            if p == "/v1/enroll":
                if not rate_ok(self._ip()): return self._json(429, {"error": "muitas tentativas; aguarde 1 minuto"})
                code = str(body.get("code", "")).strip().upper().replace(" ", "")
                inv = c.execute("SELECT * FROM invites WHERE code=?", (code,)).fetchone()
                if not inv or inv["status"] == "removed":
                    audit(c, self._ip(), "enroll_fail", code); return self._json(403, {"error": "código de convite inválido"})
                if inv["status"] == "suspended": return self._json(403, {"error": "convite suspenso"})
                n = c.execute("SELECT COUNT(*) FROM devices WHERE invite_id=? AND revoked=0", (inv["id"],)).fetchone()[0]
                if n >= inv["max_devices"]: return self._json(403, {"error": "limite de aparelhos deste convite atingido"})
                tok = gen_token()
                c.execute("INSERT INTO devices(invite_id, token, device_name, platform, created_at, last_seen) VALUES(?,?,?,?,?,?)",
                          (inv["id"], tok, str(body.get("device_name", ""))[:80], str(body.get("platform", ""))[:40], now(), now()))
                audit(c, self._ip(), "enroll", f"{inv['name']} / {body.get('device_name','')}")
                inv = rollover(c, inv)
                return self._json(200, {"token": tok, "server": server_config(), "name": inv["name"],
                    "status": effective_status(inv), "remaining_minutes": remaining(inv), "monthly_minutes": inv["monthly_minutes"],
                    "allowed_ids": inv_public(inv)["allowed_ids"]})
            if p == "/v1/usage":
                d, inv = self._device(c)
                if not d: return self._json(401, {"error": "token inválido", "status": "removed"})
                st = effective_status(inv)
                if st != "active": return self._json(403, {"status": st, "remaining_minutes": remaining(inv)})
                mins = max(0, min(int(body.get("minutes", 1)), 5))
                c.execute("INSERT INTO usage(device_id, invite_id, session_id, target_id, minutes, kind, ts) VALUES(?,?,?,?,?,?,?)",
                          (d["id"], inv["id"], str(body.get("session_id", ""))[:64], str(body.get("target_id", ""))[:32], mins, str(body.get("kind", ""))[:16], now()))
                c.execute("UPDATE invites SET used_minutes=used_minutes+?, updated_at=? WHERE id=?", (mins, now(), inv["id"]))
                inv = c.execute("SELECT * FROM invites WHERE id=?", (inv["id"],)).fetchone()
                return self._json(200, {"status": effective_status(inv), "remaining_minutes": remaining(inv)})
            if p == "/admin/login":
                if not rate_ok(self._ip(), limit=5): return self._json(429, {"error": "muitas tentativas"})
                if not hmac.compare_digest(str(body.get("password", "")), admin_token()):
                    audit(c, self._ip(), "admin_login_fail"); return self._json(401, {"error": "senha incorreta"})
                s = gen_token(); c.execute("INSERT INTO admin_sessions(token, created_at, expires_at) VALUES(?,?,?)", (s, now(), now() + 12 * 3600))
                audit(c, self._ip(), "admin_login")
                return self._json(200, {"session": s, "expires_in": 12 * 3600},
                                  cookie=f"olune_admin={s}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age={12*3600}")
            if not self._is_admin(c): return self._json(401, {"error": "não autorizado"})
            if p == "/admin/invites":
                name = str(body.get("name", "")).strip()[:80]
                if not name: return self._json(400, {"error": "nome obrigatório"})
                hours = float(body.get("monthly_hours", 10)); mins = 0 if hours <= 0 else int(hours * 60)
                allowed = body.get("allowed_ids", "*"); allowed = "*" if allowed in ("*", None, []) else json.dumps([str(x).replace(" ", "") for x in allowed])
                code = gen_code()
                c.execute("INSERT INTO invites(name, code, monthly_minutes, month_key, allowed_ids, max_devices, note, created_at, updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                          (name, code, mins, month_key(), allowed, int(body.get("max_devices", 3)), str(body.get("note", ""))[:300], now(), now()))
                audit(c, "admin", "invite_create", f"{name} {hours}h {allowed}")
                inv = c.execute("SELECT * FROM invites WHERE code=?", (code,)).fetchone()
                r = inv_public(inv); r["code"] = code
                return self._json(200, r)
            if p.startswith("/admin/invites/") and p.endswith("/regenerate-code"):
                iid = int(p.split("/")[3]); code = gen_code()
                c.execute("UPDATE invites SET code=?, updated_at=? WHERE id=?", (code, now(), iid)); audit(c, "admin", "invite_regen", str(iid))
                return self._json(200, {"id": iid, "code": code})
            return self._json(404, {"error": "rota"})
        except Exception as e:
            return self._json(400, {"error": str(e)})
        finally: c.close()

    def do_PATCH(self):
        p = urlparse(self.path).path; c = db()
        try:
            if not self._is_admin(c): return self._json(401, {"error": "não autorizado"})
            if p.startswith("/admin/invites/"):
                iid = int(p.split("/")[3]); body = self._body()
                inv = c.execute("SELECT * FROM invites WHERE id=?", (iid,)).fetchone()
                if not inv: return self._json(404, {"error": "convite não existe"})
                sets, vals = [], []
                if "status" in body and body["status"] in ("active", "suspended"): sets.append("status=?"); vals.append(body["status"])
                if "name" in body: sets.append("name=?"); vals.append(str(body["name"])[:80])
                if "monthly_hours" in body:
                    h = float(body["monthly_hours"]); sets.append("monthly_minutes=?"); vals.append(0 if h <= 0 else int(h * 60))
                if "allowed_ids" in body:
                    a = body["allowed_ids"]; sets.append("allowed_ids=?"); vals.append("*" if a in ("*", None, []) else json.dumps([str(x).replace(" ", "") for x in a]))
                if "max_devices" in body: sets.append("max_devices=?"); vals.append(int(body["max_devices"]))
                if "note" in body: sets.append("note=?"); vals.append(str(body["note"])[:300])
                if body.get("reset_usage"): sets.append("used_minutes=0"); sets.append("month_key=?"); vals.append(month_key())
                if not sets: return self._json(400, {"error": "nada para alterar"})
                sets.append("updated_at=?"); vals.append(now()); vals.append(iid)
                c.execute(f"UPDATE invites SET {', '.join(sets)} WHERE id=?", vals)
                audit(c, "admin", "invite_update", f"{iid} {json.dumps(body)[:200]}")
                inv = c.execute("SELECT * FROM invites WHERE id=?", (iid,)).fetchone()
                r = inv_public(inv); r["code"] = inv["code"]
                return self._json(200, r)
            return self._json(404, {"error": "rota"})
        except Exception as e:
            return self._json(400, {"error": str(e)})
        finally: c.close()

    def do_DELETE(self):
        p = urlparse(self.path).path; c = db()
        try:
            if not self._is_admin(c): return self._json(401, {"error": "não autorizado"})
            if p.startswith("/admin/invites/"):
                iid = int(p.split("/")[3])
                c.execute("UPDATE invites SET status='removed', updated_at=? WHERE id=?", (now(), iid))
                c.execute("UPDATE devices SET revoked=1 WHERE invite_id=?", (iid,))
                audit(c, "admin", "invite_remove", str(iid)); return self._json(200, {"removed": iid})
            if p.startswith("/admin/devices/"):
                did = int(p.split("/")[3]); c.execute("UPDATE devices SET revoked=1 WHERE id=?", (did,))
                audit(c, "admin", "device_revoke", str(did)); return self._json(200, {"revoked": did})
            return self._json(404, {"error": "rota"})
        finally: c.close()

if __name__ == "__main__":
    init_db()
    print(f"olune-access em {LISTEN[0]}:{LISTEN[1]} db={DB_PATH}", flush=True)
    ThreadingHTTPServer(LISTEN, H).serve_forever()
