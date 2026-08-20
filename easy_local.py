
import os, sqlite3, json, csv, io, html, secrets, hashlib, hmac, time, re
from datetime import datetime, date, timedelta
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs, urlencode
from http.cookies import SimpleCookie

APP_NAME = "MSME Pro Workforce Planner"
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", "5000"))
DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
DB_PATH = os.environ.get("MSME_DB_PATH", os.path.join(os.path.dirname(__file__), "msme.db"))
SESSION_TIMEOUT = int(os.environ.get("SESSION_TIMEOUT_MINUTES", "30")) * 60
IS_PROD = os.environ.get("PRODUCTION", "0") == "1"

# ---------------- Database adapter ----------------
class Database:
    def __init__(self):
        self.backend = "postgres" if DATABASE_URL.startswith(("postgres://", "postgresql://")) else "sqlite"
        self._pg = None
        if self.backend == "postgres":
            try:
                import psycopg
                from psycopg.rows import dict_row
                self._pg = (psycopg, dict_row)
            except Exception as e:
                raise RuntimeError(
                    "DATABASE_URL points to PostgreSQL, but psycopg is not installed. "
                    "For zero-install local use, remove DATABASE_URL. For PostgreSQL run: "
                    "py -m pip install -r requirements-postgres.txt"
                ) from e

    def conn(self):
        if self.backend == "sqlite":
            con = sqlite3.connect(DB_PATH)
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA foreign_keys = ON")
            return con
        psycopg, dict_row = self._pg
        return psycopg.connect(DATABASE_URL, row_factory=dict_row)

    def q(self, sql):
        return sql if self.backend == "sqlite" else sql.replace("?", "%s")

    def execute(self, sql, params=(), *, one=False, all=False, commit=False):
        con = self.conn()
        try:
            cur = con.cursor()
            cur.execute(self.q(sql), params)
            result = None
            if one:
                result = cur.fetchone()
            elif all:
                result = cur.fetchall()
            if commit:
                con.commit()
            return result
        finally:
            con.close()

    def script(self, statements):
        con = self.conn()
        try:
            cur = con.cursor()
            for stmt in statements:
                cur.execute(self.q(stmt))
            con.commit()
        finally:
            con.close()

db = Database()

def init_db():
    if db.backend == "sqlite":
        idcol = "INTEGER PRIMARY KEY AUTOINCREMENT"
        boolcol = "INTEGER"
    else:
        idcol = "SERIAL PRIMARY KEY"
        boolcol = "INTEGER"
    stmts = [
        f"""CREATE TABLE IF NOT EXISTS admins (
            id {idcol},
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            business_name TEXT NOT NULL,
            entrepreneur_code TEXT,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            failed_attempts INTEGER NOT NULL DEFAULT 0,
            lock_until TEXT,
            reset_token TEXT,
            reset_expires TEXT,
            profile_json TEXT NOT NULL DEFAULT '{{}}',
            family_json TEXT NOT NULL DEFAULT '{{}}',
            skills_json TEXT NOT NULL DEFAULT '{{}}',
            created_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS employees (
            id {idcol},
            admin_id INTEGER NOT NULL,
            category TEXT NOT NULL CHECK(category IN ('Staff','Worker')),
            code TEXT NOT NULL,
            surname TEXT,
            middle_name TEXT,
            last_name TEXT,
            email TEXT,
            phone TEXT,
            emergency_contact TEXT,
            emergency_relation TEXT,
            dob TEXT,
            gender TEXT,
            temporary_address TEXT,
            permanent_address TEXT,
            hobbies TEXT,
            religion TEXT,
            marital_status TEXT,
            aadhaar TEXT,
            highest_qualification TEXT,
            passing_year TEXT,
            department TEXT,
            designation TEXT,
            joining_date TEXT,
            total_experience TEXT,
            active {boolcol} NOT NULL DEFAULT 1,
            family_json TEXT NOT NULL DEFAULT '{{}}',
            skills_json TEXT NOT NULL DEFAULT '{{}}',
            created_at TEXT NOT NULL,
            UNIQUE(admin_id, code)
        )""",
        f"""CREATE TABLE IF NOT EXISTS attendance (
            id {idcol},
            admin_id INTEGER NOT NULL,
            employee_id INTEGER NOT NULL,
            work_date TEXT NOT NULL,
            status TEXT NOT NULL CHECK(status IN ('Present','Absent','Leave','Unmarked')),
            reason TEXT,
            replacement_employee_id INTEGER,
            replacement_score INTEGER,
            task_note TEXT,
            created_at TEXT NOT NULL,
            UNIQUE(admin_id, employee_id, work_date)
        )""",
        f"""CREATE TABLE IF NOT EXISTS leaves (
            id {idcol},
            admin_id INTEGER NOT NULL,
            employee_id INTEGER NOT NULL,
            leave_type TEXT NOT NULL,
            start_date TEXT NOT NULL,
            end_date TEXT NOT NULL,
            reason TEXT,
            status TEXT NOT NULL DEFAULT 'Pending',
            created_at TEXT NOT NULL
        )""",
        f"""CREATE TABLE IF NOT EXISTS audit (
            id {idcol},
            admin_id INTEGER NOT NULL,
            action TEXT NOT NULL,
            subject TEXT,
            details TEXT,
            created_at TEXT NOT NULL
        )"""
    ]
    db.script(stmts)

init_db()

# ---------------- Security/session helpers ----------------
SESSIONS = {}

def now_iso():
    return datetime.now().isoformat(timespec="seconds")

def hash_password(password, salt_hex=None):
    salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
    key = hashlib.scrypt(password.encode("utf-8"), salt=salt, n=2**14, r=8, p=1)
    return key.hex(), salt.hex()

def verify_password(password, stored_hash, salt_hex):
    candidate, _ = hash_password(password, salt_hex)
    return hmac.compare_digest(candidate, stored_hash)

def escape(v):
    return html.escape("" if v is None else str(v), quote=True)

def jload(v):
    try: return json.loads(v or "{}")
    except Exception: return {}

def jdumps(v):
    return json.dumps(v, ensure_ascii=False)

def normalize_email(v):
    return (v or "").strip().lower()

def parse_date(v):
    try: return datetime.strptime(v, "%Y-%m-%d").date()
    except Exception: return None

def age_from_dob(v):
    d = parse_date(v)
    if not d: return ""
    t = date.today()
    return t.year - d.year - ((t.month, t.day) < (d.month, d.day))

def login_required(handler):
    sess = handler.get_session()
    if not sess or not sess.get("admin_id"):
        handler.redirect("/login")
        return None
    return sess

def audit(admin_id, action, subject="", details=""):
    db.execute(
        "INSERT INTO audit(admin_id,action,subject,details,created_at) VALUES(?,?,?,?,?)",
        (admin_id, action, subject, details, now_iso()), commit=True
    )

def admin_row(admin_id):
    return db.execute("SELECT * FROM admins WHERE id=?", (admin_id,), one=True)

# ---------------- HTML rendering ----------------
CSS = r"""
:root{--navy:#082744;--blue:#0b66c3;--light:#f4f7fb;--muted:#6b7280;--green:#11875d;--red:#b42318;--amber:#b7791f}
*{box-sizing:border-box} body{margin:0;font-family:Inter,Segoe UI,Arial,sans-serif;background:var(--light);color:#172033}
a{color:inherit;text-decoration:none}.topbar{position:sticky;top:0;z-index:5;background:#fff;border-bottom:1px solid #e5e7eb;padding:12px 20px;display:flex;gap:18px;align-items:center}
.brand{font-weight:800;color:var(--navy);font-size:20px}.nav{display:flex;gap:8px;flex-wrap:wrap}.nav a{padding:8px 10px;border-radius:8px}.nav a:hover{background:#eef5ff}
.spacer{flex:1}.container{max-width:1200px;margin:24px auto;padding:0 16px}.hero{display:grid;grid-template-columns:1fr 1fr;min-height:100vh}.hero-left{background:#031426;color:#fff;padding:70px;display:flex;flex-direction:column;justify-content:center}.hero-left h1{font-size:48px;margin:0 0 14px}.hero-left strong{color:#2b9cff}.auth{display:flex;align-items:center;justify-content:center;padding:30px}.card{background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:22px;box-shadow:0 8px 24px rgba(8,39,68,.06)}
.auth .card{max-width:480px;width:100%}.grid{display:grid;gap:16px}.g2{grid-template-columns:repeat(2,minmax(0,1fr))}.g4{grid-template-columns:repeat(4,minmax(0,1fr))}
.metric{padding:18px;border-radius:14px;background:#fff;border:1px solid #e6e8ec}.metric b{display:block;font-size:30px;margin-top:8px}.muted{color:var(--muted);font-size:14px}
h1,h2,h3{color:var(--navy)}.section-title{background:#0b4a80;color:#fff;padding:12px 14px;border-radius:10px;margin:18px 0 12px}
label{display:block;font-weight:650;margin:8px 0 6px}input,select,textarea{width:100%;padding:10px 11px;border:1px solid #cfd6df;border-radius:8px;background:#fff}textarea{min-height:86px}
button,.btn{display:inline-block;border:0;border-radius:9px;padding:10px 14px;background:var(--blue);color:#fff;cursor:pointer;font-weight:650}.btn.secondary{background:#fff;color:var(--navy);border:1px solid #cfd6df}.btn.danger{background:var(--red)}.btn.green{background:var(--green)}
.actions{display:flex;gap:10px;flex-wrap:wrap;margin-top:14px}.flash{padding:12px 14px;border-radius:8px;margin:12px 0}.flash.ok{background:#eaf8f2;color:#0f6b4a}.flash.warn{background:#fff5dd;color:#7a5100}.flash.err{background:#fdecec;color:#9b1c1c}
table{width:100%;border-collapse:collapse;background:#fff}th,td{padding:11px;border-bottom:1px solid #e5e7eb;text-align:left;font-size:14px}th{background:#f8fafc}.scroll{overflow:auto}
.badge{display:inline-block;padding:4px 8px;border-radius:999px;font-size:12px;background:#eaf2ff;color:#174ea6}.present{background:#e8f7ef;color:#0c6b45}.absent{background:#fdecec;color:#9b1c1c}.leave{background:#fff4df;color:#855400}
.bell{position:relative}.bell-badge{position:absolute;top:-8px;right:-8px;background:#d92d20;color:#fff;border-radius:999px;padding:2px 6px;font-size:11px}.notif{position:absolute;right:10px;top:52px;width:340px;background:#fff;border:1px solid #d8dee8;border-radius:12px;box-shadow:0 12px 30px rgba(0,0,0,.15);padding:12px;display:none}.notif.show{display:block}
.chart{display:flex;align-items:end;gap:16px;height:190px;padding:12px;border:1px solid #e5e7eb;border-radius:12px;background:#fff}.bar-wrap{flex:1;text-align:center}.bar{background:#0b66c3;border-radius:8px 8px 0 0;min-height:4px}.bar-wrap a{display:block}.workforce-tabs{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:10px}.workforce-tabs button{background:#eef5ff;color:#0b4a80}.person-row{padding:9px 0;border-bottom:1px solid #edf0f5}
.priority{border-left:5px solid #0b66c3}.priority:first-child{border-left-color:#11875d}.score{font-size:30px;font-weight:800;color:#0b4a80}.small{font-size:12px}.nowrap{white-space:nowrap}
@media(max-width:800px){.hero{grid-template-columns:1fr}.hero-left{display:none}.g2,.g4{grid-template-columns:1fr}.topbar{align-items:flex-start}.nav{display:none}.container{margin-top:12px}.auth{padding:16px}.card{padding:16px}.notif{position:fixed;left:10px;right:10px;width:auto;top:70px}.hero-left h1{font-size:36px}}
"""

JS = r"""
function toggleNotif(){document.getElementById('notif').classList.toggle('show')}
function filterWorkforce(kind){
  document.querySelectorAll('[data-status]').forEach(el=>{
    el.style.display=(kind==='All'||el.dataset.status===kind)?'block':'none'
  })
}
function confirmDelete(){return confirm('Delete this record? This cannot be undone.')}
"""

def layout(title, body, *, admin=None, flash_msg=None, notifications=None):
    nav = ""
    if admin:
        ncount = len(notifications or [])
        nav = f"""
        <div class="topbar">
          <div class="brand">🏭 {escape(admin['business_name'])}</div>
          <div class="nav">
            <a href="/dashboard">Dashboard</a>
            <a href="/employees">Staff & Workers</a>
            <a href="/attendance">Attendance</a>
            <a href="/leaves">Leaves</a>
            <a href="/entrepreneur/details">Entrepreneur</a>
            <a href="/audit">Audit</a>
          </div>
          <div class="spacer"></div>
          <div class="bell">
            <button class="btn secondary" onclick="toggleNotif()">🔔</button>
            {f'<span class="bell-badge">{ncount}</span>' if ncount else ''}
            <div class="notif" id="notif">
              <b>Notifications</b>
              {''.join(f'<div class="person-row">{escape(x)}</div>' for x in (notifications or [])) or '<div class="muted">No new notifications</div>'}
            </div>
          </div>
          <a class="btn secondary" href="/logout">Logout</a>
        </div>"""
    flash_html = ""
    if flash_msg:
        kind, msg = flash_msg
        flash_html = f'<div class="flash {kind}">{escape(msg)}</div>'
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)} - {APP_NAME}</title><style>{CSS}</style></head>
<body>{nav}<div class="container">{flash_html}{body}</div><script>{JS}</script></body></html>"""

def auth_page(title, content):
    return f"""<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{escape(title)}</title><style>{CSS}</style></head><body>
<div class="hero"><div class="hero-left"><div class="brand" style="color:white">🏭 MSME OS</div>
<h1>MSME<br><strong>WORKFORCE</strong><br>PLANNER</h1>
<p>Manage staff, workers, attendance, leave, family information, skills and replacement priorities from one workspace.</p></div>
<div class="auth">{content}</div></div></body></html>"""

def csrf_input(sess):
    return f'<input type="hidden" name="csrf" value="{escape(sess["csrf"])}">'

def input_field(name, label, value="", typ="text", required=False, attrs=""):
    req = "required" if required else ""
    return f'<div><label>{escape(label)}</label><input type="{typ}" name="{escape(name)}" value="{escape(value)}" {req} {attrs}></div>'

def textarea_field(name, label, value=""):
    return f'<div><label>{escape(label)}</label><textarea name="{escape(name)}">{escape(value)}</textarea></div>'

def select_field(name, label, options, selected=""):
    opts = ['<option value="">Select</option>']
    for o in options:
        sel = "selected" if str(selected)==str(o) else ""
        opts.append(f'<option {sel} value="{escape(o)}">{escape(o)}</option>')
    return f'<div><label>{escape(label)}</label><select name="{escape(name)}">{"".join(opts)}</select></div>'

# ---------------- Business logic ----------------
def get_notifications(admin_id):
    today = date.today()
    employees = db.execute("SELECT * FROM employees WHERE admin_id=? AND active=1", (admin_id,), all=True)
    att = db.execute("SELECT * FROM attendance WHERE admin_id=? AND work_date=?", (admin_id, today.isoformat()), all=True)
    amap = {r["employee_id"]: r for r in att}
    absent = sum(1 for e in employees if amap.get(e["id"]) and amap[e["id"]]["status"]=="Absent")
    pending = db.execute("SELECT COUNT(*) AS c FROM leaves WHERE admin_id=? AND status='Pending'", (admin_id,), one=True)["c"]
    birthday_count = 0
    anniversary_count = 0
    for e in employees:
        d = parse_date(e["dob"])
        if d:
            next_b = d.replace(year=today.year)
            if next_b < today: next_b = d.replace(year=today.year+1)
            if 0 <= (next_b-today).days <= 7: birthday_count += 1
        jd = parse_date(e["joining_date"])
        if jd:
            next_a = jd.replace(year=today.year)
            if next_a < today: next_a = jd.replace(year=today.year+1)
            if 0 <= (next_a-today).days <= 7: anniversary_count += 1
    out=[]
    if absent: out.append(f"{absent} employee(s) absent today")
    if birthday_count: out.append(f"{birthday_count} birthday(s) within 7 days")
    if anniversary_count: out.append(f"{anniversary_count} work anniversary/anniversaries within 7 days")
    if pending: out.append(f"{pending} leave request(s) awaiting review")
    return out

def employee_name(e):
    return " ".join(x for x in [e["surname"], e["middle_name"], e["last_name"]] if x) or e["code"]

def skill_tokens(e):
    data = jload(e["skills_json"])
    text = " ".join(str(v) for v in data.values() if isinstance(v, (str,int,float)))
    toks = {x.lower() for x in re.split(r"[^A-Za-z0-9+#.]+", text) if len(x) >= 2}
    return toks

def replacement_candidates(admin_id, absent_emp, work_date):
    all_emp = db.execute("SELECT * FROM employees WHERE admin_id=? AND active=1 AND id<>?", (admin_id, absent_emp["id"]), all=True)
    rows=[]
    absent_skills = skill_tokens(absent_emp)
    for e in all_emp:
        a = db.execute("SELECT * FROM attendance WHERE admin_id=? AND employee_id=? AND work_date=?",
                       (admin_id,e["id"],work_date), one=True)
        if a and a["status"] in ("Absent","Leave"):
            continue
        score=0
        reasons=[]
        if (e["designation"] or "").strip().lower() == (absent_emp["designation"] or "").strip().lower() and e["designation"]:
            score += 40; reasons.append("Same designation +40")
        if (e["department"] or "").strip().lower() == (absent_emp["department"] or "").strip().lower() and e["department"]:
            score += 25; reasons.append("Same department +25")
        if e["category"] == absent_emp["category"]:
            score += 5; reasons.append("Same workforce type +5")
        st = skill_tokens(e)
        if absent_skills:
            overlap = len(absent_skills & st)
            match = round(25 * overlap / max(1, len(absent_skills)))
            if match:
                score += match; reasons.append(f"Recorded skill overlap +{match}")
        if a and a["status"]=="Present":
            score += 5; reasons.append("Confirmed present +5")
        score=min(100, score)
        rows.append((score,e,reasons))
    rows.sort(key=lambda x:(-x[0], employee_name(x[1]).lower()))
    return rows

# ---------------- HTTP handler ----------------
class AppHandler(BaseHTTPRequestHandler):
    server_version = "MSMEPlanner/1.0"

    def log_message(self, fmt, *args):
        print("[%s] %s" % (self.log_date_time_string(), fmt%args))

    def send_html(self, content, status=200, extra_headers=None):
        data=content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type","text/html; charset=utf-8")
        self.send_header("Content-Length",str(len(data)))
        if extra_headers:
            for k,v in extra_headers: self.send_header(k,v)
        self.end_headers(); self.wfile.write(data)

    def send_csv(self, text, filename):
        data=text.encode("utf-8-sig")
        self.send_response(200)
        self.send_header("Content-Type","text/csv; charset=utf-8")
        self.send_header("Content-Disposition",f'attachment; filename="{filename}"')
        self.send_header("Content-Length",str(len(data)))
        self.end_headers(); self.wfile.write(data)

    def redirect(self, path, cookie=None):
        self.send_response(303); self.send_header("Location",path)
        if cookie: self.send_header("Set-Cookie",cookie)
        self.end_headers()

    def parsed(self):
        return urlparse(self.path)

    def query(self):
        return {k:v[0] for k,v in parse_qs(self.parsed().query).items()}

    def form(self):
        n=int(self.headers.get("Content-Length","0") or 0)
        raw=self.rfile.read(n).decode("utf-8")
        return {k:v[0] for k,v in parse_qs(raw).items()}

    def get_session(self):
        c=SimpleCookie(self.headers.get("Cookie",""))
        sid=c.get("msme_session")
        if not sid: return None
        sess=SESSIONS.get(sid.value)
        if not sess: return None
        if time.time()-sess.get("last",0)>SESSION_TIMEOUT:
            SESSIONS.pop(sid.value,None); return None
        sess["last"]=time.time()
        return sess

    def new_session(self, admin_id=None):
        sid=secrets.token_urlsafe(32)
        SESSIONS[sid]={"admin_id":admin_id,"csrf":secrets.token_urlsafe(24),"last":time.time(),"flash":None}
        parts=[f"msme_session={sid}","Path=/","HttpOnly","SameSite=Lax",f"Max-Age={SESSION_TIMEOUT}"]
        if IS_PROD: parts.append("Secure")
        return sid, "; ".join(parts)

    def flash(self, sess, kind, msg):
        sess["flash"]=(kind,msg)

    def take_flash(self, sess):
        x=sess.get("flash"); sess["flash"]=None; return x

    def check_csrf(self, sess, form):
        return sess and hmac.compare_digest(str(form.get("csrf","")), str(sess.get("csrf","")))

    def do_GET(self):
        try: self.route("GET")
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_html(layout("Error",f"<div class='card'><h2>Something went wrong</h2><p>{escape(e)}</p><p class='muted'>See the terminal for technical details.</p></div>"),500)

    def do_POST(self):
        try: self.route("POST")
        except Exception as e:
            import traceback
            traceback.print_exc()
            self.send_html(layout("Error",f"<div class='card'><h2>Something went wrong</h2><p>{escape(e)}</p><p class='muted'>See the terminal for technical details.</p></div>"),500)

    def route(self, method):
        p=self.parsed().path
        if p=="/": return self.dashboard() if self.get_session() else self.redirect("/login")
        if p=="/signup": return self.signup(method)
        if p=="/login": return self.login(method)
        if p=="/logout": return self.logout()
        if p=="/forgot": return self.forgot(method)
        if p=="/reset": return self.reset(method)
        if p=="/dashboard": return self.dashboard()
        if p=="/employees": return self.employees()
        if p=="/worker/new": return self.worker_form(method, None)
        if p=="/staff/new": return self.staff_form(method, None)
        if p=="/employee/new": return self.employee_form(method, None)
        if p=="/employee/edit": return self.employee_form(method, self.query().get("id"))
        if p=="/employee": return self.employee_detail()
        if p=="/employee/delete": return self.employee_delete(method)
        if p=="/employee/family": return self.family_form(method)
        if p=="/employee/skills": return self.skills_form(method)
        if p=="/entrepreneur/details": return self.entrepreneur_details(method)
        if p=="/entrepreneur/family": return self.entrepreneur_family(method)
        if p=="/entrepreneur/skills": return self.entrepreneur_skills(method)
        if p=="/attendance": return self.attendance(method)
        if p=="/replacement": return self.replacement()
        if p=="/replacement/assign": return self.replacement_assign(method)
        if p=="/leaves": return self.leaves(method)
        if p=="/leave/status": return self.leave_status(method)
        if p=="/audit": return self.audit_page()
        if p=="/export.csv": return self.export_csv()
        self.send_html(layout("Not found","<div class='card'><h2>404 - Page not found</h2></div>"),404)

    # ---------- Authentication ----------
    def signup(self, method):
        if method=="GET":
            sess=self.get_session()
            if not sess:
                _,cookie=self.new_session()
                temp_sid=cookie.split("=",1)[1].split(";",1)[0]
                sess=SESSIONS[temp_sid]
                content=f"""<div class="card"><h2>Create entrepreneur account</h2><p class="muted">Each entrepreneur gets a separate MSME workspace.</p>
                <form method="post">{csrf_input(sess)}
                {input_field("name","Entrepreneur Name",required=True)}
                {input_field("email","Email",typ="email",required=True)}
                {input_field("business_name","Business Name",required=True)}
                {input_field("entrepreneur_code","Entrepreneur ID / Code")}
                {input_field("password","Password",typ="password",required=True,attrs='minlength="8"')}
                {input_field("confirm","Confirm Password",typ="password",required=True,attrs='minlength="8"')}
                <div class="actions"><button>Create Account</button><a class="btn secondary" href="/login">Login</a></div></form></div>"""
                return self.send_html(auth_page("Create Account",content),extra_headers=[("Set-Cookie",cookie)])
            content=f"""<div class="card"><h2>Create entrepreneur account</h2>
            <form method="post">{csrf_input(sess)}
            {input_field("name","Entrepreneur Name",required=True)}{input_field("email","Email",typ="email",required=True)}
            {input_field("business_name","Business Name",required=True)}{input_field("entrepreneur_code","Entrepreneur ID / Code")}
            {input_field("password","Password",typ="password",required=True,attrs='minlength="8"')}
            {input_field("confirm","Confirm Password",typ="password",required=True,attrs='minlength="8"')}
            <div class="actions"><button>Create Account</button><a class="btn secondary" href="/login">Login</a></div></form></div>"""
            return self.send_html(auth_page("Create Account",content))
        form=self.form(); sess=self.get_session()
        if not self.check_csrf(sess,form): return self.send_html(auth_page("Error","<div class='card'><h2>Invalid form token</h2><a href='/signup'>Try again</a></div>"),400)
        name=form.get("name","").strip(); email=normalize_email(form.get("email")); business=form.get("business_name","").strip()
        code=form.get("entrepreneur_code","").strip(); pw=form.get("password",""); conf=form.get("confirm","")
        if not all([name,email,business,pw]) or pw!=conf or len(pw)<8:
            self.flash(sess,"err","Please complete all fields. Passwords must match and contain at least 8 characters.")
            return self.redirect("/signup")
        if db.execute("SELECT id FROM admins WHERE email=?", (email,), one=True):
            self.flash(sess,"warn","An entrepreneur account already exists with this email. Please login or use Forgot Password.")
            return self.redirect("/login")
        ph,salt=hash_password(pw)
        try:
            db.execute("""INSERT INTO admins(name,email,business_name,entrepreneur_code,password_hash,salt,created_at)
                          VALUES(?,?,?,?,?,?,?)""",(name,email,business,code,ph,salt,now_iso()),commit=True)
        except Exception:
            if db.execute("SELECT id FROM admins WHERE email=?", (email,), one=True):
                self.flash(sess,"warn","An entrepreneur account already exists with this email. Please login.")
                return self.redirect("/login")
            raise
        admin=db.execute("SELECT * FROM admins WHERE email=?", (email,), one=True)
        audit(admin["id"],"Account created",name,business)
        sid,cookie=self.new_session(admin["id"])
        SESSIONS[sid]["flash"]=("ok","Account created successfully. Welcome to your MSME dashboard.")
        return self.redirect("/dashboard",cookie)

    def login(self, method):
        if method=="GET":
            sess=self.get_session()
            if not sess:
                _,cookie=self.new_session()
                sid=cookie.split("=",1)[1].split(";",1)[0]; sess=SESSIONS[sid]
                headers=[("Set-Cookie",cookie)]
            else: headers=None
            flash_html=""
            fm=self.take_flash(sess)
            if fm: flash_html=f'<div class="flash {fm[0]}">{escape(fm[1])}</div>'
            content=f"""<div class="card"><h2>Sign in to your workspace</h2><p class="muted">Entrepreneur-only access.</p>{flash_html}
            <form method="post">{csrf_input(sess)}{input_field("email","Email",typ="email",required=True)}
            {input_field("password","Password",typ="password",required=True)}
            <div class="actions"><button>Login</button><a class="btn secondary" href="/signup">Create account</a></div>
            <p><a href="/forgot">Forgot password?</a></p></form></div>"""
            return self.send_html(auth_page("Login",content),extra_headers=headers)
        form=self.form(); sess=self.get_session()
        if not self.check_csrf(sess,form): return self.send_html(auth_page("Error","<div class='card'>Invalid form token</div>"),400)
        email=normalize_email(form.get("email")); pw=form.get("password","")
        admin=db.execute("SELECT * FROM admins WHERE email=?", (email,), one=True)
        if not admin:
            self.flash(sess,"err","Invalid email or password."); return self.redirect("/login")
        if admin["lock_until"]:
            try:
                until=datetime.fromisoformat(admin["lock_until"])
                if datetime.now()<until:
                    self.flash(sess,"err",f"Account temporarily locked until {until.strftime('%H:%M')}.")
                    return self.redirect("/login")
            except Exception: pass
        if not verify_password(pw,admin["password_hash"],admin["salt"]):
            fa=(admin["failed_attempts"] or 0)+1
            lock=None
            if fa>=5: lock=(datetime.now()+timedelta(minutes=15)).isoformat(timespec="seconds"); fa=0
            db.execute("UPDATE admins SET failed_attempts=?, lock_until=? WHERE id=?",(fa,lock,admin["id"]),commit=True)
            self.flash(sess,"err","Invalid email or password."); return self.redirect("/login")
        db.execute("UPDATE admins SET failed_attempts=0, lock_until=NULL WHERE id=?",(admin["id"],),commit=True)
        sid,cookie=self.new_session(admin["id"]); audit(admin["id"],"Login",admin["name"],"Successful login")
        return self.redirect("/dashboard",cookie)

    def logout(self):
        c=SimpleCookie(self.headers.get("Cookie","")); sid=c.get("msme_session")
        if sid: SESSIONS.pop(sid.value,None)
        return self.redirect("/login","msme_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax")

    def forgot(self, method):
        sess=self.get_session()
        headers=None
        if not sess:
            _,cookie=self.new_session(); sid=cookie.split("=",1)[1].split(";",1)[0]; sess=SESSIONS[sid]; headers=[("Set-Cookie",cookie)]
        if method=="GET":
            content=f"""<div class="card"><h2>Forgot password</h2><p class="muted">For this project demo, a secure reset link is displayed after verification. In production, connect an email provider.</p>
            <form method="post">{csrf_input(sess)}{input_field("email","Registered Email",typ="email",required=True)}
            <div class="actions"><button>Create reset link</button><a class="btn secondary" href="/login">Back</a></div></form></div>"""
            return self.send_html(auth_page("Forgot Password",content),extra_headers=headers)
        form=self.form()
        if not self.check_csrf(sess,form): return self.send_html(auth_page("Error","<div class='card'>Invalid form token</div>"),400)
        email=normalize_email(form.get("email")); admin=db.execute("SELECT * FROM admins WHERE email=?",(email,),one=True)
        if not admin:
            self.flash(sess,"warn","If that email exists, a reset link has been prepared.")
            return self.redirect("/login")
        token=secrets.token_urlsafe(32); exp=(datetime.now()+timedelta(minutes=20)).isoformat(timespec="seconds")
        db.execute("UPDATE admins SET reset_token=?, reset_expires=? WHERE id=?",(token,exp,admin["id"]),commit=True)
        content=f"""<div class="card"><h2>Password reset link</h2><p>This demo shows the reset link directly:</p>
        <p><a class="btn" href="/reset?token={escape(token)}">Reset password now</a></p><p class="muted">The link expires in 20 minutes.</p></div>"""
        return self.send_html(auth_page("Reset Link",content))

    def reset(self, method):
        q=self.query(); token=q.get("token","")
        admin=db.execute("SELECT * FROM admins WHERE reset_token=?",(token,),one=True) if token else None
        if not admin: return self.send_html(auth_page("Invalid link","<div class='card'><h2>Invalid reset link</h2><a href='/forgot'>Request another</a></div>"),400)
        try:
            if datetime.now()>datetime.fromisoformat(admin["reset_expires"]): raise ValueError()
        except Exception:
            return self.send_html(auth_page("Expired","<div class='card'><h2>Reset link expired</h2><a href='/forgot'>Request another</a></div>"),400)
        sess=self.get_session(); headers=None
        if not sess:
            _,cookie=self.new_session(); sid=cookie.split("=",1)[1].split(";",1)[0]; sess=SESSIONS[sid]; headers=[("Set-Cookie",cookie)]
        if method=="GET":
            content=f"""<div class="card"><h2>Set a new password</h2><form method="post" action="/reset?token={escape(token)}">{csrf_input(sess)}
            {input_field("password","New Password",typ="password",required=True,attrs='minlength="8"')}
            {input_field("confirm","Confirm Password",typ="password",required=True,attrs='minlength="8"')}
            <div class="actions"><button>Update password</button></div></form></div>"""
            return self.send_html(auth_page("Reset Password",content),extra_headers=headers)
        form=self.form()
        if not self.check_csrf(sess,form): return self.send_html(auth_page("Error","<div class='card'>Invalid form token</div>"),400)
        pw=form.get("password",""); conf=form.get("confirm","")
        if len(pw)<8 or pw!=conf: return self.send_html(auth_page("Error","<div class='card'>Passwords must match and contain at least 8 characters.</div>"),400)
        ph,salt=hash_password(pw)
        db.execute("UPDATE admins SET password_hash=?,salt=?,reset_token=NULL,reset_expires=NULL WHERE id=?",(ph,salt,admin["id"]),commit=True)
        self.flash(sess,"ok","Password changed successfully. Please login.")
        return self.redirect("/login")

    # ---------- Dashboard ----------
    def dashboard(self):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); today=date.today().isoformat()
        emps=db.execute("SELECT * FROM employees WHERE admin_id=? AND active=1 ORDER BY category,surname,last_name",(admin["id"],),all=True)
        att=db.execute("SELECT * FROM attendance WHERE admin_id=? AND work_date=?",(admin["id"],today),all=True)
        amap={a["employee_id"]:a for a in att}
        counts={"Present":0,"Absent":0,"Leave":0,"Unmarked":0}
        staff=sum(1 for e in emps if e["category"]=="Staff"); workers=len(emps)-staff
        dept={}
        workforce=[]
        for e in emps:
            st=amap.get(e["id"])["status"] if amap.get(e["id"]) else "Unmarked"
            counts[st]+=1; dept[e["department"] or "Unassigned"]=dept.get(e["department"] or "Unassigned",0)+1
            workforce.append((e,st))
        # Today's birthday panel: employees plus entrepreneur.
        today_birthdays = []
        for e in emps:
            bd = parse_date(e["dob"])
            if bd and (bd.month, bd.day) == (date.today().month, date.today().day):
                today_birthdays.append({
                    "name": employee_name(e),
                    "type": e["category"],
                    "department": e["department"] or "Unassigned",
                    "designation": e["designation"] or ""
                })

        entrepreneur_profile = jload(admin["profile_json"])
        entrepreneur_dob = parse_date(entrepreneur_profile.get("dob", ""))
        if entrepreneur_dob and (entrepreneur_dob.month, entrepreneur_dob.day) == (date.today().month, date.today().day):
            entrepreneur_name = " ".join(
                x for x in [
                    entrepreneur_profile.get("surname", ""),
                    entrepreneur_profile.get("middle_name", ""),
                    entrepreneur_profile.get("last_name", "")
                ] if x
            ) or admin["name"]
            today_birthdays.insert(0, {
                "name": entrepreneur_name,
                "type": "Entrepreneur",
                "department": entrepreneur_profile.get("department", "Management") or "Management",
                "designation": entrepreneur_profile.get("designation", "Entrepreneur") or "Entrepreneur"
            })

        birthday_rows = "".join(
            f"""<tr><td>🎂 <b>{escape(b["name"])}</b></td><td>{escape(b["type"])}</td><td>{escape(b["department"])}</td><td>{escape(b["designation"])}</td><td><span class="badge present">Birthday Today</span></td></tr>"""
            for b in today_birthdays
        )
        if not birthday_rows:
            birthday_rows = '<tr><td colspan="5" class="muted">No entrepreneur, staff or worker birthdays today.</td></tr>'

        notifs=get_notifications(admin["id"])
        if today_birthdays:
            notifs.insert(0, f"🎂 {len(today_birthdays)} birthday(s) today")
        month_prefix=date.today().strftime("%Y-%m")
        month_rows=db.execute("SELECT status,COUNT(*) c FROM attendance WHERE admin_id=? AND work_date LIKE ? GROUP BY status",(admin["id"],month_prefix+"%"),all=True)
        mcounts={r["status"]:r["c"] for r in month_rows}
        bars=lambda items,maxv: ''.join(
            f'<div class="bar-wrap"><a href="{escape(url)}"><div class="bar" style="height:{max(4,int(140*v/max(1,maxv)))}px"></div><b>{v}</b><div class="small">{escape(lbl)}</div></a></div>'
            for lbl,v,url in items)
        cat_items=[("Staff",staff,"/employees?category=Staff"),("Workers",workers,"/employees?category=Worker")]
        status_items=[(k,counts[k],f"/employees?status={k}") for k in ("Present","Absent","Leave","Unmarked")]
        dept_items=[(k,v,"/employees?department="+urlencode({"x":k}).split("=",1)[1]) for k,v in sorted(dept.items(), key=lambda x:-x[1])[:6]]
        month_items=[(k,mcounts.get(k,0),"/attendance") for k in ("Present","Absent","Leave")]
        wf_html=''.join(f'<div class="person-row" data-status="{st}"><b>{escape(employee_name(e))}</b> <span class="badge {st.lower()}">{st}</span><div class="muted">{escape(e["category"])} · {escape(e["department"])} · {escape(e["designation"])}</div></div>' for e,st in workforce) or '<div class="muted">No staff or workers yet.</div>'
        body=f"""
        <div style="display:flex;justify-content:space-between;gap:14px;align-items:center;flex-wrap:wrap"><div><h1>Today's workforce</h1><p class="muted">{date.today().strftime('%d %B %Y')}</p></div>
        <div class="actions"><a class="btn" href="/worker/new">+ Worker</a><a class="btn" href="/staff/new">+ Staff</a><a class="btn secondary" href="/export.csv">Export CSV</a></div></div>
        <div class="grid g4">
          <div class="metric"><span>Total Workforce</span><b>{len(emps)}</b></div>
          <div class="metric"><span>Present</span><b>{counts["Present"]}</b></div>
          <div class="metric"><span>Absent</span><b>{counts["Absent"]}</b></div>
          <div class="metric"><span>On Leave</span><b>{counts["Leave"]}</b></div>
          <div class="metric"><span>🎂 Today's Birthdays</span><b>{len(today_birthdays)}</b><div class="muted">Entrepreneur / Staff / Worker</div></div>
        </div>
        <div class="card" style="margin-top:16px">
          <div style="display:flex;justify-content:space-between;gap:12px;align-items:center;flex-wrap:wrap">
            <div><h3 style="margin-bottom:4px">🎂 Today's Birthdays</h3><p class="muted" style="margin-top:0">Entrepreneur, staff and worker birthdays for today.</p></div>
            <span class="badge">{len(today_birthdays)} birthday(s) today</span>
          </div>
          <div class="scroll">
            <table>
              <thead><tr><th>Name</th><th>Role Type</th><th>Department</th><th>Designation</th><th>Status</th></tr></thead>
              <tbody>{birthday_rows}</tbody>
            </table>
          </div>
        </div>
        <div class="grid g2" style="margin-top:16px">
          <div class="card"><h3>Staff vs Workers</h3><div class="chart">{bars(cat_items,max(staff,workers,1))}</div></div>
          <div class="card"><h3>Today's attendance</h3><div class="chart">{bars(status_items,max(counts.values()) if counts else 1)}</div></div>
          <div class="card"><h3>Department distribution</h3><div class="chart">{bars(dept_items,max(dept.values()) if dept else 1)}</div></div>
          <div class="card"><h3>This month's attendance</h3><div class="chart">{bars(month_items,max(mcounts.values()) if mcounts else 1)}</div></div>
        </div>
        <div class="card" style="margin-top:16px"><h3>Today's workforce panel</h3>
          <div class="workforce-tabs"><button onclick="filterWorkforce('All')">All {len(emps)}</button><button onclick="filterWorkforce('Present')">Present {counts['Present']}</button><button onclick="filterWorkforce('Absent')">Absent {counts['Absent']}</button><button onclick="filterWorkforce('Leave')">Leave {counts['Leave']}</button><button onclick="filterWorkforce('Unmarked')">Unmarked {counts['Unmarked']}</button></div>
          {wf_html}
        </div>"""
        return self.send_html(layout("Dashboard",body,admin=admin,flash_msg=self.take_flash(sess),notifications=notifs))

    # ---------- Employees ----------
    def employees(self):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); q=self.query(); category=q.get("category",""); search=(q.get("q","") or "").lower()
        department=q.get("department",""); status_filter=q.get("status",""); today=date.today().isoformat()
        emps=db.execute("SELECT * FROM employees WHERE admin_id=? AND active=1 ORDER BY category,surname,last_name",(admin["id"],),all=True)
        rows=[]
        for e in emps:
            if category and e["category"]!=category: continue
            if department and (e["department"] or "")!=department: continue
            text=" ".join(str(e[k] or "") for k in ("code","surname","middle_name","last_name","email","department","designation")).lower()
            if search and search not in text: continue
            a=db.execute("SELECT status FROM attendance WHERE admin_id=? AND employee_id=? AND work_date=?",(admin["id"],e["id"],today),one=True)
            st=a["status"] if a else "Unmarked"
            if status_filter and st!=status_filter: continue
            rows.append((e,st))
        tr=''.join(f"""<tr><td>{escape(e['code'])}</td><td><a href="/employee?id={e['id']}"><b>{escape(employee_name(e))}</b></a></td><td>{escape(e['category'])}</td><td>{escape(e['department'])}</td><td>{escape(e['designation'])}</td><td><span class="badge {st.lower()}">{st}</span></td><td><a class="btn secondary" href="/employee/edit?id={e['id']}">Edit</a></td></tr>""" for e,st in rows)
        body=f"""<div style="display:flex;justify-content:space-between;gap:12px;flex-wrap:wrap"><h1>Staff & Workers</h1><div class="actions"><a class="btn" href="/staff/new">+ Staff</a><a class="btn" href="/worker/new">+ Worker</a></div></div>
        <div class="card"><form method="get" class="grid g2">{input_field("q","Search",q.get("q",""))}{select_field("category","Type",["Staff","Worker"],category)}<div class="actions"><button>Filter</button><a class="btn secondary" href="/employees">Clear</a></div></form></div>
        <div class="card scroll" style="margin-top:16px"><table><thead><tr><th>Code</th><th>Name</th><th>Type</th><th>Department</th><th>Designation</th><th>Today</th><th>Action</th></tr></thead><tbody>{tr or '<tr><td colspan=7>No records found.</td></tr>'}</tbody></table></div>"""
        return self.send_html(layout("Employees",body,admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))


    def worker_form(self, method, eid=None):
        # Dedicated Worker Details Form
        q = self.query()
        if eid:
            return self.employee_form(method, eid)
        # Force Worker category while preserving the same validated save logic.
        original_path = self.path
        if "?" in original_path:
            base = original_path.split("?",1)[0]
            self.path = base + "?category=Worker"
        else:
            self.path = original_path + "?category=Worker"
        try:
            return self.employee_form(method, None)
        finally:
            self.path = original_path

    def staff_form(self, method, eid=None):
        # Dedicated Staff Details Form
        q = self.query()
        if eid:
            return self.employee_form(method, eid)
        original_path = self.path
        if "?" in original_path:
            base = original_path.split("?",1)[0]
            self.path = base + "?category=Staff"
        else:
            self.path = original_path + "?category=Staff"
        try:
            return self.employee_form(method, None)
        finally:
            self.path = original_path

    def employee_form(self, method, eid):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); e=None
        if eid: e=db.execute("SELECT * FROM employees WHERE id=? AND admin_id=?",(eid,admin["id"]),one=True)
        q=self.query(); category=(e["category"] if e else q.get("category","Worker"))
        if method=="GET":
            v=lambda k: e[k] if e else ""
            # Category is fixed on dedicated Worker/Staff pages. Edit mode keeps the stored category.
            category_control = f'<input type="hidden" name="category" value="{escape(category)}">'
            form=f"""<form method="post">{csrf_input(sess)}{category_control}
            <div class="section-title">{escape(category)} Details Form</div>
            <div class="grid g2">
            {input_field("code",f"{category} ID",v("code"),required=True)}
            {input_field("surname",f"{category} Surname",v("surname"))}
            {input_field("middle_name",f"{category} Middle Name",v("middle_name"))}
            {input_field("last_name",f"{category} Last Name",v("last_name"))}
            {input_field("email","Email",v("email"),typ="email")}
            {input_field("phone","Phone Number",v("phone"))}
            {input_field("emergency_contact","Emergency Contact",v("emergency_contact"))}
            {input_field("emergency_relation",f"Relation with {category}",v("emergency_relation"))}
            {input_field("dob","Date of Birth",v("dob"),typ="date")}
            {input_field("age","Age (automatic)",age_from_dob(v("dob")),attrs="readonly")}
            {select_field("gender","Gender",["Male","Female","Other"],v("gender"))}
            </div>
            {textarea_field("temporary_address","Temporary Address",v("temporary_address"))}
            {textarea_field("permanent_address","Permanent Address",v("permanent_address"))}
            {textarea_field("hobbies","Hobbies",v("hobbies"))}
            <div class="grid g2">
            {select_field("religion","Religion",["Hindu","Muslim","Christian","Sikh","Buddhist","Jain","Other","Prefer not to say"],v("religion"))}
            {select_field("marital_status","Marital Status",["Single","Married","Divorced","Widowed","Other"],v("marital_status"))}
            {input_field("aadhaar","Aadhaar / National ID",v("aadhaar"))}
            {select_field("highest_qualification","Highest Qualification",["10th","12th","ITI","Diploma","Bachelor's","Master's","Doctorate","Other"],v("highest_qualification"))}
            {input_field("passing_year","Year of Passing",v("passing_year"))}
            {input_field("department","Department",v("department"))}
            {input_field("designation","Designation",v("designation"))}
            {input_field("joining_date","Date of Joining",v("joining_date"),typ="date")}
            {input_field("total_experience","Total Experience",v("total_experience"))}
            </div>
            <div class="actions"><button>Save {escape(category)}</button><button type="reset" class="btn secondary">Reset</button><a class="btn secondary" href="/employees">Cancel</a></div></form>"""
            return self.send_html(layout(("Edit " if e else "New ")+category,f"<div class='card'><h1>{'Edit' if e else 'New'} {escape(category)} Details Form</h1>{form}</div>",admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))
        f=self.form()
        if not self.check_csrf(sess,f): return self.send_html(layout("Error","<div class='card'>Invalid form token</div>",admin=admin),400)
        fields=["category","code","surname","middle_name","last_name","email","phone","emergency_contact","emergency_relation","dob","gender","temporary_address","permanent_address","hobbies","religion","marital_status","aadhaar","highest_qualification","passing_year","department","designation","joining_date","total_experience"]
        vals=[f.get(k,"").strip() for k in fields]
        if not vals[1]:
            self.flash(sess,"err","Employee ID is required."); return self.redirect(self.parsed().path)
        try:
            if e:
                sets=",".join(f"{k}=?" for k in fields)
                db.execute(f"UPDATE employees SET {sets} WHERE id=? AND admin_id=?",tuple(vals+[e["id"],admin["id"]]),commit=True)
                audit(admin["id"],"Employee edited",vals[1],employee_name(e))
                self.flash(sess,"ok","Employee details updated.")
                return self.redirect(f"/employee?id={e['id']}")
            db.execute("""INSERT INTO employees(admin_id,category,code,surname,middle_name,last_name,email,phone,emergency_contact,emergency_relation,dob,gender,temporary_address,permanent_address,hobbies,religion,marital_status,aadhaar,highest_qualification,passing_year,department,designation,joining_date,total_experience,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",tuple([admin["id"]]+vals+[now_iso()]),commit=True)
            ne=db.execute("SELECT * FROM employees WHERE admin_id=? AND code=?",(admin["id"],vals[1]),one=True)
            audit(admin["id"],"Employee created",vals[1],employee_name(ne))
            self.flash(sess,"ok",f"{vals[0]} created. Add family and skill information next.")
            return self.redirect(f"/employee?id={ne['id']}")
        except Exception as ex:
            if "UNIQUE" in str(ex).upper():
                self.flash(sess,"err","That Staff/Worker ID already exists. Please use a different ID.")
                return self.redirect(self.parsed().path)
            raise

    def employee_detail(self):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); eid=self.query().get("id")
        e=db.execute("SELECT * FROM employees WHERE id=? AND admin_id=?",(eid,admin["id"]),one=True)
        if not e:return self.redirect("/employees")
        stats={}
        for st in ("Present","Absent","Leave"):
            stats[st]=db.execute("SELECT COUNT(*) c FROM attendance WHERE admin_id=? AND employee_id=? AND status=?",(admin["id"],e["id"],st),one=True)["c"]
        body=f"""<div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap"><div><h1>{escape(employee_name(e))}</h1><p class="muted">{escape(e['category'])} · {escape(e['code'])}</p></div>
        <div class="actions"><a class="btn" href="/employee/edit?id={e['id']}">Edit / Rewrite</a><a class="btn secondary" href="/employee/family?id={e['id']}">{escape(e['category'])} Family Form</a><a class="btn secondary" href="/employee/skills?id={e['id']}">{escape(e['category'])} Skills Form</a></div></div>
        <div class="grid g4"><div class="metric"><span>Present days</span><b>{stats['Present']}</b></div><div class="metric"><span>Absent days</span><b>{stats['Absent']}</b></div><div class="metric"><span>Leave days</span><b>{stats['Leave']}</b></div><div class="metric"><span>Age</span><b>{age_from_dob(e['dob']) or '-'}</b></div></div>
        <div class="grid g2" style="margin-top:16px"><div class="card"><h3>Employment</h3><p><b>Department:</b> {escape(e['department'])}</p><p><b>Designation:</b> {escape(e['designation'])}</p><p><b>Joining:</b> {escape(e['joining_date'])}</p><p><b>Experience:</b> {escape(e['total_experience'])}</p></div>
        <div class="card"><h3>Contact & personal</h3><p><b>Phone:</b> {escape(e['phone'])}</p><p><b>Email:</b> {escape(e['email'])}</p><p><b>DOB:</b> {escape(e['dob'])}</p><p><b>Gender:</b> {escape(e['gender'])}</p></div></div>
        <div class="card" style="margin-top:16px"><form method="post" action="/employee/delete?id={e['id']}" onsubmit="return confirmDelete()">{csrf_input(sess)}<button class="btn danger">Delete employee</button></form></div>"""
        return self.send_html(layout("Employee Profile",body,admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))

    def employee_delete(self, method):
        sess=login_required(self)
        if not sess:return
        if method!="POST": return self.redirect("/employees")
        f=self.form()
        if not self.check_csrf(sess,f): return self.redirect("/employees")
        eid=self.query().get("id"); e=db.execute("SELECT * FROM employees WHERE id=? AND admin_id=?",(eid,sess["admin_id"]),one=True)
        if e:
            db.execute("DELETE FROM attendance WHERE admin_id=? AND employee_id=?",(sess["admin_id"],e["id"]),commit=True)
            db.execute("DELETE FROM leaves WHERE admin_id=? AND employee_id=?",(sess["admin_id"],e["id"]),commit=True)
            db.execute("DELETE FROM employees WHERE id=? AND admin_id=?",(e["id"],sess["admin_id"]),commit=True)
            audit(sess["admin_id"],"Employee deleted",e["code"],employee_name(e))
            self.flash(sess,"ok","Employee deleted.")
        return self.redirect("/employees")

    # ---------- Family forms ----------
    FAMILY_FIELDS=[
        ("father_name","Father's Name"),("father_dob","Father Date of Birth"),("father_occupation","Father Occupation"),("father_phone","Father Phone Number"),
        ("mother_name","Mother's Name"),("mother_dob","Mother Date of Birth"),("mother_occupation","Mother Occupation"),("mother_phone","Mother Phone Number"),
        ("living_with","Living With Employee"),
        ("sibling1_name","Sibling Name 1"),("sibling1_dob","Sibling 1 Date of Birth"),("sibling1_occupation","Sibling 1 Occupation"),("sibling1_phone","Sibling 1 Phone Number"),
        ("sibling2_name","Sibling Name 2"),("sibling2_dob","Sibling 2 Date of Birth"),("sibling2_occupation","Sibling 2 Occupation"),("sibling2_phone","Sibling 2 Phone Number"),
        ("spouse_name","Spouse Name"),("spouse_dob","Spouse Date of Birth"),("spouse_occupation","Spouse Occupation"),("spouse_phone","Spouse Phone Number"),
        ("child1_name","Child 1 Name"),("child1_dob","Child 1 Date of Birth"),("child1_gender","Child 1 Gender"),("child1_school","Child 1 School / College"),("child1_class","Child 1 Class"),
        ("child2_name","Child 2 Name"),("child2_dob","Child 2 Date of Birth"),("child2_gender","Child 2 Gender"),("child2_school","Child 2 School / College"),("child2_class","Child 2 Class"),
        ("medical_history","Employee Medical History"),("family_medical_history","Family Medical History"),("blood_group","Blood Group"),("hospital_preference","Hospital Preference"),("family_doctor","Family Doctor"),("doctor_number","Doctor Number"),
        ("father_birthday","Father Birthday"),("mother_birthday","Mother Birthday"),("spouse_birthday","Spouse Birthday"),("child1_birthday","Child 1 Birthday"),("child2_birthday","Child 2 Birthday"),
        ("wedding_anniversary","Wedding Anniversary"),("parents_anniversary","Parents Anniversary"),("other_important_date","Other Important Date"),("festival_reminder","Festival Reminder"),("special_occasion","Special Occasion")
    ]
    DATE_KEYS={k for k,_ in FAMILY_FIELDS if any(x in k for x in ("dob","birthday","anniversary","date"))}

    def family_form(self, method):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); eid=self.query().get("id")
        e=db.execute("SELECT * FROM employees WHERE id=? AND admin_id=?",(eid,admin["id"]),one=True)
        if not e:return self.redirect("/employees")
        data=jload(e["family_json"])
        if method=="GET":
            sections=[]
            def sec(title, keys):
                items=[]
                for k,lbl in keys:
                    if k=="living_with": items.append(select_field(k,lbl,["Yes","No"],data.get(k,"")))
                    elif "gender" in k: items.append(select_field(k,lbl,["Male","Female","Other"],data.get(k,"")))
                    elif k in self.DATE_KEYS: items.append(input_field(k,lbl,data.get(k,""),typ="date"))
                    elif "history" in k: items.append(textarea_field(k,lbl,data.get(k,"")))
                    else: items.append(input_field(k,lbl,data.get(k,"")))
                return f'<div class="section-title">{title}</div><div class="grid g2">{"".join(items)}</div>'
            groups=[
                ("Parents Details",self.FAMILY_FIELDS[0:9]),("Siblings Details",self.FAMILY_FIELDS[9:17]),
                ("Spouse Details",self.FAMILY_FIELDS[17:21]),("Children Details",self.FAMILY_FIELDS[21:31]),
                ("Medical History",self.FAMILY_FIELDS[31:37]),("Important Family Dates",self.FAMILY_FIELDS[37:])
            ]
            content="".join(sec(t,ks) for t,ks in groups)
            form=f"""<form method="post">{csrf_input(sess)}<div class="section-title">{escape(e['category'])} Family Information Form</div>
            <div class="card"><b>{escape(e['code'])}</b> · {escape(employee_name(e))} · {escape(e['department'])} · {escape(e['designation'])}</div>
            {content}<div class="section-title">Declaration</div><label><input style="width:auto" type="checkbox" name="declaration" value="yes" {'checked' if data.get('declaration')=='yes' else ''}> I declare the above information is true and authorize its use for employee welfare, emergency support, insurance administration and family occasions.</label>
            <div class="actions"><button>Submit Family Details</button><button type="reset" class="btn secondary">Reset Form</button><a class="btn secondary" href="/employee?id={e['id']}">Back</a></div></form>"""
            return self.send_html(layout("Family Information",f"<div class='card'>{form}</div>",admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))
        f=self.form()
        if not self.check_csrf(sess,f): return self.redirect(f"/employee/family?id={e['id']}")
        data={k:f.get(k,"").strip() for k,_ in self.FAMILY_FIELDS}; data["declaration"]=f.get("declaration","")
        db.execute("UPDATE employees SET family_json=? WHERE id=? AND admin_id=?",(jdumps(data),e["id"],admin["id"]),commit=True)
        audit(admin["id"],"Family details updated",e["code"],employee_name(e)); self.flash(sess,"ok","Family information saved.")
        return self.redirect(f"/employee?id={e['id']}")

    # ---------- Skill forms ----------
    def skills_form(self, method):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); eid=self.query().get("id")
        e=db.execute("SELECT * FROM employees WHERE id=? AND admin_id=?",(eid,admin["id"]),one=True)
        if not e:return self.redirect("/employees")
        data=jload(e["skills_json"])
        if method=="GET":
            common=f"""<div class="section-title">{escape(e['category'])} Skill Inventory Form</div>
            <div class="grid g2">{input_field("date_of_joining","Date of Joining",data.get("date_of_joining",e["joining_date"] or ""),typ="date")}{input_field("total_experience","Total Experience",data.get("total_experience",e["total_experience"] or ""))}</div>"""
            if e["category"]=="Worker":
                specific=f"""<div class="grid g2">{select_field("driving_skill","Driving Skill",["Yes","No"],data.get("driving_skill",""))}{select_field("driving_vehicle_type","Driving Vehicle Type",["2-wheeler","3-wheeler","4-wheeler","Heavy Vehicle","Other"],data.get("driving_vehicle_type",""))}{input_field("driving_license","Driving License Number",data.get("driving_license",""))}</div>
                {textarea_field("hobbies","Hobbies",data.get("hobbies",""))}{textarea_field("extra_curricular","Extra Curricular Activities",data.get("extra_curricular",""))}{input_field("languages","Languages Known",data.get("languages",""))}"""
            else:
                specific=f"""{textarea_field("basic_skills","Basic Skills",data.get("basic_skills",""))}{textarea_field("computer_skills","Computer Skills",data.get("computer_skills",""))}{textarea_field("extra_curricular","Extra Curricular Activities",data.get("extra_curricular",""))}{input_field("languages","Languages Known",data.get("languages",""))}
                <div class="section-title">Technical Skills</div><div class="grid g2">
                {input_field("tech1","Technology 1",data.get("tech1",""))}{input_field("tech1_exp","Experience",data.get("tech1_exp",""))}{select_field("tech1_prof","Proficiency",["Beginner","Intermediate","Advanced","Expert"],data.get("tech1_prof",""))}{input_field("tech1_last","Last Used",data.get("tech1_last",""))}
                {input_field("tech2","Technology 2",data.get("tech2",""))}{input_field("tech2_exp","Experience",data.get("tech2_exp",""))}{select_field("tech2_prof","Proficiency",["Beginner","Intermediate","Advanced","Expert"],data.get("tech2_prof",""))}{input_field("tech2_last","Last Used",data.get("tech2_last",""))}
                {input_field("tech3","Technology 3",data.get("tech3",""))}{input_field("tech3_exp","Experience",data.get("tech3_exp",""))}{select_field("tech3_prof","Proficiency",["Beginner","Intermediate","Advanced","Expert"],data.get("tech3_prof",""))}{input_field("tech3_last","Last Used",data.get("tech3_last",""))}</div>"""
            prev=f"""<div class="section-title">Previous Work / Employment Experience</div><div class="grid g2">
            {input_field("prev1_company","Company 1",data.get("prev1_company",""))}{input_field("prev1_year","Year",data.get("prev1_year",""))}{input_field("prev1_designation","Designation",data.get("prev1_designation",""))}{input_field("prev1_duration","Duration",data.get("prev1_duration",""))}{textarea_field("prev1_resp","Responsibilities",data.get("prev1_resp",""))}
            {input_field("prev2_company","Company 2",data.get("prev2_company",""))}{input_field("prev2_year","Year",data.get("prev2_year",""))}{input_field("prev2_designation","Designation",data.get("prev2_designation",""))}{input_field("prev2_duration","Duration",data.get("prev2_duration",""))}{textarea_field("prev2_resp","Responsibilities",data.get("prev2_resp",""))}</div>"""
            form=f"""<form method="post">{csrf_input(sess)}{common}{specific}{prev}<div class="actions"><button>Submit Skills</button><button type="reset" class="btn secondary">Reset</button><a class="btn secondary" href="/employee?id={e['id']}">Back</a></div></form>"""
            return self.send_html(layout("Skill Inventory",f"<div class='card'>{form}</div>",admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))
        f=self.form()
        if not self.check_csrf(sess,f): return self.redirect(f"/employee/skills?id={e['id']}")
        data={k:v.strip() for k,v in f.items() if k!="csrf"}
        db.execute("UPDATE employees SET skills_json=? WHERE id=? AND admin_id=?",(jdumps(data),e["id"],admin["id"]),commit=True)
        audit(admin["id"],"Skills updated",e["code"],employee_name(e)); self.flash(sess,"ok","Skill inventory saved.")
        return self.redirect(f"/employee?id={e['id']}")

    # ---------- Entrepreneur forms ----------
    def entrepreneur_details(self, method):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); data=jload(admin["profile_json"])
        if method=="GET":
            v=lambda k:data.get(k,"")
            form=f"""<form method="post">{csrf_input(sess)}<div class="section-title">Entrepreneur Details Form</div><div class="grid g2">
            {input_field("entrepreneur_id","Entrepreneur ID",admin["entrepreneur_code"] or "")}
            {input_field("surname","Entrepreneur Surname",v("surname"))}{input_field("middle_name","Entrepreneur Middle Name",v("middle_name"))}{input_field("last_name","Entrepreneur Last Name",v("last_name"))}
            {input_field("phone","Phone Number",v("phone"))}{input_field("emergency_contact","Emergency Contact",v("emergency_contact"))}{input_field("emergency_relation","Relation with Entrepreneur",v("emergency_relation"))}
            {input_field("dob","Date of Birth",v("dob"),typ="date")}{input_field("age","Age (automatic)",age_from_dob(v("dob")),attrs="readonly")}{select_field("gender","Gender",["Male","Female","Other"],v("gender"))}</div>
            {textarea_field("temporary_address","Temporary Address",v("temporary_address"))}{textarea_field("permanent_address","Permanent Address",v("permanent_address"))}{textarea_field("hobbies","Hobbies",v("hobbies"))}
            <div class="grid g2">{select_field("religion","Religion",["Hindu","Muslim","Christian","Sikh","Buddhist","Jain","Other","Prefer not to say"],v("religion"))}{select_field("marital_status","Marital Status",["Single","Married","Divorced","Widowed","Other"],v("marital_status"))}{input_field("aadhaar","Aadhaar / National ID",v("aadhaar"))}{input_field("highest_qualification","Highest Qualification",v("highest_qualification"))}{input_field("passing_year","Year of Passing",v("passing_year"))}{input_field("department","Department",v("department"))}{input_field("designation","Designation",v("designation"))}{input_field("joining_date","Date of Joining",v("joining_date"),typ="date")}{input_field("total_experience","Total Experience",v("total_experience"))}</div>
            <div class="actions"><button>Save Entrepreneur Details</button><button type="reset" class="btn secondary">Reset</button></div></form>"""
            tabs='<div class="actions"><a class="btn secondary" href="/entrepreneur/family">Family Information</a><a class="btn secondary" href="/entrepreneur/skills">Skill Inventory</a></div>'
            return self.send_html(layout("Entrepreneur",f"<div class='card'><h1>Entrepreneur Profile</h1>{tabs}{form}</div>",admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))
        f=self.form()
        if not self.check_csrf(sess,f):return self.redirect("/entrepreneur/details")
        data={k:v.strip() for k,v in f.items() if k not in ("csrf","entrepreneur_id","age")}
        db.execute("UPDATE admins SET entrepreneur_code=?,profile_json=? WHERE id=?",(f.get("entrepreneur_id","").strip(),jdumps(data),admin["id"]),commit=True)
        audit(admin["id"],"Entrepreneur details updated",admin["name"],"Profile edited"); self.flash(sess,"ok","Entrepreneur details saved.")
        return self.redirect("/entrepreneur/details")

    def entrepreneur_family(self, method):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); data=jload(admin["family_json"])
        if method=="GET":
            items=[]
            for k,lbl in self.FAMILY_FIELDS:
                if k=="living_with": items.append(select_field(k,lbl,["Yes","No"],data.get(k,"")))
                elif "gender" in k: items.append(select_field(k,lbl,["Male","Female","Other"],data.get(k,"")))
                elif k in self.DATE_KEYS: items.append(input_field(k,lbl,data.get(k,""),typ="date"))
                elif "history" in k: items.append(textarea_field(k,lbl,data.get(k,"")))
                else: items.append(input_field(k,lbl,data.get(k,"")))
            form=f"""<form method="post">{csrf_input(sess)}<div class="section-title">Entrepreneur Family Information Form</div><div class="grid g2">{''.join(items)}</div>
            <div class="section-title">Declaration</div><label><input style="width:auto" type="checkbox" name="declaration" value="yes" {'checked' if data.get('declaration')=='yes' else ''}> I declare the information is true.</label>
            <div class="actions"><button>Submit Family Details</button><button type="reset" class="btn secondary">Reset</button><a class="btn secondary" href="/entrepreneur/details">Back</a></div></form>"""
            return self.send_html(layout("Entrepreneur Family",f"<div class='card'>{form}</div>",admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))
        f=self.form()
        if not self.check_csrf(sess,f):return self.redirect("/entrepreneur/family")
        data={k:f.get(k,"").strip() for k,_ in self.FAMILY_FIELDS};data["declaration"]=f.get("declaration","")
        db.execute("UPDATE admins SET family_json=? WHERE id=?",(jdumps(data),admin["id"]),commit=True);audit(admin["id"],"Entrepreneur family updated",admin["name"],"Family form edited");self.flash(sess,"ok","Entrepreneur family information saved.")
        return self.redirect("/entrepreneur/details")

    def entrepreneur_skills(self, method):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); data=jload(admin["skills_json"])
        if method=="GET":
            form=f"""<form method="post">{csrf_input(sess)}<div class="section-title">Entrepreneur Skill Inventory Form</div>
            <div class="grid g2">{input_field("department","Department",data.get("department",""))}{input_field("designation","Designation",data.get("designation",""))}{input_field("date_of_joining","Date of Joining",data.get("date_of_joining",""),typ="date")}{input_field("total_experience","Total Experience",data.get("total_experience",""))}</div>
            {textarea_field("computer_skills","Computer Skills",data.get("computer_skills",""))}{textarea_field("business_skills","Business Skills",data.get("business_skills",""))}{textarea_field("extra_curricular","Extra Curricular Activities",data.get("extra_curricular",""))}{input_field("languages","Languages Known",data.get("languages",""))}{input_field("programming_languages","Programming Languages Known",data.get("programming_languages",""))}
            <div class="section-title">Technical Skills</div><div class="grid g2">
            {input_field("tech1","Technology 1",data.get("tech1",""))}{input_field("tech1_exp","Experience",data.get("tech1_exp",""))}{select_field("tech1_prof","Proficiency",["Beginner","Intermediate","Advanced","Expert"],data.get("tech1_prof",""))}{input_field("tech1_last","Last Used",data.get("tech1_last",""))}
            {input_field("tech2","Technology 2",data.get("tech2",""))}{input_field("tech2_exp","Experience",data.get("tech2_exp",""))}{select_field("tech2_prof","Proficiency",["Beginner","Intermediate","Advanced","Expert"],data.get("tech2_prof",""))}{input_field("tech2_last","Last Used",data.get("tech2_last",""))}
            {input_field("tech3","Technology 3",data.get("tech3",""))}{input_field("tech3_exp","Experience",data.get("tech3_exp",""))}{select_field("tech3_prof","Proficiency",["Beginner","Intermediate","Advanced","Expert"],data.get("tech3_prof",""))}{input_field("tech3_last","Last Used",data.get("tech3_last",""))}</div>
            <div class="section-title">Previous Experience</div><div class="grid g2">{input_field("prev1_company","Company 1",data.get("prev1_company",""))}{input_field("prev1_year","Year",data.get("prev1_year",""))}{input_field("prev1_designation","Designation",data.get("prev1_designation",""))}{input_field("prev1_duration","Duration",data.get("prev1_duration",""))}{textarea_field("prev1_resp","Responsibilities",data.get("prev1_resp",""))}</div>
            <div class="actions"><button>Submit Skills</button><button type="reset" class="btn secondary">Reset</button><a class="btn secondary" href="/entrepreneur/details">Back</a></div></form>"""
            return self.send_html(layout("Entrepreneur Skills",f"<div class='card'>{form}</div>",admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))
        f=self.form()
        if not self.check_csrf(sess,f):return self.redirect("/entrepreneur/skills")
        data={k:v.strip() for k,v in f.items() if k!="csrf"}
        db.execute("UPDATE admins SET skills_json=? WHERE id=?",(jdumps(data),admin["id"]),commit=True);audit(admin["id"],"Entrepreneur skills updated",admin["name"],"Skill form edited");self.flash(sess,"ok","Entrepreneur skill inventory saved.")
        return self.redirect("/entrepreneur/details")

    # ---------- Attendance / replacement ----------
    def attendance(self, method):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); q=self.query(); work_date=q.get("date",date.today().isoformat())
        emps=db.execute("SELECT * FROM employees WHERE admin_id=? AND active=1 ORDER BY category,surname,last_name",(admin["id"],),all=True)
        if method=="POST":
            f=self.form()
            if not self.check_csrf(sess,f):return self.redirect("/attendance?"+urlencode({"date":work_date}))
            eid=int(f.get("employee_id")); status=f.get("status","Unmarked"); reason=f.get("reason","").strip()
            if status=="Absent" and not reason:
                self.flash(sess,"err","An absence reason is required.")
                return self.redirect("/attendance?"+urlencode({"date":work_date}))
            if status in ("Present","Leave","Unmarked"): reason = reason if status=="Leave" else ""
            existing=db.execute("SELECT id FROM attendance WHERE admin_id=? AND employee_id=? AND work_date=?",(admin["id"],eid,work_date),one=True)
            if existing:
                db.execute("UPDATE attendance SET status=?,reason=?,created_at=? WHERE id=?",(status,reason,now_iso(),existing["id"]),commit=True)
            else:
                db.execute("INSERT INTO attendance(admin_id,employee_id,work_date,status,reason,created_at) VALUES(?,?,?,?,?,?)",(admin["id"],eid,work_date,status,reason,now_iso()),commit=True)
            e=db.execute("SELECT * FROM employees WHERE id=?",(eid,),one=True);audit(admin["id"],"Attendance updated",e["code"],f"{work_date}: {status}. {reason}")
            self.flash(sess,"ok","Attendance saved.")
            if status=="Absent": return self.redirect(f"/replacement?id={eid}&date={work_date}")
            return self.redirect("/attendance?"+urlencode({"date":work_date}))
        rows=[]
        for e in emps:
            a=db.execute("SELECT * FROM attendance WHERE admin_id=? AND employee_id=? AND work_date=?",(admin["id"],e["id"],work_date),one=True)
            st=a["status"] if a else "Unmarked"; rs=a["reason"] if a else ""
            rows.append(f"""<tr><td>{escape(e['code'])}</td><td>{escape(employee_name(e))}</td><td>{escape(e['category'])}</td><td><span class="badge {st.lower()}">{st}</span></td><td>{escape(rs)}</td><td>
            <form method="post" class="grid" style="grid-template-columns:150px 1fr auto">{csrf_input(sess)}<input type="hidden" name="employee_id" value="{e['id']}">
            <select name="status"><option {'selected' if st=='Present' else ''}>Present</option><option {'selected' if st=='Absent' else ''}>Absent</option><option {'selected' if st=='Leave' else ''}>Leave</option><option {'selected' if st=='Unmarked' else ''}>Unmarked</option></select>
            <input name="reason" value="{escape(rs)}" placeholder="Reason required if absent"><button>Save</button></form>
            {f'<a class="small" href="/replacement?id={e["id"]}&date={work_date}">Find replacement</a>' if st=="Absent" else ''}</td></tr>""")
        body=f"""<div style="display:flex;justify-content:space-between;gap:10px;flex-wrap:wrap"><h1>Attendance</h1><form method="get"><input type="date" name="date" value="{escape(work_date)}" onchange="this.form.submit()"></form></div>
        <div class="card scroll"><table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Status</th><th>Reason</th><th>Update</th></tr></thead><tbody>{''.join(rows) or '<tr><td colspan=6>No employees.</td></tr>'}</tbody></table></div>"""
        return self.send_html(layout("Attendance",body,admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))

    def replacement(self):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); q=self.query(); eid=q.get("id"); work_date=q.get("date",date.today().isoformat())
        absent=db.execute("SELECT * FROM employees WHERE id=? AND admin_id=?",(eid,admin["id"]),one=True)
        if not absent:return self.redirect("/attendance")
        a=db.execute("SELECT * FROM attendance WHERE admin_id=? AND employee_id=? AND work_date=?",(admin["id"],absent["id"],work_date),one=True)
        reason=a["reason"] if a else ""
        cands=replacement_candidates(admin["id"],absent,work_date)
        cards=[]
        for idx,(score,e,reasons) in enumerate(cands,1):
            cards.append(f"""<div class="card priority"><div style="display:flex;justify-content:space-between;gap:16px;align-items:start"><div><h3>Priority #{idx}: {escape(employee_name(e))}</h3><p class="muted">{escape(e['code'])} · {escape(e['category'])} · {escape(e['department'])} · {escape(e['designation'])}</p><p>{'<br>'.join(escape(x) for x in reasons) or 'General availability match'}</p></div><div class="score">{score}</div></div>
            <form method="post" action="/replacement/assign">{csrf_input(sess)}<input type="hidden" name="absent_id" value="{absent['id']}"><input type="hidden" name="replacement_id" value="{e['id']}"><input type="hidden" name="work_date" value="{escape(work_date)}"><input type="hidden" name="score" value="{score}">
            <label>Today's handover / work to complete</label><textarea name="task_note" placeholder="Describe the work this person should complete today"></textarea><div class="actions"><button class="btn green">Assign Priority #{idx}</button></div></form></div>""")
        body=f"""<h1>Replacement Priority</h1><div class="card"><h3>Absent employee: {escape(employee_name(absent))}</h3><p><b>Reason:</b> {escape(reason)}</p><p><b>Work:</b> {escape(absent['department'])} · {escape(absent['designation'])}</p><p class="muted">Candidates who are absent or on leave are excluded. Higher score = stronger recorded fit based on designation, department, skills, workforce type and confirmed presence.</p></div>
        <div class="grid" style="margin-top:16px">{''.join(cards) or '<div class="card"><b>No available replacement candidates found.</b></div>'}</div>"""
        return self.send_html(layout("Replacement Priority",body,admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))

    def replacement_assign(self, method):
        sess=login_required(self)
        if not sess:return
        if method!="POST":return self.redirect("/attendance")
        f=self.form()
        if not self.check_csrf(sess,f):return self.redirect("/attendance")
        aid=int(f["absent_id"]); rid=int(f["replacement_id"]); wd=f["work_date"]; score=int(f["score"]); note=f.get("task_note","").strip()
        a=db.execute("SELECT * FROM attendance WHERE admin_id=? AND employee_id=? AND work_date=?",(sess["admin_id"],aid,wd),one=True)
        if not a:return self.redirect("/attendance?"+urlencode({"date":wd}))
        db.execute("UPDATE attendance SET replacement_employee_id=?,replacement_score=?,task_note=? WHERE id=?",(rid,score,note,a["id"]),commit=True)
        ae=db.execute("SELECT * FROM employees WHERE id=?",(aid,),one=True); re_=db.execute("SELECT * FROM employees WHERE id=?",(rid,),one=True)
        audit(sess["admin_id"],"Replacement assigned",ae["code"],f"{employee_name(ae)} -> {employee_name(re_)}; score {score}; {note}")
        self.flash(sess,"ok",f"{employee_name(re_)} assigned as replacement with score {score}.")
        return self.redirect("/attendance?"+urlencode({"date":wd}))

    # ---------- Leaves ----------
    def leaves(self, method):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); emps=db.execute("SELECT * FROM employees WHERE admin_id=? AND active=1 ORDER BY surname,last_name",(admin["id"],),all=True)
        if method=="POST":
            f=self.form()
            if not self.check_csrf(sess,f):return self.redirect("/leaves")
            eid=int(f["employee_id"]); lt=f.get("leave_type","Other"); sd=f.get("start_date",""); ed=f.get("end_date",""); reason=f.get("reason","").strip()
            if not sd or not ed or ed<sd:
                self.flash(sess,"err","Please enter a valid leave date range.");return self.redirect("/leaves")
            db.execute("INSERT INTO leaves(admin_id,employee_id,leave_type,start_date,end_date,reason,status,created_at) VALUES(?,?,?,?,?,?,?,?)",(admin["id"],eid,lt,sd,ed,reason,"Pending",now_iso()),commit=True)
            e=db.execute("SELECT * FROM employees WHERE id=?",(eid,),one=True);audit(admin["id"],"Leave request created",e["code"],f"{lt} {sd} to {ed}")
            self.flash(sess,"ok","Leave request added.");return self.redirect("/leaves")
        leaves=db.execute("""SELECT l.*,e.code,e.surname,e.middle_name,e.last_name FROM leaves l JOIN employees e ON e.id=l.employee_id WHERE l.admin_id=? ORDER BY l.created_at DESC""",(admin["id"],),all=True)
        opts=''.join(f'<option value="{e["id"]}">{escape(e["code"])} - {escape(employee_name(e))}</option>' for e in emps)
        rows=''.join(f"""<tr><td>{escape(r['code'])}</td><td>{escape(' '.join(x for x in [r['surname'],r['middle_name'],r['last_name']] if x))}</td><td>{escape(r['leave_type'])}</td><td>{escape(r['start_date'])} → {escape(r['end_date'])}</td><td>{escape(r['reason'])}</td><td><span class="badge">{escape(r['status'])}</span></td><td>
        <form method="post" action="/leave/status">{csrf_input(sess)}<input type="hidden" name="leave_id" value="{r['id']}"><button name="status" value="Approved" class="btn green">Approve</button> <button name="status" value="Rejected" class="btn danger">Reject</button></form></td></tr>""" for r in leaves)
        body=f"""<h1>Leave Management</h1><div class="card"><h3>New leave request</h3><form method="post">{csrf_input(sess)}<div class="grid g2"><div><label>Employee</label><select name="employee_id" required><option value="">Select</option>{opts}</select></div>{select_field("leave_type","Leave Type",["Casual Leave","Sick Leave","Annual Leave","Emergency Leave","Other"])}{input_field("start_date","Start Date",typ="date",required=True)}{input_field("end_date","End Date",typ="date",required=True)}</div>{textarea_field("reason","Reason")}<div class="actions"><button>Add leave request</button></div></form></div>
        <div class="card scroll" style="margin-top:16px"><table><thead><tr><th>ID</th><th>Name</th><th>Type</th><th>Dates</th><th>Reason</th><th>Status</th><th>Action</th></tr></thead><tbody>{rows or '<tr><td colspan=7>No leave requests.</td></tr>'}</tbody></table></div>"""
        return self.send_html(layout("Leaves",body,admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))

    def leave_status(self, method):
        sess=login_required(self)
        if not sess:return
        if method!="POST":return self.redirect("/leaves")
        f=self.form()
        if not self.check_csrf(sess,f):return self.redirect("/leaves")
        lid=int(f["leave_id"]); status=f.get("status","Pending")
        l=db.execute("SELECT * FROM leaves WHERE id=? AND admin_id=?",(lid,sess["admin_id"]),one=True)
        if l:
            db.execute("UPDATE leaves SET status=? WHERE id=?",(status,lid),commit=True)
            if status=="Approved":
                d=parse_date(l["start_date"]); end=parse_date(l["end_date"])
                if d and end:
                    while d<=end:
                        ex=db.execute("SELECT id FROM attendance WHERE admin_id=? AND employee_id=? AND work_date=?",(sess["admin_id"],l["employee_id"],d.isoformat()),one=True)
                        if ex: db.execute("UPDATE attendance SET status='Leave',reason=? WHERE id=?",(l["reason"],ex["id"]),commit=True)
                        else: db.execute("INSERT INTO attendance(admin_id,employee_id,work_date,status,reason,created_at) VALUES(?,?,?,?,?,?)",(sess["admin_id"],l["employee_id"],d.isoformat(),"Leave",l["reason"],now_iso()),commit=True)
                        d+=timedelta(days=1)
            audit(sess["admin_id"],"Leave status changed",str(lid),status)
        return self.redirect("/leaves")

    # ---------- Audit/export ----------
    def audit_page(self):
        sess=login_required(self)
        if not sess:return
        admin=admin_row(sess["admin_id"]); rows=db.execute("SELECT * FROM audit WHERE admin_id=? ORDER BY id DESC LIMIT 300",(admin["id"],),all=True)
        tr=''.join(f"<tr><td>{escape(r['created_at'])}</td><td>{escape(r['action'])}</td><td>{escape(r['subject'])}</td><td>{escape(r['details'])}</td></tr>" for r in rows)
        body=f"""<h1>Audit Log</h1><div class="card scroll"><table><thead><tr><th>Time</th><th>Action</th><th>Subject</th><th>Details</th></tr></thead><tbody>{tr or '<tr><td colspan=4>No activity yet.</td></tr>'}</tbody></table></div>"""
        return self.send_html(layout("Audit",body,admin=admin,flash_msg=self.take_flash(sess),notifications=get_notifications(admin["id"])))

    def export_csv(self):
        sess=login_required(self)
        if not sess:return
        emps=db.execute("SELECT * FROM employees WHERE admin_id=? ORDER BY category,code",(sess["admin_id"],),all=True)
        out=io.StringIO(); w=csv.writer(out); w.writerow(["Category","ID","Name","Email","Phone","Department","Designation","DOB","Joining Date","Experience"])
        for e in emps:w.writerow([e["category"],e["code"],employee_name(e),e["email"],e["phone"],e["department"],e["designation"],e["dob"],e["joining_date"],e["total_experience"]])
        return self.send_csv(out.getvalue(),"msme_workforce.csv")

if __name__=="__main__":
    print("="*64)
    print(APP_NAME)
    print("Local:   http://127.0.0.1:%s" % PORT)
    print("Network: http://<YOUR-PC-IP>:%s" % PORT)
    print("Database:", "PostgreSQL" if db.backend=="postgres" else DB_PATH)
    print("="*64)
    ThreadingHTTPServer((HOST,PORT),AppHandler).serve_forever()
