
import os, tempfile, subprocess, time, urllib.request, urllib.parse, http.cookiejar, sys
from pathlib import Path

ROOT=Path(__file__).resolve().parent
db=ROOT/"_test_msme.db"
try: db.unlink()
except FileNotFoundError: pass

env=os.environ.copy()
env["PORT"]="5099"
env["MSME_DB_PATH"]=str(db)
p=subprocess.Popen([sys.executable, str(ROOT/"easy_local.py")], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

# Wait until the server accepts connections (up to 12 seconds).
for _ in range(60):
    try:
        urllib.request.urlopen("http://127.0.0.1:5099/login", timeout=0.5).read()
        break
    except Exception:
        time.sleep(0.2)
else:
    out = p.stdout.read() if p.stdout else ""
    raise RuntimeError("Server did not start. Output:\n" + out)
cj=http.cookiejar.CookieJar()
opener=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

def get(path):
    return opener.open("http://127.0.0.1:5099"+path, timeout=5).read().decode()

def post(path, data):
    return opener.open("http://127.0.0.1:5099"+path, data=urllib.parse.urlencode(data).encode(), timeout=5).read().decode()

try:
    page=get("/signup")
    import re
    csrf=re.search(r'name="csrf" value="([^"]+)"',page).group(1)
    page=post("/signup",{"csrf":csrf,"name":"Test Owner","email":"owner@test.local","business_name":"Test MSME","entrepreneur_code":"ENT001","password":"TestPass123!","confirm":"TestPass123!"})
    assert "Today's workforce" in page

    page=get("/worker/new")
    csrf=re.search(r'name="csrf" value="([^"]+)"',page).group(1)
    post("/worker/new",{
      "csrf":csrf,"category":"Worker","code":"W001","surname":"Ravi","middle_name":"","last_name":"Kumar",
      "email":"","phone":"123","emergency_contact":"","emergency_relation":"","dob":"1995-01-01","gender":"Male",
      "temporary_address":"","permanent_address":"","hobbies":"","religion":"","marital_status":"","aadhaar":"",
      "highest_qualification":"ITI","passing_year":"2015","department":"Production","designation":"Machine Operator",
      "joining_date":"2026-01-01","total_experience":"5 years"
    })
    page=get("/worker/new")
    csrf=re.search(r'name="csrf" value="([^"]+)"',page).group(1)
    post("/worker/new",{
      "csrf":csrf,"category":"Worker","code":"W002","surname":"Suresh","middle_name":"","last_name":"Rao",
      "email":"","phone":"456","emergency_contact":"","emergency_relation":"","dob":"1993-02-02","gender":"Male",
      "temporary_address":"","permanent_address":"","hobbies":"","religion":"","marital_status":"","aadhaar":"",
      "highest_qualification":"ITI","passing_year":"2013","department":"Production","designation":"Machine Operator",
      "joining_date":"2025-01-01","total_experience":"7 years"
    })
    page=get("/attendance")
    csrf=re.search(r'name="csrf" value="([^"]+)"',page).group(1)
    # W001 is first employee id 1 in fresh test db
    page=post("/attendance",{"csrf":csrf,"employee_id":"1","status":"Absent","reason":"Fever"})
    assert "Replacement Priority" in page
    assert "Priority #1" in page
    print("ALL TESTS PASSED")
finally:
    p.terminate()
    try:p.wait(timeout=3)
    except: p.kill()
    try: db.unlink()
    except FileNotFoundError: pass
