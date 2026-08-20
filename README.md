
# MSME Pro Workforce Planner — Complete Rebuilt Edition

This project is designed to run locally with only Python's standard library.

## Easiest Windows run

1. Extract the ZIP.
2. Open the extracted folder.
3. Double-click `run_easy_windows.bat`.
4. Open `http://127.0.0.1:5000`
5. Create an entrepreneur account.

No venv and no pip install are required for the default local SQLite mode.

## What is included

- Entrepreneur create account, login, forgot password, reset password.
- Strong scrypt password hashing.
- Duplicate-email protection.
- Login lockout after repeated failed attempts.
- Session timeout and HttpOnly/SameSite session cookie.
- CSRF token protection for write forms.
- Separate data workspace per entrepreneur.
- Staff Details form.
- Staff Family Information form.
- Staff Skill Inventory form.
- Worker Details form.
- Worker Family Information form.
- Worker Skill Inventory form.
- Entrepreneur Details form.
- Entrepreneur Family Information form.
- Entrepreneur Skill Inventory form.
- Edit / rewrite and delete options.
- Today's workforce counts: Total, Present, Absent, Leave, Unmarked.
- Search and filters.
- Attendance with mandatory absence reason.
- Replacement Priority engine for absent workers/staff.
- Leave request, approval and rejection.
- Birthday and work-anniversary notifications.
- Dashboard charts for workforce type, attendance, departments and monthly attendance.
- Audit log.
- CSV export.
- Mobile responsive layout.

## Replacement Priority

When an employee is absent, the system ranks available replacements.

Scoring:
- Same designation: +40
- Same department: +25
- Recorded skill overlap: up to +25
- Same workforce type (Staff/Worker): +5
- Confirmed present today: +5

Employees already marked Absent or Leave are excluded.

The entrepreneur chooses the final replacement and can enter a handover/task note for today's work.

## Phone access on same Wi-Fi

Keep the program running, find your PC IPv4 address with:

    ipconfig

Then on your phone open:

    http://YOUR-PC-IP:5000

Example:

    http://192.168.1.15:5000

## PostgreSQL / online deployment

Local mode uses SQLite automatically.

For PostgreSQL:
1. Install the optional driver:
   `py -m pip install -r requirements-postgres.txt`
2. Set:
   `DATABASE_URL=postgresql://...`
3. Start:
   `py easy_local.py`

For hosted deployment, set `PRODUCTION=1` so session cookies use the Secure flag.

## Notes

The forgot-password page intentionally displays a reset link directly in demo/local mode. For a production company deployment, connect an email provider and send the token by email instead of displaying it.


## Separate Details Forms

The rebuilt version now has separate entry pages:

- `/worker/new` → Worker Details Form
- `/staff/new` → Staff Details Form
- `/entrepreneur/details` → Entrepreneur Details Form

The Worker and Staff forms are not combined on one screen. Each opens as its own dedicated page. Their Family and Skills forms remain separate as well.
