# CampusFix User and Deployment Guide

CampusFix is a standalone campus-services application. It has no connection to Chania or to a university production system.

## Roles and everyday use

| Role | Main capabilities |
|---|---|
| Student / Lecturer | Report and track maintenance issues; submit feedback or reopen a resolved issue; post lost/found notices and possible matches; request a vehicle sticker |
| Technician | See assigned maintenance tasks, record work notes, and update work status |
| Supervisor | Review maintenance issues, assign technicians and due dates, review possible lost-item matches, and approve/reject vehicle requests |
| Administrator | Manage accounts and campus catalogues, review audit history, use reports, and download a database backup |

### Maintenance request

1. Register as a student or lecturer and sign in.
2. On the dashboard, choose a category, building, room, priority, title, and description. Attach an optional JPG, PNG, or WebP photo.
3. Keep the ticket number to look up the issue. A supervisor assigns an active technician and may set a due date.
4. The technician records notes and progresses the ticket through **Assigned**, **In Progress**, and **Resolved**.
5. The reporter can confirm and rate the fix, or reopen a resolved issue if work is incomplete.

### Lost property and vehicle stickers

Open **Campus services** to post a lost/found notice with its date and location. Other students/lecturers may submit a possible match. Staff review the claim; the notice owner can mark it returned after staff approve a match.

Students and lecturers can submit a vehicle registration, make, model, colour, and vehicle type. A supervisor or administrator reviews the request. Approval generates a CampusFix sticker number; the requester sees the result and receives an in-app notification.

## Local setup

In PowerShell, from the project directory:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Visit `http://127.0.0.1:5000`. The app creates or migrates `campusfix.db` and seeds demonstration data. Bootstrap is loaded from a CDN; internet access is needed for the full styling.

## Environment settings

Set environment variables in the same PowerShell window before starting the application:

```powershell
$env:CAMPUSFIX_SECRET_KEY = "<long-random-secret>"
$env:CAMPUSFIX_ENV = "production"
$env:CAMPUSFIX_COOKIE_SECURE = "true"
python app.py
```

Generate a key with `python -c "import secrets; print(secrets.token_hex(32))"`. Keep it out of source control. `CAMPUSFIX_COOKIE_SECURE=true` requires HTTPS; do not use it for plain local HTTP.

| Variable | Default / behavior |
|---|---|
| `CAMPUSFIX_SECRET_KEY` | Random per-process key in local mode; must be supplied in production so sessions survive restarts |
| `CAMPUSFIX_ENV` | Set to `production` to require `CAMPUSFIX_SECRET_KEY` |
| `CAMPUSFIX_COOKIE_SECURE` | `false`; set to `true` only when HTTPS is configured |
| `CAMPUSFIX_HOST` | `127.0.0.1`; use a trusted reverse proxy/host configuration for deployment |
| `CAMPUSFIX_PORT` | `5000` |
| `CAMPUSFIX_DATABASE_PATH` | `<project directory>/campusfix.db` |
| `CAMPUSFIX_BACKUP_FOLDER` | `<project directory>/backups` |
| `CAMPUSFIX_ORGANIZATION_NAME` | `CampusFix Campus Services`; included on reports |
| `CAMPUSFIX_SMTP_HOST` | Unset; without SMTP, reset-email delivery is unavailable |
| `CAMPUSFIX_SMTP_PORT` | `587` |
| `CAMPUSFIX_SMTP_USER`, `CAMPUSFIX_SMTP_PASSWORD` | Optional SMTP credentials |
| `CAMPUSFIX_SMTP_FROM` | SMTP user or `campusfix@localhost` |
| `CAMPUSFIX_SHOW_RESET_LINK` | Unset; set to `true` only for local demo use to expose reset links in the UI/log |

SMTP example (use a provider-specific app password, not a personal account password):

```powershell
$env:CAMPUSFIX_SMTP_HOST = "smtp.example.edu"
$env:CAMPUSFIX_SMTP_PORT = "587"
$env:CAMPUSFIX_SMTP_USER = "campusfix@example.edu"
$env:CAMPUSFIX_SMTP_PASSWORD = "<smtp-app-password>"
$env:CAMPUSFIX_SMTP_FROM = "campusfix@example.edu"
```

Password reset tokens are random, stored as hashes, expire after 30 minutes, and are single use. In local development, set `CAMPUSFIX_SHOW_RESET_LINK=true` to see a reset link without an SMTP server. Never enable this setting in production.

## Account security

- Passwords are stored as salted hashes. Registration, admin-created accounts, and password resets require at least 10 characters.
- State-changing forms require a CSRF token. Sessions use HTTP-only, SameSite cookies and role checks are verified against the current database account.
- Password reset, password changes, and account deactivation invalidate existing sessions.
- Administrators and supervisors can enroll an authenticator app from **Security**. Admins can require enrollment. Save the secret securely; the secret can generate login codes.
- Change or remove the demonstration passwords before using real personal data.

## Backups and restore

- A daily database snapshot is created at startup. When started with `python app.py`, a background worker checks for a new daily snapshot.
- The administrator **Database backup** action creates and downloads a fresh SQLite snapshot; the snapshot is integrity-checked before delivery.
- When using a WSGI server instead of `python app.py`, configure an external daily scheduled backup because the in-process worker is started only by the direct-run entry point.
- Keep backups access-controlled and outside any publicly served static directory.

To restore: stop CampusFix; copy the current database to a safe location; copy a verified `.sqlite` backup to the configured database path (named `campusfix.db` by default); then start CampusFix and check the dashboard and reports. Keep the original file until the restored instance has been verified.

## Tests

Run:

```powershell
python -m unittest discover -s tests -v
```

The integration suite creates isolated temporary databases and does not use the project database.

## Deployment and acceptance limits

Use a production WSGI server behind HTTPS, configure a stable secret, SMTP, backups, and access-controlled storage, and remove/change the sample accounts. SQLite is intended for a local demonstration or a single application host; use a managed database and deployment review before serving larger or multi-host workloads.

Hosting, SMTP delivery, HTTPS, term-time availability, and the guideline's three-second response target depend on the actual deployment and workload. Measure response times on the target network and establish uptime/backup monitoring as operational tasks; the local application cannot certify those conditions.
