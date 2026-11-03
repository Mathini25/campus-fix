# CampusFix

CampusFix is a standalone campus-services web application built with Flask and SQLite. Students and lecturers can report maintenance issues, post lost-and-found notices, and request vehicle stickers. CampusFix is an independent example system: it does not connect to Chania or to any university production service.

## Features

- Student and lecturer self-registration and role-based accounts for technicians, supervisors, and administrators
- Facilities reports for faulty projectors, leaking taps, broken desks, and other campus problems, with location, optional photo, priority, and ticket tracking
- Supervisor assignment and due-date workflow; technician work notes and status changes; reporter feedback and reopening
- Lost-and-found notices, possible-match claims, staff review, and returned-item tracking
- Vehicle registrations, staff approval, unique sticker numbers, and notifications
- Admin management and search for users, categories, buildings, and rooms; audit history
- Filtered reports with CampusFix branding, generated date, organization name, PDF, and Excel exports
- CSRF protection, password hashing and reset, session invalidation, authenticator-based two-factor authentication for administrators/supervisors, and access controls
- Verified SQLite backups, an admin-triggered current backup, an ER diagram, and user/deployment guidance

## Run locally (Windows)

From the project directory in PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000). Flask renders the front end and serves the admin/staff pages; there is no separate front-end build step. Bootstrap styling is loaded from a CDN, so the browser needs internet access to load those styles.

The app initializes `schema.sql` on startup and adds missing columns to an existing database without deleting its records. It seeds sample categories, campus locations, and demonstration requests. Change the sample campus catalog to match the institution.

### Demonstration accounts

These are for local evaluation only; change the passwords before deployment:

| Role | Email | Password |
|---|---|---|
| Administrator | `admin@campusfix.com` | `admin123` |
| Supervisor | `supervisor@campusfix.com` | `supervisor123` |
| Technician | `tech@campusfix.com` | `tech123` |
| Student | `student@campusfix.com` | `student123` |

## How it works

1. A student or lecturer registers and signs in.
2. They submit a maintenance report with a category and campus location, then track the ticket.
3. A supervisor reviews it, assigns an active technician, and sets a priority/deadline.
4. The technician records work and moves the issue through **Assigned**, **In Progress**, and **Resolved**. The reporter receives in-app updates and can confirm/rate the fix or reopen it.
5. From **Campus services**, a user can post a lost/found notice or request a vehicle sticker. Another user can submit a possible item match; staff review matches and sticker applications. Approved stickers receive a unique number.
6. Administrators manage accounts and campus catalog data, inspect audit history, export reports, and download backups.

## Configuration and deployment

See the [user and deployment guide](docs/user_and_deployment_guide.md) for all settings, SMTP password recovery, authenticator enrollment, backup restoration, role workflows, and limitations.

For production, set `CAMPUSFIX_ENV=production` and a long random `CAMPUSFIX_SECRET_KEY`; serve behind HTTPS and set `CAMPUSFIX_COOKIE_SECURE=true`. Configure SMTP to deliver reset links and email notifications. Do not deploy the demonstration accounts with their example passwords.

Key optional environment variables:

| Variable | Purpose |
|---|---|
| `CAMPUSFIX_SECRET_KEY` | Stable, secret Flask session-signing key; required in production |
| `CAMPUSFIX_ENV` | Set to `production` to require the secret key |
| `CAMPUSFIX_COOKIE_SECURE` | Set to `true` when served over HTTPS |
| `CAMPUSFIX_HOST`, `CAMPUSFIX_PORT` | Bind address and port for `python app.py` |
| `CAMPUSFIX_DATABASE_PATH`, `CAMPUSFIX_BACKUP_FOLDER` | Optional database and backup paths |
| `CAMPUSFIX_ORGANIZATION_NAME` | Organization name printed on reports |
| `CAMPUSFIX_SMTP_HOST`, `CAMPUSFIX_SMTP_PORT`, `CAMPUSFIX_SMTP_USER`, `CAMPUSFIX_SMTP_PASSWORD`, `CAMPUSFIX_SMTP_FROM` | SMTP settings for reset emails and notifications |
| `CAMPUSFIX_SHOW_RESET_LINK` | Allow reset links in local demo mode; never enable for production |

Daily backups are created at startup and by the worker when the app is run directly with `python app.py`. The admin **Database backup** link makes a fresh, current snapshot. If deploying through a WSGI server, configure a daily scheduled backup separately. The guide describes a restore procedure.

## Tests

Run the isolated workflow tests with:

```powershell
python -m unittest discover -s tests -v
```

The tests use temporary SQLite databases and exercise CSRF, account/session security, two-factor login, maintenance assignment/resolution/feedback, lost-and-found, vehicle stickers, admin catalogue conflicts, report exports, and backups.

## Project files

- `app.py` — Flask routes and application logic
- `schema.sql` — database schema
- `templates/`, `static/` — server-rendered front end, styles, and brand asset
- `docs/campusfix_er_diagram.md` — downloadable Mermaid ER diagram
- `docs/user_and_deployment_guide.md` — user instructions and deployment configuration
- `tests/test_workflows.py` — isolated integration tests

## Delivery status and limits

The application includes the front end, role-based admin/staff interface, relational database, maintenance and campus-service workflows, reporting, help, and security controls. SMTP delivery, hosting/HTTPS, operational availability, and the course's three-second response target depend on the deployment environment and must be configured or measured there; they cannot be guaranteed by a local demo. CampusFix remains separate from Chania.
