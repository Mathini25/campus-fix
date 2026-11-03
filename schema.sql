PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('student', 'lecturer', 'technician', 'supervisor', 'admin')),
    phone TEXT,
    two_factor_enabled INTEGER NOT NULL DEFAULT 0,
    two_factor_secret TEXT,
    auth_version INTEGER NOT NULL DEFAULT 0,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
);

CREATE TABLE IF NOT EXISTS buildings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS rooms (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    building_id INTEGER NOT NULL,
    room_number TEXT NOT NULL,
    UNIQUE(building_id, room_number),
    FOREIGN KEY(building_id) REFERENCES buildings(id)
);

CREATE TABLE IF NOT EXISTS issues (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ticket_number TEXT NOT NULL UNIQUE,
    reporter_id INTEGER NOT NULL,
    category_id INTEGER NOT NULL,
    building_id INTEGER NOT NULL,
    room_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    priority TEXT NOT NULL DEFAULT 'Medium',
    status TEXT NOT NULL DEFAULT 'Pending',
    photo_url TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    due_date TEXT,
    resolved_at TEXT,
    reporter_rating INTEGER,
    reporter_comment TEXT,
    FOREIGN KEY(reporter_id) REFERENCES users(id),
    FOREIGN KEY(category_id) REFERENCES categories(id),
    FOREIGN KEY(building_id) REFERENCES buildings(id),
    FOREIGN KEY(room_id) REFERENCES rooms(id)
);

CREATE TABLE IF NOT EXISTS assignments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id INTEGER NOT NULL,
    technician_id INTEGER NOT NULL,
    supervisor_id INTEGER NOT NULL,
    assigned_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'Assigned',
    FOREIGN KEY(issue_id) REFERENCES issues(id),
    FOREIGN KEY(technician_id) REFERENCES users(id),
    FOREIGN KEY(supervisor_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS work_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assignment_id INTEGER NOT NULL,
    technician_id INTEGER NOT NULL,
    note TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(assignment_id) REFERENCES assignments(id),
    FOREIGN KEY(technician_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    issue_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    is_read INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(user_id) REFERENCES users(id),
    FOREIGN KEY(issue_id) REFERENCES issues(id)
);

CREATE TABLE IF NOT EXISTS feedback (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    issue_id INTEGER NOT NULL UNIQUE,
    rating INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
    comment TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(issue_id) REFERENCES issues(id)
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    action TEXT NOT NULL,
    details TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS lost_found_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reference_number TEXT NOT NULL UNIQUE,
    reporter_id INTEGER NOT NULL,
    item_type TEXT NOT NULL CHECK(item_type IN ('Lost', 'Found')),
    item_name TEXT NOT NULL,
    description TEXT NOT NULL,
    category TEXT NOT NULL,
    location TEXT NOT NULL,
    date_occurred TEXT NOT NULL,
    contact_phone TEXT,
    status TEXT NOT NULL DEFAULT 'Open' CHECK(status IN ('Open', 'Matched', 'Returned', 'Closed')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(reporter_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS lost_found_claims (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    item_id INTEGER NOT NULL,
    claimant_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Approved', 'Rejected')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    reviewer_id INTEGER,
    UNIQUE(item_id, claimant_id),
    FOREIGN KEY(item_id) REFERENCES lost_found_items(id),
    FOREIGN KEY(claimant_id) REFERENCES users(id),
    FOREIGN KEY(reviewer_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS vehicle_registrations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    registration_number TEXT NOT NULL UNIQUE COLLATE NOCASE,
    make TEXT NOT NULL,
    model TEXT NOT NULL,
    colour TEXT NOT NULL,
    vehicle_type TEXT NOT NULL DEFAULT 'Car',
    status TEXT NOT NULL DEFAULT 'Pending' CHECK(status IN ('Pending', 'Approved', 'Rejected')),
    sticker_number TEXT UNIQUE,
    submitted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TEXT,
    reviewer_id INTEGER,
    FOREIGN KEY(owner_id) REFERENCES users(id),
    FOREIGN KEY(reviewer_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS service_notifications (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    target_url TEXT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    read_at TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_lost_found_items_status_created
    ON lost_found_items(status, created_at);
CREATE INDEX IF NOT EXISTS idx_lost_found_items_reporter
    ON lost_found_items(reporter_id, created_at);
CREATE INDEX IF NOT EXISTS idx_lost_found_claims_status
    ON lost_found_claims(status, created_at);
CREATE INDEX IF NOT EXISTS idx_vehicle_registrations_owner
    ON vehicle_registrations(owner_id, submitted_at);
CREATE INDEX IF NOT EXISTS idx_vehicle_registrations_status
    ON vehicle_registrations(status, submitted_at);
CREATE INDEX IF NOT EXISTS idx_password_resets_user_expiry
    ON password_resets(user_id, expires_at);
CREATE INDEX IF NOT EXISTS idx_service_notifications_user_created
    ON service_notifications(user_id, created_at);
CREATE INDEX IF NOT EXISTS idx_issues_status_created
    ON issues(status, created_at);
CREATE INDEX IF NOT EXISTS idx_assignments_technician_status
    ON assignments(technician_id, status);
