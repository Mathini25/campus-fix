import base64
import atexit
import hashlib
import io
import os
import sqlite3
import tempfile
import time
import unittest
import zipfile
from unittest.mock import patch

_bootstrap = tempfile.TemporaryDirectory(prefix='campusfix-test-bootstrap-')
atexit.register(_bootstrap.cleanup)
os.environ['CAMPUSFIX_DATABASE_PATH'] = os.path.join(_bootstrap.name, 'bootstrap.sqlite')
os.environ['CAMPUSFIX_BACKUP_FOLDER'] = os.path.join(_bootstrap.name, 'backups')
import app as campusfix


class CampusFixWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.database_path = os.path.join(self.temp_dir.name, 'test-campusfix.sqlite')
        self.backup_folder = os.path.join(self.temp_dir.name, 'backups')
        os.makedirs(self.backup_folder)
        self.database_patch = patch.object(campusfix, 'DATABASE_PATH', self.database_path)
        self.backup_patch = patch.object(campusfix, 'BACKUP_FOLDER', self.backup_folder)
        self.database_patch.start()
        self.backup_patch.start()
        campusfix.app.config.update(TESTING=True, SECRET_KEY='test-session-secret')
        campusfix.init_db()
        self.client = campusfix.app.test_client()

    def tearDown(self):
        self.database_patch.stop()
        self.backup_patch.stop()
        self.temp_dir.cleanup()

    def csrf_token(self, client):
        with client.session_transaction() as browser_session:
            if browser_session.get('user_id'):
                page = '/dashboard'
            elif browser_session.get('pending_2fa_user_id'):
                page = '/security/two-factor/verify'
            elif browser_session.get('pending_2fa_setup_user_id'):
                page = '/security/two-factor/setup'
            else:
                page = '/login'
        client.get(page)
        with client.session_transaction() as browser_session:
            return browser_session['_csrf_token']

    def post(self, client, path, data=None, **kwargs):
        form_data = dict(data or {})
        form_data['_csrf_token'] = self.csrf_token(client)
        return client.post(path, data=form_data, **kwargs)

    def login(self, client, email, password):
        response = self.post(
            client,
            '/login',
            {'email': email, 'password': password},
        )
        return response

    def user_id(self, email):
        with campusfix.app.app_context():
            return campusfix.get_db().execute(
                'SELECT id FROM users WHERE email = ?',
                (email,),
            ).fetchone()['id']

    def test_csrf_required_and_public_pages_render(self):
        self.assertEqual(self.client.get('/').status_code, 200)
        self.assertEqual(self.client.get('/help').status_code, 200)
        guide = self.client.get('/help/guide')
        self.assertEqual(guide.status_code, 200)
        self.assertIn(b'CampusFix is a standalone', guide.data)
        self.assertEqual(self.client.post('/forgot-password', data={'email': 'nobody@example.test'}).status_code, 400)
        response = self.client.get('/static/campusfix-logo.svg')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'<svg', response.data)

    def test_role_access_logout_and_auth_version_invalidation(self):
        self.login(self.client, 'student@campusfix.com', 'student123')
        self.assertEqual(self.client.get('/dashboard').status_code, 200)
        forbidden = self.client.get('/admin')
        self.assertEqual(forbidden.status_code, 302)
        self.assertIn('/dashboard', forbidden.headers['Location'])

        self.assertEqual(self.client.get('/logout').status_code, 405)
        self.post(self.client, '/logout')
        self.assertEqual(self.client.get('/dashboard').status_code, 302)

        user_client = campusfix.app.test_client()
        self.login(user_client, 'student@campusfix.com', 'student123')
        reset_token = 'known-reset-token-for-test'
        reset_hash = hashlib.sha256(reset_token.encode('utf-8')).hexdigest()
        with campusfix.app.app_context():
            user_id = self.user_id('student@campusfix.com')
            campusfix.get_db().execute(
                'INSERT INTO password_resets (user_id, token_hash, expires_at) VALUES (?, ?, ?)',
                (user_id, reset_hash, time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(time.time() + 1800))),
            )
            campusfix.get_db().commit()
        reset = self.post(
            self.client,
            f'/reset-password/{reset_token}',
            {'password': 'replacement-password-2026'},
        )
        self.assertEqual(reset.status_code, 302)
        self.assertEqual(user_client.get('/dashboard').status_code, 302)

    def test_authenticator_login_and_five_attempt_limit(self):
        secret = base64.b32encode(b'\x01' * 20).decode('ascii').rstrip('=')
        with campusfix.app.app_context():
            campusfix.get_db().execute(
                'UPDATE users SET two_factor_enabled = 1, two_factor_secret = ? WHERE email = ?',
                (secret, 'admin@campusfix.com'),
            )
            campusfix.get_db().commit()

        client = campusfix.app.test_client()
        response = self.login(client, 'admin@campusfix.com', 'admin123')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/security/two-factor/verify', response.headers['Location'])
        for attempt in range(4):
            response = self.post(client, '/security/two-factor/verify', {'code': '000000'})
            self.assertIn(response.status_code, (200, 302))
        with client.session_transaction() as browser_session:
            self.assertEqual(browser_session.get('pending_2fa_attempts'), 4)
        response = self.post(client, '/security/two-factor/verify', {'code': '000000'})
        self.assertEqual(response.status_code, 302)
        with client.session_transaction() as browser_session:
            self.assertNotIn('pending_2fa_user_id', browser_session)

        client = campusfix.app.test_client()
        self.login(client, 'admin@campusfix.com', 'admin123')
        code = campusfix.totp_code(secret)
        verified = self.post(client, '/security/two-factor/verify', {'code': code})
        self.assertEqual(verified.status_code, 302)
        self.assertEqual(client.get('/admin').status_code, 200)

    def test_maintenance_assignment_resolution_and_reporter_feedback(self):
        self.login(self.client, 'student@campusfix.com', 'student123')
        category_id = self.get_id('categories', 'name', 'Plumbing')
        building_id = self.get_id('buildings', 'name', 'Main Library')
        room_id = self.get_room_id(building_id, 'L201')
        created = self.post(
            self.client,
            '/issues/new',
            {
                'category_id': str(category_id),
                'building_id': str(building_id),
                'room_id': str(room_id),
                'title': 'Test leaking tap',
                'description': 'The test tap is leaking and needs repair.',
                'priority': 'High',
            },
        )
        self.assertEqual(created.status_code, 302)
        issue_id = self.get_id('issues', 'title', 'Test leaking tap')
        technician_id = self.user_id('tech@campusfix.com')

        supervisor = campusfix.app.test_client()
        self.login(supervisor, 'supervisor@campusfix.com', 'supervisor123')
        assigned = self.post(
            supervisor,
            f'/issues/{issue_id}/assign',
            {
                'technician_id': str(technician_id),
                'priority': 'High',
                'due_date': '2030-01-01',
            },
        )
        self.assertEqual(assigned.status_code, 302)

        technician = campusfix.app.test_client()
        self.login(technician, 'tech@campusfix.com', 'tech123')
        self.post(
            technician,
            f'/issues/{issue_id}/status',
            {'status': 'In Progress', 'work_note': 'Inspection started.'},
        )
        self.post(
            technician,
            f'/issues/{issue_id}/status',
            {'status': 'Resolved', 'work_note': 'Replaced the faulty tap.'},
        )
        with campusfix.app.app_context():
            issue = campusfix.get_db().execute(
                'SELECT status, due_date FROM issues WHERE id = ?',
                (issue_id,),
            ).fetchone()
            logs = campusfix.get_db().execute(
                'SELECT COUNT(*) FROM work_logs WHERE assignment_id IN (SELECT id FROM assignments WHERE issue_id = ?)',
                (issue_id,),
            ).fetchone()[0]
        self.assertEqual(issue['status'], 'Resolved')
        self.assertEqual(issue['due_date'], '2030-01-01')
        self.assertEqual(logs, 2)

        confirmed = self.post(
            self.client,
            f'/issues/{issue_id}/feedback',
            {'action': 'confirm', 'rating': '5', 'comment': 'Repair confirmed.'},
        )
        self.assertEqual(confirmed.status_code, 302)
        with campusfix.app.app_context():
            status = campusfix.get_db().execute(
                'SELECT status FROM issues WHERE id = ?',
                (issue_id,),
            ).fetchone()['status']
        self.assertEqual(status, 'Closed')

    def test_lost_found_claim_vehicle_sticker_and_service_notifications(self):
        self.login(self.client, 'student@campusfix.com', 'student123')
        self.post(
            self.client,
            '/services/lost-found',
            {
                'item_type': 'Lost',
                'item_name': 'Blue notebook',
                'description': 'Blue notebook with a name written inside.',
                'item_category': 'Books',
                'location': 'Main Library',
                'date_occurred': '2026-11-01',
                'contact_phone': '',
            },
        )
        item_id = self.get_id('lost_found_items', 'item_name', 'Blue notebook')

        lecturer = campusfix.app.test_client()
        self.post(
            lecturer,
            '/register',
            {
                'first_name': 'Test',
                'last_name': 'Lecturer',
                'email': 'lecturer@example.test',
                'password': 'lecturer-password-2026',
                'role': 'lecturer',
            },
        )
        self.login(lecturer, 'lecturer@example.test', 'lecturer-password-2026')
        self.post(
            lecturer,
            f'/services/lost-found/{item_id}/claim',
            {'message': 'I found a notebook matching this description.'},
        )
        claim_id = self.get_id('lost_found_claims', 'item_id', item_id)

        supervisor = campusfix.app.test_client()
        self.login(supervisor, 'supervisor@campusfix.com', 'supervisor123')
        self.post(
            supervisor,
            f'/services/claims/{claim_id}/review',
            {'decision': 'Approved'},
        )
        self.post(
            self.client,
            f'/services/lost-found/{item_id}/status',
            {'status': 'Returned'},
        )
        with campusfix.app.app_context():
            item_status = campusfix.get_db().execute(
                'SELECT status FROM lost_found_items WHERE id = ?',
                (item_id,),
            ).fetchone()['status']
        self.assertEqual(item_status, 'Returned')

        self.post(
            self.client,
            '/services/vehicles',
            {
                'registration_number': 'KAA 123A',
                'make': 'Toyota',
                'model': 'Corolla',
                'colour': 'White',
                'vehicle_type': 'Car',
            },
        )
        vehicle_id = self.get_id('vehicle_registrations', 'registration_number', 'KAA 123A')
        self.post(
            supervisor,
            f'/services/vehicles/{vehicle_id}/review',
            {'decision': 'Approved'},
        )
        with campusfix.app.app_context():
            vehicle = campusfix.get_db().execute(
                'SELECT status, sticker_number FROM vehicle_registrations WHERE id = ?',
                (vehicle_id,),
            ).fetchone()
            notification_count = campusfix.get_db().execute(
                'SELECT COUNT(*) FROM service_notifications WHERE user_id = ?',
                (self.user_id('student@campusfix.com'),),
            ).fetchone()[0]
        self.assertEqual(vehicle['status'], 'Approved')
        self.assertTrue(vehicle['sticker_number'].startswith('CF-ST-'))
        self.assertGreaterEqual(notification_count, 2)

    def test_admin_catalog_conflicts_reports_and_manual_backup(self):
        self.login(self.client, 'admin@campusfix.com', 'admin123')
        response = self.post(
            self.client,
            '/admin',
            {'action': 'add_category', 'name': 'Test Category'},
        )
        self.assertEqual(response.status_code, 302)
        category_id = self.get_id('categories', 'name', 'Test Category')
        conflict = self.post(
            self.client,
            '/admin',
            {
                'action': 'edit_category',
                'category_id': str(category_id),
                'name': 'Electrical',
            },
        )
        self.assertEqual(conflict.status_code, 302)
        with campusfix.app.app_context():
            category_name = campusfix.get_db().execute(
                'SELECT name FROM categories WHERE id = ?',
                (category_id,),
            ).fetchone()['name']
        self.assertEqual(category_name, 'Test Category')

        self.assertEqual(self.client.get('/reports').status_code, 200)
        pdf = self.client.get('/reports/export/pdf')
        excel = self.client.get('/reports/export/xlsx')
        self.assertEqual(pdf.status_code, 200)
        self.assertTrue(pdf.data.startswith(b'%PDF-'))
        self.assertEqual(excel.status_code, 200)
        self.assertTrue(excel.data.startswith(b'PK'))
        with zipfile.ZipFile(io.BytesIO(excel.data)) as workbook:
            logo_files = [name for name in workbook.namelist() if name.startswith('xl/media/')]
            self.assertTrue(logo_files)
            self.assertTrue(workbook.read(logo_files[0]).startswith(b'\x89PNG\r\n\x1a\n'))

        backup = self.client.get('/admin/backup')
        self.assertEqual(backup.status_code, 200)
        self.assertTrue(backup.data.startswith(b'SQLite format 3\x00'))
        self.assertIn('campusfix-manual-', backup.headers['Content-Disposition'])
        backup.close()

    def get_id(self, table, column, value):
        allowed = {
            'categories': {'name'},
            'buildings': {'name'},
            'issues': {'title'},
            'lost_found_items': {'item_name'},
            'lost_found_claims': {'item_id'},
            'vehicle_registrations': {'registration_number'},
        }
        self.assertIn(column, allowed.get(table, set()))
        with campusfix.app.app_context():
            row = campusfix.get_db().execute(
                f'SELECT id FROM {table} WHERE {column} = ? ORDER BY id DESC LIMIT 1',
                (value,),
            ).fetchone()
            self.assertIsNotNone(row)
            return row['id']

    def get_room_id(self, building_id, room_number):
        with campusfix.app.app_context():
            return campusfix.get_db().execute(
                'SELECT id FROM rooms WHERE building_id = ? AND room_number = ?',
                (building_id, room_number),
            ).fetchone()['id']


if __name__ == '__main__':
    unittest.main()
