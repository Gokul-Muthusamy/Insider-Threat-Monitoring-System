"""
Automated tests for the Insider Threat Monitoring System.
Run with: python -m pytest tests/ -v
"""
import json
import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app import create_app
from app.models import db, User, Activity, Alert, SimulatedFile
from app.config import Config


class TestConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


@pytest.fixture
def app():
    app = create_app(TestConfig)
    with app.app_context():
        yield app


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def runner(app):
    return app.test_cli_runner()


# --- Authentication Tests ---

class TestAuth:
    def test_login_page_loads(self, client):
        response = client.get('/login')
        assert response.status_code == 200
        assert b'Insider Threat Monitor' in response.data

    def test_login_success_admin(self, client):
        response = client.post('/login', data={
            'username': 'Pranav',
            'password': '123'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Security Dashboard' in response.data or b'Dashboard' in response.data

    def test_login_success_employee(self, client):
        response = client.post('/login', data={
            'username': 'Gokul',
            'password': '123'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Welcome' in response.data or b'Workspace' in response.data

    def test_login_failure(self, client):
        response = client.post('/login', data={
            'username': 'Gokul',
            'password': 'wrong'
        }, follow_redirects=True)
        assert response.status_code == 200
        assert b'Invalid' in response.data

    def test_logout(self, client):
        client.post('/login', data={'username': 'Gokul', 'password': '123'})
        response = client.get('/logout', follow_redirects=True)
        assert response.status_code == 200
        assert b'Sign In' in response.data or b'Login' in response.data


# --- Authorization Tests ---

class TestAuthorization:
    def test_employee_cannot_access_admin(self, client):
        client.post('/login', data={'username': 'Gokul', 'password': '123'})
        response = client.get('/admin/')
        assert response.status_code == 403

    def test_admin_cannot_access_employee(self, client):
        client.post('/login', data={'username': 'Pranav', 'password': '123'})
        response = client.get('/employee/')
        assert response.status_code == 403

    def test_unauthenticated_redirect(self, client):
        response = client.get('/employee/')
        assert response.status_code == 302

    def test_admin_api_blocked_for_employee(self, client):
        client.post('/login', data={'username': 'Gokul', 'password': '123'})
        response = client.get('/api/chart/risk-comparison')
        assert response.status_code == 403


# --- Detection Engine Tests ---

class TestDetection:
    def test_failed_login_detection(self, client, app):
        """Test that repeated failed logins generate alerts."""
        with app.app_context():
            # Login with wrong password multiple times
            for i in range(5):
                client.post('/login', data={'username': 'Gokul', 'password': 'wrong'})

            # Check alerts were created
            alerts = Alert.query.filter_by(alert_type='repeated_auth_failure').all()
            assert len(alerts) > 0

    def test_bulk_download_detection(self, client, app):
        """Test bulk download scenario triggers alert."""
        client.post('/login', data={'username': 'Gokul', 'password': '123'})

        with app.app_context():
            response = client.post('/api/scenario/bulk-download')
            data = json.loads(response.data)
            assert data['success'] == True
            assert len(data['alerts']) > 0

    def test_bulk_share_detection(self, client, app):
        """Test bulk share scenario triggers alert."""
        client.post('/login', data={'username': 'Bharath', 'password': '123'})

        with app.app_context():
            response = client.post('/api/scenario/bulk-share')
            data = json.loads(response.data)
            assert data['success'] == True
            assert len(data['alerts']) > 0

    def test_sensitive_access_detection(self, client, app):
        """Test sensitive file access triggers alert."""
        client.post('/login', data={'username': 'Gokul', 'password': '123'})

        with app.app_context():
            response = client.post('/api/scenario/sensitive-access')
            data = json.loads(response.data)
            assert data['success'] == True
            assert len(data['alerts']) > 0

    def test_large_export_detection(self, client, app):
        """Test large data export triggers alert."""
        client.post('/login', data={'username': 'Bharath', 'password': '123'})

        with app.app_context():
            response = client.post('/api/scenario/large-export')
            data = json.loads(response.data)
            assert data['success'] == True
            assert len(data['alerts']) > 0

    def test_risk_score_increases(self, client, app):
        """Test that risk score increases after suspicious activity."""
        client.post('/login', data={'username': 'Gokul', 'password': '123'})

        with app.app_context():
            user = User.query.filter_by(username='Gokul').first()
            initial_score = user.risk_score

            client.post('/api/scenario/bulk-download')

            db.session.refresh(user)
            assert user.risk_score > initial_score


# --- Database Tests ---

class TestDatabase:
    def test_users_seeded(self, app):
        with app.app_context():
            users = User.query.all()
            assert len(users) == 3

            pranav = User.query.filter_by(username='Pranav').first()
            assert pranav is not None
            assert pranav.is_admin()

            gokul = User.query.filter_by(username='Gokul').first()
            assert gokul is not None
            assert not gokul.is_admin()
            assert gokul.department == 'Finance'
            assert gokul.shift_start == '20:00'
            assert gokul.shift_end == '04:00'

    def test_files_seeded(self, app):
        with app.app_context():
            files = SimulatedFile.query.all()
            assert len(files) >= 15

            restricted = SimulatedFile.query.filter_by(sensitivity='restricted').all()
            assert len(restricted) > 0

    def test_password_hashing(self, app):
        with app.app_context():
            user = User.query.filter_by(username='Gokul').first()
            assert user.password_hash != '123'
            assert user.check_password('123')
            assert not user.check_password('wrong')


# --- Admin Functionality Tests ---

class TestAdminFunctions:
    def test_admin_dashboard(self, client):
        client.post('/login', data={'username': 'Pranav', 'password': '123'})
        response = client.get('/admin/')
        assert response.status_code == 200
        assert b'Dashboard' in response.data

    def test_admin_alerts_page(self, client):
        client.post('/login', data={'username': 'Pranav', 'password': '123'})
        response = client.get('/admin/alerts')
        assert response.status_code == 200

    def test_admin_employees_page(self, client):
        client.post('/login', data={'username': 'Pranav', 'password': '123'})
        response = client.get('/admin/employees')
        assert response.status_code == 200
        assert b'Gokul' in response.data
        assert b'Bharath' in response.data

    def test_admin_audit_log(self, client):
        client.post('/login', data={'username': 'Pranav', 'password': '123'})
        response = client.get('/admin/audit-log')
        assert response.status_code == 200

    def test_alert_investigation_update(self, client, app):
        """Test admin can update alert status and add notes."""
        # First generate an alert
        client.post('/login', data={'username': 'Gokul', 'password': '123'})
        client.post('/api/scenario/bulk-download')
        client.get('/logout')

        # Login as admin
        client.post('/login', data={'username': 'Pranav', 'password': '123'})

        with app.app_context():
            alert = Alert.query.first()
            if alert:
                response = client.post(f'/admin/alerts/{alert.id}/update', data={
                    'status': 'investigating',
                    'investigation_notes': 'Looking into this alert'
                }, follow_redirects=True)
                assert response.status_code == 200

                db.session.refresh(alert)
                assert alert.status == 'investigating'
                assert 'Looking into this alert' in alert.investigation_notes


# --- Employee Functionality Tests ---

class TestEmployeeFunctions:
    def test_employee_workspace(self, client):
        client.post('/login', data={'username': 'Gokul', 'password': '123'})
        response = client.get('/employee/')
        assert response.status_code == 200

    def test_employee_file_browser(self, client):
        client.post('/login', data={'username': 'Gokul', 'password': '123'})
        response = client.get('/employee/files')
        assert response.status_code == 200

    def test_employee_activity_log(self, client):
        client.post('/login', data={'username': 'Gokul', 'password': '123'})
        response = client.get('/employee/activity')
        assert response.status_code == 200

    def test_employee_profile(self, client):
        client.post('/login', data={'username': 'Gokul', 'password': '123'})
        response = client.get('/employee/profile')
        assert response.status_code == 200
        assert b'Finance' in response.data

    def test_file_action_download(self, client, app):
        """Test employee can download files."""
        client.post('/login', data={'username': 'Gokul', 'password': '123'})

        with app.app_context():
            file = SimulatedFile.query.first()
            response = client.post('/employee/files/action', data={
                'action': 'access',
                'file_ids': [str(file.id)]
            }, follow_redirects=True)
            assert response.status_code == 200


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
