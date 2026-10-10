"""
Detection engine for identifying suspicious insider activities.
Uses rule-based detection with optional IsolationForest ML enhancement.
"""
import json
from datetime import datetime, timedelta
from .models import db, Activity, Alert, User


class DetectionEngine:
    """Core detection engine with configurable thresholds."""

    def __init__(self, app=None):
        self.app = app
        self.thresholds = {
            'bulk_download': 5,
            'bulk_share': 5,
            'failed_login': 3,
            'large_export_mb': 50,
            'risk_high': 70,
            'risk_medium': 40,
        }
        if app:
            self.init_app(app)

    def init_app(self, app):
        self.app = app
        self.thresholds['bulk_download'] = app.config.get('BULK_DOWNLOAD_THRESHOLD', 5)
        self.thresholds['bulk_share'] = app.config.get('BULK_SHARE_THRESHOLD', 5)
        self.thresholds['failed_login'] = app.config.get('FAILED_LOGIN_THRESHOLD', 3)
        self.thresholds['large_export_mb'] = app.config.get('LARGE_EXPORT_SIZE_MB', 50)
        self.thresholds['risk_high'] = app.config.get('RISK_SCORE_HIGH', 70)
        self.thresholds['risk_medium'] = app.config.get('RISK_SCORE_MEDIUM', 40)

    def analyze_activity(self, activity):
        """Analyze a single activity for suspicious patterns. Returns list of alerts."""
        alerts = []

        if activity.activity_type == 'login_failure':
            alert = self._check_failed_logins(activity)
            if alert:
                alerts.append(alert)

        if activity.activity_type == 'login_success':
            alert = self._check_after_hours_login(activity)
            if alert:
                alerts.append(alert)

        if activity.activity_type == 'bulk_download':
            alert = self._check_bulk_download(activity)
            if alert:
                alerts.append(alert)

        if activity.activity_type == 'bulk_share':
            alert = self._check_bulk_share(activity)
            if alert:
                alerts.append(alert)

        if activity.activity_type == 'sensitive_access':
            alert = self._check_sensitive_access(activity)
            if alert:
                alerts.append(alert)

        if activity.activity_type == 'data_export':
            alert = self._check_large_export(activity)
            if alert:
                alerts.append(alert)

        # Update risk score
        if alerts:
            self._update_risk_score(activity.user_id, alerts)

        return alerts

    def _check_failed_logins(self, activity):
        """Detect repeated authentication failures."""
        user = User.query.get(activity.user_id)
        if not user:
            return None

        # Count recent failed logins (last 30 minutes)
        cutoff = datetime.now() - timedelta(minutes=30)
        recent_failures = Activity.query.filter(
            Activity.user_id == activity.user_id,
            Activity.activity_type == 'login_failure',
            Activity.timestamp >= cutoff
        ).count()

        if recent_failures >= self.thresholds['failed_login']:
            activity.is_suspicious = True
            activity.risk_contribution = 15.0
            db.session.commit()

            return Alert(
                user_id=activity.user_id,
                alert_type='repeated_auth_failure',
                severity='high' if recent_failures >= 5 else 'medium',
                title=f'Repeated Authentication Failures — {user.display_name}',
                description=f'{recent_failures} failed login attempts detected in the last 30 minutes for {user.display_name} ({user.employee_id}).',
                evidence=json.dumps({
                    'failed_attempts': recent_failures,
                    'time_window': '30 minutes',
                    'employee_id': user.employee_id,
                    'department': user.department,
                    'last_attempt': activity.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                }),
                risk_score_impact=15.0,
            )
        return None

    def _check_after_hours_login(self, activity):
        """Detect logins outside employee's configured working hours."""
        user = User.query.get(activity.user_id)
        if not user or not user.shift_start or not user.shift_end:
            return None

        login_time = activity.timestamp
        current_hour_min = login_time.strftime('%H:%M')

        shift_start = user.shift_start
        shift_end = user.shift_end

        # Check if login is outside shift hours
        is_outside = False
        if shift_start <= shift_end:
            # Normal shift (e.g., 09:00-17:00)
            if current_hour_min < shift_start or current_hour_min > shift_end:
                is_outside = True
        else:
            # Overnight shift (e.g., 20:00-04:00)
            if current_hour_min < shift_start and current_hour_min > shift_end:
                is_outside = True

        if is_outside:
            activity.is_suspicious = True
            activity.risk_contribution = 20.0
            db.session.commit()

            return Alert(
                user_id=activity.user_id,
                alert_type='after_hours_login',
                severity='medium',
                title=f'After-Hours Login — {user.display_name}',
                description=f'{user.display_name} logged in at {current_hour_min} which is outside their configured shift ({shift_start}–{shift_end}).',
                evidence=json.dumps({
                    'login_time': current_hour_min,
                    'shift_start': shift_start,
                    'shift_end': shift_end,
                    'employee_id': user.employee_id,
                    'department': user.department,
                }),
                risk_score_impact=20.0,
            )
        return None

    def _check_bulk_download(self, activity):
        """Detect bulk download attempts (more than threshold files)."""
        user = User.query.get(activity.user_id)
        if not user:
            return None

        try:
            details = json.loads(activity.details) if activity.details else {}
        except (json.JSONDecodeError, TypeError):
            details = {}

        file_count = details.get('file_count', 0)

        if file_count > self.thresholds['bulk_download']:
            activity.is_suspicious = True
            activity.risk_contribution = 25.0
            db.session.commit()

            return Alert(
                user_id=activity.user_id,
                alert_type='bulk_download',
                severity='high',
                title=f'Bulk Download Detected — {user.display_name}',
                description=f'{user.display_name} attempted to download {file_count} files in a single operation (threshold: {self.thresholds["bulk_download"]}).',
                evidence=json.dumps({
                    'file_count': file_count,
                    'threshold': self.thresholds['bulk_download'],
                    'files': details.get('files', []),
                    'employee_id': user.employee_id,
                    'department': user.department,
                }),
                risk_score_impact=25.0,
            )
        return None

    def _check_bulk_share(self, activity):
        """Detect bulk file sharing/transfer attempts."""
        user = User.query.get(activity.user_id)
        if not user:
            return None

        try:
            details = json.loads(activity.details) if activity.details else {}
        except (json.JSONDecodeError, TypeError):
            details = {}

        file_count = details.get('file_count', 0)

        if file_count > self.thresholds['bulk_share']:
            activity.is_suspicious = True
            activity.risk_contribution = 25.0
            db.session.commit()

            return Alert(
                user_id=activity.user_id,
                alert_type='bulk_share',
                severity='high',
                title=f'Bulk File Sharing Detected — {user.display_name}',
                description=f'{user.display_name} attempted to share {file_count} files in a single operation (threshold: {self.thresholds["bulk_share"]}).',
                evidence=json.dumps({
                    'file_count': file_count,
                    'threshold': self.thresholds['bulk_share'],
                    'files': details.get('files', []),
                    'recipient': details.get('recipient', 'Unknown'),
                    'employee_id': user.employee_id,
                    'department': user.department,
                }),
                risk_score_impact=25.0,
            )
        return None

    def _check_sensitive_access(self, activity):
        """Detect access to sensitive/restricted files."""
        user = User.query.get(activity.user_id)
        if not user:
            return None

        try:
            details = json.loads(activity.details) if activity.details else {}
        except (json.JSONDecodeError, TypeError):
            details = {}

        sensitivity = details.get('sensitivity', 'normal')

        if sensitivity in ('confidential', 'restricted'):
            activity.is_suspicious = True
            risk = 30.0 if sensitivity == 'restricted' else 15.0
            activity.risk_contribution = risk
            db.session.commit()

            return Alert(
                user_id=activity.user_id,
                alert_type='sensitive_file_access',
                severity='critical' if sensitivity == 'restricted' else 'high',
                title=f'Sensitive File Access — {user.display_name}',
                description=f'{user.display_name} accessed a {sensitivity} file: {details.get("filename", "Unknown")}.',
                evidence=json.dumps({
                    'filename': details.get('filename', 'Unknown'),
                    'sensitivity': sensitivity,
                    'file_path': details.get('filepath', ''),
                    'employee_id': user.employee_id,
                    'department': user.department,
                }),
                risk_score_impact=risk,
            )
        return None

    def _check_large_export(self, activity):
        """Detect large data exports."""
        user = User.query.get(activity.user_id)
        if not user:
            return None

        try:
            details = json.loads(activity.details) if activity.details else {}
        except (json.JSONDecodeError, TypeError):
            details = {}

        size_mb = details.get('size_mb', 0)

        if size_mb >= self.thresholds['large_export_mb']:
            activity.is_suspicious = True
            activity.risk_contribution = 20.0
            db.session.commit()

            return Alert(
                user_id=activity.user_id,
                alert_type='large_data_export',
                severity='high',
                title=f'Large Data Export — {user.display_name}',
                description=f'{user.display_name} exported {size_mb} MB of data (threshold: {self.thresholds["large_export_mb"]} MB).',
                evidence=json.dumps({
                    'size_mb': size_mb,
                    'threshold_mb': self.thresholds['large_export_mb'],
                    'export_type': details.get('export_type', 'Unknown'),
                    'employee_id': user.employee_id,
                    'department': user.department,
                }),
                risk_score_impact=20.0,
            )
        return None

    def _update_risk_score(self, user_id, alerts):
        """Update user's risk score based on new alerts."""
        user = User.query.get(user_id)
        if not user:
            return

        total_impact = sum(a.risk_score_impact for a in alerts)
        user.risk_score = min(100.0, user.risk_score + total_impact)
        db.session.commit()

    def get_risk_level(self, risk_score):
        """Return risk level string based on score."""
        if risk_score >= self.thresholds['risk_high']:
            return 'high'
        elif risk_score >= self.thresholds['risk_medium']:
            return 'medium'
        return 'low'

    def get_risk_breakdown(self, user_id):
        """Get breakdown of risk score contributions."""
        activities = Activity.query.filter(
            Activity.user_id == user_id,
            Activity.is_suspicious == True
        ).order_by(Activity.timestamp.desc()).all()

        breakdown = []
        for act in activities:
            breakdown.append({
                'activity_type': act.activity_type,
                'description': act.description,
                'risk_contribution': act.risk_contribution,
                'timestamp': act.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            })
        return breakdown


# Singleton instance
detection_engine = DetectionEngine()
