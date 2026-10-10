"""
API routes for AJAX calls, chart data, and demo scenario triggers.
"""
import json
from datetime import datetime, timedelta
from flask import Blueprint, request, jsonify, abort
from flask_login import login_required, current_user
from ..models import db, User, Activity, Alert, SimulatedFile
from ..detection import detection_engine

api_bp = Blueprint('api', __name__)


def admin_api_required(f):
    """Decorator for admin-only API endpoints."""
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin():
            return jsonify({'error': 'Unauthorized'}), 403
        return f(*args, **kwargs)
    return decorated


@api_bp.route('/chart/risk-comparison')
@login_required
@admin_api_required
def risk_comparison():
    """Risk score comparison data for Chart.js."""
    employees = User.query.filter_by(role='employee').all()
    data = {
        'labels': [e.display_name for e in employees],
        'scores': [round(e.risk_score, 1) for e in employees],
        'colors': [],
    }
    for e in employees:
        level = detection_engine.get_risk_level(e.risk_score)
        if level == 'high':
            data['colors'].append('#ef4444')
        elif level == 'medium':
            data['colors'].append('#f59e0b')
        else:
            data['colors'].append('#22c55e')
    return jsonify(data)


@api_bp.route('/chart/activity-timeline')
@login_required
@admin_api_required
def activity_timeline():
    """Activity count over the last 7 days for Chart.js."""
    now = datetime.now()
    labels = []
    normal_counts = []
    suspicious_counts = []

    for i in range(6, -1, -1):
        day = now - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day.replace(hour=23, minute=59, second=59, microsecond=999999)

        labels.append(day.strftime('%b %d'))
        total = Activity.query.filter(
            Activity.timestamp >= day_start,
            Activity.timestamp <= day_end
        ).count()
        suspicious = Activity.query.filter(
            Activity.timestamp >= day_start,
            Activity.timestamp <= day_end,
            Activity.is_suspicious == True
        ).count()
        normal_counts.append(total - suspicious)
        suspicious_counts.append(suspicious)

    return jsonify({
        'labels': labels,
        'normal': normal_counts,
        'suspicious': suspicious_counts,
    })


@api_bp.route('/chart/alert-severity')
@login_required
@admin_api_required
def alert_severity():
    """Alert severity distribution for Chart.js."""
    data = {
        'labels': ['Critical', 'High', 'Medium', 'Low'],
        'counts': [
            Alert.query.filter_by(severity='critical').count(),
            Alert.query.filter_by(severity='high').count(),
            Alert.query.filter_by(severity='medium').count(),
            Alert.query.filter_by(severity='low').count(),
        ],
        'colors': ['#dc2626', '#ef4444', '#f59e0b', '#22c55e'],
    }
    return jsonify(data)


@api_bp.route('/scenario/failed-logins', methods=['POST'])
@login_required
def trigger_failed_logins():
    """Scenario: Generate multiple failed login attempts for current user."""
    if current_user.is_admin():
        return jsonify({'error': 'Admin users cannot trigger employee scenarios'}), 400

    now = datetime.now()
    generated_alerts = []

    for i in range(5):
        activity = Activity(
            user_id=current_user.id,
            activity_type='login_failure',
            description=f'Failed login attempt #{i+1} for {current_user.display_name} (simulated)',
            ip_address='10.0.0.' + str(100 + i),
            timestamp=now - timedelta(minutes=5 * (4 - i)),
        )
        db.session.add(activity)
        db.session.commit()

        alerts = detection_engine.analyze_activity(activity)
        for alert in alerts:
            db.session.add(alert)
            generated_alerts.append(alert.title)
        db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Generated 5 failed login attempts. {len(generated_alerts)} alert(s) triggered.',
        'alerts': generated_alerts,
    })


@api_bp.route('/scenario/bulk-download', methods=['POST'])
@login_required
def trigger_bulk_download():
    """Scenario: Simulate downloading 8 files at once."""
    if current_user.is_admin():
        return jsonify({'error': 'Admin users cannot trigger employee scenarios'}), 400

    files = SimulatedFile.query.limit(8).all()
    filenames = [f.filename for f in files]
    total_size = sum(f.size_mb for f in files)

    activity = Activity(
        user_id=current_user.id,
        activity_type='bulk_download',
        description=f'Bulk download attempt: {len(files)} files ({total_size:.1f} MB)',
        details=json.dumps({
            'file_count': len(files),
            'files': filenames,
            'total_size_mb': total_size,
        }),
        ip_address=request.remote_addr,
        timestamp=datetime.now(),
    )
    db.session.add(activity)
    db.session.commit()

    alerts = detection_engine.analyze_activity(activity)
    alert_titles = []
    for alert in alerts:
        db.session.add(alert)
        alert_titles.append(alert.title)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Simulated bulk download of {len(files)} files. {len(alerts)} alert(s) triggered.',
        'alerts': alert_titles,
    })


@api_bp.route('/scenario/bulk-share', methods=['POST'])
@login_required
def trigger_bulk_share():
    """Scenario: Simulate sharing 7 files to an external recipient."""
    if current_user.is_admin():
        return jsonify({'error': 'Admin users cannot trigger employee scenarios'}), 400

    files = SimulatedFile.query.limit(7).all()
    filenames = [f.filename for f in files]

    activity = Activity(
        user_id=current_user.id,
        activity_type='bulk_share',
        description=f'Bulk share attempt: {len(files)} files to external@competitor.com',
        details=json.dumps({
            'file_count': len(files),
            'files': filenames,
            'recipient': 'external@competitor.com',
        }),
        ip_address=request.remote_addr,
        timestamp=datetime.now(),
    )
    db.session.add(activity)
    db.session.commit()

    alerts = detection_engine.analyze_activity(activity)
    alert_titles = []
    for alert in alerts:
        db.session.add(alert)
        alert_titles.append(alert.title)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Simulated bulk share of {len(files)} files. {len(alerts)} alert(s) triggered.',
        'alerts': alert_titles,
    })


@api_bp.route('/scenario/sensitive-access', methods=['POST'])
@login_required
def trigger_sensitive_access():
    """Scenario: Access a restricted file."""
    if current_user.is_admin():
        return jsonify({'error': 'Admin users cannot trigger employee scenarios'}), 400

    sensitive_file = SimulatedFile.query.filter_by(sensitivity='restricted').first()
    if not sensitive_file:
        return jsonify({'error': 'No restricted files found'}), 404

    activity = Activity(
        user_id=current_user.id,
        activity_type='sensitive_access',
        description=f'Accessed restricted file: {sensitive_file.filename}',
        details=json.dumps({
            'filename': sensitive_file.filename,
            'filepath': sensitive_file.filepath,
            'sensitivity': sensitive_file.sensitivity,
        }),
        ip_address=request.remote_addr,
        timestamp=datetime.now(),
    )
    db.session.add(activity)
    db.session.commit()

    alerts = detection_engine.analyze_activity(activity)
    alert_titles = []
    for alert in alerts:
        db.session.add(alert)
        alert_titles.append(alert.title)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Accessed restricted file: {sensitive_file.filename}. {len(alerts)} alert(s) triggered.',
        'alerts': alert_titles,
    })


@api_bp.route('/scenario/large-export', methods=['POST'])
@login_required
def trigger_large_export():
    """Scenario: Simulate a large data export (75 MB)."""
    if current_user.is_admin():
        return jsonify({'error': 'Admin users cannot trigger employee scenarios'}), 400

    activity = Activity(
        user_id=current_user.id,
        activity_type='data_export',
        description='Large data export: 75.0 MB database dump',
        details=json.dumps({
            'size_mb': 75.0,
            'export_type': 'database_dump',
            'tables': ['customers', 'transactions', 'employee_records'],
        }),
        ip_address=request.remote_addr,
        timestamp=datetime.now(),
    )
    db.session.add(activity)
    db.session.commit()

    alerts = detection_engine.analyze_activity(activity)
    alert_titles = []
    for alert in alerts:
        db.session.add(alert)
        alert_titles.append(alert.title)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': f'Simulated 75 MB data export. {len(alerts)} alert(s) triggered.',
        'alerts': alert_titles,
    })
