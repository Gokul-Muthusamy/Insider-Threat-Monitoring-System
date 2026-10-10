"""
Administrator routes — dashboard, alerts, investigations, employee overview, audit log.
"""
import json
from datetime import datetime, timedelta
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import login_required, current_user
from ..models import db, User, Activity, Alert, AuditLog, SimulatedFile
from ..detection import detection_engine

admin_bp = Blueprint('admin', __name__)


def admin_required(f):
    """Decorator to restrict access to administrators only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if not current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated


@admin_bp.route('/')
@login_required
@admin_required
def dashboard():
    """Administrator dashboard with overview metrics."""
    employees = User.query.filter_by(role='employee').all()

    # Metrics
    total_activities = Activity.query.count()
    suspicious_activities = Activity.query.filter_by(is_suspicious=True).count()
    open_alerts = Alert.query.filter(Alert.status.in_(['open', 'investigating'])).count()
    total_alerts = Alert.query.count()

    # Recent alerts
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()

    # Alert severity distribution
    severity_counts = {
        'critical': Alert.query.filter_by(severity='critical').count(),
        'high': Alert.query.filter_by(severity='high').count(),
        'medium': Alert.query.filter_by(severity='medium').count(),
        'low': Alert.query.filter_by(severity='low').count(),
    }

    # Alert status distribution
    status_counts = {
        'open': Alert.query.filter_by(status='open').count(),
        'investigating': Alert.query.filter_by(status='investigating').count(),
        'resolved': Alert.query.filter_by(status='resolved').count(),
        'dismissed': Alert.query.filter_by(status='dismissed').count(),
    }

    # Recent activity timeline
    recent_activities = Activity.query.order_by(Activity.timestamp.desc()).limit(15).all()

    # Activity type distribution for chart
    activity_types = db.session.query(
        Activity.activity_type,
        db.func.count(Activity.id)
    ).group_by(Activity.activity_type).all()
    activity_type_data = {atype: count for atype, count in activity_types}

    return render_template('admin/dashboard.html',
                           employees=employees,
                           total_activities=total_activities,
                           suspicious_activities=suspicious_activities,
                           open_alerts=open_alerts,
                           total_alerts=total_alerts,
                           recent_alerts=recent_alerts,
                           severity_counts=severity_counts,
                           status_counts=status_counts,
                           recent_activities=recent_activities,
                           activity_type_data=json.dumps(activity_type_data))


@admin_bp.route('/alerts')
@login_required
@admin_required
def alerts():
    """View and manage all alerts."""
    status_filter = request.args.get('status', 'all')
    severity_filter = request.args.get('severity', 'all')

    query = Alert.query

    if status_filter != 'all':
        query = query.filter_by(status=status_filter)
    if severity_filter != 'all':
        query = query.filter_by(severity=severity_filter)

    alerts_list = query.order_by(Alert.created_at.desc()).all()

    return render_template('admin/alerts.html',
                           alerts=alerts_list,
                           status_filter=status_filter,
                           severity_filter=severity_filter)


@admin_bp.route('/alerts/<int:alert_id>')
@login_required
@admin_required
def alert_detail(alert_id):
    """View detailed alert with evidence and investigation controls."""
    alert = Alert.query.get_or_404(alert_id)
    employee = User.query.get(alert.user_id)

    # Parse evidence JSON
    evidence = {}
    if alert.evidence:
        try:
            evidence = json.loads(alert.evidence)
        except json.JSONDecodeError:
            evidence = {}

    # Get related activities
    related_activities = Activity.query.filter_by(
        user_id=alert.user_id,
        is_suspicious=True
    ).order_by(Activity.timestamp.desc()).limit(20).all()

    return render_template('admin/alert_detail.html',
                           alert=alert,
                           employee=employee,
                           evidence=evidence,
                           related_activities=related_activities)


@admin_bp.route('/alerts/<int:alert_id>/update', methods=['POST'])
@login_required
@admin_required
def update_alert(alert_id):
    """Update alert status and investigation notes."""
    alert = Alert.query.get_or_404(alert_id)
    old_status = alert.status

    new_status = request.form.get('status', alert.status)
    notes = request.form.get('investigation_notes', '')

    alert.status = new_status
    if notes:
        existing = alert.investigation_notes or ''
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        new_note = f"[{timestamp}] {current_user.display_name}: {notes}"
        alert.investigation_notes = f"{existing}\n{new_note}" if existing else new_note
    alert.investigated_by = current_user.display_name
    alert.updated_at = datetime.now()

    # Log admin action
    audit = AuditLog(
        admin_username=current_user.username,
        action=f'Updated alert #{alert_id} status: {old_status} → {new_status}',
        target=f'Alert #{alert_id}',
        details=notes,
    )
    db.session.add(audit)
    db.session.commit()

    flash(f'Alert #{alert_id} updated to "{new_status}".', 'success')
    return redirect(url_for('admin.alert_detail', alert_id=alert_id))


@admin_bp.route('/employees')
@login_required
@admin_required
def employees():
    """View all employees with risk scores."""
    employees = User.query.filter_by(role='employee').all()

    employee_data = []
    for emp in employees:
        total_acts = Activity.query.filter_by(user_id=emp.id).count()
        suspicious_acts = Activity.query.filter_by(user_id=emp.id, is_suspicious=True).count()
        alert_count = Alert.query.filter_by(user_id=emp.id).count()
        open_alerts = Alert.query.filter(
            Alert.user_id == emp.id,
            Alert.status.in_(['open', 'investigating'])
        ).count()

        employee_data.append({
            'user': emp,
            'total_activities': total_acts,
            'suspicious_activities': suspicious_acts,
            'alert_count': alert_count,
            'open_alerts': open_alerts,
            'risk_level': detection_engine.get_risk_level(emp.risk_score),
        })

    return render_template('admin/employees.html', employee_data=employee_data)


@admin_bp.route('/employees/<int:user_id>')
@login_required
@admin_required
def employee_detail(user_id):
    """Detailed employee investigation view."""
    employee = User.query.get_or_404(user_id)
    if employee.is_admin():
        abort(404)

    activities = Activity.query.filter_by(user_id=user_id) \
        .order_by(Activity.timestamp.desc()).limit(50).all()

    alerts = Alert.query.filter_by(user_id=user_id) \
        .order_by(Alert.created_at.desc()).all()

    risk_breakdown = detection_engine.get_risk_breakdown(user_id)
    risk_level = detection_engine.get_risk_level(employee.risk_score)

    return render_template('admin/employee_detail.html',
                           employee=employee,
                           activities=activities,
                           alerts=alerts,
                           risk_breakdown=risk_breakdown,
                           risk_level=risk_level)


@admin_bp.route('/audit-log')
@login_required
@admin_required
def audit_log():
    """View administrator audit history."""
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).all()
    return render_template('admin/audit_log.html', logs=logs)


@admin_bp.route('/reset-demo', methods=['POST'])
@login_required
@admin_required
def reset_demo():
    """Reset demonstration data with confirmation."""
    confirm = request.form.get('confirm', '')
    if confirm != 'RESET':
        flash('Please type RESET to confirm data reset.', 'error')
        return redirect(url_for('admin.dashboard'))

    # Log the reset action
    audit = AuditLog(
        admin_username=current_user.username,
        action='Reset demonstration data',
        target='All tables',
        details='Complete reset of activities, alerts, and risk scores',
    )
    db.session.add(audit)

    # Clear activities and alerts
    Activity.query.delete()
    Alert.query.delete()

    # Reset risk scores
    employees = User.query.filter_by(role='employee').all()
    for emp in employees:
        emp.risk_score = 0.0

    db.session.commit()

    # Re-seed demo activities
    from ..seed import seed_demo_activities
    seed_demo_activities()

    flash('Demonstration data has been reset successfully.', 'success')
    return redirect(url_for('admin.dashboard'))
