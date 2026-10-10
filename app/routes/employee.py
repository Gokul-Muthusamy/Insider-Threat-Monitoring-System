"""
Employee routes — workspace, file browser, activity log, file actions.
"""
import json
from datetime import datetime
from functools import wraps
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, abort
from flask_login import login_required, current_user
from ..models import db, User, Activity, SimulatedFile, Alert
from ..detection import detection_engine

employee_bp = Blueprint('employee', __name__)


def employee_required(f):
    """Decorator to restrict access to employees only."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for('auth.login'))
        if current_user.is_admin():
            abort(403)
        return f(*args, **kwargs)
    return decorated


@employee_bp.route('/')
@login_required
@employee_required
def workspace():
    """Employee workspace / dashboard."""
    # Get recent activities
    recent_activities = Activity.query.filter_by(user_id=current_user.id) \
        .order_by(Activity.timestamp.desc()).limit(10).all()

    # Get user's alert count
    alert_count = Alert.query.filter_by(user_id=current_user.id).count()

    # Get file counts by department
    dept_files = SimulatedFile.query.filter(
        (SimulatedFile.department == current_user.department) |
        (SimulatedFile.department == 'Shared')
    ).all()

    return render_template('employee/workspace.html',
                           activities=recent_activities,
                           alert_count=alert_count,
                           files=dept_files)


@employee_bp.route('/files')
@login_required
@employee_required
def file_browser():
    """Browse simulated corporate files."""
    department_filter = request.args.get('department', 'all')

    if department_filter == 'all':
        files = SimulatedFile.query.filter(
            (SimulatedFile.department == current_user.department) |
            (SimulatedFile.department == 'Shared')
        ).all()
    else:
        files = SimulatedFile.query.filter_by(department=department_filter).all()

    return render_template('employee/files.html', files=files, current_filter=department_filter)


@employee_bp.route('/files/action', methods=['POST'])
@login_required
@employee_required
def file_action():
    """Handle simulated file actions (download, share, access, export)."""
    action = request.form.get('action', '')
    file_ids = request.form.getlist('file_ids')

    if not file_ids:
        flash('No files selected.', 'error')
        return redirect(url_for('employee.file_browser'))

    files = SimulatedFile.query.filter(SimulatedFile.id.in_(file_ids)).all()
    if not files:
        flash('Files not found.', 'error')
        return redirect(url_for('employee.file_browser'))

    file_count = len(files)
    filenames = [f.filename for f in files]
    total_size = sum(f.size_mb for f in files)

    # Determine activity type based on action and count
    if action == 'download':
        if file_count > 5:
            activity_type = 'bulk_download'
            desc = f'Bulk download attempt: {file_count} files ({total_size:.1f} MB)'
        else:
            activity_type = 'file_download'
            desc = f'Downloaded {file_count} file(s): {", ".join(filenames[:3])}'

    elif action == 'share':
        recipient = request.form.get('recipient', 'external@example.com')
        if file_count > 5:
            activity_type = 'bulk_share'
            desc = f'Bulk share attempt: {file_count} files to {recipient}'
        else:
            activity_type = 'file_share'
            desc = f'Shared {file_count} file(s) with {recipient}: {", ".join(filenames[:3])}'

    elif action == 'export':
        activity_type = 'data_export'
        desc = f'Data export: {file_count} file(s) totaling {total_size:.1f} MB'

    elif action == 'access':
        # For single file access, check sensitivity
        f = files[0]
        if f.sensitivity in ('confidential', 'restricted'):
            activity_type = 'sensitive_access'
            desc = f'Accessed {f.sensitivity} file: {f.filename}'
        else:
            activity_type = 'file_access'
            desc = f'Accessed file: {f.filename}'
    else:
        flash('Unknown action.', 'error')
        return redirect(url_for('employee.file_browser'))

    # Build details JSON
    details = {
        'file_count': file_count,
        'files': filenames,
        'total_size_mb': total_size,
        'size_mb': total_size,
    }

    if action == 'access' and len(files) == 1:
        details['filename'] = files[0].filename
        details['filepath'] = files[0].filepath
        details['sensitivity'] = files[0].sensitivity

    if action == 'share':
        details['recipient'] = request.form.get('recipient', 'external@example.com')

    if action == 'export':
        details['export_type'] = 'file_export'

    activity = Activity(
        user_id=current_user.id,
        activity_type=activity_type,
        description=desc,
        details=json.dumps(details),
        ip_address=request.remote_addr,
        timestamp=datetime.now(),
    )
    db.session.add(activity)
    db.session.commit()

    # Run detection
    alerts = detection_engine.analyze_activity(activity)
    for alert in alerts:
        db.session.add(alert)
    db.session.commit()

    if alerts:
        flash(f'⚠️ Action completed but flagged as suspicious. {len(alerts)} alert(s) generated.', 'warning')
    else:
        flash(f'✓ {action.capitalize()} completed successfully for {file_count} file(s).', 'success')

    return redirect(url_for('employee.file_browser'))


@employee_bp.route('/activity')
@login_required
@employee_required
def activity_log():
    """View own activity log / timeline."""
    page = request.args.get('page', 1, type=int)
    per_page = 20

    activities = Activity.query.filter_by(user_id=current_user.id) \
        .order_by(Activity.timestamp.desc()) \
        .paginate(page=page, per_page=per_page, error_out=False)

    return render_template('employee/activity.html', activities=activities)


@employee_bp.route('/profile')
@login_required
@employee_required
def profile():
    """View account info and shift details."""
    risk_breakdown = detection_engine.get_risk_breakdown(current_user.id)
    total_activities = Activity.query.filter_by(user_id=current_user.id).count()
    suspicious_count = Activity.query.filter_by(user_id=current_user.id, is_suspicious=True).count()

    return render_template('employee/profile.html',
                           risk_breakdown=risk_breakdown,
                           total_activities=total_activities,
                           suspicious_count=suspicious_count)
