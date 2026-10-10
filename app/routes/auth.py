"""
Authentication routes — login, logout, role-based redirect.
"""
import json
from datetime import datetime
from flask import Blueprint, render_template, request, redirect, url_for, flash
from flask_login import login_user, logout_user, login_required, current_user
from ..models import db, User, Activity
from ..detection import detection_engine

auth_bp = Blueprint('auth', __name__)


@auth_bp.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('employee.workspace'))
    return redirect(url_for('auth.login'))


@auth_bp.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin.dashboard'))
        return redirect(url_for('employee.workspace'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)

            # Log successful login
            activity = Activity(
                user_id=user.id,
                activity_type='login_success',
                description=f'{user.display_name} logged in successfully',
                ip_address=request.remote_addr,
                timestamp=datetime.now(),
            )
            db.session.add(activity)
            db.session.commit()

            # Run detection on login
            detection_engine.analyze_activity(activity)

            if user.is_admin():
                return redirect(url_for('admin.dashboard'))
            return redirect(url_for('employee.workspace'))
        else:
            # Log failed login attempt
            if user:
                activity = Activity(
                    user_id=user.id,
                    activity_type='login_failure',
                    description=f'Failed login attempt for {user.display_name}',
                    ip_address=request.remote_addr,
                    timestamp=datetime.now(),
                )
                db.session.add(activity)
                db.session.commit()

                # Run detection on failed login
                alerts = detection_engine.analyze_activity(activity)
                for alert in alerts:
                    db.session.add(alert)
                db.session.commit()

            flash('Invalid username or password.', 'error')

    return render_template('login.html')


@auth_bp.route('/logout')
@login_required
def logout():
    # Log logout
    activity = Activity(
        user_id=current_user.id,
        activity_type='logout',
        description=f'{current_user.display_name} logged out',
        ip_address=request.remote_addr,
        timestamp=datetime.now(),
    )
    db.session.add(activity)
    db.session.commit()

    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))
