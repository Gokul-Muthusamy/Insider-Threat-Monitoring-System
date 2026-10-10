"""
Flask application factory.
"""
import os
from flask import Flask
from flask_login import LoginManager
from .models import db, User
from .config import Config
from .detection import detection_engine


def create_app(config_class=Config):
    app = Flask(__name__,
                template_folder=os.path.join(os.path.dirname(__file__), 'templates'),
                static_folder=os.path.join(os.path.dirname(__file__), 'static'))
    app.config.from_object(config_class)

    # Ensure instance directory exists
    instance_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'instance')
    os.makedirs(instance_path, exist_ok=True)

    # Initialize extensions
    db.init_app(app)
    detection_engine.init_app(app)

    # Flask-Login setup
    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    from .routes.auth import auth_bp
    from .routes.employee import employee_bp
    from .routes.admin import admin_bp
    from .routes.api import api_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(employee_bp, url_prefix='/employee')
    app.register_blueprint(admin_bp, url_prefix='/admin')
    app.register_blueprint(api_bp, url_prefix='/api')

    # Create tables and seed data
    with app.app_context():
        db.create_all()
        from .seed import seed_all
        seed_all()

    return app
