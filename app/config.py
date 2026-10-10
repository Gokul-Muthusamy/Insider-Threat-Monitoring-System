"""
Application configuration.
"""
import os

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY', 'itms-t1ps3-secret-key-2026')
    SQLALCHEMY_DATABASE_URI = f"sqlite:///{os.path.join(BASE_DIR, 'instance', 'itms.db')}"
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Detection thresholds
    BULK_DOWNLOAD_THRESHOLD = 5
    BULK_SHARE_THRESHOLD = 5
    FAILED_LOGIN_THRESHOLD = 3
    LARGE_EXPORT_SIZE_MB = 50
    RISK_SCORE_HIGH = 70
    RISK_SCORE_MEDIUM = 40
