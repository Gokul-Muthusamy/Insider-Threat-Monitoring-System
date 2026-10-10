"""
Insider Threat Monitoring System - T1-PS3
Main entry point for the application.
Run with: python run.py
"""
import os
import sys

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import create_app

app = create_app()

if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  INSIDER THREAT MONITORING SYSTEM - T1-PS3")
    print("=" * 60)
    print("  Server running at: http://127.0.0.1:5000")
    print("  Demo Credentials:")
    print("    Admin    -> Username: Pranav   | Password: 123")
    print("    Employee -> Username: Gokul  | Password: 123")
    print("    Employee -> Username: Bharath | Password: 123")
    print("=" * 60 + "\n")
    app.run(debug=True, host='127.0.0.1', port=5000)
