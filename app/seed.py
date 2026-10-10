"""
Database seed data — demo users, simulated files, and scenario data.
"""
import json
from datetime import datetime, timedelta
from .models import db, User, SimulatedFile, Activity, Alert


def seed_users():
    """Create the three demo accounts if they don't exist."""
    users_data = [
        {
            'username': 'Pranav',
            'display_name': 'Pranav',
            'password': '123',
            'employee_id': 'ADMIN_PRANAV',
            'department': None,
            'role': 'admin',
            'shift_start': None,
            'shift_end': None,
        },
        {
            'username': 'Gokul',
            'display_name': 'Gokul',
            'password': '123',
            'employee_id': 'EMP_GOKUL',
            'department': 'Finance',
            'role': 'employee',
            'shift_start': '20:00',
            'shift_end': '04:00',
        },
        {
            'username': 'Bharath',
            'display_name': 'Bharath',
            'password': '123',
            'employee_id': 'EMP_BHARATH',
            'department': 'Operations',
            'role': 'employee',
            'shift_start': '09:00',
            'shift_end': '17:00',
        },
    ]

    for udata in users_data:
        existing = User.query.filter_by(username=udata['username']).first()
        if not existing:
            user = User(
                username=udata['username'],
                display_name=udata['display_name'],
                employee_id=udata['employee_id'],
                department=udata['department'],
                role=udata['role'],
                shift_start=udata['shift_start'],
                shift_end=udata['shift_end'],
            )
            user.set_password(udata['password'])
            db.session.add(user)

    db.session.commit()


def seed_files():
    """Create simulated corporate files."""
    if SimulatedFile.query.count() > 0:
        return

    files_data = [
        # Finance department files
        {'filename': 'Q3_Revenue_Report.xlsx', 'filepath': '/Finance/Reports/Q3_Revenue_Report.xlsx',
         'file_type': 'spreadsheet', 'size_mb': 2.4, 'department': 'Finance', 'sensitivity': 'confidential'},
        {'filename': 'Annual_Budget_2026.xlsx', 'filepath': '/Finance/Reports/Annual_Budget_2026.xlsx',
         'file_type': 'spreadsheet', 'size_mb': 5.1, 'department': 'Finance', 'sensitivity': 'restricted'},
        {'filename': 'Employee_Salary_Data.csv', 'filepath': '/Finance/HR/Employee_Salary_Data.csv',
         'file_type': 'csv', 'size_mb': 1.8, 'department': 'Finance', 'sensitivity': 'restricted'},
        {'filename': 'Expense_Claims_Oct.pdf', 'filepath': '/Finance/Claims/Expense_Claims_Oct.pdf',
         'file_type': 'pdf', 'size_mb': 0.9, 'department': 'Finance', 'sensitivity': 'normal'},
        {'filename': 'Tax_Filing_Draft.docx', 'filepath': '/Finance/Tax/Tax_Filing_Draft.docx',
         'file_type': 'document', 'size_mb': 3.2, 'department': 'Finance', 'sensitivity': 'confidential'},
        {'filename': 'Invoice_Template.xlsx', 'filepath': '/Finance/Templates/Invoice_Template.xlsx',
         'file_type': 'spreadsheet', 'size_mb': 0.3, 'department': 'Finance', 'sensitivity': 'normal'},
        {'filename': 'Audit_Findings_2025.pdf', 'filepath': '/Finance/Audit/Audit_Findings_2025.pdf',
         'file_type': 'pdf', 'size_mb': 4.7, 'department': 'Finance', 'sensitivity': 'restricted'},

        # Operations department files
        {'filename': 'Supply_Chain_Report.pdf', 'filepath': '/Operations/Reports/Supply_Chain_Report.pdf',
         'file_type': 'pdf', 'size_mb': 3.5, 'department': 'Operations', 'sensitivity': 'normal'},
        {'filename': 'Vendor_Contracts.zip', 'filepath': '/Operations/Contracts/Vendor_Contracts.zip',
         'file_type': 'archive', 'size_mb': 15.2, 'department': 'Operations', 'sensitivity': 'confidential'},
        {'filename': 'Warehouse_Inventory.csv', 'filepath': '/Operations/Inventory/Warehouse_Inventory.csv',
         'file_type': 'csv', 'size_mb': 8.3, 'department': 'Operations', 'sensitivity': 'normal'},
        {'filename': 'Logistics_Plan_Q4.pptx', 'filepath': '/Operations/Plans/Logistics_Plan_Q4.pptx',
         'file_type': 'presentation', 'size_mb': 6.1, 'department': 'Operations', 'sensitivity': 'normal'},
        {'filename': 'Client_Database_Export.csv', 'filepath': '/Operations/Clients/Client_Database_Export.csv',
         'file_type': 'csv', 'size_mb': 45.0, 'department': 'Operations', 'sensitivity': 'restricted'},
        {'filename': 'Safety_Protocols.pdf', 'filepath': '/Operations/Safety/Safety_Protocols.pdf',
         'file_type': 'pdf', 'size_mb': 1.1, 'department': 'Operations', 'sensitivity': 'normal'},
        {'filename': 'Meeting_Notes_Oct.docx', 'filepath': '/Operations/Meetings/Meeting_Notes_Oct.docx',
         'file_type': 'document', 'size_mb': 0.5, 'department': 'Operations', 'sensitivity': 'normal'},

        # Shared files
        {'filename': 'Company_Policy_Handbook.pdf', 'filepath': '/Shared/Policies/Company_Policy_Handbook.pdf',
         'file_type': 'pdf', 'size_mb': 2.0, 'department': 'Shared', 'sensitivity': 'normal'},
        {'filename': 'Holiday_Calendar_2026.pdf', 'filepath': '/Shared/HR/Holiday_Calendar_2026.pdf',
         'file_type': 'pdf', 'size_mb': 0.4, 'department': 'Shared', 'sensitivity': 'normal'},
        {'filename': 'IT_Security_Guidelines.pdf', 'filepath': '/Shared/IT/IT_Security_Guidelines.pdf',
         'file_type': 'pdf', 'size_mb': 1.5, 'department': 'Shared', 'sensitivity': 'normal'},
        {'filename': 'Master_Customer_List.xlsx', 'filepath': '/Shared/Sales/Master_Customer_List.xlsx',
         'file_type': 'spreadsheet', 'size_mb': 12.3, 'department': 'Shared', 'sensitivity': 'confidential'},
        {'filename': 'Trade_Secrets_Summary.pdf', 'filepath': '/Shared/Legal/Trade_Secrets_Summary.pdf',
         'file_type': 'pdf', 'size_mb': 3.8, 'department': 'Shared', 'sensitivity': 'restricted'},
        {'filename': 'Network_Architecture.vsdx', 'filepath': '/Shared/IT/Network_Architecture.vsdx',
         'file_type': 'diagram', 'size_mb': 7.2, 'department': 'Shared', 'sensitivity': 'confidential'},
    ]

    for fdata in files_data:
        f = SimulatedFile(**fdata)
        db.session.add(f)

    db.session.commit()


def seed_demo_activities():
    """Create pre-seeded demo activities to showcase the system on first run."""
    if Activity.query.count() > 0:
        return

    gokul = User.query.filter_by(username='Gokul').first()
    bharath = User.query.filter_by(username='Bharath').first()
    if not gokul or not bharath:
        return

    now = datetime.now()

    # --- Gokul's normal activities ---
    activities = [
        Activity(user_id=gokul.id, activity_type='login_success',
                 description='Gokul logged in successfully',
                 ip_address='192.168.1.101',
                 timestamp=now - timedelta(hours=8)),
        Activity(user_id=gokul.id, activity_type='file_access',
                 description='Accessed Expense_Claims_Oct.pdf',
                 details=json.dumps({'filename': 'Expense_Claims_Oct.pdf', 'sensitivity': 'normal'}),
                 timestamp=now - timedelta(hours=7, minutes=45)),
        Activity(user_id=gokul.id, activity_type='file_download',
                 description='Downloaded Invoice_Template.xlsx',
                 details=json.dumps({'filename': 'Invoice_Template.xlsx', 'sensitivity': 'normal'}),
                 timestamp=now - timedelta(hours=7, minutes=30)),
        Activity(user_id=gokul.id, activity_type='logout',
                 description='Gokul logged out',
                 timestamp=now - timedelta(hours=4)),

        # --- Bharath's normal activities ---
        Activity(user_id=bharath.id, activity_type='login_success',
                 description='Bharath logged in successfully',
                 ip_address='192.168.1.102',
                 timestamp=now - timedelta(hours=6)),
        Activity(user_id=bharath.id, activity_type='file_access',
                 description='Accessed Supply_Chain_Report.pdf',
                 details=json.dumps({'filename': 'Supply_Chain_Report.pdf', 'sensitivity': 'normal'}),
                 timestamp=now - timedelta(hours=5, minutes=45)),
        Activity(user_id=bharath.id, activity_type='file_access',
                 description='Accessed Warehouse_Inventory.csv',
                 details=json.dumps({'filename': 'Warehouse_Inventory.csv', 'sensitivity': 'normal'}),
                 timestamp=now - timedelta(hours=5, minutes=30)),
        Activity(user_id=bharath.id, activity_type='file_download',
                 description='Downloaded Meeting_Notes_Oct.docx',
                 details=json.dumps({'filename': 'Meeting_Notes_Oct.docx', 'sensitivity': 'normal'}),
                 timestamp=now - timedelta(hours=5)),
    ]

    for a in activities:
        db.session.add(a)
    db.session.commit()


def seed_all():
    """Run all seed functions."""
    seed_users()
    seed_files()
    seed_demo_activities()
