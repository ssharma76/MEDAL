import streamlit as st
import pandas as pd
from sqlalchemy import create_engine, text
import requests
import json
import cv2
import numpy as np
import io
import os
import hashlib
import secrets
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# ==============================================================================
# 1. PAGE CONFIGURATION & SECRETS
# ==============================================================================
st.set_page_config(
    page_title="Campus Attendance & Discipline Portal",
    page_icon="🏫",
    layout="wide",
    initial_sidebar_state="collapsed"
)

try:
    INSTITUTIONAL_DOMAIN = st.secrets.get("INSTITUTIONAL_DOMAIN", "apsmeerut.com")
    DEFAULT_WEBHOOK = st.secrets.get("DEFAULT_WEBHOOK", "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=BBBB&token=CCCC")
except Exception:
    INSTITUTIONAL_DOMAIN = "apsmeerut.com"
    DEFAULT_WEBHOOK = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=BBBB&token=CCCC"

# ==============================================================================
# 2. SQLITE WITH HIGH-CONCURRENCY WAL MODE
# ==============================================================================
@st.cache_resource
def get_db_engine():
    db_engine = create_engine(
        "sqlite:///school_attendance.db",
        connect_args={"check_same_thread": False, "timeout": 30}
    )
    with db_engine.connect() as connection:
        connection.execute(text("PRAGMA journal_mode=WAL;"))
        connection.execute(text("PRAGMA synchronous=NORMAL;"))
    return db_engine

engine = get_db_engine()

# ==============================================================================
# 3. CRYPTOGRAPHY & AUDIT LOGGING UTILITIES
# ==============================================================================
def hash_password(password: str, salt: str = None) -> tuple:
    if salt is None:
        salt = secrets.token_hex(16)
    hashed = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
    return hashed, salt

def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    hashed, _ = hash_password(password, salt)
    return hashed == stored_hash

def generate_6digit_pin():
    return f"{secrets.randbelow(900000) + 100000}"

def log_activity(user_email: str, action: str, details: str = ""):
    try:
        with engine.begin() as conn:
            conn.execute(text("""
                INSERT INTO system_access_logs (user_email, action_type, details)
                VALUES (:u, :a, :d)
            """), {"u": user_email, "a": action, "d": details})
    except Exception:
        pass

# ==============================================================================
# 4. DATABASE INITIALIZATION
# ==============================================================================
def init_db():
    schema_statements = [
        """
        CREATE TABLE IF NOT EXISTS staff_directory (
            email TEXT PRIMARY KEY,
            full_name TEXT NOT NULL,
            role TEXT NOT NULL,
            assigned_class_sec TEXT DEFAULT '',
            assigned_optional_subj TEXT DEFAULT '',
            status TEXT DEFAULT 'Active',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS user_credentials (
            email TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            salt TEXT NOT NULL,
            must_change_password INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS system_access_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
            user_email TEXT NOT NULL,
            action_type TEXT NOT NULL,
            details TEXT,
            ip_address TEXT DEFAULT 'Campus Network'
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS students (
            adm_no TEXT PRIMARY KEY,
            roll_no INTEGER,
            name TEXT NOT NULL,
            class_sec TEXT NOT NULL,
            house TEXT,
            photo_url TEXT,
            class_teacher_name TEXT,
            class_teacher_email TEXT,
            class_teacher_webhook TEXT,
            status TEXT DEFAULT 'Active'
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS student_subject_enrollment (
            adm_no TEXT NOT NULL,
            subject_name TEXT NOT NULL,
            PRIMARY KEY (adm_no, subject_name),
            FOREIGN KEY (adm_no) REFERENCES students(adm_no) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS morning_attendance (
            date TEXT NOT NULL,
            adm_no TEXT NOT NULL,
            status TEXT NOT NULL,
            marked_by_email TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (date, adm_no),
            FOREIGN KEY (adm_no) REFERENCES students(adm_no) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS period_attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            period INTEGER NOT NULL,
            subject_name TEXT NOT NULL,
            adm_no TEXT NOT NULL,
            status TEXT NOT NULL,
            marked_by TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(date, period, subject_name, adm_no)
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS event_passes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            adm_no TEXT NOT NULL,
            event_name TEXT NOT NULL,
            valid_date TEXT NOT NULL,
            valid_periods TEXT NOT NULL,
            issued_by_email TEXT,
            FOREIGN KEY (adm_no) REFERENCES students(adm_no) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS corridor_incidents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            period INTEGER NOT NULL,
            adm_no TEXT NOT NULL,
            location TEXT NOT NULL,
            remarks TEXT,
            reported_by_email TEXT NOT NULL,
            resolved INTEGER DEFAULT 0,
            action_notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (adm_no) REFERENCES students(adm_no) ON DELETE CASCADE
        );
        """,
        """
        CREATE TABLE IF NOT EXISTS event_authorizations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            event_name TEXT NOT NULL,
            house TEXT DEFAULT 'ALL',
            primary_teacher_name TEXT NOT NULL,
            primary_teacher_email TEXT NOT NULL,
            standby_teacher_name TEXT NOT NULL,
            standby_teacher_email TEXT NOT NULL
        );
        """,
        "CREATE INDEX IF NOT EXISTS idx_std_class ON students(class_sec);",
        "CREATE INDEX IF NOT EXISTS idx_att_date ON morning_attendance(date);",
        "CREATE INDEX IF NOT EXISTS idx_log_email ON system_access_logs(user_email);"
    ]

    with engine.begin() as conn:
        for stmt in schema_statements:
            conn.execute(text(stmt))

        admin_email = f"admin@{INSTITUTIONAL_DOMAIN}".strip().lower()
        res = conn.execute(text("SELECT count(*) FROM staff_directory WHERE LOWER(email) = :e"), {"e": admin_email}).scalar()
        
        if res == 0:
            p_hash, p_salt = hash_password("Admin@123")
            conn.execute(text("""
                INSERT INTO user_credentials (email, password_hash, salt, must_change_password)
                VALUES (:e, :h, :s, 1)
            """), {"e": admin_email, "h": p_hash, "s": p_salt})

            conn.execute(text("""
                INSERT INTO staff_directory (email, full_name, role, assigned_class_sec, assigned_optional_subj, status)
                VALUES (:e, 'System Administrator', 'Admin', '', '', 'Active')
            """), {"e": admin_email})

            demo_staff = [
                {"e": f"neha.sharma@{INSTITUTIONAL_DOMAIN}", "n": "Mrs. Neha Sharma", "r": "Teacher", "c": "10-A", "s": ""},
                {"e": f"sachin.cs@{INSTITUTIONAL_DOMAIN}", "n": "Mr. Sachin Sharma", "r": "Teacher", "c": "", "s": "Computer Science"},
                {"e": f"coord.sec@{INSTITUTIONAL_DOMAIN}", "n": "Mr. Anand Tyagi", "r": "Coordinator", "c": "11-A", "s": ""},
                {"e": f"vp@{INSTITUTIONAL_DOMAIN}", "n": "Vice Principal Desk", "r": "Vice Principal", "c": "", "s": ""}
            ]
            for st_row in demo_staff:
                conn.execute(text("""
                    INSERT OR IGNORE INTO staff_directory (email, full_name, role, assigned_class_sec, assigned_optional_subj, status)
                    VALUES (:e, :n, :r, :c, :s, 'Active')
                """), st_row)
                
                demo_hash, demo_salt = hash_password("123456")
                conn.execute(text("""
                    INSERT OR IGNORE INTO user_credentials (email, password_hash, salt, must_change_password)
                    VALUES (:e, :h, :s, 1)
                """), {"e": st_row["e"], "h": demo_hash, "s": demo_salt})

            conn.execute(text("""
                INSERT OR IGNORE INTO event_authorizations 
                (event_name, house, primary_teacher_name, primary_teacher_email, standby_teacher_name, standby_teacher_email) VALUES
                ('Annual Athletic Meet - March Past', 'Ashoka', 'Mrs. Neha Sharma', 'neha.sharma@apsmeerut.com', 'Mr. Anand Tyagi', 'coord.sec@apsmeerut.com'),
                ('Annual Day Choir', 'ALL', 'Mr. Amit (Music)', 'amit.m@apsmeerut.com', 'Mrs. Sunita', 'sunita.m@apsmeerut.com');
            """))

            sample_students = [
                {"a": "10482", "r": 14, "n": "Aarav Sharma", "c": "10-A", "h": "Ashoka", "p": "", "ct": "Mrs. Neha Sharma", "cte": f"neha.sharma@{INSTITUTIONAL_DOMAIN}", "w": "", "st": "Active"},
                {"a": "10483", "r": 15, "n": "Rohan Verma", "c": "10-A", "h": "Shivaji", "p": "", "ct": "Mrs. Neha Sharma", "cte": f"neha.sharma@{INSTITUTIONAL_DOMAIN}", "w": "", "st": "Active"},
                {"a": "11001", "r": 1, "n": "Aditya Bhardwaj", "c": "11-A", "h": "Ashoka", "p": "", "ct": "Mr. Anand Tyagi", "cte": f"coord.sec@{INSTITUTIONAL_DOMAIN}", "w": "", "st": "Active"},
                {"a": "11002", "r": 2, "n": "Kavya Chauhan", "c": "11-B", "h": "Tagore", "p": "", "ct": "Mrs. Sen", "cte": f"sen.11b@{INSTITUTIONAL_DOMAIN}", "w": "", "st": "Active"},
                {"a": "11003", "r": 3, "n": "Dhruv Malik", "c": "11-A", "h": "Raman", "p": "", "ct": "Mr. Anand Tyagi", "cte": f"coord.sec@{INSTITUTIONAL_DOMAIN}", "w": "", "st": "Active"},
                {"a": "11004", "r": 4, "n": "Ananya Singh", "c": "11-B", "h": "Shivaji", "p": "", "ct": "Mrs. Sen", "cte": f"sen.11b@{INSTITUTIONAL_DOMAIN}", "w": "", "st": "Active"}
            ]
            for s in sample_students:
                conn.execute(text("""
                    INSERT OR IGNORE INTO students 
                    (adm_no, roll_no, name, class_sec, house, photo_url, class_teacher_name, class_teacher_email, class_teacher_webhook, status)
                    VALUES (:a, :r, :n, :c, :h, :p, :ct, :cte, :w, :st)
                """), s)

            conn.execute(text("INSERT OR IGNORE INTO student_subject_enrollment (adm_no, subject_name) VALUES ('11001', 'Computer Science')"))
            conn.execute(text("INSERT OR IGNORE INTO student_subject_enrollment (adm_no, subject_name) VALUES ('11002', 'Computer Science')"))
            conn.execute(text("INSERT OR IGNORE INTO student_subject_enrollment (adm_no, subject_name) VALUES ('11003', 'Computer Science')"))

init_db()

# ==============================================================================
# 5. RESPONSIVE MOBILE CSS
# ==============================================================================
st.markdown("""
<style>
    .block-container {
        padding-top: 1rem;
        padding-bottom: 2rem;
        padding-left: 0.6rem;
        padding-right: 0.6rem;
    }
    .mobile-id-card {
        background-color: #FFFFFF;
        border: 1px solid #CBD5E1;
        border-radius: 12px;
        padding: 14px;
        margin-bottom: 12px;
        box-shadow: 0 2px 6px rgba(0,0,0,0.06);
    }
    .badge-present {
        background-color: #DEF7EC;
        color: #03543F;
        padding: 4px 10px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 13px;
        display: inline-block;
    }
    .badge-absent {
        background-color: #FDE8E8;
        color: #9B1C1C;
        padding: 4px 10px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 13px;
        display: inline-block;
    }
    .badge-event {
        background-color: #E1EFFE;
        color: #1E429F;
        padding: 4px 10px;
        border-radius: 20px;
        font-weight: 700;
        font-size: 13px;
        display: inline-block;
    }
    .stButton > button {
        width: 100% !important;
        min-height: 48px !important;
        font-size: 16px !important;
        font-weight: 600 !important;
        border-radius: 10px !important;
    }
    .stTextInput input, .stSelectbox select {
        font-size: 16px !important;
        min-height: 44px !important;
    }
    @media (max-width: 768px) {
        div[data-testid="column"] {
            width: 100% !important;
            flex: 1 1 100% !important;
            min-width: 100% !important;
            margin-bottom: 0.6rem;
        }
    }
</style>
""", unsafe_allow_html=True)

# ==============================================================================
# 6. REPORTLAB PDF & CHAT WEBHOOK HELPERS
# ==============================================================================
def send_chat_card(webhook_url, title, subtitle, widgets_data):
    if not webhook_url or not webhook_url.startswith("https://chat.googleapis.com/"):
        return False, "Invalid or placeholder Webhook URL"
    payload = {
        "cardsV2": [{
            "cardId": f"alert_{int(datetime.now().timestamp())}",
            "card": {
                "header": {"title": title, "subtitle": subtitle, "imageType": "CIRCLE"},
                "sections": [{"widgets": widgets_data}]
            }
        }]
    }
    try:
        r = requests.post(webhook_url, headers={"Content-Type": "application/json; charset=UTF-8"}, data=json.dumps(payload), timeout=5)
        return (True, "Delivered") if r.status_code == 200 else (False, f"HTTP {r.status_code}")
    except Exception as e:
        return False, str(e)

def generate_reportlab_pdf(title, subtitle, meta_text, headers, rows, col_widths, signatures):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=25, leftMargin=25, topMargin=25, bottomMargin=25)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"<b>{title}</b>", styles['Heading1']))
    story.append(Paragraph(subtitle, styles['Heading3']))
    story.append(Spacer(1, 6))
    story.append(Paragraph(meta_text, styles['Normal']))
    story.append(Spacer(1, 12))

    table_data = [[Paragraph(f"<b>{h}</b>", styles['Normal']) for h in headers]]
    cell_s = ParagraphStyle('cell', parent=styles['Normal'], fontSize=8, leading=10)

    for row in rows:
        table_data.append([Paragraph(str(val), cell_s) for val in row])

    t = Table(table_data, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#F1F5F9")),
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
        ('VALIGN', (0,0), (-1,-1), 'TOP'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
    ]))
    story.append(t)
    story.append(Spacer(1, 30))

    sig_cells = [Paragraph(f"___________________<br/><b>{s}</b>", styles['Normal']) for s in signatures]
    sig_w = 540 / len(signatures)
    sig_table = Table([sig_cells], colWidths=[sig_w] * len(signatures))
    story.append(sig_table)

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()

def generate_consolidated_attendance_pdf(audit_date_str, summary_rows, grand_totals, signatures):
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=25,
        leftMargin=25,
        topMargin=25,
        bottomMargin=25
    )
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph("<b>ARMY PUBLIC SCHOOL MEERUT CANTT</b>", styles['Heading1']))
    story.append(Paragraph("DAILY CONSOLIDATED ATTENDANCE & ABSENTEE STATEMENT", styles['Heading3']))
    story.append(Spacer(1, 4))
    
    meta_text = (
        f"<b>Audit Date:</b> {audit_date_str} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Total Enrolled:</b> {grand_totals['enrolled']} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Present:</b> {grand_totals['present']} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Absent:</b> {grand_totals['absent']} &nbsp;&nbsp;|&nbsp;&nbsp; "
        f"<b>Attendance:</b> {grand_totals['pct']:.1f}%"
    )
    story.append(Paragraph(meta_text, styles['Normal']))
    story.append(Spacer(1, 12))

    headers = ["Class & Sec", "On Roll", "Present", "Absent", "Names & Details of Absent Students"]
    table_data = [[Paragraph(f"<b>{h}</b>", styles['Normal']) for h in headers]]
    
    cell_s = ParagraphStyle('cell', parent=styles['Normal'], fontSize=8, leading=11)
    cell_bold = ParagraphStyle('cell_bold', parent=styles['Normal'], fontSize=8, leading=11, fontName="Helvetica-Bold")
    cell_absent = ParagraphStyle('cell_abs', parent=styles['Normal'], fontSize=8, leading=10, textColor=colors.HexColor("#991B1B"))

    for row in summary_rows:
        table_data.append([
            Paragraph(f"<b>{row['class_sec']}</b>", cell_bold),
            Paragraph(str(row['on_roll']), cell_s),
            Paragraph(str(row['present']), cell_s),
            Paragraph(f"<b>{row['absent']}</b>" if row['absent'] > 0 else "0", cell_bold),
            Paragraph(row['absentees_text'], cell_absent if row['absent'] > 0 else cell_s)
        ])

    table_data.append([
        Paragraph("<b>GRAND TOTAL</b>", cell_bold),
        Paragraph(f"<b>{grand_totals['enrolled']}</b>", cell_bold),
        Paragraph(f"<b>{grand_totals['present']}</b>", cell_bold),
        Paragraph(f"<b>{grand_totals['absent']}</b>", cell_bold),
        Paragraph(f"<b>Total Absentees Across Campus: {grand_totals['absent']}</b>", cell_bold)
    ])

    t = Table(table_data, colWidths=[65, 45, 45, 45, 345], repeatRows=1)
    t.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#E2E8F0")),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#94A3B8")),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('BACKGROUND', (0, -1), (-1, -1), colors.HexColor("#F1F5F9")),
    ]))
    story.append(t)
    story.append(Spacer(1, 35))

    sig_cells = [Paragraph(f"___________________<br/><b>{s}</b>", styles['Normal']) for s in signatures]
    sig_w = 540 / len(signatures)
    sig_table = Table([sig_cells], colWidths=[sig_w] * len(signatures))
    story.append(sig_table)

    doc.build(story)
    buf.seek(0)
    return buf.getvalue()

# ==============================================================================
# 7. INITIAL LOGIN PAGE & FORCED PASSWORD RESET
# ==============================================================================
if "auth_user" not in st.session_state:
    st.session_state["auth_user"] = None
if "must_reset_pwd" not in st.session_state:
    st.session_state["must_reset_pwd"] = False

# --- SCREEN 1: LOGIN FORM ---
if not st.session_state["auth_user"]:
    st.markdown("<h2 style='text-align: center;'>🏫 Army Public School Meerut Cantt</h2>", unsafe_allow_html=True)
    st.markdown("<p style='text-align: center; color: #64748B;'>Campus Attendance, Discipline & Safety Portal</p>", unsafe_allow_html=True)

    _, col_mid, _ = st.columns([1, 2, 1])
    with col_mid:
        with st.form("login_form"):
            st.subheader("🔐 Staff Sign-In")
            st.caption(f"Authorized domain: **@{INSTITUTIONAL_DOMAIN}**")
            email_in = st.text_input("Institutional Email Address", placeholder=f"teacher@{INSTITUTIONAL_DOMAIN}").strip().lower()
            pwd_in = st.text_input("Password / Temporary 6-Digit PIN", type="password")
            
            submit_login = st.form_submit_button("Sign In with Workspace Account", type="primary")

            if submit_login:
                if not email_in:
                    st.error("Please enter your institutional email address.")
                elif not email_in.endswith(f"@{INSTITUTIONAL_DOMAIN}"):
                    st.error(f"Access Denied: Only accounts under '@{INSTITUTIONAL_DOMAIN}' are permitted.")
                else:
                    with engine.connect() as conn:
                        staff_entry = conn.execute(
                            text("SELECT role, status FROM staff_directory WHERE LOWER(email) = :e"),
                            {"e": email_in}
                        ).fetchone()

                        user_creds = conn.execute(
                            text("SELECT password_hash, salt, must_change_password FROM user_credentials WHERE LOWER(email) = :e"),
                            {"e": email_in}
                        ).fetchone()

                    if not staff_entry:
                        log_activity(email_in, "LOGIN_FAILED", "Email not registered in staff directory")
                        st.error("Email not found in Staff Directory. Contact Administrator.")
                    elif staff_entry[1] != "Active":
                        log_activity(email_in, "LOGIN_BLOCKED", "Staff account suspended")
                        st.error("Account suspended. Contact Administrator.")
                    elif not user_creds:
                        log_activity(email_in, "LOGIN_FAILED", "Credentials not initialized")
                        st.error("Password not initialized. Contact Admin for activation PIN.")
                    else:
                        stored_hash, salt, must_change = user_creds
                        if verify_password(pwd_in, stored_hash, salt):
                            log_activity(email_in, "LOGIN_SUCCESS", f"Role: {staff_entry[0]}")
                            st.session_state["auth_user"] = email_in
                            st.session_state["must_reset_pwd"] = bool(must_change)
                            st.rerun()
                        else:
                            log_activity(email_in, "LOGIN_FAILED", "Incorrect password/PIN")
                            st.error("Invalid password or 6-digit PIN.")
    st.stop()

# --- SCREEN 2: FORCED PASSWORD RESET SCREEN ---
if st.session_state["must_reset_pwd"]:
    _, col_reset, _ = st.columns([1, 2, 1])
    with col_reset:
        st.warning("⚠️ **First-Time Security Setup:** You must configure a permanent confidential password to proceed.")
        with st.form("reset_pwd_form"):
            new_pwd = st.text_input("New Password (Minimum 6 characters)", type="password")
            confirm_pwd = st.text_input("Confirm New Password", type="password")
            btn_update = st.form_submit_button("Save Password & Access Portal", type="primary")

            if btn_update:
                if len(new_pwd) < 6:
                    st.error("Password must be at least 6 characters long.")
                elif new_pwd != confirm_pwd:
                    st.error("Passwords do not match.")
                else:
                    new_hash, new_salt = hash_password(new_pwd)
                    with engine.begin() as conn:
                        conn.execute(text("""
                            UPDATE user_credentials 
                            SET password_hash = :h, salt = :s, must_change_password = 0 
                            WHERE LOWER(email) = :e
                        """), {"h": new_hash, "s": new_salt, "e": st.session_state["auth_user"]})
                    log_activity(st.session_state["auth_user"], "PASSWORD_RESET", "User configured personal password")
                    st.session_state["must_reset_pwd"] = False
                    st.success("✅ Password configured successfully! Loading dashboard...")
                    st.rerun()
    st.stop()

# ==============================================================================
# 8. POST-LOGIN ROLE ROUTING & NAVIGATION HEADER
# ==============================================================================
with engine.connect() as conn:
    staff_record = conn.execute(
        text("SELECT full_name, role, assigned_class_sec, assigned_optional_subj FROM staff_directory WHERE LOWER(email) = :e"),
        {"e": st.session_state["auth_user"]}
    ).fetchone()

if staff_record:
    staff_name, user_role, assigned_class, assigned_opt_subj = staff_record
else:
    staff_name, user_role, assigned_class, assigned_opt_subj = "Administrator", "Admin", "", ""

head_col1, head_col2 = st.columns([3, 1])
with head_col1:
    st.title("🏫 Campus Attendance & Corridor Safety")
with head_col2:
    st.caption(f"Staff: **{staff_name}** ({user_role})")
    if st.button("Log out"):
        log_activity(st.session_state["auth_user"], "LOGOUT", "")
        st.session_state["auth_user"] = None
        st.session_state["must_reset_pwd"] = False
        st.rerun()

# Dynamic Navigation Tabs based on Role
if user_role == "Admin":
    tab_names = [
        "👥 Staff & Roles Management",
        "📁 Bulk Student Upload",
        "📋 Period 1 Roll Call",
        "📚 Optional Subject Attendance",
        "🔍 Corridor Intercept",
        "🎟️ Event Passes",
        "📌 Class Teacher Desk",
        "📊 Executive Headcount",
        "🔒 System Audit Logs"
    ]
else:
    tab_names = []
    if assigned_class:
        tab_names.append("📋 Period 1 Roll Call")
    if assigned_opt_subj:
        tab_names.append("📚 Optional Subject Attendance")
    
    tab_names.append("🔍 Corridor Intercept")
    tab_names.append("🎟️ Event Passes")

    if assigned_class:
        tab_names.append("📌 Class Teacher Desk")
    if user_role in ["Vice Principal", "Coordinator"]:
        tab_names.append("📊 Executive Headcount")

ui_tabs = st.tabs(tab_names)

# ==============================================================================
# TAB: STAFF DIRECTORY & 6-DIGIT PIN DISPATCH (ADMIN ONLY)
# ==============================================================================
if "👥 Staff & Roles Management" in tab_names:
    t_idx = tab_names.index("👥 Staff & Roles Management")
    with ui_tabs[t_idx]:
        st.subheader("👥 Unified Staff & Roles Management Desk")
        st.caption("Manage staff institutional emails, roles, class/optional subject assignments, and generate 6-digit access credentials.")

        col_st1, col_st2 = st.columns([1, 1])
        with col_st1:
            st.markdown("##### 📥 Download Staff CSV Template")
            staff_template_df = pd.DataFrame([
                [f"neha.sharma@{INSTITUTIONAL_DOMAIN}", "Mrs. Neha Sharma", "Teacher", "10-A", "", "Active"],
                [f"sachin.cs@{INSTITUTIONAL_DOMAIN}", "Mr. Sachin Sharma", "Teacher", "", "Computer Science", "Active"],
                [f"coord.sec@{INSTITUTIONAL_DOMAIN}", "Mr. Anand Tyagi", "Coordinator", "11-A", "", "Active"],
                [f"vp@{INSTITUTIONAL_DOMAIN}", "Vice Principal Desk", "Vice Principal", "", "", "Active"]
            ], columns=["email", "full_name", "role", "assigned_class_sec", "assigned_optional_subj", "status"])

            csv_staff_buf = io.StringIO()
            staff_template_df.to_csv(csv_staff_buf, index=False)
            st.download_button(
                label="📥 Download Staff Template (.csv)",
                data=csv_staff_buf.getvalue(),
                file_name="staff_roles_template.csv",
                mime="text/csv"
            )

        with col_st2:
            st.markdown("##### 📤 Bulk Upload Staff Roster")
            uploaded_staff = st.file_uploader("Upload Staff CSV or Excel", type=["csv", "xlsx"], key="staff_file_uploader")

        if uploaded_staff is not None:
            try:
                df_st_up = pd.read_csv(uploaded_staff) if uploaded_staff.name.endswith(".csv") else pd.read_excel(uploaded_staff)
                df_st_up.columns = [c.strip().lower() for c in df_st_up.columns]

                required_cols = {"email", "full_name", "role"}
                if not required_cols.issubset(set(df_st_up.columns)):
                    st.error(f"Missing mandatory columns! File must include: {', '.join(required_cols)}")
                else:
                    if "assigned_class_sec" not in df_st_up.columns: df_st_up["assigned_class_sec"] = ""
                    if "assigned_optional_subj" not in df_st_up.columns: df_st_up["assigned_optional_subj"] = ""
                    if "status" not in df_st_up.columns: df_st_up["status"] = "Active"

                    df_st_up["email"] = df_st_up["email"].astype(str).str.strip().str.lower()
                    df_st_up = df_st_up.fillna("")

                    st.info(f"Loaded **{len(df_st_up)}** staff records for provisioning.")
                    with st.expander("👁️ Preview Staff Records to Provision"):
                        st.dataframe(df_st_up, use_container_width=True)

                    if st.button("🚀 Process Staff & Generate 6-Digit PINs", type="primary"):
                        dispatch_records = []
                        with engine.begin() as conn:
                            for _, r in df_st_up.iterrows():
                                conn.execute(text("""
                                    INSERT INTO staff_directory (email, full_name, role, assigned_class_sec, assigned_optional_subj, status)
                                    VALUES (:e, :n, :r, :c, :s, :st)
                                    ON CONFLICT(email) DO UPDATE SET
                                        full_name = excluded.full_name,
                                        role = excluded.role,
                                        assigned_class_sec = excluded.assigned_class_sec,
                                        assigned_optional_subj = excluded.assigned_optional_subj,
                                        status = excluded.status
                                """), {
                                    "e": r["email"], "n": r["full_name"], "r": r["role"],
                                    "c": r["assigned_class_sec"], "s": r["assigned_optional_subj"], "st": r["status"]
                                })

                                cred_exists = conn.execute(
                                    text("SELECT count(*) FROM user_credentials WHERE LOWER(email) = :e"), {"e": r["email"]}
                                ).scalar()

                                if cred_exists == 0:
                                    gen_pin = generate_6digit_pin()
                                    p_hash, p_salt = hash_password(gen_pin)
                                    conn.execute(text("""
                                        INSERT INTO user_credentials (email, password_hash, salt, must_change_password)
                                        VALUES (:e, :h, :s, 1)
                                    """), {"e": r["email"], "h": p_hash, "s": p_salt})
                                    dispatch_records.append({"Email": r["email"], "Name": r["full_name"], "Initial_PIN": gen_pin, "Role": r["role"]})

                        log_activity(st.session_state["auth_user"], "STAFF_PROVISIONED", f"Processed {len(df_st_up)} staff records")
                        st.success(f"🎉 Successfully provisioned {len(df_st_up)} staff records!")

                        if dispatch_records:
                            st.markdown("##### 🔐 Generated Credentials Dispatch Sheet")
                            st.caption("Forward these temporary 6-digit PINs to the respective teachers' institutional emails.")
                            dispatch_df = pd.DataFrame(dispatch_records)
                            st.dataframe(dispatch_df, use_container_width=True)

                            disp_buf = io.StringIO()
                            dispatch_df.to_csv(disp_buf, index=False)
                            st.download_button(
                                label="📥 Download Initial PIN Dispatch CSV",
                                data=disp_buf.getvalue(),
                                file_name="staff_credentials_dispatch.csv",
                                mime="text/csv"
                            )
            except Exception as e:
                st.error(f"Error processing staff file: {e}")

        st.markdown("---")
        st.markdown("##### 📋 Active Staff Directory")
        with engine.connect() as conn:
            staff_roster_df = pd.read_sql(text("SELECT email, full_name, role, assigned_class_sec, assigned_optional_subj, status, created_at FROM staff_directory ORDER BY role ASC, full_name ASC"), conn)
        st.dataframe(staff_roster_df, use_container_width=True, hide_index=True)

# ==============================================================================
# TAB: BULK STUDENT UPLOAD (CSV / EXCEL)
# ==============================================================================
if "📁 Bulk Student Upload" in tab_names:
    t_idx = tab_names.index("📁 Bulk Student Upload")
    with ui_tabs[t_idx]:
        st.subheader("📁 Bulk Student Directory Upload (2,500+ Students)")
        st.caption("Upload or update the active student directory in bulk using CSV or Excel.")

        template_columns = [
            "adm_no", "roll_no", "name", "class_sec", "house", 
            "photo_url", "class_teacher_name", "class_teacher_email", 
            "class_teacher_webhook", "optional_subject", "status"
        ]
        sample_rows = [
            ["11001", 1, "Aditya Bhardwaj", "11-A", "Ashoka", "", "Mr. Anand Tyagi", f"coord.sec@{INSTITUTIONAL_DOMAIN}", "", "Computer Science", "Active"],
            ["11002", 2, "Kavya Chauhan", "11-B", "Tagore", "", "Mrs. Neha Sharma", f"neha.sharma@{INSTITUTIONAL_DOMAIN}", "", "Computer Science", "Active"],
            ["10482", 14, "Aarav Sharma", "10-A", "Ashoka", "", "Mrs. Neha Sharma", f"neha.sharma@{INSTITUTIONAL_DOMAIN}", "", "", "Active"]
        ]
        sample_df = pd.DataFrame(sample_rows, columns=template_columns)
        
        csv_buffer = io.StringIO()
        sample_df.to_csv(csv_buffer, index=False)

        col_d1, col_d2 = st.columns([1, 2])
        with col_d1:
            st.download_button(
                label="📥 Download Master Student CSV Template",
                data=csv_buffer.getvalue(),
                file_name="student_directory_template.csv",
                mime="text/csv"
            )

        st.markdown("---")
        st.markdown("##### 📤 Upload Filled Student File")
        uploaded_file = st.file_uploader("Upload Student CSV or Excel File (.csv / .xlsx)", type=["csv", "xlsx"], key="bulk_std_uploader")

        if uploaded_file is not None:
            try:
                df_upload = pd.read_csv(uploaded_file) if uploaded_file.name.endswith(".csv") else pd.read_excel(uploaded_file)
                df_upload.columns = [c.strip().lower() for c in df_upload.columns]
                
                required_cols = {"adm_no", "name", "class_sec"}
                if not required_cols.issubset(set(df_upload.columns)):
                    st.error(f"Missing mandatory columns! File must include: {', '.join(required_cols)}")
                else:
                    if "roll_no" not in df_upload.columns: df_upload["roll_no"] = 0
                    if "house" not in df_upload.columns: df_upload["house"] = "Unassigned"
                    if "photo_url" not in df_upload.columns: df_upload["photo_url"] = ""
                    if "class_teacher_name" not in df_upload.columns: df_upload["class_teacher_name"] = ""
                    if "class_teacher_email" not in df_upload.columns: df_upload["class_teacher_email"] = ""
                    if "class_teacher_webhook" not in df_upload.columns: df_upload["class_teacher_webhook"] = ""
                    if "status" not in df_upload.columns: df_upload["status"] = "Active"
                    if "optional_subject" not in df_upload.columns: df_upload["optional_subject"] = ""

                    df_upload["adm_no"] = df_upload["adm_no"].astype(str).str.strip()
                    df_upload["class_sec"] = df_upload["class_sec"].astype(str).str.strip().str.upper()
                    df_upload = df_upload.fillna("")

                    st.info(f"Loaded **{len(df_upload)}** records from `{uploaded_file.name}`.")
                    with st.expander("👁️ Preview Uploaded Records"):
                        st.dataframe(df_upload.head(10), use_container_width=True)

                    if st.button("🚀 Process & Sync Students into Database", type="primary"):
                        with engine.begin() as conn:
                            for _, r in df_upload.iterrows():
                                conn.execute(text("""
                                    INSERT INTO students (adm_no, roll_no, name, class_sec, house, photo_url, class_teacher_name, class_teacher_email, class_teacher_webhook, status)
                                    VALUES (:adm_no, :roll_no, :name, :class_sec, :house, :photo_url, :class_teacher_name, :class_teacher_email, :class_teacher_webhook, :status)
                                    ON CONFLICT(adm_no) DO UPDATE SET
                                        roll_no = excluded.roll_no,
                                        name = excluded.name,
                                        class_sec = excluded.class_sec,
                                        house = excluded.house,
                                        photo_url = excluded.photo_url,
                                        class_teacher_name = excluded.class_teacher_name,
                                        class_teacher_email = excluded.class_teacher_email,
                                        class_teacher_webhook = excluded.class_teacher_webhook,
                                        status = excluded.status
                                """), {
                                    "adm_no": r["adm_no"],
                                    "roll_no": r["roll_no"],
                                    "name": r["name"],
                                    "class_sec": r["class_sec"],
                                    "house": r["house"],
                                    "photo_url": r["photo_url"],
                                    "class_teacher_name": r["class_teacher_name"],
                                    "class_teacher_email": r["class_teacher_email"],
                                    "class_teacher_webhook": r["class_teacher_webhook"],
                                    "status": r["status"]
                                })

                                opt_subj = str(r["optional_subject"]).strip()
                                if opt_subj:
                                    conn.execute(text("""
                                        INSERT INTO student_subject_enrollment (adm_no, subject_name)
                                        VALUES (:a, :s)
                                        ON CONFLICT(adm_no, subject_name) DO NOTHING
                                    """), {"a": r["adm_no"], "s": opt_subj})

                        log_activity(st.session_state["auth_user"], "STUDENTS_SYNCED", f"Synced {len(df_upload)} student records")
                        st.success(f"🎉 Successfully imported {len(df_upload)} students into SQLite!")
                        st.rerun()

            except Exception as e:
                st.error(f"Error processing student file: {e}")

# ==============================================================================
# TAB: PERIOD 1 MORNING ATTENDANCE
# ==============================================================================
if "📋 Period 1 Roll Call" in tab_names:
    t_idx = tab_names.index("📋 Period 1 Roll Call")
    with ui_tabs[t_idx]:
        st.subheader("📋 Period 1 Morning Roll Call")
        target_class = st.selectbox(
            "Select Class & Section", 
            ["10-A", "10-B", "11-A", "11-B", "11-C", "12-A"],
            index=0 if not assigned_class else (["10-A", "10-B", "11-A", "11-B", "11-C", "12-A"].index(assigned_class) if assigned_class in ["10-A", "10-B", "11-A", "11-B", "11-C", "12-A"] else 0)
        )
        
        is_class_teacher = (assigned_class == target_class) or (user_role == "Admin")
        today_str = datetime.today().strftime('%Y-%m-%d')

        with engine.connect() as conn:
            students_df = pd.read_sql(
                text("SELECT adm_no, roll_no, name FROM students WHERE class_sec = :c AND status='Active' ORDER BY roll_no ASC"),
                conn, params={"c": target_class}
            )
            existing_att = pd.read_sql(
                text("SELECT adm_no, status FROM morning_attendance WHERE date = :d"),
                conn, params={"d": today_str}
            ).set_index("adm_no")

        if not students_df.empty:
            if not existing_att.empty:
                students_df["Is Present"] = students_df["adm_no"].apply(
                    lambda x: existing_att.loc[x, "status"] == "Present" if x in existing_att.index else True
                )
            else:
                students_df["Is Present"] = True

            if is_class_teacher:
                st.success(f"Editing authorized for Class {target_class}. Uncheck absentees and submit.")
                edited = st.data_editor(
                    students_df,
                    column_config={"Is Present": st.column_config.CheckboxColumn("Present", default=True)},
                    disabled=["adm_no", "roll_no", "name"],
                    use_container_width=True,
                    hide_index=True
                )
                if st.button("Submit Morning Attendance", type="primary"):
                    records = [
                        {"d": today_str, "a": r["adm_no"], "s": "Present" if r["Is Present"] else "Absent", "m": st.session_state["auth_user"]}
                        for _, r in edited.iterrows()
                    ]
                    with engine.begin() as conn:
                        for rec in records:
                            conn.execute(text("""
                                INSERT INTO morning_attendance (date, adm_no, status, marked_by_email)
                                VALUES (:d, :a, :s, :m)
                                ON CONFLICT(date, adm_no) DO UPDATE SET
                                    status = excluded.status,
                                    marked_by_email = excluded.marked_by_email
                            """), rec)
                    log_activity(st.session_state["auth_user"], "SUBMIT_ATTENDANCE", f"Class: {target_class}, Records: {len(records)}")
                    st.success(f"Attendance for Class {target_class} successfully locked!")
            else:
                st.info(f"Viewing Class {target_class}. (Read-Only: Restricted to assigned Class Teacher).")
                st.dataframe(students_df[["roll_no", "adm_no", "name", "Is Present"]], use_container_width=True, hide_index=True)
        else:
            st.warning(f"No active students found in Class {target_class}.")

# ==============================================================================
# TAB: OPTIONAL / ELECTIVE SUBJECT ATTENDANCE
# ==============================================================================
if "📚 Optional Subject Attendance" in tab_names:
    t_idx = tab_names.index("📚 Optional Subject Attendance")
    with ui_tabs[t_idx]:
        st.subheader("📚 Optional / Elective Subject Attendance")
        st.caption("Cross-sectional student pool: Automatically grouped and sorted Class-Section wise, then alphabetically by Name.")

        chosen_subject = assigned_opt_subj if (user_role != "Admin" and assigned_opt_subj) else "Computer Science"
        if user_role == "Admin":
            with engine.connect() as conn:
                subj_list = [r[0] for r in conn.execute(text("SELECT DISTINCT subject_name FROM student_subject_enrollment")).fetchall()]
            chosen_subject = st.selectbox("Select Elective Subject (Admin View)", subj_list if subj_list else ["Computer Science"])

        col_oc1, col_oc2, col_oc3 = st.columns(3)
        with col_oc1:
            opt_date = st.date_input("Date", datetime.today(), key="opt_d")
            opt_date_str = opt_date.strftime('%Y-%m-%d')
        with col_oc2:
            opt_period = st.selectbox("Period", [3, 4, 5, 6, 7], index=1, key="opt_p")
        with col_oc3:
            sec_filter = st.selectbox("Filter Section", ["All Sections (Combined Pool)", "11-A", "11-B", "11-C", "12-A"])

        query_elective = """
            SELECT 
                s.class_sec AS 'Class & Sec',
                s.adm_no AS 'Adm No',
                s.roll_no AS 'Roll No',
                s.name AS 'Student Name',
                s.house AS 'House'
            FROM students s
            JOIN student_subject_enrollment e ON s.adm_no = e.adm_no
            WHERE e.subject_name = :subj AND s.status = 'Active'
        """
        params_elective = {"subj": chosen_subject}

        if sec_filter != "All Sections (Combined Pool)":
            query_elective += " AND s.class_sec = :cs"
            params_elective["cs"] = sec_filter

        query_elective += " ORDER BY s.class_sec ASC, s.name ASC"

        with engine.connect() as conn:
            elective_roster = pd.read_sql(text(query_elective), conn, params=params_elective)
            existing_opt_att = pd.read_sql(text("""
                SELECT adm_no, status FROM period_attendance 
                WHERE date = :d AND period = :p AND subject_name = :s
            """), conn, params={"d": opt_date_str, "p": opt_period, "s": chosen_subject}).set_index("adm_no")

        if elective_roster.empty:
            st.warning(f"No students found enrolled in '{chosen_subject}' for the selected filter.")
        else:
            if not existing_opt_att.empty:
                elective_roster["Present"] = elective_roster["Adm No"].apply(
                    lambda x: existing_opt_att.loc[x, "status"] == "Present" if x in existing_opt_att.index else True
                )
                st.info(f"Showing recorded attendance for {chosen_subject} (Period {opt_period}).")
            else:
                elective_roster["Present"] = True
                st.caption(f"Marking fresh roll call for {chosen_subject} (Period {opt_period}). Defaulted to Present.")

            breakdown = elective_roster["Class & Sec"].value_counts().to_dict()
            summary_pills = " &bull; ".join([f"<b>{k}:</b> {v} students" for k, v in sorted(breakdown.items())])
            st.markdown(f"**Total Registered Pool:** `{len(elective_roster)} students` &nbsp;({summary_pills})", unsafe_allow_html=True)

            edited_elective = st.data_editor(
                elective_roster,
                column_config={"Present": st.column_config.CheckboxColumn("Attendance", default=True)},
                disabled=["Class & Sec", "Adm No", "Roll No", "Student Name", "House"],
                use_container_width=True,
                hide_index=True
            )

            if st.button(f"💾 Save Attendance for {chosen_subject} (Period {opt_period})", type="primary"):
                records_opt = [
                    {
                        "d": opt_date_str,
                        "p": opt_period,
                        "s": chosen_subject,
                        "a": row["Adm No"],
                        "st": "Present" if row["Present"] else "Absent",
                        "by": st.session_state["auth_user"]
                    }
                    for _, row in edited_elective.iterrows()
                ]
                with engine.begin() as conn:
                    for entry in records_opt:
                        conn.execute(text("""
                            INSERT INTO period_attendance (date, period, subject_name, adm_no, status, marked_by)
                            VALUES (:d, :p, :s, :a, :st, :by)
                            ON CONFLICT(date, period, subject_name, adm_no) DO UPDATE SET
                                status = excluded.status,
                                marked_by = excluded.marked_by
                        """), entry)
                log_activity(st.session_state["auth_user"], "SUBMIT_ATTENDANCE", f"Elective: {chosen_subject}, Period: {opt_period}")
                st.success(f"✅ Elective attendance locked for all {len(records_opt)} students in {chosen_subject}!")
                st.rerun()

# ==============================================================================
# TAB: CORRIDOR INTERCEPT
# ==============================================================================
if "🔍 Corridor Intercept" in tab_names:
    t_idx = tab_names.index("🔍 Corridor Intercept")
    with ui_tabs[t_idx]:
        st.subheader("🔍 Corridor Student Verification")
        
        col_pat1, col_pat2 = st.columns(2)
        with col_pat1:
            current_period = st.selectbox("Current Period", list(range(1, 9)), index=2, key="corridor_prd")
        with col_pat2:
            hall_location = st.selectbox("Location Found", ["Ground Floor Corridor", "Science Block Area", "Canteen / Grounds", "Library Staircase", "Restroom Area"], key="corridor_loc")

        entry_mode = st.radio("Search Mode", ["Type Admission Number", "Scan QR on Badge"], index=0, horizontal=True)
        target_adm = None

        if entry_mode == "Type Admission Number":
            typed_adm = st.text_input("Enter Admission Number", placeholder="e.g. 10482", key="man_adm_input")
            if typed_adm:
                target_adm = typed_adm.strip()
        else:
            st.info("📷 Camera active. Align student ID QR badge.")
            cam_shot = st.camera_input("Point mobile camera at Student ID Badge", key="corridor_camera")
            if cam_shot:
                cv_img = cv2.imdecode(np.asarray(bytearray(cam_shot.read()), dtype=np.uint8), 1)
                qr_detector = cv2.QRCodeDetector()
                decoded, _, _ = qr_detector.detectAndDecode(cv_img)
                if decoded:
                    target_adm = decoded.strip()
                else:
                    st.warning("⚠️ Could not read QR code clearly. Switch to 'Type Admission Number'.")

        if target_adm:
            today_date = datetime.today().strftime('%Y-%m-%d')
            with engine.connect() as conn:
                student = conn.execute(
                    text("SELECT adm_no, roll_no, name, class_sec, house, photo_url, class_teacher_name, class_teacher_webhook FROM students WHERE adm_no = :a"),
                    {"a": target_adm}
                ).fetchone()
                
                att_rec = conn.execute(
                    text("SELECT status FROM morning_attendance WHERE date = :d AND adm_no = :a"),
                    {"d": today_date, "a": target_adm}
                ).fetchone()
                
                event_pass = conn.execute(
                    text("SELECT event_name, valid_periods FROM event_passes WHERE valid_date = :d AND adm_no = :a"),
                    {"d": today_date, "a": target_adm}
                ).fetchone()

            if student:
                s_adm, s_roll, s_name, s_class, s_house, s_photo, ct_name, ct_webhook = student
                morning_status = att_rec[0] if att_rec else "Not Marked"
                
                if morning_status == "Present":
                    status_html = '<span class="badge-present">🟢 MORNING: PRESENT</span>'
                elif morning_status == "Absent":
                    status_html = '<span class="badge-absent">🔴 MORNING: ABSENT</span>'
                else:
                    status_html = '<span style="background:#F3F4F6;color:#374151;padding:4px 10px;border-radius:20px;font-weight:700;font-size:13px;">⚪ UNMARKED</span>'

                has_valid_event = False
                event_html = ""
                if event_pass:
                    ev_name, ev_periods = event_pass
                    allowed = [int(p.strip()) for p in ev_periods.split(",") if p.strip().isdigit()]
                    if current_period in allowed:
                        has_valid_event = True
                        event_html = f'<div style="margin-top:6px;"><span class="badge-event">🏆 {ev_name} (Periods: {ev_periods})</span></div>'
                    else:
                        event_html = f'<div style="margin-top:6px;"><span class="badge-absent">⚠️ Pass Expired: {ev_name} (Valid: {ev_periods})</span></div>'

                img_src = s_photo if (s_photo and s_photo.startswith("http")) else "https://cdn-icons-png.flaticon.com/512/3135/3135715.png"

                st.markdown(f"""
                <div class="mobile-id-card">
                    <div style="display: flex; align-items: center; gap: 14px;">
                        <img src="{img_src}" style="width: 75px; height: 90px; object-fit: cover; border-radius: 8px; border: 1px solid #CBD5E1;" />
                        <div style="flex-grow: 1;">
                            <div style="font-size: 18px; font-weight: 700; color: #1E293B;">{s_name}</div>
                            <div style="font-size: 13px; color: #64748B;"><b>Adm:</b> {s_adm} | <b>Roll:</b> {s_roll}</div>
                            <div style="font-size: 14px; font-weight: 600; color: #334155; margin-top: 2px;">Class {s_class} &bull; {s_house} House</div>
                            <div style="font-size: 12px; color: #64748B;">Class Teacher: {ct_name}</div>
                            <div style="margin-top: 6px;">{status_html}</div>
                        </div>
                    </div>
                    {event_html}
                </div>
                """, unsafe_allow_html=True)

                if morning_status == "Absent":
                    st.error("🚨 SECURITY DISCREPANCY: Student was recorded ABSENT this morning. Escort immediately to Administration.")
                elif has_valid_event:
                    st.success("✅ Student has a sanctioned event duty pass for this period.")
                else:
                    remarks = st.text_input("Patrolling Remarks", placeholder="e.g. Found roaming near canteen without pass.")
                    if st.button("🚨 Push Alert to Class Teacher", type="primary"):
                        with engine.begin() as conn:
                            conn.execute(text("""
                                INSERT INTO corridor_incidents (date, period, adm_no, location, remarks, reported_by_email)
                                VALUES (:d, :p, :a, :loc, :rem, :rep)
                            """), {"d": today_date, "p": current_period, "a": s_adm, "loc": hall_location, "rem": remarks, "rep": st.session_state["auth_user"]})

                        chat_widgets = [
                            {"decoratedText": {"topLabel": "Student Name", "text": f"<b>{s_name}</b> (Adm: {s_adm})"}},
                            {"decoratedText": {"topLabel": "Class & House", "text": f"{s_class} | {s_house}"}},
                            {"decoratedText": {"topLabel": "Location Intercepted", "text": f"Period {current_period} @ {hall_location}"}},
                            {"decoratedText": {"topLabel": "Remarks", "text": remarks if remarks else "No valid pass provided."}},
                            {"decoratedText": {"topLabel": "Reported By", "text": st.session_state["auth_user"]}}
                        ]
                        webhook = ct_webhook if ct_webhook else DEFAULT_WEBHOOK
                        ok, msg = send_chat_card(webhook, "🚨 Corridor Roaming Defaulter", f"Class {s_class}", chat_widgets)
                        log_activity(st.session_state["auth_user"], "CORRIDOR_ALERT", f"Adm: {s_adm}, Class: {s_class}, Location: {hall_location}")
                        if ok:
                            st.success("✅ Real-time alert dispatched to Class Teacher Google Chat Space!")
                        else:
                            st.warning(f"Incident logged in SQLite database. (Google Chat status: {msg})")
            else:
                st.error(f"Admission number '{target_adm}' not found in active records.")

# ==============================================================================
# TAB: EVENT PASS REGISTRATION
# ==============================================================================
if "🎟️ Event Passes" in tab_names:
    t_idx = tab_names.index("🎟️ Event Passes")
    with ui_tabs[t_idx]:
        st.subheader("🎟️ Issue Sanctioned Event / Duty Passes")
        
        with engine.connect() as conn:
            auth_events = conn.execute(text("""
                SELECT event_name, house, primary_teacher_name, standby_teacher_name,
                       CASE 
                           WHEN primary_teacher_email = :e THEN 'Primary In-Charge'
                           WHEN standby_teacher_email = :e THEN 'Standby In-Charge'
                       END as role_type
                FROM event_authorizations 
                WHERE primary_teacher_email = :e OR standby_teacher_email = :e
            """), {"e": st.session_state["auth_user"]}).fetchall()

        if not auth_events and user_role != "Admin":
            st.warning("🔒 Access Restricted: Your email is not mapped as Primary or Standby In-Charge for any event.")
        else:
            ev_options = [r[0] for r in auth_events] if auth_events else ["All-Access Admin Pass"]
            selected_event = st.selectbox("Select Sanctioned Activity", ev_options)
            
            col_ed1, col_ed2 = st.columns(2)
            with col_ed1:
                pass_date = st.date_input("Event Date", datetime.today(), key="ev_dt_picker")
            with col_ed2:
                pass_periods = st.multiselect("Permitted Periods", list(range(1, 9)), default=[4, 5], key="ev_prd_sel")

            target_adm_input = st.text_input("Enter Student Admission Number", placeholder="e.g. 10482", key="ev_adm_in").strip()

            if target_adm_input:
                with engine.connect() as conn:
                    st_info = conn.execute(
                        text("SELECT adm_no, name, class_sec, house FROM students WHERE adm_no = :a AND status='Active'"),
                        {"a": target_adm_input}
                    ).fetchone()

                if st_info:
                    st.info(f"Student: **{st_info[1]}** (Class: {st_info[2]} | House: {st_info[3]})")
                    if st.button("Confirm & Issue Pass", type="primary"):
                        if not pass_periods:
                            st.error("Select permitted periods.")
                        else:
                            periods_str = ",".join(map(str, sorted(pass_periods)))
                            date_str = pass_date.strftime('%Y-%m-%d')
                            with engine.begin() as conn:
                                conn.execute(text("""
                                    INSERT INTO event_passes (adm_no, event_name, valid_date, valid_periods, issued_by_email)
                                    VALUES (:a, :e, :d, :p, :by)
                                """), {"a": target_adm_input, "e": selected_event, "d": date_str, "p": periods_str, "by": st.session_state["auth_user"]})
                            log_activity(st.session_state["auth_user"], "ISSUE_PASS", f"Adm: {target_adm_input}, Event: {selected_event}")
                            st.success(f"Pass issued for {st_info[1]} on {date_str} (Periods: {periods_str})!")
                else:
                    st.error("Admission number not found.")

# ==============================================================================
# TAB: CLASS TEACHER DESK & MONTHLY PDF GENERATOR
# ==============================================================================
if "📌 Class Teacher Desk" in tab_names:
    t_idx = tab_names.index("📌 Class Teacher Desk")
    with ui_tabs[t_idx]:
        st.subheader("📌 Class Teacher Review & PDF Dossier")
        review_class = st.selectbox("Select Class to Review", ["10-A", "10-B", "11-A", "11-B", "11-C", "12-A"], key="rev_cls_sel")

        with engine.connect() as conn:
            incidents = pd.read_sql(text("""
                SELECT i.id, i.date, i.period, i.adm_no, s.name, i.location, i.remarks, i.reported_by_email, i.resolved, i.action_notes
                FROM corridor_incidents i
                JOIN students s ON i.adm_no = s.adm_no
                WHERE s.class_sec = :c
                ORDER BY i.date DESC, i.period DESC
            """), conn, params={"c": review_class})

        if not incidents.empty:
            st.dataframe(incidents, use_container_width=True, hide_index=True)
            
            col_res, col_pdf = st.columns(2)
            with col_res:
                st.markdown("#### Resolve Incident")
                unresolved = incidents[incidents["resolved"] == 0]
                if not unresolved.empty:
                    inc_id = st.selectbox("Select Incident ID", unresolved["id"].tolist())
                    counsel_note = st.text_input("Counseling Notes", "Student warned; parent informed.")
                    if st.button("Mark Resolved"):
                        with engine.begin() as conn:
                            conn.execute(text("UPDATE corridor_incidents SET resolved=1, action_notes=:act WHERE id=:id"), {"act": counsel_note, "id": inc_id})
                        st.success("Incident resolved.")
                        st.rerun()
                else:
                    st.success("All incidents for this section are resolved.")

            with col_pdf:
                st.markdown("#### 🖨️ Export Monthly PDF")
                pdf_month = st.selectbox("Select Month", ["2026-10", "2026-09", "2026-08"], key="pdf_m_sel")
                if st.button("Download Monthly Dossier", type="primary"):
                    m_records = incidents[incidents["date"].astype(str).str.startswith(pdf_month)]
                    
                    rows = []
                    for _, r in m_records.iterrows():
                        rows.append([
                            r['date'], r['period'], r['adm_no'], r['name'], r['location'],
                            f"{r['remarks']} ({r['reported_by_email']})",
                            "Resolved" if r['resolved'] else "Pending"
                        ])

                    pdf_bytes = generate_reportlab_pdf(
                        title="ARMY PUBLIC SCHOOL",
                        subtitle=f"MONTHLY DISCIPLINARY & CORRIDOR BUNKING DOSSIER — {pdf_month}",
                        meta_text=f"<b>Class:</b> {review_class} &nbsp;|&nbsp; <b>Total Incidents:</b> {len(m_records)}",
                        headers=["Date", "Prd", "Adm No", "Student Name", "Location", "Remarks & Reporter", "Status"],
                        rows=rows,
                        col_widths=[55, 25, 45, 95, 105, 160, 55],
                        signatures=["Class Teacher", "Class Coordinator", "Principal"]
                    )

                    st.download_button(
                        label="📥 Download Printable PDF",
                        data=pdf_bytes,
                        file_name=f"Bunk_Report_{review_class}_{pdf_month}.pdf",
                        mime="application/pdf"
                    )
        else:
            st.info("No roaming incidents on record for this class.")

# ==============================================================================
# TAB: EXECUTIVE HEADCOUNT (CONSOLIDATED AUDIT & PDF)
# ==============================================================================
if "📊 Executive Headcount" in tab_names:
    t_idx = tab_names.index("📊 Executive Headcount")
    with ui_tabs[t_idx]:
        st.subheader("📊 School Headcount & Consolidated Attendance Dossier")
        ov_date = st.date_input("Audit Date", datetime.today(), key="exec_ov_date")
        ov_date_str = ov_date.strftime('%Y-%m-%d')

        with engine.connect() as conn:
            classes_df = pd.read_sql(text("""
                SELECT 
                    s.class_sec,
                    COUNT(s.adm_no) AS on_roll,
                    SUM(CASE WHEN m.status = 'Present' THEN 1 ELSE 0 END) AS present,
                    SUM(CASE WHEN m.status = 'Absent' THEN 1 ELSE 0 END) AS absent,
                    SUM(CASE WHEN m.status IS NULL THEN 1 ELSE 0 END) AS unmarked
                FROM students s
                LEFT JOIN morning_attendance m ON s.adm_no = m.adm_no AND m.date = :d
                WHERE s.status = 'Active'
                GROUP BY s.class_sec
                ORDER BY s.class_sec ASC
            """), conn, params={"d": ov_date_str})

            absent_details_df = pd.read_sql(text("""
                SELECT 
                    s.class_sec,
                    s.roll_no,
                    s.name,
                    s.adm_no
                FROM students s
                JOIN morning_attendance m ON s.adm_no = m.adm_no
                WHERE m.date = :d AND m.status = 'Absent' AND s.status = 'Active'
                ORDER BY s.class_sec ASC, s.roll_no ASC
            """), conn, params={"d": ov_date_str})

        if not classes_df.empty:
            t_enrolled = int(classes_df['on_roll'].sum())
            t_present = int(classes_df['present'].sum())
            t_absent = int(classes_df['absent'].sum())
            att_pct = (t_present / t_enrolled * 100) if t_enrolled > 0 else 0

            st.markdown(f"""
            <div style="background: linear-gradient(135deg, #1E3A8A, #3B82F6); padding: 16px; border-radius: 12px; color: white; margin-bottom: 14px;">
                <div style="font-size: 13px; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.9;">Campus Consolidated Strength ({ov_date_str})</div>
                <div style="font-size: 32px; font-weight: 800; margin-top: 2px;">{t_present} <span style="font-size: 18px; font-weight: 400; opacity: 0.8;">/ {t_enrolled} Present</span></div>
                <div style="margin-top: 8px; background: rgba(255,255,255,0.25); border-radius: 6px; height: 8px; width: 100%;">
                    <div style="background: #10B981; height: 100%; width: {att_pct}%;"></div>
                </div>
                <div style="display: flex; justify-content: space-between; margin-top: 10px; font-size: 13px; font-weight: 600;">
                    <span>Present: {att_pct:.1f}%</span>
                    <span>Total Absent: {t_absent}</span>
                </div>
            </div>
            """, unsafe_allow_html=True)

            absent_map = {}
            for _, r in absent_details_df.iterrows():
                c = r['class_sec']
                desc = f"{r['roll_no']}. {r['name']} ({r['adm_no']})"
                absent_map.setdefault(c, []).append(desc)

            consolidated_rows = []
            for _, r in classes_df.iterrows():
                sec = r['class_sec']
                abs_list = absent_map.get(sec, [])
                abs_text = "<br/>".join(abs_list) if abs_list else "<i>Nil</i>"
                consolidated_rows.append({
                    "class_sec": sec,
                    "on_roll": int(r['on_roll']),
                    "present": int(r['present']),
                    "absent": int(r['absent']),
                    "absentees_text": abs_text
                })

            st.dataframe(
                classes_df.rename(columns={
                    "class_sec": "Class & Sec",
                    "on_roll": "On Roll",
                    "present": "Present",
                    "absent": "Absent",
                    "unmarked": "Pending Call"
                }),
                use_container_width=True,
                hide_index=True
            )

            st.markdown("---")
            st.markdown("#### 🖨️ Export Official Consolidated Statement")
            st.caption("Generates a single-document A4 audit statement showing Class Strength and the exact Absentee list in the last column.")

            if st.button("Generate Consolidated PDF Statement", type="primary"):
                grand_totals = {
                    "enrolled": t_enrolled,
                    "present": t_present,
                    "absent": t_absent,
                    "pct": att_pct
                }

                pdf_bytes = generate_consolidated_attendance_pdf(
                    audit_date_str=ov_date_str,
                    summary_rows=consolidated_rows,
                    grand_totals=grand_totals,
                    signatures=["Attendance In-Charge", "Wing Coordinator", "Vice-Principal", "Principal"]
                )

                st.download_button(
                    label=f"📥 Download Consolidated Statement ({ov_date_str})",
                    data=pdf_bytes,
                    file_name=f"Consolidated_Attendance_{ov_date_str}.pdf",
                    mime="application/pdf"
                )

# ==============================================================================
# TAB: SYSTEM AUDIT LOGS (ADMIN ONLY)
# ==============================================================================
if "🔒 System Audit Logs" in tab_names:
    t_idx = tab_names.index("🔒 System Audit Logs")
    with ui_tabs[t_idx]:
        st.subheader("🔒 System Access & Activity Audit Trail")
        st.caption("Immutable system log monitoring staff logins, password resets, attendance locks, and disciplinary alerts.")

        col_l1, col_l2 = st.columns([2, 1])
        with col_l1:
            log_filter = st.selectbox("Filter Action Type", ["ALL", "LOGIN_SUCCESS", "LOGIN_FAILED", "PASSWORD_RESET", "SUBMIT_ATTENDANCE", "CORRIDOR_ALERT"])
        with col_l2:
            if st.button("🔄 Refresh Logs"):
                st.rerun()

        log_query = "SELECT timestamp, user_email, action_type, details, ip_address FROM system_access_logs"
        params_log = {}
        if log_filter != "ALL":
            log_query += " WHERE action_type = :a"
            params_log["a"] = log_filter
        log_query += " ORDER BY timestamp DESC LIMIT 500"

        with engine.connect() as conn:
            logs_df = pd.read_sql(text(log_query), conn, params=params_log)

        st.dataframe(logs_df, use_container_width=True, hide_index=True)
