import sqlite3
import os
from pathlib import Path
from typing import Any, Dict, List, Optional
from werkzeug.security import generate_password_hash

DB_PATH = Path("reports/threat_intel.db")

def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Create runs table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            threat_query TEXT NOT NULL,
            cve_query TEXT NOT NULL,
            model TEXT NOT NULL,
            output_path TEXT NOT NULL,
            summary TEXT,
            top_risks TEXT,
            slack_status TEXT
        )
    """)
    
    # Create findings table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            run_id INTEGER,
            finding_type TEXT NOT NULL, -- 'threat', 'cve', 'ioc'
            title TEXT NOT NULL,
            severity TEXT,
            description TEXT,
            FOREIGN KEY(run_id) REFERENCES runs(id)
        )
    """)

    # Create users table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)
    
    # Seed initial admin user if none exists
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_pass = os.getenv("ADMIN_INITIAL_PASSWORD", "scout123")
        hashed = generate_password_hash(admin_pass)
        cursor.execute(
            "INSERT INTO users (username, password_hash) VALUES (?, ?)",
            ("admin", hashed)
        )
        print(f"[*] Initial admin user created. Password: {admin_pass} (Change this ASAP!)")

    conn.commit()
    conn.close()

def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def insert_run(
    timestamp: str,
    threat_query: str,
    cve_query: str,
    model: str,
    output_path: str,
    summary: str,
    top_risks: str,
    slack_status: str
) -> int:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO runs (timestamp, threat_query, cve_query, model, output_path, summary, top_risks, slack_status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (timestamp, threat_query, cve_query, model, output_path, summary, top_risks, slack_status)
    )
    run_id = cursor.lastrowid
    conn.commit()
    conn.close()
    assert run_id is not None
    return run_id

def insert_findings(run_id: int, findings: List[Dict[str, Any]]) -> None:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    for finding in findings:
        cursor.execute(
            """
            INSERT INTO findings (run_id, finding_type, title, severity, description)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                run_id,
                finding.get("type", "unknown"),
                finding.get("title", ""),
                finding.get("severity", ""),
                finding.get("description", "")
            )
        )
    conn.commit()
    conn.close()

def get_recent_runs(limit: int = 10) -> List[Dict[str, Any]]:
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def get_run_by_id(run_id: int) -> Optional[Dict[str, Any]]:
    if not DB_PATH.exists():
        return None
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM runs WHERE id = ?", (run_id,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def get_trends() -> Dict[str, Any]:
    if not DB_PATH.exists():
        return {"total_reports": 0, "severities": {}, "top_cves": []}
        
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # total reports
    cursor.execute("SELECT COUNT(*) FROM runs")
    total_reports = cursor.fetchone()[0]
    
    # severities distribution
    cursor.execute("SELECT severity, COUNT(*) FROM findings WHERE severity != '' AND severity IS NOT NULL GROUP BY severity")
    severities = {row[0]: row[1] for row in cursor.fetchall()}
    
    # recurring threats/CVEs
    cursor.execute("""
        SELECT title, COUNT(*) as count 
        FROM findings 
        WHERE finding_type IN ('threat', 'cve')
        GROUP BY title 
        ORDER BY count DESC 
        LIMIT 5
    """)
    top_recurring = [{"title": row[0], "count": row[1]} for row in cursor.fetchall()]
    
    conn.close()
    return {
        "total_reports": total_reports,
        "severities": severities,
        "top_recurring": top_recurring
    }
