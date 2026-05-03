import sqlite3
from cyber_scout.db import init_db

def test_init_db(tmp_path, monkeypatch):
    # Use a temporary database file
    test_db = tmp_path / "test_threat_intel.db"
    monkeypatch.setattr("cyber_scout.db.DB_PATH", test_db)
    
    # Initialize the database
    init_db()
    
    assert test_db.exists()
    
    # Verify tables
    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [row[0] for row in cursor.fetchall()]
    conn.close()
    
    assert "runs" in tables
    assert "findings" in tables
    assert "users" in tables

def test_init_db_seeds_admin(tmp_path, monkeypatch):
    test_db = tmp_path / "test_threat_intel_seed.db"
    monkeypatch.setattr("cyber_scout.db.DB_PATH", test_db)
    monkeypatch.setenv("ADMIN_INITIAL_PASSWORD", "testpass123")
    
    init_db()
    
    conn = sqlite3.connect(test_db)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    row = cursor.fetchone()
    conn.close()
    
    assert row is not None
    assert row["username"] == "admin"
    # Note: we don't check the hash directly here, but init_db should have created it.
