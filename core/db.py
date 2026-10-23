import sqlite3
import os
from datetime import datetime , timezone
db_path =  os.path.join(os.path.dirname(__file__),"..","sentinel.db")
def getconnect():
    conn =  sqlite3.connect(db_path ,timeout=10)
    conn.execute("PRAGMA journal_mode=WAL;")
    return conn
def int_db():
    con = getconnect()
    cursor= con.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS security_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            dest_ip TEXT,
            protocol TEXT,
            payload_sample TEXT,
            predicted_class TEXT,
            confidence REAL,
            severity TEXT,
            status TEXT DEFAULT 'Unreviewed'
        );
    """
    )
    con.commit()
    con.close()
def int_insert_event(src_ip, dst_ip, protocal, payload, pred_class, conf, severit):
    con = getconnect()
    cursor = con.cursor()
    current_time = datetime.now(timezone.utc).isoformat()
    cursor.execute(
        """
        INSERT INTO security_events 
        (timestamp, source_ip, dest_ip, protocol, payload_sample, predicted_class, confidence, severity)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
        (
        current_time,
        src_ip,
        dst_ip,
        protocal,
        payload[:500],  # Truncate sample to avoid database bloat
        pred_class,
        float(conf),
        severit
    ))
def fetch_incident(limit=50):
    con = getconnect()
    cusor = con.cursor()
    cusor.execute("""
        SELECT id, timestamp, source_ip, dest_ip, protocol, payload_sample, predicted_class, confidence, severity 
        FROM security_events 
        ORDER BY id DESC 
        LIMIT ?
    """, (limit,))
    rows = cusor.fetchall()
    con.close()
    return rows
    
if __name__ == "__main__":
    int_db()
    print("[+] Database initialized with WAL mode.")