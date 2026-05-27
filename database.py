import sqlite3


def get_connection():
    return sqlite3.connect("data/honeypot.db")

def init_db():

    conn = sqlite3.connect("data/honeypot.db")
    cursor = conn.cursor()

    # 攻击日志表
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT,
        src_ip TEXT,
        src_port INTEGER,
        request TEXT,
        attack_type TEXT,
        risk_level TEXT,
        country TEXT
    )
    """)

    # 黑名单表
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS blocked_ips (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip TEXT UNIQUE,
        blocked_time TEXT,
        attack_count INTEGER
    )
    """)

    conn.commit()
    conn.close()


def save_log(log_entry):

    conn = sqlite3.connect("data/honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO attack_logs
    (
    timestamp,
    src_ip,
    src_port,
    request,
    attack_type,
    risk_level,
    country
)
VALUES (?, ?, ?, ?, ?, ?,?)
    """, (
        log_entry["timestamp"],
        log_entry["src_ip"],
        log_entry["src_port"],
        log_entry["request"],
        log_entry["attack_type"],
        log_entry["risk_level"],
        log_entry["country"]
    ))

    conn.commit()
    conn.close()


def add_blocked_ip(ip, blocked_time, attack_count):

    conn = sqlite3.connect("data/honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    INSERT OR REPLACE INTO blocked_ips
    (ip, blocked_time, attack_count)
    VALUES (?, ?, ?)
    """, (
        ip,
        blocked_time,
        attack_count
    ))

    conn.commit()
    conn.close()



def get_blocked_ips():

    conn = sqlite3.connect("data/honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT ip, attack_count, blocked_time
    FROM blocked_ips
    ORDER BY id DESC
    """)

    data = cursor.fetchall()

    conn.close()

    return data


def remove_blocked_ip(ip):

    conn = sqlite3.connect("data/honeypot.db")
    cursor = conn.cursor()

    cursor.execute("""
    DELETE FROM blocked_ips
    WHERE ip=?
    """, (ip,))

    conn.commit()
    conn.close()