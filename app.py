from flask import Flask, render_template, request, redirect, session

from datetime import datetime
from config import (
    SECRET_KEY,
    ADMIN_USERNAME,
    ADMIN_PASSWORD
)
from database import (
    get_connection,
    get_blocked_ips,
    remove_blocked_ip,
)

from alert import send_wechat_alert
from flask import Flask
from database import save_log, init_db
import threading

from honeypot import (
    check_and_block_ip,
    start_ssh_honeypot
)
app = Flask(__name__)
init_db()

@app.route("/login", methods=["GET", "POST"])
def login():

    ip = request.remote_addr
    ua = request.headers.get("User-Agent")
    path = request.full_path

    # 记录普通访问
    save_log({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "src_ip": ip,
        "src_port": 0,
        "request": path,
        "attack_type": "LOGIN_ACCESS",
        "risk_level": "LOW",
        "country": "Unknown"
    })

    # SQL注入检测
    sql_keywords = [
        "'",
        '"',
        "or",
        "union",
        "select",
        "--",
        "sleep",
        "benchmark",
        "drop",
        "insert"
    ]

    for keyword in sql_keywords:
        if keyword.lower() in path.lower():
            log_data = {
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "src_ip": ip,
                "src_port": 0,
                "request": path,
                "attack_type": "SQL Injection",
                "risk_level": "HIGH",
                "country": "Unknown"
            }

            # 保存日志
            save_log(log_data)

            # 微信推送
            send_wechat_alert(log_data)

            check_and_block_ip(ip)

            break

    # 登录验证
    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:

            session["login"] = True

            return redirect("/")

    return render_template("login.html")
app.secret_key = SECRET_KEY


@app.route("/")
def dashboard():

    # 未登录跳转
    if not session.get("login"):
        return redirect("/login")

    conn = get_connection()

    cursor = conn.cursor()

    # 最近日志
    cursor.execute("SELECT * FROM attack_logs ORDER BY id DESC")

    logs = cursor.fetchall()

    # 总请求数
    cursor.execute("SELECT COUNT(*) FROM attack_logs")

    total_requests = cursor.fetchone()[0]

    # SQL Injection
    cursor.execute("""
        SELECT COUNT(*) FROM attack_logs
        WHERE attack_type='SQL Injection'
    """)

    sql_count = cursor.fetchone()[0]
    # XSS Attack
    cursor.execute("""
        SELECT COUNT(*) FROM attack_logs
        WHERE attack_type='XSS Attack'
    """)
    xss_count = cursor.fetchone()[0]

    # Command Injection
    cursor.execute("""
        SELECT COUNT(*) FROM attack_logs
        WHERE attack_type='Command Injection'
    """)
    cmd_count = cursor.fetchone()[0]

    # File Inclusion
    cursor.execute("""
        SELECT COUNT(*) FROM attack_logs
        WHERE attack_type='File Inclusion'
    """)
    file_count = cursor.fetchone()[0]
    # SSH Brute Force
    cursor.execute("""
        SELECT COUNT(*) FROM attack_logs
        WHERE attack_type='SSH Brute Force'
    """)

    ssh_count = cursor.fetchone()[0]
    # Scanner Detection
    cursor.execute("""
        SELECT COUNT(*) FROM attack_logs
        WHERE attack_type='Scanner Detection'
    """)
    scanner_count = cursor.fetchone()[0]
    # Sensitive Path Scan
    cursor.execute("""
        SELECT COUNT(*) FROM attack_logs
        WHERE attack_type='Sensitive Path Scan'
    """)

    sensitive_count = cursor.fetchone()[0]

    # Directory Traversal
    cursor.execute("""
        SELECT COUNT(*) FROM attack_logs
        WHERE attack_type='Directory Traversal'
    """)

    traversal_count = cursor.fetchone()[0]

    # TOP 攻击 IP
    cursor.execute("""
        SELECT src_ip, COUNT(*)
        FROM attack_logs
        GROUP BY src_ip
        ORDER BY COUNT(*) DESC
        LIMIT 5
    """)

    top_ips = cursor.fetchall()

    # 趋势图数据
    cursor.execute("""

    SELECT
    strftime('%H:%M', timestamp),
    COUNT(*)

    FROM attack_logs

    GROUP BY strftime('%H:%M', timestamp)

    ORDER BY strftime('%H:%M', timestamp)

    """)

    trend_data = cursor.fetchall()

    blocked_ips = get_blocked_ips()

    conn.close()

    return render_template(
        "dashboard.html",
        logs=logs,
        total_requests=total_requests,
        sql_count=sql_count,
        sensitive_count=sensitive_count,
        traversal_count=traversal_count,
        xss_count=xss_count,
        cmd_count=cmd_count,
        file_count=file_count,
        scanner_count=scanner_count,
        top_ips=top_ips,
        ssh_count=ssh_count,
        blocked_ips=blocked_ips,
        trend_data=trend_data
    )

@app.route("/unblock/<ip>")
def unblock_ip(ip):

    remove_blocked_ip(ip)

    return redirect("/")

@app.route("/remove_block/<ip>")
def remove_block(ip):

    # 从数据库删除
    remove_blocked_ip(ip)

    # 从运行内存删除


    return redirect("/")

@app.route("/logout")
def logout():

    session.clear()

    return redirect("/login")

if __name__ == '__main__':

    init_db()

    ssh_thread = threading.Thread(
        target=start_ssh_honeypot
    )

    ssh_thread.start()

    app.run(
        host='0.0.0.0',
        port=5000,
        debug=False
    )