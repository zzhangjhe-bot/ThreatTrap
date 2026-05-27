import logging
import os
import socket
from datetime import datetime
import sqlite3
import urllib.parse
import re
import threading
from geoip import get_country

from database import (
    save_log,
    init_db,
    add_blocked_ip
)

from alert import send_wechat_alert


# =========================
# 创建日志目录
# =========================

if not os.path.exists("logs"):
    os.makedirs("logs")


# =========================
# logging 配置
# =========================

logging.basicConfig(
    filename="logs/honeypot.log",
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s"
)


# =========================
# 检测规则
# =========================

DETECTION_RULES = {

    "SQL Injection": [

        r"union\s+select",
        r"or\s+1=1",
        r"sleep\s*\(",
        r"drop\s+table",
        r"--",
        r"'"

    ],

    "Directory Traversal": [

        r"\.\./",
        r"\.\.\\",
        r"/etc/passwd",
        r"win\.ini"

    ],

    "Sensitive Path Scan": [

        r"/admin",
        r"/phpmyadmin",
        r"/\.git",
        r"/config"

    ]
}


# =========================
# 查询 IP 是否封禁
# =========================

def is_ip_blocked(ip):

    conn = sqlite3.connect("honeypot.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT *
        FROM blocked_ips
        WHERE ip=?
    """, (ip,))

    result = cursor.fetchone()

    conn.close()

    return result is not None


# =========================
# 自动封禁恶意 IP
# =========================

def check_and_block_ip(ip):

    conn = sqlite3.connect("honeypot.db")

    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*)
        FROM attack_logs
        WHERE src_ip=?
        AND attack_type != 'Normal or Unknown Scan'
    """, (ip,))

    attack_count = cursor.fetchone()[0]

    if attack_count >= 5:

        blocked_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        add_blocked_ip(
            ip,
            blocked_time,
            attack_count
        )

        logging.warning(f"Blocked malicious IP: {ip}")

    conn.close()


# =========================
# 流量分析
# =========================

def analyze_traffic(raw_data):

    decoded_data = raw_data.decode(
        'utf-8',
        errors='ignore'
    )

    first_line = (
        decoded_data.split('\n')[0]
        if decoded_data else ""
    )

    clear_text = urllib.parse.unquote(
        first_line.lower()
    )

    attack_type = "Normal or Unknown Scan"

    risk_level = "LOW"

    # =========================
    # SQL Injection
    # =========================

    sql_keywords = [

        "union select",
        "or 1=1",
        "sleep(",
        "drop table",
        "' or '1'='1",
        "--"

    ]

    for keyword in sql_keywords:

        if keyword.lower() in clear_text:

            attack_type = "SQL Injection"

            risk_level = "HIGH"

    # =========================
    # Directory Traversal
    # =========================

    traversal_keywords = [

        "../",
        "..\\",
        "/etc/passwd",
        "win.ini"

    ]

    for keyword in traversal_keywords:

        if keyword.lower() in clear_text:

            attack_type = "Directory Traversal"

            risk_level = "HIGH"

    # =========================
    # XSS 检测
    # =========================

    xss_keywords = [

        "<script>",
        "javascript:",
        "onerror=",
        "alert(",
        "<img"

    ]

    for keyword in xss_keywords:

        if keyword.lower() in clear_text:

            attack_type = "XSS Attack"

            risk_level = "HIGH"

    # =========================
    # Command Injection
    # =========================

    cmd_keywords = [

        ";cat",
        ";ls",
        "&&",
        "| whoami",
        "/bin/sh",
        "cmd.exe"

    ]

    for keyword in cmd_keywords:

        if keyword.lower() in clear_text:

            attack_type = "Command Injection"

            risk_level = "CRITICAL"

    # =========================
    # File Inclusion
    # =========================

    file_keywords = [

        "etc/passwd",
        "boot.ini",
        "../../",
        "..\\..\\"

    ]

    for keyword in file_keywords:

        if keyword.lower() in clear_text:

            attack_type = "File Inclusion"

            risk_level = "HIGH"

    # =========================
    # Scanner Detection
    # =========================

    scanner_keywords = [

        "sqlmap",
        "nmap",
        "nikto",
        "acunetix",
        "masscan"

    ]

    for keyword in scanner_keywords:

        if keyword.lower() in decoded_data.lower():

            attack_type = "Scanner Detection"

            risk_level = "MEDIUM"

    # =========================
    # Sensitive Path Scan
    # =========================

    sensitive_keywords = [

        "/admin",
        "/phpmyadmin",
        "/.git",
        "/config"

    ]

    for keyword in sensitive_keywords:

        if keyword.lower() in clear_text:

            attack_type = "Sensitive Path Scan"

            risk_level = "MEDIUM"

    return first_line, attack_type, risk_level

# =========================
# SSH 蜜罐
# =========================

def handle_ssh_client(client_socket, client_address):

    ip = client_address[0]

    port = client_address[1]

    logging.warning(
        f"SSH connection from {ip}:{port}"
    )

    # 先发送 SSH Banner
    try:

        client_socket.sendall(
            b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
        )

    except:
        client_socket.close()
        return

    # 接收客户端数据
    try:

        data = client_socket.recv(1024)

        logging.info(
            f"SSH Payload: {data}"
        )

    except:
        pass

    current_time = datetime.now().strftime(
        '%Y-%m-%d %H:%M:%S'
    )

    log_entry = {

        "timestamp": current_time,

        "src_ip": ip,

        "src_port": port,

        "request": "SSH Login Attempt",

        "attack_type": "SSH Brute Force",

        "risk_level": "HIGH",

        "country": get_country(ip)
    }

    save_log(log_entry)

    check_and_block_ip(ip)

    send_wechat_alert(log_entry)

    client_socket.close()


def start_ssh_honeypot():

    ssh_server = socket.socket(
        socket.AF_INET,
        socket.SOCK_STREAM
    )

    ssh_server.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    ssh_server.bind(('0.0.0.0', 2222))

    ssh_server.listen(5)

    logging.info(
        "SSH Honeypot started on port 2222"
    )

    while True:

        client_socket, client_address = ssh_server.accept()

        ssh_thread = threading.Thread(
            target=handle_ssh_client,
            args=(client_socket, client_address)
        )

        ssh_thread.start()
# =========================
# 启动蜜罐
# =========================




# =========================
# 主程序入口
# =========================

