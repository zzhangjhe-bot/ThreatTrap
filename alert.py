import urllib.request
import urllib.parse
import logging

SERVER_CHAN_KEY = "您的Server酱SCT密匙"


def send_wechat_alert(log_data):

    if not SERVER_CHAN_KEY:
        return

    url = f"https://sctapi.ftqq.com/{SERVER_CHAN_KEY}.send"

    title = f"🚨【蜜罐告警】发现来自 {log_data['src_ip']} 的恶意行为！"

    desp = (
        f"### ⚠️ 安全运营实时研判报告\n\n"
        f"- **⏰ 攻击时间:** {log_data['timestamp']}\n"
        f"- **🌐 攻击源 IP:** {log_data['src_ip']}:{log_data['src_port']}\n"
        f"- **🎯 自动化研判类型:** `{log_data['attack_type']}`\n"
        f"- **📝 原始请求流量:** `{log_data['request']}`\n\n"
        f"请立即登录 SOC 平台封禁该 IP！"
    )

    data = urllib.parse.urlencode({
        "title": title,
        "desp": desp
    }).encode('utf-8')

    try:

        req = urllib.request.Request(url, data=data)

        urllib.request.urlopen(req, timeout=5)

        logging.info("WeChat alert sent successfully")

    except Exception as e:

        logging.error(f"WeChat alert failed: {e}")