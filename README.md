# 🛡️ ThreatTrap: 轻量级全栈蜜罐与网络攻击动态监控平台

[![Python Version](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/framework-Flask%203.1.3-green.svg)](https://flask.palletsprojects.com/)
[![Docker](https://img.shields.io/badge/docker-supported-blue.svg)](https://www.docker.com/)
[![License](https://img.shields.io/badge/license-MIT-purple.svg)](LICENSE)

`ThreatTrap` 是一款基于 Python 开发的轻量级、企业级网络安全诱捕与主动防御平台。系统通过伪装高危服务端口（如 SSH 2222）和特定的 Web 登录入口，主动诱捕恶意扫描器及黑客攻击。平台内置高性能流式流量研判引擎，支持 9 种高危攻击类型的实时识别、地理位置解构（GeoIP）、秒级黑名单全自动封禁，并无缝集成微信实时告警通知与直观的 Chart.js 态势感知大屏。

---

## 🚀 功能特性

* **⚡ 双引擎诱捕架构**：多线程（Threading）并发运行，同时支持应用层（Flask Web 蜜罐）及传输层（原生 Socket 仿真 SSH 蜜罐）的联合诱捕。
* **🔍 八大高危攻击全检测**：内置深度正则与关键词过滤引擎，支持 SQL 注入、命令注入、XSS 跨站脚本、文件包含、目录遍历、敏感路径扫描、高频自动化扫描器及 SSH 暴力破解的精准识别。
* **🛑 智能判定与自动封禁**：系统自动记录攻击频次，当同一恶意 IP 的累计有效攻击次数达到预设阈值（默认 5 次）时，触发安全防御机制，自动加入数据库黑名单实施拦截，并支持在 SOC 后台一键解封。
* **🌍 地理位置实时解构**：深度集成离线 MaxMind GeoLite2 数据库，秒级将攻击源 IP 转换为地理位置国家信息，实现攻击源精准溯源。
* **🚨 微信秒级联动告警**：基于 Server酱 通道，当捕捉到高危或致命（CRITICAL）攻击行为时，秒级向运维与安全人员推送结构化的“安全运营实时研判报告”。
* **📊 态势感知数据大屏**：基于 Chart.js 打造全响应式前端控制台，支持 5 秒自适应异步刷新。直观展现总请求量、各攻击维度卡片、TOP 5 攻击源排行、实时攻击趋势折线图以及完整的黑名单拦截列表与历史日志审计。

---

## 🛠️ 技术栈

* **核心语言**：Python 3.11
* **Web 框架**：Flask 3.1.3 (用于构建 SOC 监控大屏与管理后台)
* **网络诱捕**：Socket 传输层通信 (原生仿真 SSH 协议 Banner 响应)
* **数据存储**：SQLite3 (轻量高效、零外置依赖的本地关系型数据库)
* **数据可视化**：Chart.js (全响应式前端数据态势呈现)
* **依赖库**：`geoip2` (IP 地理位置解析)、`requests` & `urllib` (微信外发通知接口)
* **容器化技术**：Docker & Docker Compose (环境全隔离，一键编排部署)

---

## 📐 项目架构

系统采用清晰的模块化微型架构，确保核心逻辑高内聚、低耦合：

```text
├── app.py                # SOC 控制面板核心、Web 路由管理及登录流 SQL 注入防御
├── honeypot.py           # 核心流量流式分析引擎、多线程 SSH 仿真诱捕服务
├── database.py           # SQLite 数据库底层 ORM，负责日志持久化与黑名单策略读写
├── alert.py              # 安全运营通知组件（基于 Server酱 的微信公众号通知）
├── geoip.py              # MaxMind 离线地理信息库连接器
├── config.py             # 平台全局核心配置文件（密钥、管理员凭证、封禁阈值）
├── Dockerfile            # 基于 AliYun 镜像加速的容器构建脚本
├── docker-compose.yml    # 本地数据流卷挂载与端口编排
├── requirements.txt      # 严格锁定的三方依赖清单
├── .dockerignore         # 容器构建虚拟环境与本地日志隔离定义
└── templates/
    ├── dashboard.html    # 态势感知数据监控大屏模板（含 Chart.js 渲染及异步刷新）
    └── login.html        # SOC 蜜罐控制台登录验证页面