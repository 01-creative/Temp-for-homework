import os
import re
import sys
import time
import subprocess
import platform
# imghdr was removed in Python 3.13. The try/except handles both
# the standard library version (< 3.13) and the 'standard-imghdr'
# backport for 3.13+. If neither is available, a magic-byte fallback
# is used in validate_image_content().
try:
    import imghdr
except ImportError:
    imghdr = None
import sqlite3
import secrets
import logging
import ipaddress
import math
import socket
import urllib.request
import urllib.error
import urllib.parse
import json
import xml.etree.ElementTree as ET
try:
    import defusedxml.ElementTree as safe_ET
    HAVE_DEFUSEDXML = True
except ImportError:
    safe_ET = ET
    HAVE_DEFUSEDXML = False
from uuid import uuid4
from datetime import datetime, timedelta
from flask import Flask, render_template, request, redirect, session, url_for
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.utils import secure_filename

app = Flask(__name__)
if os.environ.get("BEHIND_PROXY", "0") == "1":
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

# ============================================================
# 基础配置
# ============================================================
DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"
HOST = os.environ.get("FLASK_HOST", "127.0.0.1")
PORT = int(os.environ.get("FLASK_PORT", "5000"))
SESSION_SECURE = os.environ.get("FLASK_SESSION_SECURE", "1") == "1"

# ============================================================
# 数据库路径
# ============================================================
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_PATH = os.path.join(DB_DIR, "users.db")

# UID 分配常量
UID_SYSTEM_RESERVED = 10000       # 0-10000 系统保留
UID_HARD_LIMIT = 1000000          # 硬上限
UID_RANGE_SIZE = 1000             # 每次分配的区间大小


# ============================================================
# 数据库初始化
# ============================================================
def get_db():
    """获取数据库连接，启用 row_factory 以便字典式访问"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db():
    """初始化数据库：创建目录、检查架构迁移、建表、插入默认用户"""
    os.makedirs(DB_DIR, exist_ok=True)
    conn = get_db()
    try:
        # 检查是否需要迁移旧架构（无 uid 列则重建）
        cursor = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='users'"
        )
        if cursor.fetchone():
            cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
            if "uid" not in cols:
                logger.info("检测到旧版数据库架构（缺少 uid 列），正在迁移...")
                conn.execute("DROP TABLE users")
                logger.info("旧表已删除，将按新架构重建")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                uid INTEGER PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                email TEXT,
                phone TEXT,
                avatar TEXT,
                role TEXT DEFAULT 'user',
                balance INTEGER DEFAULT 0,
                first_login INTEGER DEFAULT 0,
                session_version INTEGER DEFAULT 1
            )
        """)

        # 迁移：为旧表添加 avatar 列
        cols = [row[1] for row in conn.execute("PRAGMA table_info(users)").fetchall()]
        if "avatar" not in cols:
            conn.execute("ALTER TABLE users ADD COLUMN avatar TEXT")

        # 插入默认用户（系统保留 UID: admin=1, alice=2, first_login=1）
        # 初始密码必须通过环境变量注入，严禁在源码中硬编码
        admin_pwd = os.environ.get("INIT_PWD_ADMIN", "")
        alice_pwd = os.environ.get("INIT_PWD_ALICE", "")
        if not admin_pwd:
            print("[致命错误] 必须设置环境变量 INIT_PWD_ADMIN 以指定 admin 初始密码")
            sys.exit(1)
        if not alice_pwd:
            print("[致命错误] 必须设置环境变量 INIT_PWD_ALICE 以指定 alice 初始密码")
            sys.exit(1)

        conn.execute(
            "INSERT OR IGNORE INTO users (uid, username, password, email, phone, role, balance, first_login, session_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (1, "admin", generate_password_hash(admin_pwd),
             "admin@example.com", "13800138000", "admin", 99999, 1, 1)
        )
        conn.execute(
            "INSERT OR IGNORE INTO users (uid, username, password, email, phone, role, balance, first_login, session_version) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (2, "alice", generate_password_hash(alice_pwd),
             "alice@example.com", "13900139001", "user", 100, 1, 1)
        )

        conn.commit()
        logger.info("数据库初始化完成")
    finally:
        conn.close()


# ============================================================
# UID 分配
# ============================================================

def allocate_uid():
    """
    从当前未满区间中随机分配一个空闲 UID。
    区间大小为 UID_RANGE_SIZE，从 UID_SYSTEM_RESERVED+1 开始逐区间查找。
    返回 None 表示已达硬上限，无法分配。
    """
    conn = get_db()
    try:
        conn.execute("BEGIN IMMEDIATE")
        range_start = UID_SYSTEM_RESERVED + 1  # 10001

        while range_start < UID_HARD_LIMIT:
            range_end = range_start + UID_RANGE_SIZE - 1
            if range_end >= UID_HARD_LIMIT:
                range_end = UID_HARD_LIMIT - 1

            # 查询当前区间内已被占用的 UID
            used = set(
                row[0] for row in conn.execute(
                    "SELECT uid FROM users WHERE uid >= ? AND uid <= ?",
                    (range_start, range_end)
                ).fetchall()
            )

            # 计算空闲 UID 列表
            free = [u for u in range(range_start, range_end + 1) if u not in used]
            if free:
                chosen = secrets.choice(free)
                conn.commit()
                return chosen

            range_start += UID_RANGE_SIZE

        conn.commit()
        return None  # 所有区间已满
    finally:
        conn.close()


# ============================================================
# 数据库辅助函数
# ============================================================

def db_get_user_by_username(username):
    """通过用户名获取完整用户信息（含密码哈希），不存在返回 None"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def db_get_user_full(uid):
    """通过 UID 获取完整用户信息（含密码哈希），不存在返回 None"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM users WHERE uid = ?",
            (uid,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def db_get_user_safe(uid):
    """通过 UID 获取用户安全信息（排除密码），不存在返回 None"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT uid, username, email, phone, avatar, role, balance, first_login, session_version "
            "FROM users WHERE uid = ?",
            (uid,)
        ).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def db_insert_user(uid, username, password_hash, email, phone):
    """插入新用户，返回 (success, error_message)"""
    conn = get_db()
    try:
        conn.execute(
            "INSERT INTO users (uid, username, password, email, phone) VALUES (?, ?, ?, ?, ?)",
            (uid, username, password_hash, email, phone)
        )
        conn.commit()
        return True, ""
    except sqlite3.IntegrityError:
        return False, "用户名已存在"
    except Exception as e:
        logger.error(f"插入用户失败: {e}")
        return False, "注册失败，请稍后再试"
    finally:
        conn.close()


def db_update_user_password(uid, new_password_hash):
    """更新用户密码，同时递增 session_version 并取消首次登录标记"""
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET password = ?, first_login = 0, session_version = session_version + 1 "
            "WHERE uid = ?",
            (new_password_hash, uid)
        )
        conn.commit()
    finally:
        conn.close()


def db_update_user_info(uid, email, phone, new_username=None):
    """
    更新用户信息（邮箱、手机号，可选修改用户名）。
    返回 (success, error_message)
    """
    conn = get_db()
    try:
        if new_username:
            conn.execute(
                "UPDATE users SET email = ?, phone = ?, username = ? WHERE uid = ?",
                (email, phone, new_username, uid)
            )
        else:
            conn.execute(
                "UPDATE users SET email = ?, phone = ? WHERE uid = ?",
                (email, phone, uid)
            )
        conn.commit()
        return True, ""
    except sqlite3.IntegrityError:
        return False, "用户名已存在"
    except Exception as e:
        logger.error(f"更新用户信息失败: {e}")
        return False, "更新失败，请稍后再试"
    finally:
        conn.close()


def db_get_session_version(uid):
    """获取用户当前 session_version"""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT session_version FROM users WHERE uid = ?",
            (uid,)
        ).fetchone()
        return row["session_version"] if row else 0
    finally:
        conn.close()


def db_update_balance(uid, amount):
    """使用参数化 SQL 更新用户余额（`balance = balance + ?`）。返回 True 表示成功。"""
    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET balance = balance + ? WHERE uid = ?",
            (amount, uid)
        )
        conn.commit()
        return True
    except Exception as e:
        logger.error(f"更新余额失败 (uid={uid}): {e}")
        return False
    finally:
        conn.close()


def db_search_users(keyword):
    """根据 username 和 email 进行模糊搜索，使用参数化查询"""
    conn = get_db()
    try:
        # 过滤 LIKE 通配符，防止批量导出或逐字符枚举
        safe_keyword = keyword.replace("%", "").replace("_", "")
        if len(safe_keyword) < 1:
            return []
        pattern = f"%{safe_keyword}%"
        rows = conn.execute(
            "SELECT uid, username, email, phone FROM users WHERE username LIKE ? OR email LIKE ?",
            (pattern, pattern)
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


# ============================================================
# 黑盒修复1：Debug 模式安全加固
# ============================================================
if DEBUG:
    print("""
╔══════════════════════════════════════════════════════════╗
║  ⚠️  警告: Flask 正在以 DEBUG 模式运行!                   ║
║  Debug 模式会暴露 Werkzeug 交互式调试控制台，              ║
║  可能导致远程代码执行 (RCE)。                              ║
║  此模式仅允许在本地开发环境使用，禁止对外暴露。            ║
║  确认这是开发环境吗？(y/n)                                ║
╚══════════════════════════════════════════════════════════╝
    """)
    if not sys.stdin.isatty() or os.path.exists("/.dockerenv"):
        print("[致命错误] 非交互式环境或Docker环境下不允许 DEBUG 模式启动，请设置 FLASK_DEBUG=0")
        sys.exit(1)
    answer = input("> ").strip().lower()
    if answer != "y":
        print("[已取消] 启动已中止")
        sys.exit(1)
    if HOST != "127.0.0.1" and HOST != "localhost":
        print(f"[安全] DEBUG 模式下 HOST 从 {HOST} 强制改为 127.0.0.1")
        HOST = "127.0.0.1"

# ============================================================
# Secret Key — 环境变量优先，加强校验
# ============================================================
_raw_key = os.environ.get("FLASK_SECRET_KEY", "")
if _raw_key:
    if len(_raw_key) < 32:
        print(f"[致命错误] FLASK_SECRET_KEY 长度仅 {len(_raw_key)} 字符，必须 ≥ 32 字符")
        print("[致命错误] 弱密钥可被暴力猜测导致 Session 伪造攻击，拒绝启动")
        sys.exit(1)
    app.secret_key = _raw_key
else:
    app.secret_key = os.urandom(32).hex()
    print("[信息] 未设置 FLASK_SECRET_KEY，已使用随机密钥（重启后所有 session 将失效）")

# ============================================================
# Session Cookie 安全属性
# ============================================================
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=SESSION_SECURE,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_NAME="session",
    MAX_CONTENT_LENGTH=16 * 1024 * 1024,
)

# ============================================================
# 自动创建上传目录
# ============================================================
UPLOAD_FOLDER = os.path.join(BASE_DIR, "static", "uploads")
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 允许的图片扩展名白名单
ALLOWED_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "webp"}
# 允许的 MIME 类型白名单
ALLOWED_MIME_TYPES = {"image/jpeg", "image/png", "image/gif", "image/webp"}


def allowed_file(filename):
    """检查文件扩展名是否在白名单内"""
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def validate_image_content(content):
    """
    验证文件内容是否为合法图片（基于魔术字节，支持 imghdr 和降级方案）。
    在写入磁盘之前调用，消除 TOCTOU 风险。
    返回 image_type（如 'jpeg', 'png', 'gif', 'webp'）或 None。
    """
    if imghdr is not None:
        # imghdr.what(None, h=...) 支持内存字节判断
        img_type = imghdr.what(None, h=content)
        if img_type and img_type in ALLOWED_EXTENSIONS:
            return img_type
        return None

    # ---- imghdr 不可用时的魔数降级检测 ----
    if not isinstance(content, bytes):
        return None
    # JPEG: \xFF\xD8\xFF
    if content[:3] == b'\xff\xd8\xff':
        return 'jpeg'
    # PNG
    if content[:8] == b'\x89PNG\r\n\x1a\n':
        return 'png'
    # GIF87a / GIF89a
    if content[:6] in (b'GIF87a', b'GIF89a'):
        return 'gif'
    # WebP: RIFF + size + WEBP
    if len(content) >= 12 and content[:4] == b'RIFF' and content[8:12] == b'WEBP':
        return 'webp'
    return None


# 上传文件大小上限（同时受 Flask MAX_CONTENT_LENGTH 保护）
UPLOAD_MAX_SIZE = 16 * 1024 * 1024

# ============================================================
# 移除 Server 响应头
# ============================================================
@app.after_request
def remove_server_header(response):
    response.headers["Server"] = "WEB"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    if SESSION_SECURE:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# ============================================================
# 413 请求实体过大处理
# ============================================================
@app.errorhandler(413)
def request_entity_too_large(error):
    """当上传超过 MAX_CONTENT_LENGTH 时返回友好提示"""
    uid = session.get("uid")
    if uid:
        return render_template("upload.html",
            error="文件大小超过限制（最大 16MB），请压缩后重新上传"), 413
    return render_template("login.html", error="请求内容过大"), 413


# ============================================================
# 登录频率限制（双窗口 + 用户名维度）
# ============================================================
import threading
_rate_limit_lock = threading.Lock()
REGISTER_ATTEMPTS = {}
REGISTER_MAX_PER_IP = 3
REGISTER_WINDOW_MIN = 5

LOGIN_ATTEMPTS = {}
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 5
SHORT_THRESHOLD = 3
SHORT_WINDOW_SEC = 60
SHORT_LOCK_SEC = 60

PER_USERNAME_LIMIT = 10
PER_USERNAME_LOCKOUT_MIN = 15

# 时序侧信道 — 假哈希
DUMMY_HASH = generate_password_hash("__dummy_constant_string_for_timing__")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ======================== 辅助函数 ========================

def get_safe_user(uid):
    """返回用户安全信息（排除密码）"""
    return db_get_user_safe(uid)


def get_greeting():
    """根据系统时间返回问候语"""
    hour = datetime.now().hour
    if hour < 6:
        return "夜深了，注意休息"
    elif hour < 9:
        return "早上好"
    elif hour < 12:
        return "上午好"
    elif hour < 14:
        return "中午好"
    elif hour < 18:
        return "下午好"
    elif hour < 22:
        return "晚上好"
    else:
        return "夜深了，注意休息"


def generate_csrf_token():
    """生成 CSRF Token"""
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(32)
    return session["csrf_token"]


def validate_csrf():
    """校验 POST 请求中的 CSRF Token，捕获畸形数据防止 500"""
    if request.method != "POST":
        return True
    try:
        token = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not token or not secrets.compare_digest(token, expected):
            logger.warning(f"CSRF 校验失败，IP: {request.remote_addr}")
            return False
        return True
    except RequestEntityTooLarge:
        # 请求体超过 MAX_CONTENT_LENGTH 时重新抛出，触发 413 错误处理器
        raise
    except Exception:
        logger.warning(f"CSRF 请求解析异常（畸形表单数据），IP: {request.remote_addr}")
        return False


def _make_rate_key(ip, username=None):
    """生成限流用的复合键"""
    if username:
        return f"user:{username}:ip:{ip}"
    return f"ip:{ip}"


def cleanup_login_attempts(now):
    """清理已完全过期的条目"""
    stale_keys = []
    for key, record in LOGIN_ATTEMPTS.items():
        long_expired = (not record.get("locked_until") or now >= record["locked_until"])
        short_expired = (not record.get("short_locked_until") or now >= record["short_locked_until"])
        recent = record.get("recent_failures", [])
        recent_active = [t for t in recent if (now - t).total_seconds() <= SHORT_WINDOW_SEC]
        no_recent = len(recent_active) == 0
        no_count = record.get("count", 0) == 0
        if long_expired and short_expired and no_recent and no_count:
            stale_keys.append(key)
    for key in stale_keys:
        LOGIN_ATTEMPTS.pop(key, None)
    if len(LOGIN_ATTEMPTS) > 10000:
        logger.warning("LOGIN_ATTEMPTS 超过 10000 条，触发强制清理")
        keys = list(LOGIN_ATTEMPTS.keys())
        for key in keys[:len(keys) // 2]:
            LOGIN_ATTEMPTS.pop(key, None)


def check_rate_limit(key, max_attempts, lock_minutes, short_thresh, short_sec, lock_sec):
    """通用限流检查，返回 (allowed, remaining_seconds)"""
    now = datetime.now()
    with _rate_limit_lock:
        cleanup_login_attempts(now)

        record = LOGIN_ATTEMPTS.get(key)
        if not record:
            return True, 0

        if record.get("locked_until") and now < record["locked_until"]:
            remaining = int((record["locked_until"] - now).total_seconds())
            return False, remaining

        if record.get("short_locked_until") and now < record["short_locked_until"]:
            remaining = int((record["short_locked_until"] - now).total_seconds())
            return False, remaining

        if record.get("locked_until") and now >= record["locked_until"]:
            record["locked_until"] = None
            record["count"] = 0
        if record.get("short_locked_until") and now >= record["short_locked_until"]:
            record["short_locked_until"] = None
            record["recent_failures"] = []

        LOGIN_ATTEMPTS[key] = record
        return True, 0


def record_rate_failure(key, max_attempts, lock_minutes, short_thresh, short_sec, lock_sec):
    """通用失败记录"""
    now = datetime.now()
    with _rate_limit_lock:
        record = LOGIN_ATTEMPTS.get(key, {
            "count": 0, "locked_until": None,
            "recent_failures": [], "short_locked_until": None,
        })
        record["count"] = record.get("count", 0) + 1
        if record["count"] >= max_attempts:
            record["locked_until"] = now + timedelta(minutes=lock_minutes)
            logger.warning(f"[限流锁定] {key} 累计失败{record['count']}次，锁定{lock_minutes}分钟")

        recent = record.get("recent_failures", [])
        recent.append(now)
        recent = [t for t in recent if (now - t).total_seconds() <= short_sec]
        record["recent_failures"] = recent
        if len(recent) >= short_thresh:
            record["short_locked_until"] = now + timedelta(seconds=lock_sec)
            logger.warning(f"[限流短锁] {key} {short_sec}秒内失败{len(recent)}次")

        LOGIN_ATTEMPTS[key] = record


def reset_rate_limit(key):
    """清除指定键的限流记录"""
    LOGIN_ATTEMPTS.pop(key, None)


def validate_password_strength(password):
    """验证密码强度"""
    if len(password) < 8:
        return False, "密码长度不能少于 8 位"
    if not any(c.isupper() for c in password):
        return False, "密码必须包含至少一个大写字母"
    if not any(c.islower() for c in password):
        return False, "密码必须包含至少一个小写字母"
    if not any(c.isdigit() for c in password):
        return False, "密码必须包含至少一个数字"
    if not any(c in "!@#$%^&*()_+-=[]{}|;':\",./<>?`~" for c in password):
        return False, "密码必须包含至少一个特殊字符"
    return True, ""


def sanitize_input(value, field_name):
    """输入防 XSS 校验，使用白名单而非黑名单"""
    if not value:
        return True, ""
    if re.search(r'<[^>]*>', value):
        return False, f"{field_name} 不允许包含 HTML 标签"
    if field_name == "邮箱":
        if not re.match(r'^[a-zA-Z0-9@._+\-]+$', value):
            return False, f"{field_name} 包含不允许的字符"
    if field_name == "手机":
        if not re.match(r'^\+?\d[\d\-]*$', value):
            return False, f"{field_name} 包含不允许的字符"
    return True, ""


# ======================== 模板上下文注入 ========================

@app.context_processor
def inject_template_vars():
    """向模板注入全局变量，通过 uid 查找当前用户名"""
    uid = session.get("uid")
    current_username = None
    if uid:
        user = db_get_user_safe(uid)
        if user:
            current_username = user["username"]
    return {
        "csrf_token": session.get("csrf_token", ""),
        "current_username": current_username,
    }


# ======================== 全局钩子 ========================

@app.before_request
def enforce_password_change():
    """强制首次登录改密不可绕过（仅系统默认用户触发）"""
    uid = session.get("uid")
    if uid:
        user = db_get_user_safe(uid)
        if user and user.get("first_login"):
            if request.endpoint not in ("change_password", "logout", "static"):
                return redirect(url_for("change_password"))


@app.before_request
def enforce_session_version():
    """改密后旧 Session 失效"""
    uid = session.get("uid")
    if uid:
        sess_ver = session.get("session_version", 0)
        user_ver = db_get_session_version(uid)
        if sess_ver != user_ver:
            logger.info(f"用户 uid={uid} session 版本不匹配，强制登出")
            session.clear()
            return redirect(url_for("login"))


# ======================== Ping 诊断输入校验 ========================

def is_valid_ip_or_hostname(value):
    """白名单校验：仅允许合法 IPv4/IPv6 地址和标准域名格式"""
    ipv4_re = r'^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\Z'
    ipv6_re = r'^([0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\Z'
    hostname_re = r'^([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])(\.([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]))*\Z'
    if re.match(ipv4_re, value) or re.match(ipv6_re, value) or re.match(hostname_re, value):
        return True
    return False


# ======================== 路由 ========================

@app.route("/")
def index():
    uid = session.get("uid")
    user = db_get_user_safe(uid) if uid else None
    username = user["username"] if user else None
    greeting = get_greeting()
    return render_template("index.html", username=username, user=user, greeting=greeting)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        if not validate_csrf():
            return render_template("login.html", error="请求校验失败，请刷新页面后重试")

        username = request.form.get("username", "").strip().replace("\n", " ").replace("\r", " ")
        password = request.form.get("password", "")

        client_ip = request.remote_addr

        # IP + 用户名双重维度限流
        ip_key = _make_rate_key(client_ip)
        user_key = _make_rate_key(client_ip, username)

        ip_allowed, _ = check_rate_limit(ip_key, MAX_ATTEMPTS, LOCKOUT_MINUTES,
                                          SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)
        user_allowed, _ = check_rate_limit(user_key, PER_USERNAME_LIMIT, PER_USERNAME_LOCKOUT_MIN,
                                            SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)

        if not ip_allowed or not user_allowed:
            return render_template("login.html", error="请求过于频繁，请稍后再试")

        # 时序侧信道防御
        user_record = db_get_user_by_username(username)
        if user_record is not None:
            pwd_valid = check_password_hash(user_record["password"], password)
        else:
            check_password_hash(DUMMY_HASH, password)
            pwd_valid = False

        if pwd_valid:
            # Prevent session fixation: clear old session data first
            session.clear()
            session["uid"] = user_record["uid"]
            session["session_version"] = user_record["session_version"]
            # Generate new CSRF token for the new session
            generate_csrf_token()

            reset_rate_limit(ip_key)
            reset_rate_limit(user_key)
            logger.info(f"用户 '{username}' (uid={user_record['uid']}) 登录成功")

            if user_record.get("first_login", False):
                session["force_change_password"] = True
                return redirect(url_for("change_password"))

            return redirect(url_for("index"))

        record_rate_failure(ip_key, MAX_ATTEMPTS, LOCKOUT_MINUTES,
                            SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)
        record_rate_failure(user_key, PER_USERNAME_LIMIT, PER_USERNAME_LOCKOUT_MIN,
                            SHORT_THRESHOLD, SHORT_WINDOW_SEC, SHORT_LOCK_SEC)
        logger.warning(f"用户 '{username}' 从 {client_ip} 登录失败")
        return render_template("login.html", error="用户名或密码错误")

    generate_csrf_token()
    return render_template("login.html")


# ============================================================
# 用户注册
# ============================================================
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if not validate_csrf():
            return render_template("register.html", error="请求校验失败，请刷新页面后重试")

        # Registration rate limiting by IP
        client_ip = request.remote_addr
        now_dt = datetime.now()
        reg_key = f"reg:{client_ip}"
        reg_record = REGISTER_ATTEMPTS.get(reg_key, {"count": 0, "window_start": now_dt})
        if (now_dt - reg_record["window_start"]).total_seconds() > REGISTER_WINDOW_MIN * 60:
            reg_record = {"count": 0, "window_start": now_dt}
        if reg_record["count"] >= REGISTER_MAX_PER_IP:
            return render_template("register.html", error="注册请求过于频繁，请稍后再试")
        reg_record["count"] += 1
        REGISTER_ATTEMPTS[reg_key] = reg_record

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")
        email = request.form.get("email", "").strip()
        phone = request.form.get("phone", "").strip()

        # 长度校验
        if len(username) > 50:
            return render_template("register.html", error="用户名不能超过50个字符")

        # XSS 输入过滤（与邮箱、手机一致）
        if username:
            ok, err = sanitize_input(username, "用户名")
            if not ok:
                return render_template("register.html", error=err)
        if len(password) > 128:
            return render_template("register.html", error="密码不能超过128个字符")
        if len(email) > 255:
            return render_template("register.html", error="邮箱不能超过255个字符")
        if len(phone) > 32:
            return render_template("register.html", error="手机号不能超过32个字符")

        # 用户名不能为空
        if not username:
            return render_template("register.html", error="用户名不能为空")

        # 密码不能为空
        if not password:
            return render_template("register.html", error="密码不能为空")

        # 两次密码一致
        if password != confirm_password:
            return render_template("register.html", error="两次输入的密码不一致")

        # 密码强度
        valid, msg = validate_password_strength(password)
        if not valid:
            return render_template("register.html", error=msg)

        # 邮箱格式
        if email and "@" not in email:
            return render_template("register.html", error="请输入有效的邮箱地址")

        # XSS 输入过滤
        if email:
            ok, err = sanitize_input(email, "邮箱")
            if not ok:
                return render_template("register.html", error=err)
        if phone:
            ok, err = sanitize_input(phone, "手机")
            if not ok:
                return render_template("register.html", error=err)

        # 检查用户名是否已存在
        if db_get_user_by_username(username):
            return render_template("register.html", error="用户名已存在，请选择其他用户名")

        # 检查邮箱唯一性
        if email:
            conn = get_db()
            try:
                existing = conn.execute(
                    "SELECT uid FROM users WHERE email = ?",
                    (email,)
                ).fetchone()
                if existing:
                    return render_template("register.html", error="该邮箱已被注册")
            finally:
                conn.close()

        # 分配 UID（注册成功时才分配）
        uid = allocate_uid()
        if uid is None:
            return render_template("register.html", error="注册失败：用户数量已达上限，请联系管理员")

        # 插入数据库
        password_hash = generate_password_hash(password)
        success, db_error = db_insert_user(uid, username, password_hash, email, phone)
        if not success:
            return render_template("register.html", error=db_error)

        safe_log_username = username.replace("\n", " ").replace("\r", " ")
        logger.info(f"新用户 '{safe_log_username}' (uid={uid}) 注册成功")
        return redirect(url_for("login", registered="1"))

    generate_csrf_token()
    return render_template("register.html")


# ============================================================
# 用户搜索
# ============================================================
@app.route("/search")
def search():
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))
    user = db_get_user_safe(uid)
    username = user["username"] if user else None
    greeting = get_greeting()

    keyword = request.args.get("keyword", "").strip()
    search_results = []
    search_performed = False

    if keyword:
        search_performed = True
        start_time = time.time()
        search_results = db_search_users(keyword)
        elapsed_ms = int((time.time() - start_time) * 1000)

        safe_log_keyword = keyword.replace("\n", " ").replace("\r", " ")
        logger.info(
            f"[搜索] 方法={request.method} | keyword=\"{safe_log_keyword}\" | "
            f"耗时={elapsed_ms}ms | 结果数={len(search_results)}"
        )

    return render_template(
        "index.html",
        username=username,
        user=user,
        greeting=greeting,
        keyword=keyword,
        search_results=search_results,
        search_performed=search_performed,
    )


# ============================================================
# Logout — POST + CSRF
# ============================================================
@app.route("/logout", methods=["POST"])
def logout():
    if not validate_csrf():
        return redirect(url_for("index"))
    uid = session.get("uid")
    if uid:
        # Increment session_version to invalidate the current session
        conn = get_db()
        try:
            conn.execute(
                "UPDATE users SET session_version = session_version + 1 WHERE uid = ?",
                (uid,)
            )
            conn.commit()
        finally:
            conn.close()
        logger.info(f"用户 uid={uid} 已登出")
    session.clear()
    return redirect(url_for("index"))


# ======================== 修改密码 ========================

@app.route("/change-password", methods=["GET", "POST"])
def change_password():
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    user = db_get_user_full(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))
    is_forced = user.get("first_login", False)

    if request.method == "POST":
        if not validate_csrf():
            return render_template("change_password.html",
                error="请求校验失败，请刷新页面后重试", is_forced=is_forced)

        old_password = request.form.get("old_password", "")
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not is_forced:
            if not check_password_hash(user["password"], old_password):
                return render_template("change_password.html",
                    error="原密码错误", is_forced=False)

        valid, msg = validate_password_strength(new_password)
        if not valid:
            return render_template("change_password.html", error=msg, is_forced=is_forced)

        if new_password != confirm_password:
            return render_template("change_password.html",
                error="两次输入的新密码不一致", is_forced=is_forced)

        db_update_user_password(uid, generate_password_hash(new_password))
        # Do NOT sync session_version here — the mismatch will force re-login
        # via enforce_session_version on the next request, invalidating old sessions
        session.pop("force_change_password", None)
        logger.info(f"用户 uid={uid} 修改密码成功 (强制={is_forced})")

        return redirect(url_for("profile"))

    generate_csrf_token()
    return render_template("change_password.html", is_forced=is_forced)


# ======================== 个人中心 ========================

@app.route("/profile", methods=["GET", "POST"])
def profile():
    uid = session.get("uid")
    if not uid:
        session.clear()
        return redirect(url_for("login"))

    user = db_get_user_safe(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    greeting = get_greeting()

    if request.method == "POST":
        if not validate_csrf():
            return render_template("profile.html", user=user, greeting=greeting,
                info_error="请求校验失败，请刷新页面后重试")

        action = request.form.get("action", "")

        if action == "change_password":
            old_password = request.form.get("old_password", "")
            new_password = request.form.get("new_password", "")
            confirm_password = request.form.get("confirm_password", "")

            user_full = db_get_user_full(uid)
            if not user_full or not check_password_hash(user_full["password"], old_password):
                return render_template("profile.html", user=user, greeting=greeting,
                    pwd_error="原密码错误")

            valid, msg = validate_password_strength(new_password)
            if not valid:
                return render_template("profile.html", user=user, greeting=greeting,
                    pwd_error=msg)

            if new_password != confirm_password:
                return render_template("profile.html", user=user, greeting=greeting,
                    pwd_error="两次输入的新密码不一致")

            db_update_user_password(uid, generate_password_hash(new_password))
            # Do NOT sync session_version — enforce_session_version will force re-login
            # on the next request, invalidating any old session
            logger.info(f"用户 uid={uid} 在个人中心修改密码")
            return redirect(url_for("login"))

        elif action == "update_info":
            new_username = request.form.get("username", "").strip()
            new_email = request.form.get("email", "").strip()
            new_phone = request.form.get("phone", "").strip()

            errors = []

            # 用户名校验
            if not new_username:
                errors.append("用户名不能为空")
            elif len(new_username) > 50:
                errors.append("用户名不能超过50个字符")

            # 邮箱校验
            email_ok, email_err = sanitize_input(new_email, "邮箱")
            if not email_ok:
                errors.append(email_err)
            elif not new_email or "@" not in new_email:
                errors.append("请输入有效的邮箱地址")

            # 手机号校验
            phone_ok, phone_err = sanitize_input(new_phone, "手机")
            if not phone_ok:
                errors.append(phone_err)
            elif not new_phone or len(new_phone) < 11:
                errors.append("请输入有效的手机号码（至少11位）")

            if errors:
                return render_template("profile.html", user=user, greeting=greeting,
                    info_error="；".join(errors))

            # Sanitize username (matching registration behavior)
            if new_username:
                ok, err = sanitize_input(new_username, "用户名")
                if not ok:
                    return render_template("profile.html", user=user, greeting=greeting,
                        info_error=err)

            # 如果用户名有变更，检查是否重复
            username_to_update = new_username if new_username != user["username"] else None
            success, db_error = db_update_user_info(uid, new_email, new_phone, username_to_update)
            if not success:
                return render_template("profile.html", user=user, greeting=greeting,
                    info_error=db_error)

            logger.info(f"用户 uid={uid} 更新了个人信息")

            # 刷新 user 数据
            user = db_get_user_safe(uid)
            return render_template("profile.html", user=user, greeting=greeting,
                info_success="个人信息更新成功")

    generate_csrf_token()
    return render_template("profile.html", user=user, greeting=greeting)


# ============================================================
# 余额充值
# ============================================================

@app.route("/recharge", methods=["POST"])
def recharge():
    """安全余额充值，仅接受 POST 请求。身份仅从 session['uid'] 获取。"""
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    user = db_get_user_safe(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    greeting = get_greeting()

    if not validate_csrf():
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="请求校验失败，请刷新页面后重试")

    amount_str = request.form.get("amount", "").strip()

    # 严格校验：必须存在且非空
    if not amount_str:
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="金额不能为空")

    # 严格校验：必须能转为数值
    try:
        amount = float(amount_str)
    except (ValueError, TypeError):
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="金额必须是有效的数字")

    # 严格校验：必须为有限数字（拒绝 NaN / Infinity）
    if math.isnan(amount) or math.isinf(amount):
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="金额必须是有效的数字")

    # 严格校验：必须 > 0
    if amount <= 0:
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="充值金额必须大于 0")

    # 严格校验：必须 <= 100000
    if amount > 100000:
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="单次充值金额不能超过 100000")

    # Round to whole number (INTEGER column compatibility)
    amount = round(amount)

    # 使用参数化 SQL 更新余额
    success = db_update_balance(uid, amount)
    if not success:
        return render_template("profile.html", user=user, greeting=greeting,
            recharge_error="充值失败，请稍后重试")

    logger.info(f"用户 uid={uid} 充值成功: {amount}")
    return redirect(url_for("profile"))


# ============================================================
# 头像上传
# ============================================================
@app.route("/upload", methods=["GET", "POST"])
def upload_avatar():
    """安全头像上传（仅限登录用户）"""
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    user = db_get_user_safe(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        if not validate_csrf():
            return render_template("upload.html", error="请求校验失败，请刷新页面后重试")

        try:
            # 检查是否有文件
            if "avatar" not in request.files:
                return render_template("upload.html", error="请选择要上传的图片文件")

            file = request.files["avatar"]
            if not file.filename:
                return render_template("upload.html", error="请选择要上传的图片文件")

            # 文件扩展名白名单校验
            if not allowed_file(file.filename):
                return render_template("upload.html",
                    error="不支持的文件格式，仅允许上传 jpg、jpeg、png、gif、webp 格式的图片")

            # MIME 类型校验（防御纵深：Content-Type 由客户端控制，不可单独依赖）
            mime_type = file.content_type
            if mime_type not in ALLOWED_MIME_TYPES:
                return render_template("upload.html",
                    error=f"不支持的 MIME 类型 '{mime_type}'，仅允许上传图片文件")

            # 安全化文件名（防路径遍历/截断攻击）
            safe_name = secure_filename(file.filename)
            if not safe_name:
                return render_template("upload.html", error="文件名不合法，请重新命名后上传")

            # 若 secure_filename 将扩展名剥离（例如中文或纯点号文件名），重新附上
            original_ext = file.filename.rsplit(".", 1)[1].lower() if "." in file.filename else ""
            if '.' not in safe_name and original_ext in ALLOWED_EXTENSIONS:
                safe_name = safe_name + '.' + original_ext

            # 读取文件内容到内存（关闭 TOCTOU 窗口 + 显式大小检查）
            file_content = file.read()
            file_length = len(file_content)

            # 显式文件大小检查（防御纵深：MAX_CONTENT_LENGTH 在 chunked 编码下可能旁路）
            if file_length > UPLOAD_MAX_SIZE:
                logger.warning(f"用户 uid={uid} 上传文件过大: {file_length} 字节")
                return render_template("upload.html",
                    error="文件大小超过限制（最大 16MB），请压缩后重新上传")

            # 使用 imghdr / 魔数验证真实图片内容（在写入磁盘之前完成）
            image_type = validate_image_content(file_content)
            if image_type is None:
                return render_template("upload.html",
                    error="文件内容不是有效的图片，请上传真正的图片文件")

            # 图片尺寸验证 + 重新编码（使用 Pillow，最大 2000x2000，最大 5MB）
            # 重新编码通过 Pillow 去除任何附加的恶意载荷
            try:
                from PIL import Image
                import io as _io
                img = Image.open(_io.BytesIO(file_content))
                width, height = img.size
                if width > 2000 or height > 2000:
                    return render_template("upload.html",
                        error=f"图片尺寸过大（{width}x{height}），最大允许 2000x2000 像素")
                if file_length > 5 * 1024 * 1024:
                    return render_template("upload.html",
                        error="文件大小超过限制（最大 5MB），请压缩后重新上传")
                # Re-encode to strip hidden payloads and standardize format
                output = _io.BytesIO()
                img_format = 'JPEG' if image_type == 'jpeg' else image_type.upper()
                if img.mode in ('RGBA', 'LA', 'P'):
                    img = img.convert('RGBA')
                else:
                    img = img.convert('RGB')
                img.save(output, format=img_format, quality=90)
                file_content = output.getvalue()
                img.close()
            except Exception:
                return render_template("upload.html",
                    error="无法识别图片尺寸，请上传有效的图片文件")

            # UUID 前缀防止文件覆盖和枚举
            unique_name = f"{uuid4().hex}_{safe_name}"
            save_path = os.path.join(UPLOAD_FOLDER, unique_name)

            # 写入磁盘（此时内容已通过全部安全检查）
            with open(save_path, 'wb') as f:
                f.write(file_content)

            # 保存头像文件名到用户数据库
            conn = get_db()
            try:
                conn.execute("UPDATE users SET avatar = ? WHERE uid = ?", (unique_name, uid))
                conn.commit()
            finally:
                conn.close()

            # 生成访问 URL
            image_url = url_for("static", filename=f"uploads/{unique_name}")
            logger.info(f"用户 uid={uid} 上传头像成功: {unique_name} ({image_type}, {file_length} 字节, {width}x{height})")

            return render_template("upload.html", success=True, image_url=image_url,
                username=user["username"])

        except RequestEntityTooLarge:
            raise
        except Exception as e:
            logger.exception(f"上传头像异常 (uid={uid})")
            return render_template("upload.html", error="上传失败，请稍后重试")

    generate_csrf_token()
    return render_template("upload.html")


# ============================================================
# 安全动态页面加载
# ============================================================
PAGES_DIR = os.path.realpath(os.path.join(BASE_DIR, "pages"))


@app.route("/page")
def dynamic_page():
    """
    安全加载 pages/ 目录下的静态页面。
    name 参数经过严格路径穿越校验后才用于文件读取。
    """
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    try:
        name = request.args.get("name", "").strip()
    except Exception:
        return "页面不存在", 404

    # 空参数直接拒绝
    if not name:
        return "页面不存在", 404

    try:
        # 安全做法：先拼接再解析，绝不直接拼接用户输入
        # 第一步：尝试按原名解析
        candidate = os.path.realpath(os.path.join(PAGES_DIR, name))

        # 检查是否仍在 pages 目录范围内
        # 使用 os.sep 后缀防止 PAGES_DIR 前缀被类似 "pages-backup" 的路径绕过
        pages_dir_prefix = PAGES_DIR + os.sep
        if (candidate.startswith(pages_dir_prefix) or candidate == PAGES_DIR):
            if os.path.isfile(candidate):
                with open(candidate, "r", encoding="utf-8") as f:
                    content = f.read()
                return content, 200, {"Content-Type": "text/html; charset=utf-8"}

        # 第二步：尝试附加 .html 扩展名
        candidate_html = os.path.realpath(os.path.join(PAGES_DIR, name + ".html"))
        if (candidate_html.startswith(pages_dir_prefix) or candidate_html == PAGES_DIR):
            if os.path.isfile(candidate_html):
                with open(candidate_html, "r", encoding="utf-8") as f:
                    content = f.read()
                return content, 200, {"Content-Type": "text/html; charset=utf-8"}
    except (ValueError, OSError, UnicodeError):
        # 路径中包含非法字符（如空字节）、权限不足、编码错误等
        # 统一返回"页面不存在"以防止信息泄露
        pass

    # 所有尝试均失败
    return "页面不存在", 404


# ============================================================
# URL 安全获取功能
# ============================================================


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """禁止重定向的 handler，SSRF 防御：防止重定向到内部地址"""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _check_ip_safety(ip_str):
    """检查单个 IP 是否为危险地址（回环、私有、链路本地）"""
    # 特殊处理 0.0.0.0（某些系统上相当于 localhost）
    # Block entire 0.0.0.0/8 range (many kernels route this to localhost)
    try:
        if ipaddress.ip_address(ip_str) in ipaddress.ip_network("0.0.0.0/8"):
            return True
    except ValueError:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_loopback:
            return True
        if ip.is_private:
            return True
        if ip.is_link_local:
            return True
        # 补充 Python ipaddress 未覆盖的保留地址段
        if ip in ipaddress.ip_network("100.64.0.0/10"):   # CGNAT (RFC 6598)
            return True
        if ip in ipaddress.ip_network("198.18.0.0/15"):   # 基准测试 (RFC 2544)
            return True
        return False
    except ValueError:
        return True  # 无法解析的 IP 视为危险


def _resolve_and_check_ips(hostname):
    """
    解析主机名所有 IP 并检查安全性。
    返回 (safe_ips, error_message) —— 任一 IP 危险即返回错误。
    """
    try:
        addrinfo = socket.getaddrinfo(hostname, None)
    except socket.gaierror:
        return None, "无法解析主机名，请检查 URL 是否正确"
    except Exception:
        return None, "DNS 解析失败，请稍后重试"

    resolved_ips = set()
    for info in addrinfo:
        ip_str = info[4][0]
        # 剥离 IPv6 作用域 ID（如 %eth0、%3）
        if '%' in ip_str:
            ip_str = ip_str.split('%')[0]
        resolved_ips.add(ip_str)

    for ip_str in resolved_ips:
        if _check_ip_safety(ip_str):
            return None, "不允许访问内部网络或本地地址"

    return list(resolved_ips), None


def _is_suspicious_hostname(hostname):
    """
    检查主机名是否为可疑的数值 IP 表示法（整数、十六进制、八进制）。
    某些系统会将纯数值解析为 IP 地址，可能绕过安全检查。
    """
    # 纯十进制数字（如 2130706433 = 127.0.0.1）
    if re.match(r'^\d+$', hostname):
        return True
    # 十六进制表示（如 0x7f000001 = 127.0.0.1）
    if re.match(r'^0x[0-9a-f]+$', hostname, re.IGNORECASE):
        return True
    # 八进制点分表示（如 0177.0.0.1 = 127.0.0.1）
    if re.match(r'^0[0-7]+(\.[0-7]+){0,3}$', hostname):
        return True
    # Mixed notation: hex/octal in any octet position (e.g., 0x7f.0.0.1)
    if '.' in hostname:
        parts = hostname.split('.')
        for part in parts:
            if re.match(r'^0[xX][0-9a-fA-F]+$', part) or re.match(r'^0[0-7]+$', part):
                return True
    return False


@app.route("/fetch-url", methods=["POST"])
def fetch_url():
    """安全 URL 获取接口（仅限登录用户，POST + CSRF）"""
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    user = db_get_user_safe(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    username = user["username"]
    greeting = get_greeting()

    if not validate_csrf():
        return render_template("index.html",
            url_error="请求校验失败，请刷新页面后重试",
            username=username, user=user, greeting=greeting)

    url = request.form.get("url", "").strip()
    if not url:
        return render_template("index.html",
            url_error="请输入要获取的 URL 地址",
            username=username, user=user, greeting=greeting)

    # 协议校验：仅允许 http / https
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return render_template("index.html",
            url_error="URL 格式无效，请检查后重新输入",
            username=username, user=user, greeting=greeting)

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return render_template("index.html",
            url_error=f"不支持的协议 '{parsed.scheme}'，仅允许 http 和 https 协议",
            username=username, user=user, greeting=greeting)

    hostname = parsed.hostname
    if not hostname:
        return render_template("index.html",
            url_error="URL 中缺少主机名",
            username=username, user=user, greeting=greeting)

    # 检查 localhost 字符串
    if hostname.lower() == "localhost":
        return render_template("index.html",
            url_error="不允许访问本地服务（localhost）",
            username=username, user=user, greeting=greeting)

    # 检查可疑数值 IP 表示法（十进制/十六进制/八进制）
    if _is_suspicious_hostname(hostname):
        return render_template("index.html",
            url_error="不允许访问该地址（非标准主机名格式）",
            username=username, user=user, greeting=greeting)

    # DNS 解析 + IP 安全检查
    safe_ips, dns_error = _resolve_and_check_ips(hostname)
    if dns_error:
        return render_template("index.html",
            url_error=dns_error,
            username=username, user=user, greeting=greeting)

    # ---- 构建实际请求 ----
    # 为了防御 DNS 重绑定攻击，对 HTTP 请求将主机名替换为已校验通过的 IP
    # 并设置 Host 头部为原始域名，以确保虚拟主机正常工作
    # 优先使用 IPv4 地址（兼容性更好），无可用的 IPv4 时才使用 IPv6
    if scheme == 'http' and safe_ips:
        ipv4_candidates = [ip for ip in safe_ips if '.' in ip]
        ipv6_candidates = [ip for ip in safe_ips if ':' in ip]
        if ipv4_candidates:
            actual_ip = ipv4_candidates[0]
        elif ipv6_candidates:
            actual_ip = ipv6_candidates[0]
        else:
            actual_ip = safe_ips[0]

        original_netloc = parsed.netloc
        original_port = parsed.port

        # 构建新的 host 部分（IPv6 需要方括号包裹）
        if ':' in actual_ip:
            host_part = f"[{actual_ip}]"
        else:
            host_part = actual_ip

        if original_port:
            host_part = f"{host_part}:{original_port}"

        # 保留 user:password 认证信息
        if '@' in original_netloc:
            userinfo = original_netloc.split('@')[0]
            new_netloc = f"{userinfo}@{host_part}"
        else:
            new_netloc = host_part

        # 构建新的 URL（IP 替换域名）和 Host 请求头
        actual_url = parsed._replace(netloc=new_netloc).geturl()
        host_header_value = hostname if not original_port else f"{hostname}:{original_port}"
        extra_headers = {"Host": host_header_value}
    else:
        # HTTPS with DNS rebinding protection:
        # Re-verify DNS hasn't changed before connecting
        import ssl as _ssl

        # Re-check DNS right before connecting
        try:
            recheck_ips, dns_err = _resolve_and_check_ips(hostname)
            if recheck_ips is None:
                return render_template("index.html",
                    url_error=dns_err,
                    username=username, user=user, greeting=greeting)
            # Verify no new IPs appeared that weren't in the original safe set
            if set(safe_ips) != set(recheck_ips):
                return render_template("index.html",
                    url_error="DNS 解析结果已变更，为安全起见已拒绝请求",
                    username=username, user=user, greeting=greeting)
        except Exception:
            return render_template("index.html",
                url_error="DNS 验证失败，请稍后重试",
                username=username, user=user, greeting=greeting)

        # Use original URL but with verified consistent DNS
        actual_url = url
        extra_headers = {}

    # 构建自定义 opener（不跟随重定向）
    opener = urllib.request.build_opener(_NoRedirectHandler)

    # 构建请求头
    request_headers = {
        "User-Agent": "Mozilla/5.0 (compatible; URLFetcher/1.0)",
    }
    request_headers.update(extra_headers)

    # 发起请求
    try:
        req = urllib.request.Request(actual_url, headers=request_headers)
        with opener.open(req, timeout=10) as resp:
            status_code = resp.status
            content_type = resp.headers.get("Content-Type", "未知")
            raw_data = resp.read(5000)
            content = raw_data.decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        # 3xx/4xx/5xx 响应（3xx 因 NoRedirectHandler 不会自动跟随）
        status_code = e.code
        content_type = e.headers.get("Content-Type", "未知") if e.headers else "未知"
        try:
            raw_data = e.read(5000)
            content = raw_data.decode("utf-8", errors="replace")
        except Exception:
            content = ""
    except urllib.error.URLError as e:
        # 不暴露具体系统错误信息
        return render_template("index.html",
            url_error="无法连接到目标服务器，请检查 URL 是否正确",
            username=username, user=user, greeting=greeting)
    except socket.timeout:
        return render_template("index.html",
            url_error="请求超时（10 秒），目标服务器响应过慢或无法连接",
            username=username, user=user, greeting=greeting)
    except Exception:
        # 捕获所有其他异常，不暴露内部细节
        return render_template("index.html",
            url_error="获取 URL 时发生错误，请稍后重试",
            username=username, user=user, greeting=greeting)

    # 限制显示长度（最多 5000 字符）
    display_content = content[:5000]

    return render_template("index.html",
        username=username,
        user=user,
        greeting=greeting,
        url_result=True,
        url_status=status_code,
        url_content_type=content_type,
        url_content=display_content,
        url_original=url,
    )


# ============================================================
# 安全 Ping 诊断
# ============================================================

@app.route("/ping", methods=["GET", "POST"])
def ping():
    """安全 Ping 诊断（仅限登录用户）"""
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    user = db_get_user_safe(uid)
    if not user:
        session.clear()
        return redirect(url_for("login"))

    if request.method == "POST":
        if not validate_csrf():
            user = db_get_user_safe(uid) or user
            return render_template("ping.html", error="请求校验失败，请刷新页面后重试")

        ip = request.form.get("ip", "").strip()

        if not ip:
            return render_template("ping.html", error="请输入 IP 地址或域名")

        if not is_valid_ip_or_hostname(ip):
            return render_template("ping.html", error="非法输入")

        # Block internal/private IPs (same protection as fetch-url)
        try:
            ip_obj = ipaddress.ip_address(ip)
            if ip_obj.is_loopback or ip_obj.is_private or ip_obj.is_link_local:
                return render_template("ping.html", error="不允许 Ping 内部网络地址")
            if ip_obj in ipaddress.ip_network("0.0.0.0/8"):
                return render_template("ping.html", error="不允许 Ping 内部网络地址")
        except ValueError:
            pass  # Hostname, will be resolved by ping command

        # Platform-aware command list — shell=False by default
        system_name = platform.system().lower()
        if system_name == "windows":
            cmd = ["ping", "-n", "3", ip]
        else:
            cmd = ["ping", "-c", "3", ip]

        try:
            output = subprocess.check_output(cmd, timeout=30, stderr=subprocess.STDOUT)
            result = output.decode("utf-8", errors="replace")
        except subprocess.TimeoutExpired:
            result = "Ping 超时（30 秒）"
        except subprocess.CalledProcessError as e:
            result = e.output.decode("utf-8", errors="replace") if e.output else "Ping 失败"
        except FileNotFoundError:
            result = "系统没有 ping 命令"
        except Exception:
            result = "Ping 执行错误"

        return render_template("ping.html", result=result)

    return render_template("ping.html")


# ============================================================
# 安全 XML 导入
# ============================================================

@app.route("/xml-import", methods=["GET", "POST"])
def xml_import():
    """安全 XML 导入（仅限登录用户，POST + CSRF）"""
    uid = session.get("uid")
    if not uid:
        return redirect(url_for("login"))

    if request.method == "POST":
        if not validate_csrf():
            return render_template("xml_import.html", error="请求校验失败，请刷新页面后重试")

        xml_data = request.form.get("xml_data", "").strip()

        if not xml_data:
            return render_template("xml_import.html", error="请输入 XML 数据")

        # 大小限制：最大 100KB
        if len(xml_data.encode("utf-8")) > 100 * 1024:
            return render_template("xml_import.html", error="XML 数据大小超过限制（最大 100KB），已拒绝处理")

        # ============ 安全检测 ============
        # 第一道防线：拒绝 DOCTYPE 声明（case-insensitive）
        if re.search(r"<!DOCTYPE", xml_data, re.IGNORECASE):
            return render_template("xml_import.html", error="不支持 DOCTYPE 声明，已拒绝处理")

        # 第二道防线：拒绝 ENTITY 声明（case-insensitive）
        if re.search(r"<!ENTITY", xml_data, re.IGNORECASE):
            return render_template("xml_import.html", error="不支持 ENTITY 声明，已拒绝处理")

        # 第三道防线：拒绝 SYSTEM / PUBLIC 关键字（case-insensitive 含词边界）
        if re.search(r"\bSYSTEM\b", xml_data, re.IGNORECASE) or \
           re.search(r"\bPUBLIC\b", xml_data, re.IGNORECASE):
            return render_template("xml_import.html", error="XML 中包含不允许的关键字（SYSTEM/PUBLIC），已拒绝处理")

        # 第四道防线：使用 defusedxml（如可用，提供最全面的防护）
        #         Python 3.7.1+ 默认 expat 已禁用外部实体解析，但 defusedxml
        #         额外防护了 XInclude、DTD 拉取、实体扩展炸弹等攻击
        try:
            if HAVE_DEFUSEDXML:
                root = safe_ET.fromstring(xml_data)
            else:
                # Python 3.7.1+ 默认 expat 解析器安全（外部实体禁闭）
                # 配合上方关键词检测构成纵深防御
                root = ET.fromstring(xml_data)
        except ET.ParseError as e:
            logger.warning(f"XML 解析失败: {e}")
            return render_template("xml_import.html", error="XML 解析失败，请检查格式是否正确")
        except Exception as e:
            logger.warning(f"XML 处理异常: {e}")
            return render_template("xml_import.html", error="XML 处理失败，请检查数据格式")

        # 提取 <user> 元素
        users = []
        try:
            for user_elem in root.findall(".//user"):
                name = ""
                email = ""
                name_node = user_elem.find("name")
                email_node = user_elem.find("email")
                if name_node is not None and name_node.text:
                    name = name_node.text
                if email_node is not None and email_node.text:
                    email = email_node.text
                users.append({"name": name, "email": email})
        except Exception as e:
            logger.warning(f"XML 数据提取失败: {e}")
            return render_template("xml_import.html", error="XML 数据提取失败，请检查 XML 结构")

        # 转换为 JSON（Jinja2 自动转义，不使用 | safe）
        result_json = json.dumps(users, ensure_ascii=False, indent=2)
        return render_template("xml_import.html", result=result_json)

    # GET 请求
    return render_template("xml_import.html")


# ============================================================
# 应用启动：初始化数据库
# ============================================================
init_db()

if __name__ == "__main__":
    print(f"[启动] Debug={DEBUG}, Host={HOST}, Port={PORT}")
    print(f"[启动] Session Cookie: HttpOnly=True, SameSite=Lax, Secure=False (HTTPS部署时请改为True)")
    app.run(debug=DEBUG, host=HOST, port=PORT)
