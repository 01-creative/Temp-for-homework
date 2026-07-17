# 用户信息管理平台

基于 Python Flask 的简易用户信息管理系统，支持登录、个人信息管理、密码修改等功能。

## 快速启动

```bash
# 1. 进入项目目录
cd flask-user-mgmt-fixed

# 2. 安装依赖
pip install -r requirements.txt

# 3. 设置环境变量
export FLASK_SECRET_KEY="your-secret-key-at-least-32-characters"
export INIT_PWD_ADMIN="AdminInitialPassword@2025"
export INIT_PWD_ALICE="AliceInitialPassword@2025"

# 4. 启动服务（默认监听 127.0.0.1:5000）
python app.py
```

**环境变量说明：**

| 变量 | 必填 | 说明 |
|------|------|------|
| `FLASK_SECRET_KEY` | 是 | Session 签名密钥，至少 32 字符 |
| `FLASK_DEBUG` | 否 | 调试模式开关，默认 `0`（关闭）。仅本地开发可设为 `1` |
| `FLASK_HOST` | 否 | 监听地址，默认 `127.0.0.1` |
| `FLASK_PORT` | 否 | 监听端口，默认 `5000` |
| `INIT_PWD_ADMIN` | 是 | admin 用户初始密码 |
| `INIT_PWD_ALICE` | 是 | alice 用户初始密码 |

> 启动成功后在浏览器访问 `http://127.0.0.1:5000`

## 预置用户

首次启动时通过环境变量设置初始密码。系统内置两个用户：

| 用户名 | 角色 | 首次登录行为 |
|--------|------|-------------|
| `admin` | 管理员 | 强制修改密码 |
| `alice` | 普通用户 | 强制修改密码 |

## 功能说明

### 登录

访问 `/login` 页面，输入用户名和密码登录。

- 首次使用初始密码登录后，系统会强制跳转到改密页面
- 连续多次登录失败会触发频率限制，需等待后重试

### 首页

登录后进入首页 `/`，展示：
- 根据当前时间的问候语（早上好/下午好/晚上好等）
- 用户名、邮箱、手机、角色、余额等信息
- 个人中心入口和退出登录按钮

未登录时显示"请先登录"提示。

### 个人中心

访问 `/profile`，提供两项功能：

**个人信息编辑：**
- 修改邮箱地址
- 修改手机号码
- 用户名和角色不可修改

**修改密码：**
- 需输入原密码验证身份
- 新密码要求：不少于 8 位，包含大写字母、小写字母、数字和特殊字符

### 首次登录改密

首次使用初始密码登录后，系统自动跳转到 `/change-password` 页面：
- 设置新密码（需满足强度要求）
- 修改成功后自动清除首次登录标记，下次登录不再拦截

### 退出登录

点击导航栏或首页的"退出"按钮即可登出。

## 项目结构

```
flask-user-mgmt-fixed/
├── app.py                   # 主应用
├── requirements.txt          # Python 依赖
├── README.md                 # 本文件
├── templates/
│   ├── base.html             # 基础模板（导航栏）
│   ├── login.html            # 登录页
│   ├── index.html            # 首页
│   ├── profile.html          # 个人中心
│   └── change_password.html  # 修改密码页
└── static/
    └── css/
        └── style.css          # 样式文件
```

## 依赖

- Python >= 3.8
- Flask >= 3.0
- Werkzeug（Flask 自带）
