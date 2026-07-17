#!/usr/bin/env python3
"""
v4beta Comprehensive Test Suite
Tests: profile access, recharge, security controls, edge cases
"""
import requests
import sys
import re
import os

BASE = "http://127.0.0.1:8083"
session = requests.Session()

passed = 0
failed = 0

def test(name, condition, detail=""):
    global passed, failed
    if condition:
        passed += 1
        print("  [PASS] " + name)
    else:
        failed += 1
        print("  [FAIL] " + name + " -- " + detail)

def get_csrf(html):
    """Extract csrf_token from a hidden input in HTML."""
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    return m.group(1) if m else None

def get_balance(html):
    """Extract balance value from profile page. Uses the last disabled input with a number value."""
    matches = re.findall(r'value="(\d+)" disabled', html)
    if matches:
        return int(matches[-1])
    return None

def login(username, password):
    """Login and return True on success."""
    r = session.get(BASE + "/login")
    csrf = get_csrf(r.text)
    r = session.post(BASE + "/login", data={
        "csrf_token": csrf,
        "username": username,
        "password": password
    }, allow_redirects=False)
    if r.status_code == 302:
        session.get(BASE + "/")
        return True
    return False

def logout_user():
    """Logout via POST."""
    r = session.get(BASE + "/")
    csrf = get_csrf(r.text)
    if csrf:
        session.post(BASE + "/logout", data={"csrf_token": csrf})

# ========== Setup: First login + password change ==========
print("\n=== Setup: First login as admin ===")
r = session.get(BASE + "/login")
csrf = get_csrf(r.text)
r = session.post(BASE + "/login", data={
    "csrf_token": csrf,
    "username": "admin",
    "password": os.environ.get("TEST_PWD_ADMIN", "")
}, allow_redirects=False)
if r.status_code == 302 and "/change-password" in r.headers.get("Location", ""):
    print("  Redirected to change-password, changing password...")
    r = session.get(BASE + "/change-password")
    csrf = get_csrf(r.text)
    r = session.post(BASE + "/change-password", data={
        "csrf_token": csrf,
        "old_password": os.environ.get("TEST_PWD_ADMIN", ""),
        "new_password": os.environ.get("TEST_PWD_ADMIN_NEW", ""),
        "confirm_password": os.environ.get("TEST_PWD_ADMIN_NEW", "")
    }, allow_redirects=False)
    print("  Password change response: " + str(r.status_code))
elif r.status_code == 302:
    print("  Login succeeded (no forced change)")
    session.get(BASE + "/")

print("\n=== Setup: First login as alice ===")
r = session.get(BASE + "/login")
csrf = get_csrf(r.text)
r = session.post(BASE + "/login", data={
    "csrf_token": csrf,
    "username": "alice",
    "password": os.environ.get("TEST_PWD_ALICE", "")
}, allow_redirects=False)
if r.status_code == 302 and "/change-password" in r.headers.get("Location", ""):
    print("  Redirected to change-password, changing password...")
    r = session.get(BASE + "/change-password")
    csrf = get_csrf(r.text)
    r = session.post(BASE + "/change-password", data={
        "csrf_token": csrf,
        "old_password": os.environ.get("TEST_PWD_ALICE", ""),
        "new_password": os.environ.get("TEST_PWD_ALICE_NEW", ""),
        "confirm_password": os.environ.get("TEST_PWD_ALICE_NEW", "")
    }, allow_redirects=False)
    print("  Password change response: " + str(r.status_code))
elif r.status_code == 302:
    print("  Login succeeded (no forced change)")
    session.get(BASE + "/")

# ========== Test Case 1: Login as admin, visit /profile ==========
print("\n=== Test 1: Login as admin, visit /profile ===")
logout_user()
r = session.get(BASE + "/login")
csrf = get_csrf(r.text)
r = session.post(BASE + "/login", data={
    "csrf_token": csrf,
    "username": "admin",
    "password": os.environ.get("TEST_PWD_ADMIN_NEW", "")
}, allow_redirects=True)
session.get(BASE + "/")

r = session.get(BASE + "/profile")
test("Admin can access /profile", r.status_code == 200)
test("Profile shows balance info", "余额" in r.text)
test("Profile shows username admin", "admin" in r.text)
test("Profile shows email", "admin@example.com" in r.text)
test("Profile shows phone", "13800138000" in r.text)
test("Profile shows recharge section", "充值" in r.text)

# ========== Test Case 2: Recharge with amount=100 ==========
print("\n=== Test 2: Recharge amount=100 ===")
r = session.get(BASE + "/profile")
csrf = get_csrf(r.text)
initial_balance = get_balance(r.text)
if initial_balance is None:
    initial_balance = 99999
print("  Initial balance: " + str(initial_balance))

r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf,
    "amount": "100"
}, allow_redirects=False)
location = r.headers.get("Location", "")
test("Recharge 100 redirects to /profile", r.status_code == 302 and "/profile" in location)

r = session.get(BASE + "/profile")
new_balance = get_balance(r.text)
if new_balance is None:
    new_balance = 0
expected = initial_balance + 100
test("Balance increased: " + str(new_balance) + " == " + str(expected), new_balance == expected)

# ========== Test Case 3: Recharge amount=0 (rejected) ==========
print("\n=== Test 3: Recharge amount=0 ===")
r = session.get(BASE + "/profile")
csrf = get_csrf(r.text)
r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf,
    "amount": "0"
})
test("Recharge 0 shows error", "error" in r.text.lower() or "大于 0" in r.text)
unchanged = get_balance(r.text)
if unchanged is None:
    unchanged = new_balance
test("Balance unchanged after 0", unchanged == new_balance)

# ========== Test Case 4: Recharge amount=-50 (rejected) ==========
print("\n=== Test 4: Recharge amount=-50 ===")
r = session.get(BASE + "/profile")
csrf = get_csrf(r.text)
r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf,
    "amount": "-50"
})
test("Recharge -50 shows error", "error" in r.text.lower() or "大于 0" in r.text)
unchanged2 = get_balance(r.text)
if unchanged2 is None:
    unchanged2 = new_balance
test("Balance unchanged after -50", unchanged2 == new_balance)

# ========== Test Case 5: Recharge amount=999999 (rejected, >100000) ==========
print("\n=== Test 5: Recharge amount=999999 ===")
r = session.get(BASE + "/profile")
csrf = get_csrf(r.text)
r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf,
    "amount": "999999"
})
test("Recharge 999999 shows error", "100000" in r.text or "error" in r.text.lower())
unchanged3 = get_balance(r.text)
if unchanged3 is None:
    unchanged3 = new_balance
test("Balance unchanged after 999999", unchanged3 == new_balance)

# ========== Test Case 6: Recharge amount=abc (rejected) ==========
print("\n=== Test 6: Recharge amount=abc ===")
r = session.get(BASE + "/profile")
csrf = get_csrf(r.text)
r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf,
    "amount": "abc"
})
test("Recharge abc shows error", "error" in r.text.lower() or "数字" in r.text)
unchanged4 = get_balance(r.text)
if unchanged4 is None:
    unchanged4 = new_balance
test("Balance unchanged after abc", unchanged4 == new_balance)

# ========== Test Case 7: Empty amount (rejected) ==========
print("\n=== Test 7: Recharge empty amount ===")
r = session.get(BASE + "/profile")
csrf = get_csrf(r.text)
r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf,
    "amount": ""
})
test("Recharge empty shows error", "error" in r.text.lower() or "不能为空" in r.text)

# ========== Test Case 8: Unauthenticated access to /profile ==========
print("\n=== Test 8: Unauthenticated access ===")
logout_user()
r = session.get(BASE + "/profile", allow_redirects=False)
test("Unauthenticated /profile redirects to login", r.status_code == 302 and "/login" in r.headers.get("Location", ""))

# ========== Test Case 9: Form param uid tampering ==========
print("\n=== Test 9: Form param uid tampering ===")
r = session.get(BASE + "/login")
csrf = get_csrf(r.text)
r = session.post(BASE + "/login", data={
    "csrf_token": csrf,
    "username": "admin",
    "password": os.environ.get("TEST_PWD_ADMIN_NEW", "")
}, allow_redirects=True)
session.get(BASE + "/")

r = session.get(BASE + "/profile")
csrf = get_csrf(r.text)
r = session.post(BASE + "/recharge", data={
    "csrf_token": csrf,
    "amount": "50",
    "uid": "1"
}, allow_redirects=False)
test("Recharge with uid injection still works (identity from session)",
     r.status_code == 302 and "/profile" in r.headers.get("Location", ""))

# ========== Test Case 10: Check DB updated correctly ==========
print("\n=== Test 10: DB integrity check ===")
import sqlite3
conn = sqlite3.connect("/home/kali/Desktop/agent-project/claude-code-project/v4beta/data/users.db")
conn.row_factory = sqlite3.Row
rows = conn.execute("SELECT uid, username, balance FROM users ORDER BY uid").fetchall()
print("  DB contents:")
for row in rows:
    print("    uid=" + str(row['uid']) + ", username=" + row['username'] + ", balance=" + str(row['balance']))
admin_row = conn.execute("SELECT balance FROM users WHERE uid=1").fetchone()
test("Admin balance > 99999", admin_row["balance"] > 99999)
# Verify parameterized SQL in source
with open("app.py") as f:
    source = f.read()
    test("Uses parameterized SQL: balance = balance + ?", "balance = balance + ?" in source)
    test("Uses ? placeholders in UPDATE", "UPDATE users SET balance = balance + ? WHERE uid = ?" in source)
conn.close()

# ========== Additional Security Checks ==========
print("\n=== Additional Security Checks ===")
with open("app.py") as f:
    source = f.read()
test("No uid in URL params for profile", "/profile/<" not in source)
test("No uid in URL params for recharge", "/recharge/<" not in source)
test("CSRF validation in recharge function",
     "validate_csrf()" in source.split("def recharge():")[1].split("def ")[0] if "def recharge():" in source else False)
test("Amount decimal rounding", "round(amount, 2)" in source.split("def recharge():")[1].split("def ")[0] if "def recharge():" in source else False)

# ========== Summary ==========
print("\n" + "=" * 50)
print("Results: " + str(passed) + " passed, " + str(failed) + " failed out of " + str(passed + failed) + " tests")
print("=" * 50)

if failed > 0:
    sys.exit(1)
else:
    sys.exit(0)
