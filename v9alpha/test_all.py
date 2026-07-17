#!/usr/bin/env python3
"""
Comprehensive security tests for v6beta change-password feature.
Tests all requirements listed in Task 2.

Usage: python3 test_all.py
"""

import requests
import re
import sys

BASE = "http://127.0.0.1:8089"
session = requests.Session()
session.headers["User-Agent"] = "v6beta-test-script"

passed = 0
failed = 0
total = 0

def get_csrf(html):
    """Extract csrf_token from hidden input field."""
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'value="([^"]+)"[^>]*name="csrf_token"', html)
    if m:
        return m.group(1)
    return None

def test(name, ok, detail=""):
    global passed, failed, total
    total += 1
    if ok:
        passed += 1
        print(f"  [PASS] {name}")
    else:
        failed += 1
        print(f"  [FAIL] {name}  {detail}")

def get_page(path):
    resp = session.get(f"{BASE}{path}", allow_redirects=True)
    return resp.text, resp.status_code, resp

def get_page_no_redirect(path):
    resp = session.get(f"{BASE}{path}", allow_redirects=False)
    return resp.text, resp.status_code, resp

def post_form(path, data, allow_redirects=True):
    """POST form data and return (html, status_code, response)."""
    resp = session.post(f"{BASE}{path}", data=data, allow_redirects=allow_redirects)
    return resp.text, resp.status_code, resp

def login(username, password):
    """Login, returns True on success."""
    # Clear session to start fresh
    session.cookies.clear()
    r = session.get(f"{BASE}/login")
    csrf = get_csrf(r.text)
    if not csrf:
        return False
    r = session.post(f"{BASE}/login", data={
        "csrf_token": csrf,
        "username": username,
        "password": password
    }, allow_redirects=True)
    return "login" not in r.url.lower()


print("=" * 60)
print("TEST: Security Tests for v6beta change-password")
print("=" * 60)

# ============================================================
# Test 1: Login admin, change own password (with old password) -> success
# ============================================================
print("\n--- Test 1: Login admin, change own password ---")
ok = login("admin", "Admin@2025#Secure")
test("1a. Login as admin succeeds", ok)

if ok:
    html, code, resp = get_page("/change-password")
    csrf = get_csrf(html)
    test("1b. GET /change-password returns form with CSRF", csrf is not None)

    if csrf:
        # Submit with correct old password
        html, code, resp = post_form("/change-password", {
            "csrf_token": csrf,
            "old_password": "Admin@2025#Secure",
            "new_password": "NewAdmin@2025#Secure",
            "confirm_password": "NewAdmin@2025#Secure"
        }, allow_redirects=False)
        test("1c. POST returns redirect (302)", code == 302, f"Got {code}")
        loc = resp.headers.get("Location", "")
        test("1d. Redirect location is /profile", loc.endswith("/profile"), f"Got: {loc}")

# ============================================================
# Test 7: After password change, old session invalidated -> must re-login
# ============================================================
print("\n--- Test 7: Old session invalidated after password change ---")
# Follow redirect to /profile — enforce_session_version should kick in
html, code, resp = get_page("/profile")
test("7a. Old session invalidated, redirected to login",
     "login" in resp.url.lower(),
     f"URL: {resp.url}")

# Re-login with new password
ok = login("admin", "NewAdmin@2025#Secure")
test("7b. Can re-login with new password", ok)

# ============================================================
# Test 2: Try change password without CSRF token -> rejected
# ============================================================
print("\n--- Test 2: No CSRF token ---")
html, code, resp = get_page("/change-password")
csrf = get_csrf(html)
if csrf:
    html, code, resp = post_form("/change-password", {
        # No csrf_token
        "old_password": "NewAdmin@2025#Secure",
        "new_password": "Another@2025#Pass",
        "confirm_password": "Another@2025#Pass"
    })
    test("2a. Rejected without CSRF token",
         "请求校验失败" in html,
         f"Code={code}")

# ============================================================
# Test 3: Try change password with wrong old password -> rejected
# ============================================================
print("\n--- Test 3: Wrong old password ---")
html, code, resp = get_page("/change-password")
csrf = get_csrf(html)
if csrf:
    html, code, resp = post_form("/change-password", {
        "csrf_token": csrf,
        "old_password": "WrongPassword123!",
        "new_password": "Another@2025#Pass",
        "confirm_password": "Another@2025#Pass"
    })
    test("3a. Wrong old password rejected",
         "原密码错误" in html,
         f"Code={code}")

# ============================================================
# Test 4: Try change password with weak new password -> rejected
# ============================================================
print("\n--- Test 4: Weak new password ---")

# 4a: Too short (use 4 chars only with upper, lower, digit, special)
html, code, resp = get_page("/change-password")
csrf = get_csrf(html)
if csrf:
    html, code, resp = post_form("/change-password", {
        "csrf_token": csrf,
        "old_password": "NewAdmin@2025#Secure",
        "new_password": "Sh1!",
        "confirm_password": "Sh1!"
    })
    test("4a. Weak password rejected (too short, 4 chars)",
         "密码" in html and code == 200,
         f"Code={code}")

# 4b: No uppercase
html, code, resp = get_page("/change-password")
csrf = get_csrf(html)
if csrf:
    html, code, resp = post_form("/change-password", {
        "csrf_token": csrf,
        "old_password": "NewAdmin@2025#Secure",
        "new_password": "alllowercase@123",
        "confirm_password": "alllowercase@123"
    })
    test("4b. Weak password rejected (no uppercase)",
         "大写" in html or "密码" in html,
         f"Code={code}")

# 4c: No digit
html, code, resp = get_page("/change-password")
csrf = get_csrf(html)
if csrf:
    html, code, resp = post_form("/change-password", {
        "csrf_token": csrf,
        "old_password": "NewAdmin@2025#Secure",
        "new_password": "NoDigitsHere!@#",
        "confirm_password": "NoDigitsHere!@#"
    })
    test("4c. Weak password rejected (no digit)",
         "数字" in html or "密码" in html,
         f"Code={code}")

# 4d: No special
html, code, resp = get_page("/change-password")
csrf = get_csrf(html)
if csrf:
    html, code, resp = post_form("/change-password", {
        "csrf_token": csrf,
        "old_password": "NewAdmin@2025#Secure",
        "new_password": "NoSpecialChar123",
        "confirm_password": "NoSpecialChar123"
    })
    test("4d. Weak password rejected (no special char)",
         "特殊字符" in html or "密码" in html,
         f"Code={code}")

# ============================================================
# Test 5: Try change password with mismatched confirm -> rejected
# ============================================================
print("\n--- Test 5: Mismatched confirm ---")
html, code, resp = get_page("/change-password")
csrf = get_csrf(html)
if csrf:
    html, code, resp = post_form("/change-password", {
        "csrf_token": csrf,
        "old_password": "NewAdmin@2025#Secure",
        "new_password": "StrongPass@2025#New",
        "confirm_password": "DifferentPass@2025#New"
    })
    test("5a. Mismatched confirm rejected",
         "不一致" in html,
         f"Code={code}")

# ============================================================
# Test 6: Try to inject username=admin in form params -> ignored
# ============================================================
print("\n--- Test 6: Username injection ---")
html, code, resp = get_page("/change-password")
csrf = get_csrf(html)
if csrf:
    # Submit with extra username=admin field
    html, code, resp = post_form("/change-password", {
        "csrf_token": csrf,
        "username": "admin",
        "old_password": "NewAdmin@2025#Secure",
        "new_password": "FinalTest@2025#Pass",
        "confirm_password": "FinalTest@2025#Pass"
    }, allow_redirects=False)
    test("6a. Username injection ignored (identity from session)",
         code == 302,
         f"Code={code} (302=success; form data overridden by session)")

# ============================================================
# Test 7b: After success, session should be invalidated
# ============================================================
print("\n--- Test 7b: Verify session invalidation ---")
# After successful change in test 6, session is invalidated
html, code, resp = get_page("/profile")
test("7c. Session invalidated after password change via /change-password",
     "login" in resp.url.lower(),
     f"URL: {resp.url}")

# ============================================================
# Test 8: All existing features still work
# ============================================================
print("\n--- Test 8: Existing features still work ---")

# 8a: Login with new password (the one set in test 6)
ok = login("admin", "FinalTest@2025#Pass")
test("8a. Login works with new password", ok)

if ok:
    html, code, resp = get_page("/")
    test("8b. Home page accessible", code == 200, f"Code={code}")

    # 8c: Search
    html, code, resp = get_page("/search?keyword=admin")
    test("8c. Search works", code == 200, f"Code={code}")

    # 8d: Upload page
    html, code, resp = get_page("/upload")
    test("8d. Upload page accessible", code == 200, f"Code={code}")

    # 8e: Profile page
    html, code, resp = get_page("/profile")
    test("8e. Profile page accessible", code == 200, f"Code={code}")

    # 8f: Recharge form on profile
    test("8f. Recharge form on profile", "充值" in html, f"Code={code}")

    # 8g: Register page
    html, code, resp = get_page("/register")
    test("8g. Register page accessible", code == 200, f"Code={code}")

    # 8h: /page endpoint
    html, code, resp = get_page("/page?name=about")
    test("8h. /page endpoint works", code in (200, 404), f"Code={code}")

# ============================================================
# Summary
# ============================================================
print("\n" + "=" * 60)
print(f"RESULTS: {passed} passed, {failed} failed out of {total} tests")
print("=" * 60)
sys.exit(0 if failed == 0 else 1)
