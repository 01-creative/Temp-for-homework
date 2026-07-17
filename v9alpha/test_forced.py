#!/usr/bin/env python3
"""
Test forced password change flow (alice has first_login=1).
"""

import requests
import re
import sys

BASE = "http://127.0.0.1:8089"
session = requests.Session()

def get_csrf(html):
    m = re.search(r'name="csrf_token"\s+value="([^"]+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'value="([^"]+)"[^>]*name="csrf_token"', html)
    if m:
        return m.group(1)
    return None

# Login as alice (first_login=1, will be forced to change password)
r = session.get(f"{BASE}/login")
csrf = get_csrf(r.text)
assert csrf, "No CSRF on login page"

r = session.post(f"{BASE}/login", data={
    "csrf_token": csrf,
    "username": "alice",
    "password": "Alice@2025#User!"
}, allow_redirects=False)

print(f"Login response: {r.status_code} redirect to {r.headers.get('Location','')}")
assert r.status_code == 302, "Should redirect"
loc = r.headers.get("Location", "")
assert "change-password" in loc, f"Should redirect to change-password, got: {loc}"

# Follow the redirect manually
r = session.get(f"{BASE}/change-password")
print(f"GET /change-password: {r.status_code}")
csrf = get_csrf(r.text)
assert csrf, "No CSRF on change-password page"
print("Has CSRF token: YES")

# Should show forced change form (no old_password field)
assert 'name="old_password"' not in r.text, "Should NOT have old_password field"
assert 'name="new_password"' in r.text, "Should have new_password field"
assert 'name="confirm_password"' in r.text, "Should have confirm_password field"
print("Form fields correct (no old_password, has new_password + confirm_password)")

# Submit forced password change
r = session.post(f"{BASE}/change-password", data={
    "csrf_token": csrf,
    "new_password": "AliceNew@2025#Pass",
    "confirm_password": "AliceNew@2025#Pass"
}, allow_redirects=False)

print(f"POST /change-password: {r.status_code} redirect to {r.headers.get('Location','')}")
assert r.status_code == 302, "Should redirect on success"
assert "/profile" in r.headers.get("Location", ""), "Should redirect to /profile"

# Now verify that session is invalidated (enforce_session_version kicks in)
r = session.get(f"{BASE}/profile", allow_redirects=False)
print(f"GET /profile after change: {r.status_code} redirect to {r.headers.get('Location','')}")
assert r.status_code == 302, "Should be redirected to login"
assert "/login" in r.headers.get("Location", ""), f"Should redirect to /login, got: {r.headers.get('Location','')}"
print("Session invalidated: users must re-login")

# Can we re-login with new password?
r = session.get(f"{BASE}/login")
csrf = get_csrf(r.text)
r = session.post(f"{BASE}/login", data={
    "csrf_token": csrf,
    "username": "alice",
    "password": "AliceNew@2025#Pass"
}, allow_redirects=False)

print(f"Re-login: {r.status_code} redirect to {r.headers.get('Location','')}")
assert r.status_code == 302, "Should redirect after login"
# Should NOT be redirected to /change-password (first_login is now 0)
loc = r.headers.get("Location", "")
assert "change-password" not in loc, f"Should NOT be forced to change password again, got: {loc}"
print("Login successful with new password, no forced change prompt")

# Verify we can access profile
r = session.get(f"{BASE}/profile")
print(f"GET /profile: {r.status_code}")
assert r.status_code == 200, "Should access profile"
print("Profile accessible")

print("\n=== ALL FORCED PASSWORD CHANGE TESTS PASSED ===")
