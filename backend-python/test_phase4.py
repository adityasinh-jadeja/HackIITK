"""Quick verification test for Phase 4 Sandbox endpoints."""
import requests
import json

BASE = "http://localhost:8000"

print("=" * 60)
print("PHASE 4 VERIFICATION: Sandboxing & Network Security")
print("=" * 60)

# Test 1: Create sandbox session
print("\n📦 Test 1: Create Sandbox Session")
r = requests.post(f"{BASE}/api/sandbox/create")
data = r.json()
session_id = data.get("session_id")
permissions = data.get("permissions", {})
print(f"  session_id: {session_id}")
print(f"  permissions: {json.dumps(permissions, indent=2)[:200]}")
assert session_id, "No session_id returned!"
assert permissions.get("geolocation") == "blocked", "Geolocation should be blocked!"
assert permissions.get("camera") == "blocked", "Camera should be blocked!"
print("  ✅ PASSED — Sandbox session created with correct permission restrictions\n")

# Test 2: Navigate to safe page
print("📦 Test 2: Navigate Sandbox (Example.com)")
r = requests.post(f"{BASE}/api/sandbox/{session_id}/navigate", json={
    "url": "https://example.com"
})
data = r.json()
print(f"  title: {data.get('title')}")
print(f"  status_code: {data.get('status_code')}")
print(f"  network_log entries: {len(data.get('network_log', []))}")
print(f"  network_stats: {data.get('network_stats')}")
assert data.get("title") == "Example Domain", f"Expected 'Example Domain', got '{data.get('title')}'"
assert data.get("status_code") == 200, f"Expected 200, got {data.get('status_code')}"
assert len(data.get("html", "")) > 100, "HTML should be non-empty"
print("  ✅ PASSED — Page rendered in sandbox with network activity logged\n")

# Test 3: Get network log
print("📦 Test 3: Network Activity Log")
r = requests.get(f"{BASE}/api/sandbox/{session_id}/network")
data = r.json()
print(f"  total log entries: {len(data.get('log', []))}")
print(f"  blocked_count: {data.get('blocked_count')}")
print(f"  stats: {data.get('stats')}")
assert len(data.get("log", [])) > 0, "Should have at least one network log entry"
print("  ✅ PASSED — Network log recorded successfully\n")

# Test 4: Execute action (scroll - reliable action that doesn't depend on elements)
print("📦 Test 4: Execute Scroll Action")
r = requests.post(f"{BASE}/api/sandbox/{session_id}/action", json={
    "type": "scroll",
    "direction": "down",
    "amount": 200
})
data = r.json()
print(f"  result: {data}")
assert data.get("success") == True, f"Scroll action failed: {data}"
print("  ✅ PASSED — Scroll action executed in sandbox\n")

# Test 5: List sessions
print("📦 Test 5: List Active Sessions")
r = requests.get(f"{BASE}/api/sandbox/sessions")
data = r.json()
print(f"  active sessions: {data.get('count')}")
assert data.get("count") >= 1, "Should have at least 1 active session"
print("  ✅ PASSED — Session tracking works\n")

# Test 6: Destroy session
print("📦 Test 6: Destroy Sandbox Session")
r = requests.delete(f"{BASE}/api/sandbox/{session_id}")
data = r.json()
print(f"  result: {data}")
assert "destroyed" in data.get("message", ""), "Destroy message incorrect"

# Verify destroyed session is no longer in the list
r = requests.get(f"{BASE}/api/sandbox/sessions")
data = r.json()
sessions = data.get("sessions", [])
assert session_id not in sessions, f"Session {session_id} should be destroyed but still in list"
print("  ✅ PASSED — Session destroyed and cleaned up\n")

# Test 7: Full evaluate endpoint with auto-sandbox
print("📦 Test 7: /api/evaluate with Auto-Sandbox (benign page)")
r = requests.post(f"{BASE}/api/evaluate", json={
    "url": "file:///D:/Hackathon/Secure_browser/ABS_HACKIITK/backend-python/tests/test_pages/benign_shopping.html",
    "goal": "Buy a laptop"
})
data = r.json()
print(f"  policy action: {data.get('policy_decision', {}).get('action')}")
print(f"  network_stats: {data.get('network_stats')}")
print(f"  session_id returned: {bool(data.get('session_id'))}")
assert data.get("policy_decision", {}).get("action") == "ALLOW", "Benign page should be ALLOW"
assert data.get("session_id"), "Should return session_id"
assert data.get("network_stats"), "Should return network_stats"
print("  ✅ PASSED — Auto-sandbox evaluation works correctly\n")

# Test 8: Health check version bump
print("📦 Test 8: Version Check")
r = requests.get(f"{BASE}/api/health")
data = r.json()
print(f"  version: {data.get('version')}")
assert data.get("version") == "0.2.0", f"Expected 0.2.0, got {data.get('version')}"
print("  ✅ PASSED — Version updated to 0.2.0\n")

print("=" * 60)
print("🎉 ALL PHASE 4 TESTS PASSED!")
print("=" * 60)
