"""
Phase 5 Agent Pipeline — End-to-end test.
Uses requests (sync) to start agent, then polls /api/dashboard for status updates.
"""
import requests
import time
import json

BASE = "http://localhost:8000"

def test_agent():
    print("=" * 60)
    print("PHASE 5 VERIFICATION: Task Agent Pipeline")
    print("=" * 60)

    # Step 1: Health check
    print("\n[1] Health Check")
    r = requests.get(f"{BASE}/api/health")
    assert r.status_code == 200, f"Server not running: {r.text}"
    print(f"    OK - version {r.json()['version']}")

    # Step 2: Start agent with a clear, achievable goal
    print("\n[2] Starting Agent...")
    r = requests.post(
        f"{BASE}/api/agent/start",
        json={"goal": "Go to https://example.com and tell me the main heading text on the page."}
    )
    assert r.status_code == 200, f"Failed to start agent: {r.text}"
    data = r.json()
    session_id = data.get("session_id")
    print(f"    Agent started | session_id: {session_id}")

    # Step 3: Poll dashboard for up to 60 seconds
    print("\n[3] Polling Dashboard for Agent Status...")
    terminal_states = {"finished", "failed", "error", "idle"}
    last_status = None

    for i in range(30):  # 30 polls x 2s = 60s max
        time.sleep(2)
        r = requests.get(f"{BASE}/api/dashboard")
        state = r.json()
        status = state.get("agentStatus", "unknown")
        goal_info = state.get("currentGoal", "")

        if status != last_status:
            print(f"    [{i*2:3d}s] agentStatus={status:15s} | {goal_info}")
            last_status = status

        if status in terminal_states:
            break

    # Step 4: Stop agent (cleanup)
    print("\n[4] Stopping Agent...")
    r = requests.post(f"{BASE}/api/agent/stop")
    print(f"    {r.json()}")

    # Step 5: Verify final state
    print("\n[5] Final Dashboard State:")
    r = requests.get(f"{BASE}/api/dashboard")
    final = r.json()
    print(f"    agentStatus : {final.get('agentStatus')}")
    print(f"    currentGoal : {final.get('currentGoal')}")
    print(f"    overallRisk : {final.get('overallRisk')}")

    print("\n" + "=" * 60)
    if last_status == "finished":
        print("ALL PHASE 5 TESTS PASSED!")
    elif last_status == "error":
        print("AGENT HIT AN ERROR (see details above)")
    else:
        print(f"AGENT ENDED WITH STATUS: {last_status}")
    print("=" * 60)


if __name__ == "__main__":
    test_agent()
