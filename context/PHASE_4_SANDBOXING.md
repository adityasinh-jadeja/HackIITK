# Phase 4: Sandboxing & Network Security

> **Duration**: Days 5–7 | **Parallel tracks**: Backend (Browser Sandbox + Network Proxy) + Frontend (Network Log UI)
> **Prerequisites**: Phase 3 complete (Security Gate working with DOM Scanner + Guard LLM + Policy Engine)
> **Outcome**: Every browsed page runs in an isolated Playwright context with network traffic monitored, blocked, and logged

---

## 📖 Context for This Phase

Read `PROJECT_CONTEXT.md` first for full architecture and data models.

**What Phase 3 gave you:**
- `SecurityGate.evaluate_url(url, goal)` → full 3-layer security check
- Policy Engine with ALLOW/WARN/REQUIRE_APPROVAL/BLOCK decisions
- HITL approval flow end-to-end
- Guard LLM reasoning via Gemini

**What this phase builds:**
- Playwright browser context isolation (separate cookie jars, storage, permissions per session)
- Network request interception proxy
- Domain-based network filtering (block malicious, log suspicious)
- Data exfiltration detection on outbound requests
- Network activity log for the dashboard

---

## 🔧 Backend Track — Sandbox Manager

### 4.1 — `app/sandbox/browser_context.py`

```python
"""
Browser Context Sandbox Manager

Creates isolated Playwright browser contexts for each browsing session.
Each context has:
- Isolated cookies, localStorage, sessionStorage
- No permissions (camera, mic, geolocation denied)
- Network request interception
- Page load timeout enforcement
- Console and error logging

Manages lifecycle: create → use → destroy
"""

from playwright.async_api import async_playwright, Browser, BrowserContext, Page
from app.config import settings
from app.sandbox.permissions import SandboxPermissions
from app.security.network_proxy import NetworkProxy
import uuid


class SandboxManager:
    """
    Manages isolated browser contexts for secure browsing.
    """

    def __init__(self):
        self._playwright = None
        self._browser: Browser = None
        self._contexts: dict[str, BrowserContext] = {}  # session_id → context
        self._pages: dict[str, Page] = {}  # session_id → page
        self.network_proxy = NetworkProxy()

    async def initialize(self):
        """Start Playwright and launch browser."""
        self._playwright = await async_playwright().start()
        self._browser = await self._playwright.chromium.launch(
            headless=settings.PLAYWRIGHT_HEADLESS,
            args=[
                '--disable-extensions',
                '--disable-plugins',
                '--disable-popup-blocking',  # We handle popups ourselves
                '--no-first-run',
                '--disable-default-apps',
                '--disable-sync',
                '--disable-background-networking',
            ]
        )

    async def create_session(self, session_id: str = None) -> str:
        """
        Create a new isolated browser context.
        Returns the session_id.
        """
        if not self._browser:
            await self.initialize()

        session_id = session_id or str(uuid.uuid4())
        permissions = SandboxPermissions()

        context = await self._browser.new_context(
            # Isolation
            storage_state=None,  # No pre-existing storage
            ignore_https_errors=False,
            java_script_enabled=True,

            # Permissions — deny everything by default
            permissions=[],

            # Viewport
            viewport={'width': 1280, 'height': 720},

            # User agent (avoid fingerprinting as automation)
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',

            # Geolocation denied (no location passed)
            # No proxy — we intercept at the route level
        )

        # Set up network interception
        await context.route("**/*", lambda route: self.network_proxy.handle_route(route, session_id))

        # Block specific resource types for performance
        if permissions.block_media:
            await context.route("**/*.{png,jpg,jpeg,gif,svg,mp4,webm,mp3,wav}", lambda route: route.abort())

        # Create page
        page = await context.new_page()

        # Inject Content Security Policy
        await page.add_init_script("""
            // Override dangerous APIs
            window.eval = function() { 
                console.warn('[SANDBOX] eval() blocked'); 
                return undefined; 
            };
            
            // Monitor clipboard access
            const originalClipboard = navigator.clipboard;
            navigator.clipboard.readText = async function() {
                console.warn('[SANDBOX] Clipboard read blocked');
                return '';
            };
            
            // Block file downloads
            window.open = function(url) {
                console.warn('[SANDBOX] window.open blocked: ' + url);
                return null;
            };
        """)

        self._contexts[session_id] = context
        self._pages[session_id] = page

        return session_id

    async def navigate(self, session_id: str, url: str) -> dict:
        """
        Navigate a sandboxed session to a URL.
        Returns page data (HTML, title, etc.)
        """
        page = self._pages.get(session_id)
        if not page:
            raise ValueError(f"Session {session_id} not found")

        response = await page.goto(
            url,
            wait_until="networkidle",
            timeout=settings.MAX_PAGE_LOAD_TIMEOUT,
        )

        # Wait for dynamic content
        await page.wait_for_timeout(2000)

        return {
            "html": await page.content(),
            "title": await page.title(),
            "url": page.url,
            "status_code": response.status if response else None,
            "network_log": self.network_proxy.get_log(session_id),
        }

    async def execute_action(self, session_id: str, action: dict) -> dict:
        """
        Execute a browser action in the sandbox.
        Actions: click, type, scroll, select, wait

        action format: {"type": "click", "selector": "#btn", ...}
        """
        page = self._pages.get(session_id)
        if not page:
            raise ValueError(f"Session {session_id} not found")

        action_type = action.get("type")
        selector = action.get("selector", "")

        try:
            if action_type == "click":
                await page.click(selector, timeout=5000)
            elif action_type == "type":
                text = action.get("text", "")
                await page.fill(selector, text, timeout=5000)
            elif action_type == "scroll":
                direction = action.get("direction", "down")
                amount = action.get("amount", 300)
                if direction == "down":
                    await page.evaluate(f"window.scrollBy(0, {amount})")
                else:
                    await page.evaluate(f"window.scrollBy(0, -{amount})")
            elif action_type == "select":
                value = action.get("value", "")
                await page.select_option(selector, value)
            elif action_type == "wait":
                ms = action.get("ms", 1000)
                await page.wait_for_timeout(ms)
            elif action_type == "screenshot":
                screenshot = await page.screenshot(full_page=True)
                return {"success": True, "screenshot": screenshot}
            else:
                return {"success": False, "error": f"Unknown action type: {action_type}"}

            return {
                "success": True,
                "url": page.url,
                "title": await page.title(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    async def get_page_content(self, session_id: str) -> str:
        """Get current page HTML for security scanning."""
        page = self._pages.get(session_id)
        if not page:
            raise ValueError(f"Session {session_id} not found")
        return await page.content()

    async def destroy_session(self, session_id: str):
        """Close and clean up a sandboxed session."""
        context = self._contexts.pop(session_id, None)
        self._pages.pop(session_id, None)
        if context:
            await context.close()
        self.network_proxy.clear_log(session_id)

    async def shutdown(self):
        """Close all sessions and the browser."""
        for session_id in list(self._contexts.keys()):
            await self.destroy_session(session_id)
        if self._browser:
            await self._browser.close()
        if self._playwright:
            await self._playwright.stop()
```

### 4.2 — `app/sandbox/permissions.py`

```python
"""
Sandbox permission configuration.
Defines what a sandboxed browser context is allowed to do.
"""

from pydantic import BaseModel


class SandboxPermissions(BaseModel):
    """
    Permission set for a sandboxed browser context.
    Default: everything restricted.
    """
    allow_javascript: bool = True       # JS is needed for most pages
    allow_cookies: bool = True          # Session cookies needed for navigation
    allow_local_storage: bool = True    # Some sites need this
    allow_geolocation: bool = False     # Deny
    allow_camera: bool = False          # Deny
    allow_microphone: bool = False      # Deny
    allow_notifications: bool = False   # Deny
    allow_clipboard_read: bool = False  # Deny — potential data exfil
    allow_clipboard_write: bool = False # Deny
    allow_downloads: bool = False       # Deny — no file system access
    allow_popups: bool = False          # Deny — we control navigation
    block_media: bool = False           # Optional performance optimization
    max_requests_per_minute: int = 100  # Rate limiting
    allowed_domains: list[str] = []     # Empty = allow all non-blocklisted
    blocked_domains: list[str] = []     # Extra domain blocks specific to this session
```

### 4.3 — `app/security/network_proxy.py`

```python
"""
Network Proxy — Intercepts, logs, and filters all network requests from sandboxed pages.

Capabilities:
1. Block requests to known malicious domains
2. Detect potential data exfiltration (large POST bodies, sensitive data patterns)
3. Rate-limit outbound requests
4. Log all network activity for the dashboard
5. Block specific resource types if needed
"""

from playwright.async_api import Route
from datetime import datetime, timezone
import re
from collections import defaultdict


class NetworkProxy:
    """
    Intercepts all network requests via Playwright route handlers.
    """

    # Threat intelligence — malicious domains
    BLOCKED_DOMAINS = [
        r"evil\.com",
        r"malware\.",
        r"phishing\.",
        r".*\.onion$",
        r"bit\.ly",            # URL shorteners (potential redirect to malicious)
        r"tinyurl\.com",
    ]

    # Sensitive data patterns (for exfiltration detection)
    SENSITIVE_PATTERNS = [
        r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",       # Credit card
        r"\b\d{3}-\d{2}-\d{4}\b",                                # SSN
        r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", # Email
        r"password|passwd|secret|token|api_key|apikey",            # Keywords
    ]

    def __init__(self):
        self._logs: dict[str, list] = defaultdict(list)  # session_id → list of log entries
        self._request_counts: dict[str, int] = defaultdict(int)

    async def handle_route(self, route: Route, session_id: str):
        """
        Intercept and evaluate a network request.
        Called for every request from a sandboxed browser context.
        """
        request = route.request
        url = request.url
        method = request.method
        resource_type = request.resource_type

        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "url": url,
            "method": method,
            "resource_type": resource_type,
            "action": "ALLOW",  # Default
            "reason": None,
        }

        # Check 1: Blocked domains
        for pattern in self.BLOCKED_DOMAINS:
            if re.search(pattern, url, re.IGNORECASE):
                log_entry["action"] = "BLOCK"
                log_entry["reason"] = f"Domain matches blocklist pattern: {pattern}"
                self._logs[session_id].append(log_entry)
                await route.abort("blockedbyclient")
                return

        # Check 2: Data exfiltration on POST requests
        if method == "POST":
            post_data = request.post_data or ""
            if len(post_data) > 0:
                for pattern in self.SENSITIVE_PATTERNS:
                    if re.search(pattern, post_data, re.IGNORECASE):
                        log_entry["action"] = "BLOCK"
                        log_entry["reason"] = f"Sensitive data detected in POST body (pattern: {pattern[:30]})"
                        self._logs[session_id].append(log_entry)
                        await route.abort("blockedbyclient")
                        return

        # Check 3: Rate limiting
        self._request_counts[session_id] += 1
        if self._request_counts[session_id] > 100:  # Per minute — simplified
            log_entry["action"] = "BLOCK"
            log_entry["reason"] = "Rate limit exceeded (>100 requests)"
            self._logs[session_id].append(log_entry)
            await route.abort("blockedbyclient")
            return

        # Allow the request
        self._logs[session_id].append(log_entry)
        await route.continue_()

    def get_log(self, session_id: str) -> list:
        """Get all network log entries for a session."""
        return self._logs.get(session_id, [])

    def get_blocked_count(self, session_id: str) -> int:
        """Count blocked requests for a session."""
        return sum(1 for entry in self._logs.get(session_id, []) if entry["action"] == "BLOCK")

    def clear_log(self, session_id: str):
        """Clear logs for a destroyed session."""
        self._logs.pop(session_id, None)
        self._request_counts.pop(session_id, None)
```

### 4.4 — API Endpoints for Sandbox

Add to `app/main.py`:

```python
from app.sandbox.browser_context import SandboxManager

sandbox = SandboxManager()

@app.on_event("startup")
async def startup():
    await sandbox.initialize()

@app.on_event("shutdown")
async def shutdown():
    await sandbox.shutdown()

@app.post("/api/sandbox/create")
async def create_sandbox():
    """Create a new sandboxed browsing session."""
    session_id = await sandbox.create_session()
    return {"session_id": session_id}

@app.post("/api/sandbox/{session_id}/navigate")
async def sandbox_navigate(session_id: str, body: dict):
    """Navigate sandboxed session to a URL."""
    url = body.get("url")
    result = await sandbox.navigate(session_id, url)
    return result

@app.post("/api/sandbox/{session_id}/action")
async def sandbox_action(session_id: str, body: dict):
    """Execute an action in a sandboxed session."""
    result = await sandbox.execute_action(session_id, body)
    return result

@app.get("/api/sandbox/{session_id}/network")
async def sandbox_network(session_id: str):
    """Get network log for a sandboxed session."""
    return {
        "log": sandbox.network_proxy.get_log(session_id),
        "blocked_count": sandbox.network_proxy.get_blocked_count(session_id),
    }

@app.delete("/api/sandbox/{session_id}")
async def destroy_sandbox(session_id: str):
    """Destroy a sandboxed session and clean up."""
    await sandbox.destroy_session(session_id)
    return {"message": f"Session {session_id} destroyed"}
```

### 4.5 — Update Security Gate to Use Sandbox

Modify `app/security/security_gate.py` to use the sandbox manager instead of direct Playwright:

```python
# Replace render_and_extract(url) calls with:
page_data = await sandbox_manager.navigate(session_id, url)

# After security check, if BLOCKED:
await sandbox_manager.destroy_session(session_id)

# If ALLOWED, keep the session alive for the agent pipeline
```

---

## 🎨 Frontend Track — Network Activity UI

### 4.6 — `NetworkLog.jsx` (NEW Component)

A real-time network activity panel for the dashboard.

```
┌──────────────────────────────────────────────────────┐
│  🌐 Network Activity            Blocked: 3 / 47     │
│                                                       │
│  Filters: [All ▼] [Blocked Only □] [POST Only □]     │
│                                                       │
│  ┌────────────────────────────────────────────────┐   │
│  │ ✅ GET  | https://cdn.site.com/styles.css       │   │
│  │    14:23:01 | stylesheet | 2.3kb               │   │
│  ├────────────────────────────────────────────────┤   │
│  │ ❌ POST | https://evil.com/steal               │   │
│  │    14:23:02 | xhr | BLOCKED: Domain blacklist  │   │
│  ├────────────────────────────────────────────────┤   │
│  │ ✅ GET  | https://api.site.com/products        │   │
│  │    14:23:02 | fetch | 12.1kb                   │   │
│  ├────────────────────────────────────────────────┤   │
│  │ ❌ POST | https://analytics.com/track          │   │
│  │    14:23:03 | xhr | BLOCKED: Sensitive data    │   │
│  └────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────┘
```

Features:
- Real-time streaming via WebSocket
- Color-coded: green (allowed), red (blocked)
- Filterable by method, action, resource type
- Expandable rows showing full request details
- Block reason displayed inline for blocked requests

### 4.7 — Sandbox Status Indicator

Add to `BrowserUI.jsx`:
- A small badge showing sandbox status: "🔒 Sandboxed" / "⚠️ Not Sandboxed"
- Active session count display
- Permission summary tooltip (what's allowed/blocked)

### 4.8 — Add Network Tab to Dashboard

Add a "Network" tab in the sidebar navigation that shows:
- `NetworkLog` component
- Summary stats: total requests, blocked, by resource type
- Top blocked domains chart

---

## ✅ Verification Checklist

- [ ] `POST /api/sandbox/create` → returns `{"session_id": "uuid"}`
- [ ] `POST /api/sandbox/{id}/navigate {"url": "https://example.com"}` → returns HTML
- [ ] Navigate to a blocked domain (evil.com) → request aborted, logged as blocked
- [ ] POST with credit card pattern in body → blocked and logged
- [ ] Rate limiting kicks in after 100+ rapid requests
- [ ] Each session has separate cookies (login in one session doesn't affect another)
- [ ] `eval()` is blocked inside sandboxed pages
- [ ] `window.open()` is blocked inside sandboxed pages
- [ ] Clipboard read is blocked inside sandboxed pages
- [ ] Network log shows in dashboard in real time
- [ ] `DELETE /api/sandbox/{id}` → context cleaned up, memory freed
- [ ] Sandbox indicator shows "🔒 Sandboxed" in browser UI

---

## 🔗 Interfaces for Next Phases

| Interface | Used By | Description |
|---|---|---|
| `SandboxManager.create_session()` | Phase 5 | Agent creates sandbox at start |
| `SandboxManager.navigate()` | Phase 5 | Agent navigates in sandbox |
| `SandboxManager.execute_action()` | Phase 5 | Agent runs actions in sandbox |
| `SandboxManager.destroy_session()` | Phase 5 | Agent cleans up on completion |
| `NetworkProxy.get_log()` | Phase 6 | Forensics includes network activity |
| Network log data | Phase 6 | Attack replay shows blocked requests |

---

## 🧪 Manual Testing Steps

### Prerequisites
- Phases 1-3 complete (Security Gate working)
- Playwright Chromium browser installed: `playwright install chromium`
- Backend running on port 8000

### Test 1: Create a Sandbox Session

```bash
curl -X POST http://localhost:8000/api/sandbox/create
```

**✅ Expected**: `{"session_id": "uuid-string-here"}`

Save the returned `session_id` — you'll use it in the following tests:
```bash
# On Windows PowerShell:
$SESSION_ID = (curl -s -X POST http://localhost:8000/api/sandbox/create | ConvertFrom-Json).session_id
echo $SESSION_ID

# On Linux/Mac:
SESSION_ID=$(curl -s -X POST http://localhost:8000/api/sandbox/create | jq -r '.session_id')
echo $SESSION_ID
```

---

### Test 2: Navigate to a Safe Page

```bash
curl -X POST http://localhost:8000/api/sandbox/$SESSION_ID/navigate \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**✅ Expected**: JSON response with:
- `html` — full rendered HTML of example.com
- `title` — "Example Domain"
- `url` — "https://example.com/"
- `status_code` — 200
- `network_log` — array of network requests made during page load

---

### Test 3: Execute Click Action

```bash
curl -X POST http://localhost:8000/api/sandbox/$SESSION_ID/action \
  -H "Content-Type: application/json" \
  -d '{"type": "click", "selector": "a"}'
```

**✅ Expected**: `{"success": true, "url": "https://www.iana.org/...", "title": "..."}`
(example.com has a link to IANA)

---

### Test 4: Execute Type Action

First navigate to a page with an input:
```bash
curl -X POST http://localhost:8000/api/sandbox/$SESSION_ID/navigate \
  -H "Content-Type: application/json" \
  -d '{"url": "https://www.google.com"}'

curl -X POST http://localhost:8000/api/sandbox/$SESSION_ID/action \
  -H "Content-Type: application/json" \
  -d '{"type": "type", "selector": "textarea[name=q], input[name=q]", "text": "secure browser"}'
```

**✅ Expected**: `{"success": true, ...}` — text typed into the search field.

---

### Test 5: Network Proxy — Blocked Domain

Navigate to a domain that's in the blocklist:

```bash
curl -X POST http://localhost:8000/api/sandbox/$SESSION_ID/navigate \
  -H "Content-Type: application/json" \
  -d '{"url": "https://evil.com"}'
```

**✅ Expected**: Navigation fails or returns error. Check the network log:

```bash
curl http://localhost:8000/api/sandbox/$SESSION_ID/network
```

**Expected response**:
```json
{
  "log": [
    {
      "url": "https://evil.com/",
      "method": "GET",
      "action": "BLOCK",
      "reason": "Domain matches blocklist pattern: evil\\.com"
    }
  ],
  "blocked_count": 1
}
```

---

### Test 6: Network Proxy — Data Exfiltration Blocked

Create a test page that makes a POST with sensitive data, or manually trigger:

```bash
# This test requires a page that triggers a POST with credit card data
# The network proxy should detect and block the pattern
# Check the network log after browsing a deceptive form page

curl -X POST http://localhost:8000/api/sandbox/$SESSION_ID/navigate \
  -H "Content-Type: application/json" \
  -d '{"url": "file:///path/to/test_pages/deceptive_form.html"}'

# Then check network log
curl http://localhost:8000/api/sandbox/$SESSION_ID/network
```

**✅ Expected**: If the form submitted data containing credit card patterns, those requests are BLOCKED in the network log.

---

### Test 7: Session Isolation

Create two sandbox sessions and verify they don't share state:

```bash
# Create session A
SESSION_A=$(curl -s -X POST http://localhost:8000/api/sandbox/create | python -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

# Create session B
SESSION_B=$(curl -s -X POST http://localhost:8000/api/sandbox/create | python -c "import sys,json; print(json.load(sys.stdin)['session_id'])")

# Navigate session A to a page
curl -s -X POST "http://localhost:8000/api/sandbox/$SESSION_A/navigate" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Navigate session B to a different page
curl -s -X POST "http://localhost:8000/api/sandbox/$SESSION_B/navigate" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://httpbin.org"}'
```

**✅ Expected**: Each session navigates independently. Cookies and localStorage are not shared between sessions.

---

### Test 8: Sandbox API Overrides (eval Blocked)

Navigate to a page with JavaScript, then test that `eval()` is blocked:

```bash
# Navigate to a page
curl -s -X POST "http://localhost:8000/api/sandbox/$SESSION_ID/navigate" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'

# Try to execute an action that relies on eval (the sandbox overrides it)
# The eval test is checked via the init script injected into the context
```

To verify: Create a simple HTML page that calls `eval("alert(1)")` and check the browser console logs for `[SANDBOX] eval() blocked`.

---

### Test 9: Destroy Session

```bash
curl -X DELETE http://localhost:8000/api/sandbox/$SESSION_ID
```

**✅ Expected**: `{"message": "Session <uuid> destroyed"}`

Then verify the session can't be used:
```bash
curl -X POST "http://localhost:8000/api/sandbox/$SESSION_ID/navigate" \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**✅ Expected**: Error response — session not found.

---

### Test 10: Network Activity in Dashboard

1. Open the dashboard at `http://localhost:5173`
2. Create a sandbox session and navigate to a few pages (use curl commands above)
3. Check the Network tab in the dashboard

**✅ Expected**:
- Network requests stream in as they happen
- Blocked requests shown in red with block reason
- Allowed requests shown in green
- Filter buttons work (All / Blocked Only / POST Only)
- Blocked count displays correctly

---

### Test 11: Sandbox Status Indicator

Check the BrowserUI shows sandbox status:

**✅ Expected**:
- "🔒 Sandboxed" badge visible when a sandbox session is active
- Permission summary tooltip shows what's blocked (camera, mic, geolocation, etc.)
- Active session count updates as sessions are created/destroyed

---

### Troubleshooting

| Problem | Fix |
|---|---|
| Playwright crashes on launch | Run `playwright install chromium` again; check disk space |
| Session not found | Session may have been garbage collected; create a new one |
| Navigation hangs | Check `MAX_PAGE_LOAD_TIMEOUT` in `.env` (default 30s) |
| Network proxy blocks everything | Check `BLOCKED_DOMAINS` regex patterns; may be too aggressive |
| `window.open` still works | Verify the init script is injected correctly in `browser_context.py` |
