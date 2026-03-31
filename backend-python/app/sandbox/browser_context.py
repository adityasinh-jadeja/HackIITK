"""
Browser Context Sandbox Manager

Creates isolated Playwright browser contexts for each browsing session.
Each context has:
- Isolated cookies, localStorage, sessionStorage
- No permissions (camera, mic, geolocation denied)
- Network request interception via NetworkProxy
- Page load timeout enforcement
- Dangerous API overrides (eval, window.open, clipboard)

IMPORTANT: sync_playwright is NOT thread-safe. All Playwright operations MUST
run on the same thread where the browser was launched. We use a single-worker
ThreadPoolExecutor to guarantee all calls are dispatched to the same thread.
"""

from playwright.sync_api import sync_playwright
from app.config import settings
from app.sandbox.permissions import SandboxPermissions
from app.security.network_proxy import NetworkProxy
import uuid
import asyncio
from concurrent.futures import ThreadPoolExecutor


# Init script injected into every sandboxed page to override dangerous APIs
SANDBOX_INIT_SCRIPT = """
(function() {
    // Override eval() to prevent arbitrary code execution
    const originalEval = window.eval;
    window.eval = function() { 
        console.warn('[SANDBOX] eval() blocked by security policy'); 
        return undefined; 
    };
    
    // Monitor and block clipboard read access
    if (navigator.clipboard) {
        navigator.clipboard.readText = async function() {
            console.warn('[SANDBOX] Clipboard read blocked');
            return '';
        };
    }
    
    // Block unsolicited window opens / popups
    window.open = function(url) {
        console.warn('[SANDBOX] window.open blocked: ' + url);
        return null;
    };
    
    // Block file downloads via anchor click
    const origCreateElement = document.createElement.bind(document);
    document.createElement = function(tag) {
        const el = origCreateElement(tag);
        if (tag.toLowerCase() === 'a') {
            const origClick = el.click;
            el.click = function() {
                if (el.download) {
                    console.warn('[SANDBOX] Download blocked: ' + el.href);
                    return;
                }
                origClick.call(el);
            };
        }
        return el;
    };
})();
"""


class SandboxManager:
    """
    Manages isolated browser contexts for secure browsing.
    
    Uses a dedicated single-worker ThreadPoolExecutor to ensure all
    Playwright operations happen on the same thread (sync_playwright
    is NOT thread-safe).
    """

    def __init__(self):
        self._pw = None
        self._browser = None
        self._contexts = {}    # session_id → context
        self._pages = {}       # session_id → page
        self._permissions = {} # session_id → SandboxPermissions
        self.network_proxy = NetworkProxy()
        self._initialized = False
        # Single thread executor — ALL Playwright operations go here
        self._executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="playwright")

    def _ensure_browser(self):
        """Start Playwright and launch browser if not already running."""
        if self._initialized and self._browser:
            return
        
        self._pw = sync_playwright().start()
        self._browser = self._pw.chromium.launch(
            headless=settings.PLAYWRIGHT_HEADLESS,
            args=[
                '--disable-extensions',
                '--disable-plugins',
                '--disable-popup-blocking',
                '--no-first-run',
                '--disable-default-apps',
                '--disable-sync',
                '--disable-background-networking',
                '--disable-component-update',
            ]
        )
        self._initialized = True

    def _create_session_sync(self, session_id=None):
        """Create a new isolated browser context (sync, runs on playwright thread)."""
        self._ensure_browser()

        session_id = session_id or str(uuid.uuid4())
        permissions = SandboxPermissions()

        context = self._browser.new_context(
            storage_state=None,
            ignore_https_errors=True,
            java_script_enabled=permissions.allow_javascript,
            permissions=[],
            viewport={'width': 1280, 'height': 720},
            user_agent=(
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
                'AppleWebKit/537.36 (KHTML, like Gecko) '
                'Chrome/120.0.0.0 Safari/537.36'
            ),
        )

        # Set up network interception — sync handler
        proxy = self.network_proxy
        sid = session_id
        context.route("**/*", lambda route: proxy.handle_route_sync(route, sid))

        # Block media resources if configured
        if permissions.block_media:
            context.route(
                "**/*.{png,jpg,jpeg,gif,svg,mp4,webm,mp3,wav}",
                lambda route: route.abort()
            )

        # Create page and inject sandbox init script
        page = context.new_page()
        page.add_init_script(SANDBOX_INIT_SCRIPT)

        self._contexts[session_id] = context
        self._pages[session_id] = page
        self._permissions[session_id] = permissions

        return session_id

    def _navigate_sync(self, session_id, url):
        """Navigate a sandboxed session to a URL (sync)."""
        page = self._pages.get(session_id)
        if not page:
            raise ValueError(f"Session {session_id} not found")

        is_local = url.startswith("file://")
        wait_cond = "load" if is_local else "domcontentloaded"
        timeout_ms = 10000 if is_local else settings.MAX_PAGE_LOAD_TIMEOUT

        try:
            response = page.goto(url, wait_until=wait_cond, timeout=timeout_ms)
            page.wait_for_timeout(1000)  # Wait for dynamic content

            return {
                "html": page.content(),
                "title": page.title(),
                "url": page.url,
                "status_code": response.status if response and not is_local else 200,
                "network_log": self.network_proxy.get_log(session_id),
                "network_stats": self.network_proxy.get_stats(session_id),
            }
        except Exception as e:
            return {
                "html": "",
                "title": "Error",
                "url": url,
                "status_code": 0,
                "error": str(e),
                "network_log": self.network_proxy.get_log(session_id),
                "network_stats": self.network_proxy.get_stats(session_id),
            }

    def _execute_action_sync(self, session_id, action):
        """Execute a browser action in the sandbox (sync)."""
        page = self._pages.get(session_id)
        if not page:
            raise ValueError(f"Session {session_id} not found")

        action_type = action.get("type")
        selector = action.get("selector", "")

        try:
            if action_type == "click":
                page.click(selector, timeout=5000)
            elif action_type == "type":
                text = action.get("text", "")
                page.fill(selector, text, timeout=5000)
            elif action_type == "scroll":
                direction = action.get("direction", "down")
                amount = action.get("amount", 300)
                delta = amount if direction == "down" else -amount
                page.evaluate(f"window.scrollBy(0, {delta})")
            elif action_type == "select":
                value = action.get("value", "")
                page.select_option(selector, value)
            elif action_type == "wait":
                ms = action.get("ms", 1000)
                page.wait_for_timeout(ms)
            elif action_type == "screenshot":
                screenshot = page.screenshot(full_page=True)
                return {"success": True, "screenshot_bytes": len(screenshot)}
            else:
                return {"success": False, "error": f"Unknown action type: {action_type}"}

            return {
                "success": True,
                "url": page.url,
                "title": page.title(),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def _get_page_content_sync(self, session_id):
        """Get current page HTML for security scanning (sync)."""
        page = self._pages.get(session_id)
        if not page:
            raise ValueError(f"Session {session_id} not found")
        return page.content()

    def _destroy_session_sync(self, session_id):
        """Close and clean up a sandboxed session (sync)."""
        context = self._contexts.pop(session_id, None)
        self._pages.pop(session_id, None)
        self._permissions.pop(session_id, None)
        if context:
            try:
                context.close()
            except Exception:
                pass
        self.network_proxy.clear_log(session_id)

    def _shutdown_sync(self):
        """Close all sessions and the browser (sync)."""
        for session_id in list(self._contexts.keys()):
            self._destroy_session_sync(session_id)
        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
        if self._pw:
            try:
                self._pw.stop()
            except Exception:
                pass
        self._initialized = False

    # --- Async wrappers using the dedicated single-thread executor ---

    async def _run_on_pw_thread(self, fn, *args):
        """Run a sync function on the dedicated Playwright thread."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(self._executor, fn, *args)

    async def create_session(self, session_id=None):
        return await self._run_on_pw_thread(self._create_session_sync, session_id)

    async def navigate(self, session_id, url):
        return await self._run_on_pw_thread(self._navigate_sync, session_id, url)

    async def execute_action(self, session_id, action):
        return await self._run_on_pw_thread(self._execute_action_sync, session_id, action)

    async def get_page_content(self, session_id):
        return await self._run_on_pw_thread(self._get_page_content_sync, session_id)

    async def destroy_session(self, session_id):
        return await self._run_on_pw_thread(self._destroy_session_sync, session_id)

    async def shutdown(self):
        result = await self._run_on_pw_thread(self._shutdown_sync)
        self._executor.shutdown(wait=False)
        return result

    def get_session_info(self, session_id):
        """Get info about a sandbox session (non-blocking, reads only)."""
        if session_id not in self._contexts:
            return None
        perms = self._permissions.get(session_id, SandboxPermissions())
        return {
            "session_id": session_id,
            "active": True,
            "permissions": perms.to_summary(),
            "network_stats": self.network_proxy.get_stats(session_id),
        }

    def get_active_sessions(self):
        """List all active session IDs."""
        return list(self._contexts.keys())
