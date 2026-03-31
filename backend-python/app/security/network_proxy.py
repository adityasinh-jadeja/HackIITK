"""
Network Proxy — Intercepts, logs, and filters all network requests from sandboxed pages.

Capabilities:
1. Block requests to known malicious domains
2. Detect potential data exfiltration (large POST bodies, sensitive data patterns)
3. Rate-limit outbound requests
4. Log all network activity for the dashboard
5. Block specific resource types if needed

This runs inside a sync Playwright context (via thread pool) on Windows.
All methods in this class are synchronous — they're called from the sync
route handlers in browser_context.py.
"""

from datetime import datetime, timezone
import re
from collections import defaultdict


class NetworkProxy:
    """
    Intercepts all network requests via Playwright route handlers.
    All methods are synchronous — called from sync Playwright context.
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

    def handle_route_sync(self, route, session_id: str):
        """
        Intercept and evaluate a network request (synchronous version).
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
                log_entry["reason"] = f"Domain matches blocklist: {pattern}"
                self._logs[session_id].append(log_entry)
                route.abort("blockedbyclient")
                return

        # Check 2: Data exfiltration on POST requests
        if method == "POST":
            post_data = request.post_data or ""
            if len(post_data) > 0:
                for pattern in self.SENSITIVE_PATTERNS:
                    if re.search(pattern, post_data, re.IGNORECASE):
                        log_entry["action"] = "BLOCK"
                        log_entry["reason"] = f"Sensitive data in POST body ({pattern[:30]}...)"
                        self._logs[session_id].append(log_entry)
                        route.abort("blockedbyclient")
                        return

        # Check 3: Rate limiting
        self._request_counts[session_id] += 1
        if self._request_counts[session_id] > 100:
            log_entry["action"] = "BLOCK"
            log_entry["reason"] = "Rate limit exceeded (>100 requests)"
            self._logs[session_id].append(log_entry)
            route.abort("blockedbyclient")
            return

        # Allow the request
        self._logs[session_id].append(log_entry)
        route.continue_()

    def get_log(self, session_id: str) -> list:
        """Get all network log entries for a session."""
        return self._logs.get(session_id, [])

    def get_blocked_count(self, session_id: str) -> int:
        """Count blocked requests for a session."""
        return sum(1 for entry in self._logs.get(session_id, []) if entry["action"] == "BLOCK")

    def get_stats(self, session_id: str) -> dict:
        """Get summary stats for a session."""
        log = self._logs.get(session_id, [])
        blocked = sum(1 for e in log if e["action"] == "BLOCK")
        total = len(log)
        return {
            "total_requests": total,
            "blocked": blocked,
            "allowed": total - blocked,
            "block_rate": round((blocked / total * 100), 1) if total > 0 else 0,
        }

    def clear_log(self, session_id: str):
        """Clear logs for a destroyed session."""
        self._logs.pop(session_id, None)
        self._request_counts.pop(session_id, None)
