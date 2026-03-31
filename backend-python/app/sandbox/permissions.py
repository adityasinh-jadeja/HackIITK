"""
Sandbox permission configuration.
Defines what a sandboxed browser context is allowed to do.
"""

from pydantic import BaseModel


class SandboxPermissions(BaseModel):
    """
    Permission set for a sandboxed browser context.
    Default: everything restricted except what's needed for basic browsing.
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

    def to_summary(self) -> dict:
        """Return a human-readable summary of what's blocked/allowed."""
        return {
            "javascript": "allowed" if self.allow_javascript else "blocked",
            "cookies": "allowed" if self.allow_cookies else "blocked",
            "geolocation": "blocked",
            "camera": "blocked",
            "microphone": "blocked",
            "notifications": "blocked",
            "clipboard": "blocked",
            "downloads": "blocked",
            "popups": "blocked",
            "media": "blocked" if self.block_media else "allowed",
            "rate_limit": f"{self.max_requests_per_minute}/min",
        }
