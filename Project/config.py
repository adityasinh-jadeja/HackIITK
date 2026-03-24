"""Central configuration for the Secure Agentic Browser."""

from __future__ import annotations

from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    """Application-wide settings loaded from environment / .env file."""

    # --- OPA ---
    opa_url: str = Field(
        default="http://localhost:8181",
        description="Base URL of the Open Policy Agent server",
    )
    opa_policy_path: str = Field(
        default="/v1/data/browser/action",
        description="OPA decision document path",
    )

    # --- Risk thresholds ---
    risk_low_max: float = Field(default=0.3, description="Upper bound for Low risk")
    risk_medium_max: float = Field(default=0.7, description="Upper bound for Medium risk")

    # --- Allowed domains ---
    allowed_domains: list[str] = Field(
        default_factory=lambda: ["example.com"],
        description="Domains the browser is allowed to navigate to",
    )

    # --- Browser launch args ---
    browser_args: list[str] = Field(
        default_factory=lambda: [
            "--disable-gpu",
            "--disable-extensions",
            "--disable-dev-shm-usage",
            "--disable-background-networking",
            "--disable-sync",
            "--disable-translate",
            "--no-first-run",
            "--disable-default-apps",
            "--disable-popup-blocking",
        ],
        description="Chromium launch arguments for sandboxing",
    )

    # --- Data exfiltration threshold ---
    max_outbound_body_bytes: int = Field(
        default=4096,
        description="Maximum allowed body size (bytes) for outbound requests to non-allowed domains",
    )

    model_config = {"env_prefix": "SAB_", "env_file": ".env", "extra": "ignore"}


settings = Settings()
