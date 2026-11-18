"""
Global configuration settings for Sentinel & Footprint.
"""
from dataclasses import dataclass

@dataclass(frozen=True)
class Settings:
    APP_NAME: str = "Sentinel & Footprint"
    VERSION: str = "0.1.0"
    DEFAULT_TIMEOUT: int = 10
    USER_AGENT: str = "SentinelSecAuditor/0.1 (+https://github.com/security/sentinel-footprint)"
    TRACKER_FILE: str = "privacy_tracker.json"

settings = Settings()
