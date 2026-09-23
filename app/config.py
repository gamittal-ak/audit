from functools import lru_cache
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    secret_key: str = "dev-secret-key"
    app_password: str = "changeme"
    redis_url: str = "redis://localhost:6379/0"
    edgerc_host_path: str = "./.edgerc"
    edgerc_path: str = "/run/secrets/edgerc"
    edgerc_section: str = "default"
    edgerc_reporting_section: str = "reporting"
    reports_base_dir: str = "./reports"
    concurrency_limit: int = Field(default=10, ge=1)
    # Shared deployment budgets, below Akamai's documented sustained limits.
    papi_requests_per_minute: float = Field(default=80, gt=0, le=80)
    reporting_requests_per_minute: float = Field(default=15, gt=0, le=15)
    akamai_global_requests_per_second: float = Field(default=2, gt=0, le=2)
    akamai_max_attempts: int = Field(default=6, ge=1, le=10)
    akamai_waf_cooldown_seconds: float = Field(default=610, ge=610)
    rule_tree_cache_ttl: int = 3600
    traffic_chunk_size: int = 100
    traffic_chunk_delay_seconds: float = 0.25
    traffic_max_retries: int = Field(default=6, ge=1, le=10)

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
