from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    secret_key: str = "dev-secret-key"
    app_password: str = "changeme"
    redis_url: str = "redis://localhost:6379/0"
    edgerc_host_path: str = "./.edgerc"
    edgerc_path: str = "/run/secrets/edgerc"
    edgerc_section: str = "default"
    edgerc_reporting_section: str = "reporting"
    reports_base_dir: str = "./reports"
    concurrency_limit: int = 10
    rule_tree_cache_ttl: int = 3600
    traffic_chunk_size: int = 100
    traffic_chunk_delay_seconds: float = 0.25
    traffic_max_retries: int = 6

    class Config:
        env_file = ".env"
        extra = "ignore"


@lru_cache
def get_settings() -> Settings:
    return Settings()
