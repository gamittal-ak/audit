from functools import lru_cache
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    secret_key: str = "dev-secret-key"
    app_password: str = "changeme"
    redis_url: str = "redis://localhost:6379/0"
    edgerc_path: str = "/run/secrets/edgerc"
    edgerc_section: str = "default"
    edgerc_reporting_section: str = "reporting"
    reports_base_dir: str = "./reports"
    concurrency_limit: int = 10
    rule_tree_cache_ttl: int = 3600

    class Config:
        env_file = ".env"


@lru_cache
def get_settings() -> Settings:
    return Settings()
