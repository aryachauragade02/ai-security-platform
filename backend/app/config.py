"""All settings come from environment variables (or a local backend/.env file).

Real keys NEVER go in code. See ../.env.example for the full list.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # Google Gemini (get a free key at https://aistudio.google.com/apikey)
    gemini_api_key: str = ""
    gemini_model: str = "gemini-2.0-flash"

    # Supabase (Project Settings -> API)
    supabase_url: str = ""
    supabase_service_key: str = ""  # the secret "service_role" key. Backend only!

    # Optional protection for your own endpoints
    gateway_api_key: str = ""  # if set, /v1/chat needs header x-gateway-key
    admin_api_key: str = ""  # if set, admin actions need header x-admin-key

    allowed_origins: str = "*"  # comma separated, e.g. https://my-app.vercel.app

    # Behaviour
    block_threshold: int = 50  # risk score (0-100) at which a prompt is blocked
    rate_limit_per_minute: int = 20  # per client, /v1/chat
    demo_rate_limit_per_minute: int = 10  # per IP, public demo endpoint
    scan_cooldown_seconds: int = 20  # minimum gap between red-team scans


settings = Settings()
