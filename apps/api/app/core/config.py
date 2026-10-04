from packages.config.settings import Settings, get_settings

settings: Settings = get_settings()

__all__ = ["Settings", "get_settings", "settings"]
