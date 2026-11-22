import pytest

from footprintx.core.config import Settings


@pytest.fixture
def settings() -> Settings:
    """Built-in defaults, independent of config/config.yaml."""
    return Settings()
