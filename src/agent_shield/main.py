"""ASGI entry point: `uvicorn agent_shield.main:app`."""

from .api import create_app

app = create_app()
