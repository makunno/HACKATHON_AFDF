"""API module - FastAPI server"""
from entropyguard.api.main import app
from entropyguard.api.routes import router

__all__ = ["app", "router"]
