from slowapi import Limiter
from slowapi.util import get_remote_address
from fastapi import FastAPI

# Настройка rate limiter (задание 6.5)
limiter = Limiter(key_func=get_remote_address)

def setup_rate_limiter(app: FastAPI):
    """Настройка rate limiter для приложения"""
    app.state.limiter = limiter