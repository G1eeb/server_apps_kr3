from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from passlib.context import CryptContext
import secrets
import jwt
from datetime import datetime, timedelta
from typing import Optional, Dict
from config import settings
from models import UserInDB

# Настройка хеширования паролей (задание 6.2)
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Настройка security
security_basic = HTTPBasic()
security_bearer = HTTPBearer(auto_error=False)

# In-memory база данных (задания 6.1-6.2)
fake_users_db: Dict[str, UserInDB] = {}

def get_password_hash(password: str) -> str:
    """Хеширование пароля"""
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Проверка пароля"""
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security_basic)) -> UserInDB:
    """
    Зависимость для аутентификации пользователя (задания 6.1-6.2)
    """
    username = credentials.username
    password = credentials.password
    
    # Защита от тайминг-атак для поиска пользователя
    user = None
    for stored_username, stored_user in fake_users_db.items():
        if secrets.compare_digest(stored_username, username):
            user = stored_user
            break
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    if not verify_password(password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    
    return user

# JWT функции (задания 6.4-6.5)
def create_jwt_token(username: str) -> str:
    """Создание JWT токена"""
    expiration = datetime.utcnow() + timedelta(minutes=settings.JWT_EXPIRATION_MINUTES)
    payload = {
        "sub": username,
        "exp": expiration,
        "iat": datetime.utcnow()
    }
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)

def verify_jwt_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)) -> str:
    """Проверка JWT токена"""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    token = credentials.credentials
    
    try:
        payload = jwt.decode(
            token, 
            settings.JWT_SECRET_KEY, 
            algorithms=[settings.JWT_ALGORITHM]
        )
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )