from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import HTTPBasicCredentials
from fastapi.responses import HTMLResponse, JSONResponse
import secrets
import sqlite3
from typing import Dict, List
from enum import Enum

from config import settings
from database import init_database, get_db_connection
from models import User, UserInDB, UserRegister, TodoCreate, TodoUpdate, TodoResponse
from auth import (
    authenticate_user, get_password_hash, verify_password, 
    create_jwt_token, verify_jwt_token, fake_users_db, security_basic
)
from rate_limiter import limiter, setup_rate_limiter

# Инициализация приложения
app = FastAPI(title="Auth API")

# Настройка rate limiter
setup_rate_limiter(app)

# Инициализация базы данных при запуске
@app.on_event("startup")
async def startup_event():
    init_database()

# ============= ЗАДАНИЕ 6.1 =============
@app.get("/login_basic")
async def login_basic(user: UserInDB = Depends(authenticate_user)):
    """
    Защищенная базовая аутентификация
    GET /login_basic - требует Basic Auth
    """
    return {"message": "You got my secret, welcome"}

# ============= ЗАДАНИЕ 6.2 =============
@app.post("/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("1/minute")
async def register_user(request: Request, user: User):
    """
    Регистрация нового пользователя
    POST /register
    """
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )
    
    hashed_password = get_password_hash(user.password)
    user_in_db = UserInDB(username=user.username, hashed_password=hashed_password)
    fake_users_db[user.username] = user_in_db
    
    return {"message": "New user created"}

@app.get("/login")
async def login(user: UserInDB = Depends(authenticate_user)):
    """
    Логин с базовой аутентификацией
    GET /login
    """
    return {"message": f"Welcome, {user.username}!"}

# ============= ЗАДАНИЕ 6.3 =============
def get_docs_auth(credentials: HTTPBasicCredentials = Depends(security_basic)):
    """
    Аутентификация для документации в DEV режиме
    """
    correct_username = secrets.compare_digest(credentials.username, settings.DOCS_USER)
    correct_password = secrets.compare_digest(credentials.password, settings.DOCS_PASSWORD)
    
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return True

# Настройка документации в зависимости от режима
if settings.MODE == "PROD":
    app.docs_url = None
    app.redoc_url = None
    app.openapi_url = None
elif settings.MODE == "DEV":
    @app.get("/docs", include_in_schema=False)
    async def get_docs(auth: bool = Depends(get_docs_auth)):
        return HTMLResponse(content=app.openapi_html(), status_code=200)
    
    @app.get("/openapi.json", include_in_schema=False)
    async def get_openapi(auth: bool = Depends(get_docs_auth)):
        return JSONResponse(content=app.openapi())
else:
    raise ValueError(f"Invalid MODE: {settings.MODE}. Must be DEV or PROD")

# ============= ЗАДАНИЯ 6.4 и 6.5 =============
fake_jwt_users_db: Dict[str, str] = {}

@app.post("/jwt/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("1/minute")
async def jwt_register(request: Request, user: User):
    """
    Регистрация для JWT аутентификации
    """
    if user.username in fake_jwt_users_db:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User already exists"
        )
    
    hashed_password = get_password_hash(user.password)
    fake_jwt_users_db[user.username] = hashed_password
    
    return {"message": "New user created"}

@app.post("/jwt/login")
@limiter.limit("5/minute")
async def jwt_login(request: Request, user: User):
    """
    Логин с получением JWT токена
    """
    if user.username not in fake_jwt_users_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    stored_hash = fake_jwt_users_db[user.username]
    
    if not verify_password(user.password, stored_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization failed"
        )
    
    access_token = create_jwt_token(user.username)
    
    return {
        "access_token": access_token,
        "token_type": "bearer"
    }

@app.get("/protected_resource")
async def protected_resource(username: str = Depends(verify_jwt_token)):
    """
    Защищенный ресурс с JWT аутентификацией
    """
    return {"message": "Access granted"}

# ============= ЗАДАНИЕ 7.1 =============
class UserRole(str, Enum):
    ADMIN = "admin"
    USER = "user"
    GUEST = "guest"

users_with_roles: Dict[str, Dict] = {}

def get_current_user_role(username: str) -> UserRole:
    """Получение роли пользователя"""
    if username in users_with_roles:
        return users_with_roles[username]["role"]
    return UserRole.GUEST

def require_role(required_roles: List[UserRole]):
    """Декоратор для проверки ролей"""
    async def role_checker(username: str = Depends(verify_jwt_token)):
        user_role = get_current_user_role(username)
        if user_role not in required_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Required roles: {[r.value for r in required_roles]}"
            )
        return username
    return role_checker

@app.post("/rbac/register")
async def rbac_register(user: User, role: UserRole = UserRole.USER):
    """Регистрация с указанием роли"""
    if user.username in users_with_roles:
        raise HTTPException(status_code=409, detail="User already exists")
    
    hashed_password = get_password_hash(user.password)
    users_with_roles[user.username] = {
        "password": hashed_password,
        "role": role
    }
    return {"message": f"User {user.username} registered with role {role.value}"}

@app.post("/rbac/login")
async def rbac_login(user: User):
    """Логин для RBAC"""
    if user.username not in users_with_roles:
        raise HTTPException(status_code=404, detail="User not found")
    
    stored_user = users_with_roles[user.username]
    if not verify_password(user.password, stored_user["password"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    token = create_jwt_token(user.username)
    return {"access_token": token, "token_type": "bearer"}

@app.get("/rbac/public")
async def public_resource():
    """Доступ для всех (включая гостей)"""
    return {"message": "Public resource - accessible by everyone"}

@app.get("/rbac/user_resource")
async def user_resource(username: str = Depends(require_role([UserRole.USER, UserRole.ADMIN]))):
    """Доступ только для пользователей и администраторов"""
    return {"message": f"User resource - accessible by {username}"}

@app.put("/rbac/user_resource/{item_id}")
async def update_user_resource(item_id: int, username: str = Depends(require_role([UserRole.USER, UserRole.ADMIN]))):
    """Обновление ресурса - для пользователей и администраторов"""
    return {"message": f"Resource {item_id} updated by {username}"}

@app.post("/rbac/admin_resource")
async def create_admin_resource(username: str = Depends(require_role([UserRole.ADMIN]))):
    """Создание ресурса - только для администраторов"""
    return {"message": f"Admin resource created by {username}"}

@app.delete("/rbac/admin_resource/{item_id}")
async def delete_admin_resource(item_id: int, username: str = Depends(require_role([UserRole.ADMIN]))):
    """Удаление ресурса - только для администраторов"""
    return {"message": f"Resource {item_id} deleted by {username}"}

@app.get("/rbac/protected_resource")
async def rbac_protected_resource(username: str = Depends(require_role([UserRole.USER, UserRole.ADMIN]))):
    """Защищенный ресурс - только для аутентифицированных пользователей"""
    return {"message": f"Protected resource accessed by {username}"}

# ============= ЗАДАНИЕ 8.1 =============
@app.post("/db/register", status_code=status.HTTP_201_CREATED)
async def db_register(user: UserRegister):
    """
    Регистрация с сохранением в SQLite
    POST /db/register
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (user.username, user.password)
            )
            conn.commit()
        return {"message": "User registered successfully!"}
    except sqlite3.IntegrityError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username already exists"
        )

# ============= ЗАДАНИЕ 8.2 =============
@app.post("/todos", status_code=status.HTTP_201_CREATED, response_model=TodoResponse)
async def create_todo(todo: TodoCreate):
    """Создание нового Todo"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO todos (title, description, completed) VALUES (?, ?, ?)",
            (todo.title, todo.description, False)
        )
        conn.commit()
        
        todo_id = cursor.lastrowid
        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()
        
        return TodoResponse(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            completed=bool(row["completed"])
        )

@app.get("/todos/{todo_id}", response_model=TodoResponse)
async def get_todo(todo_id: int):
    """Получение Todo по ID"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()
        
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Todo not found"
            )
        
        return TodoResponse(
            id=row["id"],
            title=row["title"],
            description=row["description"],
            completed=bool(row["completed"])
        )

@app.put("/todos/{todo_id}", response_model=TodoResponse)
async def update_todo(todo_id: int, todo_update: TodoUpdate):
    """Обновление Todo"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()
        
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Todo not found"
            )
        
        updated_title = todo_update.title if todo_update.title is not None else row["title"]
        updated_description = todo_update.description if todo_update.description is not None else row["description"]
        updated_completed = todo_update.completed if todo_update.completed is not None else row["completed"]
        
        cursor.execute(
            "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
            (updated_title, updated_description, updated_completed, todo_id)
        )
        conn.commit()
        
        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        updated_row = cursor.fetchone()
        
        return TodoResponse(
            id=updated_row["id"],
            title=updated_row["title"],
            description=updated_row["description"],
            completed=bool(updated_row["completed"])
        )

@app.delete("/todos/{todo_id}")
async def delete_todo(todo_id: int):
    """Удаление Todo"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM todos WHERE id = ?", (todo_id,))
        row = cursor.fetchone()
        
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Todo not found"
            )
        
        cursor.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
        conn.commit()
        
        return {"message": "Todo deleted successfully"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)