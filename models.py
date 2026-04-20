from pydantic import BaseModel
from typing import Optional

# Модели для заданий 6.1-6.2
class UserBase(BaseModel):
    username: str

class User(UserBase):
    password: str

class UserInDB(UserBase):
    hashed_password: str

# Модели для заданий 8.1-8.2
class UserRegister(BaseModel):
    username: str
    password: str

class TodoCreate(BaseModel):
    title: str
    description: str

class TodoUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    completed: Optional[bool] = None

class TodoResponse(BaseModel):
    id: int
    title: str
    description: str
    completed: bool