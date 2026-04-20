import sqlite3
from contextlib import contextmanager

DATABASE_NAME = "todos.db"

def init_database():
    """Инициализация базы данных и создание таблиц"""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        
        # Таблица users из задания 8.1
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL
            )
        """)
        
        # Таблица todos из задания 8.2
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                completed BOOLEAN DEFAULT 0
            )
        """)
        
        conn.commit()

@contextmanager
def get_db_connection():
    """Контекстный менеджер для работы с БД"""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()