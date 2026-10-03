"""
Работа с PostgreSQL
Все запросы параметризованные -> защита от SQL-инъекций (CWE-89)
"""

import os, contextlib, psycopg2, psycopg2.extras
from dotenv import load_dotenv, find_dotenv

# .env лежит в api/.env; find_dotenv() найдёт его при локальном запуске,
# в контейнере переменные и так приходят из docker-compose (env_file)
load_dotenv(find_dotenv())


DB_CONFIG = {
    "host":     os.getenv("DB_HOST", "127.0.0.1"),
    "port":     int(os.getenv("DB_PORT", 5432)),
    "dbname":   os.getenv("DB_NAME", "filemanager"),
    "user":     os.getenv("DB_USER", "fm_user"),
    "password": os.getenv("DB_PASSWORD", "fm_password"),
}


@contextlib.contextmanager
def get_conn():
    """Контекстный менеджер: соединение + транзакция + закрытие"""
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


@contextlib.contextmanager
def transaction():
    """
    Контекстный менеджер для нескольких операций в одной транзакции.
    Отдаёт курсор; коммит — при успехе, откат — при исключении.
    """
    conn = psycopg2.connect(**DB_CONFIG)
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def fetch_one(query: str, params: tuple = ()) -> dict | None:
    """Одна строка как dict. Всегда через параметры"""
    with get_conn() as conn, conn.cursor(
        cursor_factory=psycopg2.extras.RealDictCursor
    ) as cur:
        cur.execute(query, params)
        row = cur.fetchone()
        return dict(row) if row else None


def fetch_all(query: str, params: tuple = ()) -> list[dict]:
    """Все строки как список dict"""
    with get_conn() as conn, conn.cursor(
        cursor_factory=psycopg2.extras.RealDictCursor
    ) as cur:
        cur.execute(query, params)
        return [dict(r) for r in cur.fetchall()]


def execute(query: str, params: tuple = ()) -> int | None:
    """INSERT/UPDATE/DELETE. Возвращает id новой строки, если был RETURNING"""
    with get_conn() as conn, conn.cursor() as cur:
        cur.execute(query, params)
        if cur.description: # был RETURNING
            return cur.fetchone()[0]
        return None