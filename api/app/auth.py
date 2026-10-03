"""
Аутентификация пользователей.

Защиты:
  CWE-916  - bcrypt cost 12 вместо MD5/SHA1
  CWE-307  - rate limit по IP (таблица login_attempts)
  CWE-204  - единое сообщение об ошибке, фиктивный bcrypt
             для несуществующих username
"""

import time, secrets, bcrypt
from app.db import fetch_one, execute
from app.audit import log_event


# ---- Параметры аутентификации ----
BCRYPT_ROUNDS = 12

# ---- Параметры rate limit (по IP) ----
MAX_ATTEMPTS_PER_IP = 5       # неудачных попыток
IP_WINDOW_SECONDS   = 300      # за 5 минут

# ---- Параметры сессий ----
SESSION_TTL_MIN = 60


class AuthError(Exception):
    """Неверные учётные данные. Единый текст - без раскрытия деталей."""


class RateLimitError(Exception):
    """Слишком много неудачных попыток с одного IP."""


# ---- Rate limit (CWE-307) ----
def _record_failed_attempt(ip: str, username: str) -> None:
    """Логирует неудачную попытку и заодно чистит старые записи."""
    execute(
        "INSERT INTO login_attempts (ip, username) VALUES (%s, %s)",
        (ip, username),
    )
    _cleanup_old_attempts()


def _ip_attempts_in_window(ip: str) -> int:
    """Сколько неудачных попыток было с этого IP за окно."""
    row = fetch_one(
        "SELECT COUNT(*) AS cnt FROM login_attempts "
        "WHERE ip = %s AND attempted_at > NOW() - INTERVAL '%s seconds'",
        (ip, IP_WINDOW_SECONDS),
    )
    return int(row["cnt"]) if row else 0


def _cleanup_old_attempts() -> None:
    """Домашняя уборка: удаляем записи старше суток."""
    execute(
        "DELETE FROM login_attempts "
        "WHERE attempted_at < NOW() - INTERVAL '1 day'"
    )


# ---- Регистрация ----
def register_user(username: str, password: str) -> int:
    """Создаёт нового пользователя."""
    username = username.strip().lower()
    if not (3 <= len(username) <= 50):
        raise ValueError("Username должен быть 3–50 символов.")
    if len(password) < 8:
        raise ValueError("Пароль должен быть не короче 8 символов.")

    existing = fetch_one("SELECT id FROM users WHERE username = %s", (username,))
    if existing:
        raise ValueError("Пользователь уже существует.")

    pw_hash = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt(rounds=BCRYPT_ROUNDS),
    ).decode("utf-8")

    user_id = execute(
        "INSERT INTO users (username, password_hash) VALUES (%s, %s) RETURNING id",
        (username, pw_hash),
    )
    log_event(user_id, None, "create", f"Пользователь {username} зарегистрирован")
    return user_id


# ---- Аутентификация ----
def authenticate(username: str, password: str, ip: str) -> dict:
    """
    Проверка пары логин/пароль с rate limit по IP.

    Возвращает dict {id, username} при успехе,
    бросает RateLimitError или AuthError.
    """

    # 1. Rate limit: сколько неудач было с этого IP за окно
    attempts = _ip_attempts_in_window(ip)
    if attempts >= MAX_ATTEMPTS_PER_IP:
        # Раскрываем только факт rate limit - не то, существует ли username.
        raise RateLimitError(
            f"Слишком много попыток входа. Повторите через "
            f"{IP_WINDOW_SECONDS // 60} мин."
        )

    # 2. Ищем пользователя
    row = fetch_one(
        "SELECT id, username, password_hash "
        "FROM users WHERE username = %s",
        (username.strip().lower(),),
    )

    # 3. Фиктивный bcrypt для несуществующих username -
    #    выравнивает время ответа (CWE-204, CWE-208)
    if row is None:
        bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
        _record_failed_attempt(ip, username)
        raise AuthError("Неверное имя пользователя или пароль.")

    # 4. Проверка пароля
    if not bcrypt.checkpw(password.encode("utf-8"),
                          row["password_hash"].encode("utf-8")):
        _record_failed_attempt(ip, username)
        raise AuthError("Неверное имя пользователя или пароль.")

    # 5. Успех
    log_event(row["id"], None, "login", f"Успешный вход {row['username']}")
    return {"id": row["id"], "username": row["username"]}


# ---- Сессии (Bearer-токены) ----
def create_session(user_id: int) -> str:
    """Выпустить bearer-токен после успешного логина."""
    token = secrets.token_urlsafe(32)
    execute(
        "INSERT INTO api_sessions (token, user_id, expires_at) "
        "VALUES (%s, %s, NOW() + INTERVAL '%s minutes')",
        (token, user_id, SESSION_TTL_MIN),
    )
    return token


def resolve_session(token: str) -> dict | None:
    """Проверить bearer-токен -> вернуть пользователя или None."""
    row = fetch_one(
        "SELECT u.id, u.username FROM api_sessions s "
        "JOIN users u ON u.id = s.user_id "
        "WHERE s.token = %s AND s.expires_at > NOW()",
        (token,),
    )
    return dict(row) if row else None


def destroy_session(token: str) -> None:
    execute("DELETE FROM api_sessions WHERE token = %s", (token,))