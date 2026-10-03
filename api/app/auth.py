"""
Аутентификация пользователей.

Защиты:
  CWE-916  — bcrypt cost 12 вместо MD5/SHA1
  CWE-307  — счётчик неудач + блокировка аккаунта
  CWE-204  — единое сообщение об ошибке
"""

import time, secrets, bcrypt
from app.db import fetch_one, execute
from app.audit import log_event


# ---- Параметры аутентификации ----
BCRYPT_ROUNDS   = 12
MAX_FAILED      = 5
LOCKOUT_SECONDS = 300

# ---- Параметры сессий ----
SESSION_TTL_MIN = 60


class AuthError(Exception):
    """Общая ошибка аутентификации. Не раскрывает деталей (CWE-209)."""


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


def _is_locked(row: dict) -> tuple[bool, int]:
    locked_until = row.get("locked_until")
    if locked_until and locked_until.timestamp() > time.time():
        return True, int(locked_until.timestamp() - time.time())
    return False, 0


def _register_failure(user_id: int, current_failed: int) -> None:
    new_failed = current_failed + 1
    if new_failed >= MAX_FAILED:
        execute(
            "UPDATE users SET failed_count = %s, "
            "locked_until = NOW() + INTERVAL '%s seconds' "
            "WHERE id = %s",
            (new_failed, LOCKOUT_SECONDS, user_id),
        )
    else:
        execute(
            "UPDATE users SET failed_count = %s WHERE id = %s",
            (new_failed, user_id),
        )


def authenticate(username: str, password: str) -> dict:
    """
    Проверка пары логин/пароль.
    Возвращает строку пользователя (dict) или бросает AuthError.
    """
    username = username.strip().lower()
    
    row = fetch_one(
        "SELECT id, username, password_hash, failed_count, locked_until "
        "FROM users WHERE username = %s",
        (username,),
    )

    # Даже если пользователя нет — считаем bcrypt-хеш фиктивно,
    # чтобы выровнять время ответа (CWE-204, CWE-208).
    if row is None:
        bcrypt.hashpw(b"dummy", bcrypt.gensalt(rounds=BCRYPT_ROUNDS))
        raise AuthError("Неверное имя пользователя или пароль.")

    locked, remaining = _is_locked(row)
    if locked:
        raise AuthError(f"Аккаунт заблокирован. Повторите через {remaining} с.")

    if not bcrypt.checkpw(password.encode("utf-8"),
                          row["password_hash"].encode("utf-8")):
        _register_failure(row["id"], row["failed_count"])
        raise AuthError("Неверное имя пользователя или пароль.")

    # Успех — сбрасываем счётчики
    execute(
        "UPDATE users SET failed_count = 0, locked_until = NULL WHERE id = %s",
        (row["id"],),
    )
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