import pytest
from unittest.mock import patch
from app import auth

@patch("app.auth.fetch_one")
def test_register_user_success(mock_fetch, mocker):
    """Пользователь не существует"""
    mock_fetch.return_value = None
    mocker.patch("app.auth.execute", return_value=1)
    mocker.patch("app.auth.log_event")
    user_id = auth.register_user("testuser", "password123")
    assert user_id == 1

def test_register_user_invalid_username():
    """Слишком короткий логин"""
    with pytest.raises(ValueError, match="Username должен быть 3–50 символов."):
        auth.register_user("ab", "password123")

def test_register_user_short_password():
    """Слишком короткий пароль"""
    with pytest.raises(ValueError, match="Пароль должен быть не короче 8 символов."):
        auth.register_user("testuser", "short")

@patch("app.auth.fetch_one")
def test_register_user_already_exists(mock_fetch):
    """Пользователь уже есть в БД"""
    mock_fetch.return_value = {"id": 1}
    with pytest.raises(ValueError, match="Пользователь уже существует."):
        auth.register_user("testuser", "password123")

@patch("app.auth._get_ip_attempts_in_window")
def test_authenticate_rate_limit(mock_attempts):
    """Превышен лимит попыток (CWE-307)"""
    mock_attempts.return_value = auth.MAX_ATTEMPTS_PER_IP
    with pytest.raises(auth.RateLimitError, match="Слишком много попыток входа."):
        auth.authenticate("testuser", "password", "127.0.0.1")

@patch("app.auth.fetch_one")
def test_authenticate_non_existent_user(mock_fetch, mocker):
    """Пользователь не найден"""
    mock_fetch.return_value = None
    mocker.patch("app.auth.bcrypt.hashpw")  # Мок фиктивного хеширования
    mocker.patch("app.auth._write_failed_attempt")
    
    with pytest.raises(auth.AuthError, match="Неверное имя пользователя или пароль."):
        auth.authenticate("nobody", "password", "127.0.0.1")