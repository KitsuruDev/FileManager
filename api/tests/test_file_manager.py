import pytest
from pathlib import Path
from app.file_manager import _get_safe_path, _get_user_folder

def test_safe_path_valid(temp_storage_root):
    """Обычный путь внутри хранилища"""
    path = _get_safe_path(1, "docs/note.txt")
    expected = temp_storage_root / "users" / "1" / "docs" / "note.txt"
    assert path == expected.resolve()

def test_safe_path_with_leading_slash(temp_storage_root):
    """Ведущий слеш в пути внутри хранилища"""
    path = _get_safe_path(1, "/docs/note.txt")
    expected = temp_storage_root / "users" / "1" / "docs" / "note.txt"
    assert path == expected.resolve()

def test_safe_path_traversal_blocked(temp_storage_root):
    """Попытка выйти за пределы домашней директории (CWE-22)"""
    with pytest.raises(ValueError, match="Путь выходит за пределы хранилища."):
        _get_safe_path(1, "../../etc/passwd")

def test_safe_path_empty():
    """Пустой путь"""
    with pytest.raises(ValueError, match="Пустой путь."):
        _get_safe_path(1, "")