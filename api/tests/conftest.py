import pytest, os, shutil, tempfile
from pathlib import Path

@pytest.fixture
def temp_storage_root(monkeypatch):
    """Создание временной директории для тестов файловой системы."""
    temp_dir = tempfile.mkdtemp()
    # подмена STORAGE_ROOT в модуле file_manager
    monkeypatch.setattr("app.file_manager.STORAGE_ROOT", Path(temp_dir).resolve())
    yield Path(temp_dir).resolve()
    shutil.rmtree(temp_dir)