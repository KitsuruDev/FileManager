import pytest, os, sys, shutil, tempfile
from pathlib import Path

# добавление корневой папки api в sys.path, чтобы pytest находил модуль app
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

@pytest.fixture
def temp_storage_root(monkeypatch):
    """Создание временной директории для тестов файловой системы."""
    temp_dir = tempfile.mkdtemp()
    # подмена STORAGE_ROOT в модуле file_manager
    monkeypatch.setattr("app.file_manager.STORAGE_ROOT", Path(temp_dir).resolve())
    yield Path(temp_dir).resolve()
    shutil.rmtree(temp_dir)