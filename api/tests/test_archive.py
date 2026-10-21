import pytest, zipfile
from app.archive import extract_zip, _require_zip_extension

def test_require_zip_extension_valid():
    """Валидация верного zip"""
    _require_zip_extension("backup.zip")

def test_require_zip_extension_invalid():
    """Валидация неверного zip"""
    with pytest.raises(ValueError, match="Архив должен иметь расширение .zip."):
        _require_zip_extension("backup.txt")

def test_extract_zip_slip_blocked(temp_storage_root, mocker):
    """Зловредный zip с zip-slip (CWE-22)"""
    user_id = 1
    zip_path = temp_storage_root / "users" / str(user_id) / "evil.zip"
    zip_path.parent.mkdir(parents=True)
    
    with zipfile.ZipFile(zip_path, "w") as zf:
        # попытка записать файл за пределы разрешенной директории
        zf.writestr("../../etc/hacked.txt", "evil content")

    # мокаем проверку прав на файл, чтобы она не мешала тесту zip-slip
    mocker.patch("app.archive._get_owned_file_id", return_value=1)

    with pytest.raises(ValueError, match="Небезопасный путь в архиве:"):
        extract_zip(user_id, "evil.zip", "extracted")