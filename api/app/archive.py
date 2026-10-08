"""
Работа с ZIP-архивами.

Защиты:
  CWE-22 (zip-slip) - каждый элемент архива проверяется на выход за домашнюю директорию
  CWE-639           - архивировать можно только свои файлы
  Zip-bomb          - ограничение на общий распакованный размер

Согласованность БД и диска:
  create_zip:   если ZIP создан, но запись в files/operations не удалась -
                удаляется недописанный или "осиротевший" архив.
  extract_zip:  при сбое в середине распаковки удаляется только те файлы и каталоги,
                которые создали сами.
"""

import zipfile
from pathlib import Path
from app.file_manager import _get_safe_path, _get_user_folder, _get_owned_file_id
from app.audit import log_event
from app.db import transaction


MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024   # 100 МБ
MAX_FILES_IN_ZIP       = 1000


def _missing_parents(directory: Path, stop: Path) -> list[Path]:
    """
    Возвращает список каталогов от `stop` (исключительно) до `directory` включительно,
    которых ещё нет на диске.
    
    Порядок - от старших к младшим, чтобы их можно было создать через .mkdir() по одному.
    """

    missing: list[Path] = []
    cur = directory

    while cur != stop and cur.is_relative_to(stop):
        if cur.exists():
            break
        missing.append(cur)
        cur = cur.parent

    return list(reversed(missing))


def create_zip(user_id: int, path_zip: str, path_files: list[str]) -> int:
    """
    Создание ZIP из перечисленных файлов.

    Любая ошибка после создания zip-файла приводит к его удалению,
    чтобы не оставлять на диске битый или неотслеживаемый архив.
    """

    path_zip = _get_safe_path(user_id, path_zip)
    path_zip.parent.mkdir(parents=True, exist_ok=True)

    if path_zip.exists():
        raise FileExistsError(f"Архив уже существует: {path_zip}")

    try:
        # 1. Диск: собирается архив
        with zipfile.ZipFile(path_zip, "w", zipfile.ZIP_DEFLATED) as zf:

            for path_string in path_files:

                path_with_file = _get_safe_path(user_id, path_string)
                if not path_with_file.is_file():
                    raise FileNotFoundError(path_with_file)

                # Архивировать можно только свои файлы (CWE-639)
                if _get_owned_file_id(user_id, path_with_file) is None:
                    raise FileNotFoundError(path_with_file)
                
                # В архиве только имя файла, без ../ (CWE-22 при распаковке)
                zf.write(path_with_file, arcname=path_with_file.name)

        size = path_zip.stat().st_size

        # 2. БД: files + operations в одной транзакции
        with transaction() as cur:
            cur.execute(
                "INSERT INTO files (filename, size, location, owner_id) "
                "VALUES (%s, %s, %s, %s) RETURNING id",
                (path_zip.name, size, str(path_zip), user_id),
            )
            file_id = cur.fetchone()["id"]

            log_event(
                user_id, file_id, "zip",
                f"Создан архив {path_zip} ({size} байт) из {len(path_files)} файлов",
                cur=cur
            )

    except Exception:
        # 3. Компенсация: удаление недописанного или осиротевшего архива
        path_zip.unlink(missing_ok=True)
        raise

    return file_id


def extract_zip(user_id: int, path_zip: str, target_dir: str) -> list[str]:
    """
    Безопасная распаковка ZIP.
    Каждый элемент архива проверяется на выход за домашнюю директорию (CWE-22).
    Ограничивается общий распакованный размер (zip-bomb).

    При сбое в середине распаковки удаляется только то, что создалось при распаковке:
      - новые файлы
      - новые каталоги
    Существовавшие ранее файлы остаются - их прежнее содержимое восстановить нельзя
    """
    path_zip = _get_safe_path(user_id, path_zip)
    if not path_zip.is_file():
        raise FileNotFoundError(path_zip)

    target_path = _get_safe_path(user_id, target_dir)
    target_path.mkdir(parents=True, exist_ok=True)

    user_folder = _get_user_folder(user_id)

    # финальный набор относительных путей к файлам, которые были распакованы успешно
    extracted: list[str] = []

    # файлы и директории для очистки во время отката, если распаковка упадёт с ошибкой
    created_files: list[Path] = []
    created_dirs:  list[Path] = []

    # общий вес
    total_uncompressed = 0

    try:
        with zipfile.ZipFile(path_zip, "r") as zf:

            info_all_files = zf.infolist()
            if len(info_all_files) > MAX_FILES_IN_ZIP:
                raise ValueError(f"В архиве больше {MAX_FILES_IN_ZIP} файлов.")

            for info_file in info_all_files:

                # zip-slip: имя элемента может содержать ../
                target_file = (target_path / info_file.filename).resolve() # превращение в абсолютный путь
                if not target_file.is_relative_to(user_folder):
                    raise ValueError(f"Небезопасный путь в архиве: {info_file.filename}")

                total_uncompressed += info_file.file_size
                if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
                    raise ValueError("Превышен лимит распакованных данных.")

                # создание родительских каталогов и запоминание только новых,
                # чтобы при откате не снести чужие папки
                for parent in _missing_parents(target_file.parent, target_path):
                    parent.mkdir()
                    created_dirs.append(parent)

                if not target_file.exists():
                    # будет создан автоматически при записи байт, поэтому только добавление в список отката
                    created_files.append(target_file)

                # Ручная запись байт - гарантируется, что данные уйдут в проверенный target_file
                with zf.open(info_file) as path_file, open(target_file, "wb") as out:
                    while chunk := path_file.read(8192):
                        out.write(chunk)
 
                extracted.append(str(target_file.relative_to(user_folder))) # относительный путь

    except Exception:
        # Компенсация: удаление созданных файлов и директорий
        for f in reversed(created_files):
            f.unlink(missing_ok=True)
        for d in reversed(created_dirs):
            try:
                d.rmdir() # сработает только если каталог пуст
            except OSError:
                pass
        raise

    log_event(
        user_id, None, "unzip",
        f"Распакован {path_zip} в {target_dir} ({len(extracted)} файлов)"
    )

    return extracted