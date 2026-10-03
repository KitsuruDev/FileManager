"""
Работа с ZIP-архивами.

Защиты:
  CWE-22 (zip-slip) - каждый элемент архива проверяется на выход за домашнюю директорию
  CWE-639           - архивировать можно только свои файлы
  Zip-bomb          - ограничение на общий распакованный размер

Согласованность БД и диска:
  create_zip:   если ZIP создан, но запись в files/operations не удалась -
                удаляем недописанный или "осиротевший" архив.
  extract_zip:  при сбое в середине распаковки удаляем только те файлы
                и каталоги, которые создали сами.
"""

import zipfile
from pathlib import Path
from app.file_manager import _safe_path, _user_root, _owned_file_id
from app.audit import log_event
from app.db import transaction


MAX_TOTAL_UNCOMPRESSED = 100 * 1024 * 1024   # 100 МБ
MAX_FILES_IN_ZIP       = 1000


def create_zip(user_id: int, relative_zip: str, relative_files: list[str]) -> int:
    """
    Создание ZIP из перечисленных файлов.

    Любая ошибка после создания zip-файла приводит к его удалению,
    чтобы не оставлять на диске битый или неотслеживаемый архив.
    """

    zip_path = _safe_path(user_id, relative_zip)
    zip_path.parent.mkdir(parents=True, exist_ok=True)

    if zip_path.exists():
        raise FileExistsError(f"Архив уже существует: {relative_zip}")

    try:
        # 1. Диск: собираем архив
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for rel in relative_files:
                src = _safe_path(user_id, rel)
                if not src.is_file():
                    raise FileNotFoundError(rel)
                # Архивировать можно только свои файлы (CWE-639)
                if _owned_file_id(user_id, src) is None:
                    raise FileNotFoundError(rel)
                # В архиве только имя файла, без ../ (CWE-22 при распаковке)
                zf.write(src, arcname=src.name)

        size = zip_path.stat().st_size

        # 2. БД: files + operations в одной транзакции
        with transaction() as cur:
            cur.execute(
                "INSERT INTO files (filename, size, location, owner_id) "
                "VALUES (%s, %s, %s, %s) RETURNING id",
                (zip_path.name, size, str(zip_path), user_id),
            )
            file_id = cur.fetchone()["id"]

            log_event(user_id, file_id, "zip",
                      f"Создан архив {relative_zip} ({size} байт) "
                      f"из {len(relative_files)} файлов",
                      cur=cur)

    except Exception:
        # 3. Компенсация: удаляем недописанный или осиротевший архив
        zip_path.unlink(missing_ok=True)
        raise

    return file_id


def extract_zip(user_id: int, relative_zip: str, target_dir: str) -> list[str]:
    """
    Безопасная распаковка ZIP.
    Каждый элемент архива проверяется на выход за домашнюю директорию (CWE-22).
    Ограничивается общий распакованный размер (zip-bomb).

    При сбое в середине распаковки удаляем только то, что создали сами:
      - новые файлы
      - новые каталоги
    Существовавшие ранее файлы оставляем - их прежнее содержимое
    восстановить нельзя, это известное ограничение компенсации.
    """
    zip_path = _safe_path(user_id, relative_zip)
    if not zip_path.is_file():
        raise FileNotFoundError(relative_zip)

    target = _safe_path(user_id, target_dir)
    target.mkdir(parents=True, exist_ok=True)

    user_root = _user_root(user_id)

    extracted: list[str] = []
    created_files: list[Path] = []
    created_dirs:  list[Path] = []

    total_uncompressed = 0

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            infos = zf.infolist()
            if len(infos) > MAX_FILES_IN_ZIP:
                raise ValueError(f"В архиве больше {MAX_FILES_IN_ZIP} файлов.")

            for info in infos:
                # zip-slip: имя элемента может содержать ../
                dest = (target / info.filename).resolve()
                if not dest.is_relative_to(user_root):
                    raise ValueError(f"Небезопасный путь в архиве: {info.filename}")

                total_uncompressed += info.file_size
                if total_uncompressed > MAX_TOTAL_UNCOMPRESSED:
                    raise ValueError("Превышен лимит распакованных данных.")

                # Создаём родительские каталоги и запоминаем только новые -
                # чтобы при откате не снести чужие папки
                for parent in _missing_parents(dest.parent, target):
                    parent.mkdir()
                    created_dirs.append(parent)

                was_existing = dest.exists()

                # Ручная запись байт - гарантируем, что данные уйдут
                # ровно в проверенный dest
                with zf.open(info) as src, open(dest, "wb") as out:
                    while chunk := src.read(8192):
                        out.write(chunk)

                if not was_existing:
                    created_files.append(dest)

                extracted.append(str(dest.relative_to(user_root)))

    except Exception:
        # Компенсация: удаляем созданные файлы, затем - созданные каталоги
        for f in reversed(created_files):
            f.unlink(missing_ok=True)
        for d in reversed(created_dirs):
            try:
                d.rmdir()          # сработает только если каталог пуст
            except OSError:
                pass
        raise

    log_event(user_id, None, "unzip",
              f"Распакован {relative_zip} в {target_dir} "
              f"({len(extracted)} файлов)")

    return extracted


def _missing_parents(directory: Path, stop: Path) -> list[Path]:
    """
    Возвращает список каталогов от `stop` (исключительно) до `directory`
    включительно, которых ещё нет на диске. Порядок - от старших к младшим,
    чтобы их можно было создать через .mkdir() по одному.
    """
    missing: list[Path] = []
    cur = directory
    while cur != stop and cur.is_relative_to(stop):
        if cur.exists():
            break
        missing.append(cur)
        cur = cur.parent
    return list(reversed(missing))