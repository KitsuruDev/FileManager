"""
Операции с файлами и дисками.

Домашние директории:
  каждый пользователь работает только внутри /storage/users/<user_id>/
  это исключает кросс-пользовательские коллизии и path traversal в чужие папки.

Защиты:
  CWE-22  - path traversal: жёсткая проверка, что путь внутри домашней директории
  CWE-59  - симлинки: resolve() + проверка префикса
  CWE-639 - контроль доступа: файл доступен только своему владельцу

Согласованность БД и диска:
  файловые операции не транзакционны, поэтому используем
  компенсирующие действия - при сбое БД откатываем изменения на диске.
"""

import os, psutil
from pathlib import Path
from app.db import execute, fetch_one, fetch_all, transaction
from app.audit import log_event


STORAGE_ROOT = Path(os.getenv("STORAGE_ROOT", "./storage")).resolve()
STORAGE_ROOT.mkdir(parents=True, exist_ok=True)


def _user_root(user_id: int) -> Path:
    """
    Домашняя директория пользователя: /storage/users/<user_id>/
    Создаётся при первом обращении.
    """
    root = (STORAGE_ROOT / "users" / str(user_id)).resolve()
    root.mkdir(parents=True, exist_ok=True)
    return root


# Диски
def list_disks() -> list[dict]:
    """Список локальных накопителей и их свойства"""

    disks = []

    for part in psutil.disk_partitions(all=False):
        # Пропускаем bind-mount отдельных файлов (resolv.conf, hosts и т.п.)
        if not os.path.isdir(part.mountpoint):
            continue
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except (PermissionError, OSError):
            continue
        disks.append({
            "device":      part.device,
            "mountpoint":  part.mountpoint,
            "fstype":      part.fstype,
            "total":       usage.total,
            "used":        usage.used,
            "free":        usage.free,
            "percent":     usage.percent,
        })

    return disks


# Безопасные пути (CWE-22)
def _safe_path(user_id: int, relative: str) -> Path:
    """
    Приводит пользовательский путь к абсолютному внутри домашней директории
    пользователя. Бросает ValueError, если путь выходит за её пределы.
    """

    # Убираем ведущие слеши: "/docs/x.txt" и "docs/x.txt" - одно и то же.
    # Иначе Path(root) / "/docs/x.txt" даст абсолютный "/docs/x.txt" (POSIX),
    # и проверка is_relative_to справедливо отбросит запрос.
    relative = relative.strip().lstrip("/")

    if not relative:
        raise ValueError("Пустой путь.")

    root = _user_root(user_id)
    candidate = (root / relative).resolve()

    # Защита от ../../ и от симлинков наружу
    if not candidate.is_relative_to(root):
        raise ValueError("Путь выходит за пределы хранилища.")

    return candidate


# Контроль доступа (CWE-639)
def _owned_file_id(user_id: int, path: Path) -> int | None:
    """
    Вернуть id файла, если он принадлежит пользователю, иначе None.
    Чужой файл с точки зрения вызывающего кода неотличим от несуществующего.
    """
    row = fetch_one(
        "SELECT id FROM files WHERE location = %s AND owner_id = %s",
        (str(path), user_id),
    )
    return row["id"] if row else None


# CRUD файлов
def create_file(user_id: int, relative: str, content: bytes) -> int:
    """
    Создание файла. Фиксирует событие create.

    Порядок операций:
      1. Записать файл на диск (легко откатить через unlink).
      2. В одной транзакции: INSERT в files + INSERT в operations.
      3. Если БД упала - удалить файл с диска.
    """

    path = _safe_path(user_id, relative)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        raise FileExistsError(f"Файл уже существует: {relative}")

    # 1. Диск
    path.write_bytes(content)

    # 2. БД в одной транзакции: files + operations
    try:
        with transaction() as cur:
            cur.execute(
                "INSERT INTO files (filename, size, location, owner_id) "
                "VALUES (%s, %s, %s, %s) RETURNING id",
                (path.name, len(content), str(path), user_id),
            )
            file_id = cur.fetchone()["id"]

            log_event(user_id, file_id, "create",
                      f"Создан файл {relative} ({len(content)} байт)", cur=cur)
    except Exception:
        # 3. Компенсация: если БД не сохранила запись, файл на диске не нужен
        path.unlink(missing_ok=True)
        raise

    return file_id


def read_file(user_id: int, relative: str) -> bytes:
    """Чтение файла. Фиксирует событие read"""

    path = _safe_path(user_id, relative)
    if not path.is_file():
        raise FileNotFoundError(relative)

    # Проверяем, что файл принадлежит пользователю
    file_id = _owned_file_id(user_id, path)
    if file_id is None:
        raise FileNotFoundError(relative)

    data = path.read_bytes()

    log_event(user_id, file_id, "read",
              f"Прочитан файл {relative} ({len(data)} байт)")

    return data


def update_file(user_id: int, relative: str, content: bytes) -> None:
    """
    Перезапись файла. Фиксирует modify.

    При сбое БД восстанавливаем прежнее содержимое файла.
    """

    path = _safe_path(user_id, relative)
    if not path.is_file():
        raise FileNotFoundError(relative)

    file_id = _owned_file_id(user_id, path)
    if file_id is None:
        raise FileNotFoundError(relative)

    # Запоминаем старое содержимое - понадобится для отката
    old_content = path.read_bytes()

    # 1. Диск
    path.write_bytes(content)

    # 2. БД в одной транзакции: UPDATE files + INSERT operations
    try:
        with transaction() as cur:
            cur.execute(
                "UPDATE files SET size = %s WHERE id = %s",
                (len(content), file_id),
            )
            log_event(user_id, file_id, "modify",
                      f"Изменён файл {relative} ({len(content)} байт)", cur=cur)
    except Exception:
        # 3. Компенсация: возвращаем прежнее содержимое
        path.write_bytes(old_content)
        raise


def delete_file(user_id: int, relative: str) -> None:
    """
    Удаление файла и записи из БД. Фиксирует delete.

    При сбое БД восстанавливаем удалённый файл из памяти.

    NB: log_event вызывается с file_id=None, потому что строка в files
    уже удалена и FK-констрейнт operations.file_id -> files.id
    не пропустит ссылку на несуществующий id.
    """

    path = _safe_path(user_id, relative)
    if not path.is_file():
        raise FileNotFoundError(relative)

    file_id = _owned_file_id(user_id, path)
    if file_id is None:
        raise FileNotFoundError(relative)

    # Запоминаем содержимое - понадобится для отката
    old_content = path.read_bytes()

    # 1. Диск
    path.unlink()

    # 2. БД в одной транзакции: DELETE files + INSERT operations
    try:
        with transaction() as cur:
            cur.execute("DELETE FROM files WHERE id = %s", (file_id,))
            log_event(user_id, None, "delete",
                      f"Удалён файл {relative}", cur=cur)
    except Exception:
        # 3. Компенсация: восстанавливаем файл
        path.write_bytes(old_content)
        raise


def list_files(user_id: int) -> list[dict]:
    """
    Все файлы пользователя.
    Возвращает относительный путь от корня пользователя, сортирует по алфавиту.
    """

    rows = fetch_all(
        "SELECT id, filename, created_at, size, location "
        "FROM files WHERE owner_id = %s",
        (user_id,),
    )

    root = _user_root(user_id)
    for r in rows:
        try:
            r["path"] = str(Path(r["location"]).relative_to(root))
        except ValueError:
            # На случай «осиротевших» записей после старых версий кода
            r["path"] = r["filename"]

    rows.sort(key=lambda r: r["path"].lower())
    return rows