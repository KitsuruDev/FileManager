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


def _get_user_folder(user_id: int) -> Path:
    """
    Домашняя директория пользователя: /storage/users/<user_id>/
    Создаётся при первом обращении.
    """
    user_folder = (STORAGE_ROOT / "users" / str(user_id)).resolve()
    user_folder.mkdir(parents=True, exist_ok=True)
    return user_folder


# Диски
def get_list_disks() -> list[dict]:
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
def _get_safe_path(user_id: int, path: str) -> Path:
    """
    Приводит пользовательский путь к абсолютному внутри домашней директории
    пользователя. Бросает ValueError, если путь выходит за её пределы.
    """

    # Убираем ведущие слеши: "/docs/x.txt" и "docs/x.txt" - одно и то же.
    # Иначе Path(user_folder) / "/docs/x.txt" даст абсолютный "/docs/x.txt" (POSIX),
    # и проверка is_relative_to справедливо отбросит запрос.
    path = path.strip().lstrip("/")

    if not path:
        raise ValueError("Пустой путь.")

    user_folder = _get_user_folder(user_id)
    candidate = (user_folder / path).resolve()

    # Защита от ../../ и от симлинков наружу
    if not candidate.is_relative_to(user_folder):
        raise ValueError("Путь выходит за пределы хранилища.")

    return candidate


# Контроль доступа (CWE-639)
def _get_owned_file_id(user_id: int, path: Path) -> int | None:
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
def create_file(user_id: int, path: str, content: bytes) -> int:
    """
    Создание файла. Фиксирует событие create.

    Порядок операций:
      1. Запись файла на диск (легко откатить через unlink).
      2. В одной транзакции: INSERT в files + INSERT в operations (log_event)
      3. Если БД упала, то удаляет файл с диска.
    """

    path = _get_safe_path(user_id, path)
    path.parent.mkdir(parents=True, exist_ok=True)

    if path.exists():
        raise FileExistsError(f"Файл уже существует: {path}")

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

            log_event(
                user_id, file_id, "create",
                f"Создан файл {path} ({len(content)} байт)",
                cur=cur
            )
    except Exception:
        # 3. Компенсация: если БД не сохранила запись, файл на диске не нужен
        path.unlink(missing_ok=True)
        raise

    return file_id


def read_file(user_id: int, path: str) -> bytes:
    """Чтение файла. Фиксирует событие read"""

    path = _get_safe_path(user_id, path)
    if not path.is_file():
        raise FileNotFoundError(path)

    # Проверяем, что файл принадлежит пользователю
    file_id = _get_owned_file_id(user_id, path)
    if file_id is None:
        raise FileNotFoundError(path)

    data = path.read_bytes()

    log_event(
        user_id, file_id, "read",
        f"Прочитан файл {path} ({len(data)} байт)"
    )

    return data


def update_file(user_id: int, path: str, content: bytes) -> None:
    """
    Перезапись файла. Фиксирует modify.
    
    При сбое БД восстанавливает прежнее содержимое файла.
    """

    path = _get_safe_path(user_id, path)
    if not path.is_file():
        raise FileNotFoundError(path)

    file_id = _get_owned_file_id(user_id, path)
    if file_id is None:
        raise FileNotFoundError(path)

    # запоминание старого содержимого для отката
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
            log_event(
                user_id, file_id, "modify",
                f"Изменён файл {path} ({len(content)} байт)",
                cur=cur
            )
    except Exception:
        # 3. Компенсация: возврат прежнего содержимого
        path.write_bytes(old_content)
        raise


def delete_file(user_id: int, path: str) -> None:
    """
    Удаление файла и записи из БД. Фиксирует delete.

    При сбое БД восстанавливает удалённый файл из памяти.

    
    """

    path = _get_safe_path(user_id, path)
    if not path.is_file():
        raise FileNotFoundError(path)

    file_id = _get_owned_file_id(user_id, path)
    if file_id is None:
        raise FileNotFoundError(path)

    # Запоминаем содержимое - понадобится для отката
    old_content = path.read_bytes()

    # 1. Диск
    path.unlink()

    # 2. БД в одной транзакции: DELETE files + INSERT operations
    try:
        with transaction() as cur:
            cur.execute("DELETE FROM files WHERE id = %s", (file_id,))

            # Вызывается с file_id=None, потому что строка в files уже удалена.
            # Ключ связывает таблицы operations и files по file_id и id.
            # Он не пропустит ссылку на несуществующий id, поэтому None.
            log_event(
                user_id, None, "delete",
                f"Удалён файл {path}",
                cur=cur
            )
    except Exception:
        # 3. Компенсация: восстановление файла
        path.write_bytes(old_content)
        raise


def get_list_files(user_id: int) -> list[dict]:
    """
    Все файлы пользователя.
    Возвращает относительный путь от корня пользователя, сортирует по алфавиту.
    """

    rows = fetch_all(
        "SELECT id, filename, created_at, size, location "
        "FROM files WHERE owner_id = %s",
        (user_id,),
    )

    user_folder = _get_user_folder(user_id)
    for r in rows:
        try:
            # для каждой строки из БД вычисляется путь относительно домашней директории пользователя
            r["path"] = str(Path(r["location"]).relative_to(user_folder))
        except ValueError:
            # если пути нет (очень редкие случаи)
            r["path"] = r["filename"]

    rows.sort(key=lambda r: r["path"].lower())
    return rows