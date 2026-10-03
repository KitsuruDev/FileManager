"""
Консольный клиент файлового менеджера.
Общается с сервером по HTTPS через nginx.

Создание и загрузка файлов - с автоопределением формата по расширению:
  .json -> валидация JSON и save_json
  .xml  -> save_xml (валидация на сервере через lxml)
  иначе -> create_file (raw)
"""

import os, base64, json, requests
from getpass import getpass
from urllib.parse import quote


API_URL   = os.getenv("API_URL", "https://nginx")
CA_BUNDLE = os.getenv("CA_BUNDLE", "/certs/server.crt")

# Расширения, содержимое которых нельзя ввести текстом.
# Создать такие файлы можно только через загрузку (команда 4)
# или специализированные команды (например, ZIP через команду 8).
BINARY_EXTENSIONS = {
    ".zip", ".gz", ".tar", ".rar", ".7z", ".bz2", ".xz",
    ".pdf", ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp",
    ".exe", ".dll", ".so", ".iso", ".dylib", ".bin",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav",
    ".docx", ".xlsx", ".pptx", ".odt", ".ods",
    ".sqlite", ".db",
}


class SessionExpired(Exception):
    """Токен истёк или недействителен (HTTP 401)."""
    def __init__(self, message: str = "Сессия истекла"):
        super().__init__(message)
        self.message = message


class ApiError(Exception):
    """Прочие ошибки сервера (4xx/5xx, кроме 401)."""
    def __init__(self, code: int, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def _is_binary_extension(path: str) -> bool:
    """True, если расширение файла предполагает бинарное содержимое."""
    p = path.lower().strip()
    for ext in BINARY_EXTENSIONS:
        if p.endswith(ext):
            return True
    return False


def _ok(result: tuple[int, dict]) -> dict:
    """
    Разбирает ответ (code, data).
      2xx  -> возвращает data
      401  -> SessionExpired
      иначе -> ApiError
    """
    code, data = result
    if code == 401:
        raise SessionExpired(data.get("error", "Сессия истекла"))
    if not (200 <= code < 300):
        raise ApiError(code, data.get("error", "Неизвестная ошибка"))
    return data


def _encode_text(s: str) -> bytes:
    """
    UTF-8 с игнорированием суррогатов, которые иногда приходят
    из Windows-консоли при смене раскладки. Без этого text.encode()
    падает с UnicodeEncodeError.
    """
    return s.encode("utf-8", errors="ignore")


def _detect_format(path: str) -> str:
    """Определяет формат по расширению: 'json', 'xml' или 'raw'."""
    p = path.lower().strip()
    if p.endswith(".json"):
        return "json"
    if p.endswith(".xml"):
        return "xml"
    return "raw"


def _is_binary(data: bytes) -> bool:
    """
    Эвристика: файл считается бинарным, если в первых 8 КБ есть нулевые
    байты или содержимое не декодируется как UTF-8.
    Ловит ZIP, PDF, картинки, архивы и прочее.
    """
    sample = data[:8192]
    if b"\x00" in sample:
        return True
    try:
        sample.decode("utf-8")
        return False
    except UnicodeDecodeError:
        return True


class ApiClient:
    def __init__(self):
        self.session = requests.Session()
        self.session.verify = CA_BUNDLE   # проверяем сертификат сервера
        self.token: str | None = None

    # низкоуровневые обёртки
    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self.token}"} if self.token else {}

    def _call(self, method: str, path: str, **kw):
        url = f"{API_URL}{path}"
        headers = kw.pop("headers", {})
        headers.update(self._headers())
        kw["headers"] = headers
        kw.setdefault("timeout", 30)
        r = self.session.request(method, url, **kw)
        try:
            data = r.json()
        except ValueError:
            data = {"error": r.text[:200]}
        return r.status_code, data

    @staticmethod
    def _norm(path: str) -> str:
        """Убирает ведущие слеши из пользовательского пути."""
        return path.strip().lstrip("/")

    # публичное API
    def health(self):
        return self._call("GET", "/api/health")

    def register(self, username: str, password: str):
        return self._call("POST", "/api/register",
                          json={"username": username, "password": password})

    def login(self, username: str, password: str):
        code, data = self._call("POST", "/api/login",
                                json={"username": username, "password": password})
        if code == 200:
            self.token = data["token"]
        return code, data

    def logout(self):
        try:
            return self._call("POST", "/api/logout")
        finally:
            self.token = None

    def disks(self):
        return self._call("GET", "/api/disks")

    def files(self):
        return self._call("GET", "/api/files")

    def create_file(self, path: str, content: bytes):
        return self._call("POST", "/api/files", json={
            "path": path,
            "content_b64": base64.b64encode(content).decode(),
        })

    def read_file(self, path: str) -> tuple[int, dict]:
        rel = quote(self._norm(path), safe="/")
        code, data = self._call("GET", f"/api/files/{rel}")
        if code == 200:
            data["content"] = base64.b64decode(data["content_b64"])
        return code, data

    def update_file(self, path: str, content: bytes):
        rel = quote(self._norm(path), safe="/")
        return self._call("PUT", f"/api/files/{rel}", json={
            "content_b64": base64.b64encode(content).decode(),
        })

    def delete_file(self, path: str):
        rel = quote(self._norm(path), safe="/")
        return self._call("DELETE", f"/api/files/{rel}")

    def save_json(self, path: str, value):
        return self._call("POST", "/api/json",
                          json={"path": path, "value": value})

    def save_xml(self, path: str, xml_text: str):
        return self._call("POST", "/api/xml",
                          json={"path": path, "xml": xml_text})

    def create_zip(self, archive: str, files: list[str]):
        return self._call("POST", "/api/zip",
                          json={"archive": archive, "files": files})

    def extract_zip(self, archive: str, target: str):
        return self._call("POST", "/api/unzip",
                          json={"archive": archive, "target": target})

    def audit(self):
        return self._call("GET", "/api/audit")


# CLI
def human_size(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PiB"


def cmd_disks(api: ApiClient, _username: str):
    data = _ok(api.disks())
    disks = data.get("disks", [])
    if not disks:
        print("  (нет доступных накопителей)")
        return
    for d in disks:
        print(f"  {d['device']} ({d['fstype']}) на {d['mountpoint']}")
        print(f"    Всего:  {human_size(d['total'])}")
        print(f"    Свободно: {human_size(d['free'])}")


def cmd_files(api: ApiClient, _username: str):
    data = _ok(api.files())
    files = data.get("files", [])
    if not files:
        print("  (пусто)")
        return
    for f in files:
        print(f"  {f['path']:<40} "
              f"{human_size(f['size']):>10}  {f['created_at']}")


def cmd_create(api: ApiClient, _username: str):
    """
    Создание файла. Формат определяется по расширению пути:
      .json -> локальная валидация JSON, save_json
      .xml  -> save_xml (валидация на сервере)
      иначе -> create_file (raw)
    """
    rel = input("Путь (например note.txt, data.json, data.xml): ").strip()
    if not rel:
        print("\n[!] Пустой путь.")
        return

    if _is_binary_extension(rel):
        print("\n[!] Нельзя создать бинарный файл из текстового ввода.")
        print("    Для этого используйте:")
        print("      - команду 4 «Загрузить файл с ПК» - если файл уже есть на хосте")
        if rel.lower().endswith(".zip"):
            print("      - команду 8 «Создать ZIP» - собрать архив из файлов на сервере")
        return

    fmt = _detect_format(rel)

    if fmt == "json":
        raw = input("JSON-строка: ")
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"\n[!] Некорректный JSON: {e}")
            return
        _ok(api.save_json(rel, obj))
        print("\n  [+] JSON создан")

    elif fmt == "xml":
        xml = input("XML (одной строкой): ")
        _ok(api.save_xml(rel, xml))
        print("\n  [+] XML создан")

    else:
        text = input("Содержимое: ")
        _ok(api.create_file(rel, _encode_text(text)))
        print("\n  [+] Файл создан")


def cmd_upload(api: ApiClient, _username: str):
    """
    Загрузка локального файла из /uploads в домашнюю директорию пользователя.
    Формат определяется по расширению удалённого пути.
    """
    local  = input("Путь к локальному файлу (например /uploads/data.json): ").strip()
    remote = input("Путь на сервере (например docs/data.json): ").strip()
    if not local or not remote:
        print("\n[!] Пустой путь.")
        return

    try:
        with open(local, "rb") as f:
            content = f.read()
    except OSError as e:
        print(f"\n[!] Не удалось прочитать {local}: {e}")
        return

    fmt = _detect_format(remote)

    if fmt == "json":
        try:
            obj = json.loads(content.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            print(f"\n[!] Файл не является корректным JSON: {e}")
            return
        _ok(api.save_json(remote, obj))
        print(f"\n  [+] JSON загружен ({len(content)} байт)")

    elif fmt == "xml":
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError as e:
            print(f"\n[!] XML должен быть в UTF-8: {e}")
            return
        _ok(api.save_xml(remote, text))
        print(f"\n  [+] XML загружен ({len(content)} байт)")

    else:
        _ok(api.create_file(remote, content))
        print(f"\n  [+] Загружено ({len(content)} байт)")


def cmd_read(api: ApiClient, _username: str):
    """Чтение файла. Бинарные файлы (ZIP, PDF и т.п.) не отображаются."""
    rel = input("Путь: ").strip()
    data = _ok(api.read_file(rel))
    content = data["content"]

    if _is_binary(content):
        print(f"\n  [двоичный файл, {len(content)} байт, не отображается]")
        return

    print(content.decode("utf-8", errors="replace"))


def cmd_update(api: ApiClient, _username: str):
    """
    Обновление файла. Формат определяется по расширению:
      .json -> валидация JSON и сериализация с indent=2
      .xml  -> raw-запись через update_file
      иначе -> raw-запись
    """
    rel = input("Путь: ").strip()
    if not rel:
        print("\n[!] Пустой путь.")
        return

    if _is_binary_extension(rel):
        print("\n[!] Нельзя перезаписать бинарный файл текстовым содержимым.")
        print("   - Для этого используйте команду 4 «Загрузить файл с ПК».")
        return

    fmt = _detect_format(rel)

    if fmt == "json":
        raw = input("Новое JSON-содержимое: ")
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError as e:
            print(f"\n[!] Некорректный JSON: {e}")
            return
        text = json.dumps(obj, ensure_ascii=False, indent=2)
        _ok(api.update_file(rel, _encode_text(text)))
        print("\n  [+] JSON обновлён")

    elif fmt == "xml":
        xml = input("Новое XML-содержимое: ")
        _ok(api.update_file(rel, _encode_text(xml)))
        print("\n  [+] XML обновлён")

    else:
        text = input("Новое содержимое: ")
        _ok(api.update_file(rel, _encode_text(text)))
        print("\n  [+] Обновлено")


def cmd_delete(api: ApiClient, _username: str):
    rel = input("Путь: ").strip()
    _ok(api.delete_file(rel))
    print("\n  [+] Удалено")


def cmd_create_zip(api: ApiClient, _username: str):
    archive = input("Путь к архиву (например backup.zip): ").strip()
    files_s = input("Файлы через запятую: ")
    files = [f.strip() for f in files_s.split(",") if f.strip()]
    _ok(api.create_zip(archive, files))
    print("\n  [+] Архив создан")


def cmd_extract_zip(api: ApiClient, _username: str):
    archive = input("Путь к архиву: ").strip()
    target  = input("Куда распаковать: ").strip()
    data = _ok(api.extract_zip(archive, target))
    print(f"\n  [+] Распаковано файлов: {len(data.get('files', []))}")


def cmd_audit(api: ApiClient, _username: str):
    data = _ok(api.audit())
    ops = data.get("operations", [])
    if not ops:
        print("  (журнал пуст)")
        return
    for r in ops:
        ts = r.get("timestamp") or "-"
        who = r.get("username") or "?"
        op = r.get("operation_type", "?")
        details = r.get("details", "")
        print(f"  {ts}  {who:<10}  {op:<8}  {details}")


MENU = {
    "1":  ("Список дисков",        cmd_disks),
    "2":  ("Мои файлы",            cmd_files),
    "3":  ("Создать файл",         cmd_create),
    "4":  ("Загрузить файл с ПК",  cmd_upload),
    "5":  ("Прочитать файл",       cmd_read),
    "6":  ("Обновить файл",        cmd_update),
    "7":  ("Удалить файл",         cmd_delete),
    "8":  ("Создать ZIP",          cmd_create_zip),
    "9":  ("Распаковать ZIP",      cmd_extract_zip),
    "10": ("Журнал аудита",        cmd_audit),
    "0":  ("Выход",                None),
}


def menu(api: ApiClient, username: str):
    while True:
        print(f"\n--- Доступные команды ---")
        for key, (label, _) in MENU.items():
            print(f"  {key}. {label}")
        choice = input("\nВыберите команду: ").strip()

        if choice == "0":
            api.logout()
            return

        entry = MENU.get(choice)
        if not entry or entry[1] is None:
            print("\nНеверный пункт.")
            continue

        try:
            entry[1](api, username)
        except SessionExpired as e:
            print(f"\n[!] {e.message}. Войдите заново.")
            return
        except ApiError as e:
            print(f"\n[!] Ошибка {e.code}: {e.message}")


def main():
    api = ApiClient()

    # health-check
    code, _ = api.health()
    if code != 200:
        print("\n[!] Сервер недоступен.")
        return

    while True:
        print("\n=== Файловый менеджер (вход) ===")
        print("1. Войти")
        print("2. Зарегистрироваться")
        print("0. Выход")
        choice = input("\nВыберите команду: ").strip()
        if choice == "0":
            return
        elif choice == "1":
            u = input("Логин: ").strip()
            p = getpass("Пароль: ")
            code, data = api.login(u, p)
            if code == 200:
                print(f"\n[+] Добро пожаловать, {data['username']}!")
                menu(api, data["username"])
            else:
                print(f"\n[!] {data.get('error')}")
        elif choice == "2":
            u = input("Логин: ").strip()
            p = getpass("Пароль: ")
            code, data = api.register(u, p)
            print(f"  {code}  {data}")
        else:
            print("\nНеверный пункт.")
            continue


if __name__ == "__main__":
    main()