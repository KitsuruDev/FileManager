"""
Консольный клиент файлового менеджера.
Общается с сервером по HTTPS через nginx.
"""

import os, base64, json, requests
from getpass import getpass
from urllib.parse import quote


API_URL   = os.getenv("API_URL", "https://nginx")
CA_BUNDLE = os.getenv("CA_BUNDLE", "/certs/server.crt")


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

    def load_json(self, path: str):
        rel = quote(self._norm(path), safe="/")
        return self._call("GET", f"/api/json/{rel}")

    def save_xml(self, path: str, xml_text: str):
        return self._call("POST", "/api/xml",
                          json={"path": path, "xml": xml_text})

    def load_xml(self, path: str):
        rel = quote(self._norm(path), safe="/")
        return self._call("GET", f"/api/xml/{rel}")

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
    rel  = input("Путь: ").strip()
    text = input("Содержимое: ")
    data = _ok(api.create_file(rel, text.encode()))
    print("\n  [+] Файл создан")


def cmd_read(api: ApiClient, _username: str):
    rel = input("Путь: ").strip()
    data = _ok(api.read_file(rel))
    print(data["content"].decode("utf-8", errors="replace"))


def cmd_update(api: ApiClient, _username: str):
    rel  = input("Путь: ").strip()
    text = input("Новое содержимое: ")
    _ok(api.update_file(rel, text.encode()))
    print("\n  [+] Обновлено")


def cmd_delete(api: ApiClient, _username: str):
    rel = input("Путь: ").strip()
    _ok(api.delete_file(rel))
    print("\n  [+] Удалено")


def cmd_save_json(api: ApiClient, _username: str):
    rel = input("Путь (например data.json): ").strip()
    raw = input("JSON-строка: ")
    try:
        obj = json.loads(raw)
    except json.JSONDecodeError as e:
        print(f"\n[!] Некорректный JSON: {e}")
        return
    _ok(api.save_json(rel, obj))
    print("\n  [+] JSON сохранён")


def cmd_load_json(api: ApiClient, _username: str):
    rel = input("Путь: ").strip()
    data = _ok(api.load_json(rel))
    print(json.dumps(data.get("value"), ensure_ascii=False, indent=2))


def cmd_save_xml(api: ApiClient, _username: str):
    rel = input("Путь (например data.xml): ").strip()
    xml = input("XML (одной строкой): ")
    _ok(api.save_xml(rel, xml))
    print("\n  [+] XML сохранён")


def cmd_load_xml(api: ApiClient, _username: str):
    rel = input("Путь: ").strip()
    data = _ok(api.load_xml(rel))
    print(data.get("xml", ""))


def cmd_create_zip(api: ApiClient, _username: str):
    archive = input("Путь к архиву (например backup.zip): ").strip()
    files_s = input("Файлы через запятую: ")
    files = [f.strip() for f in files_s.split(",") if f.strip()]
    data = _ok(api.create_zip(archive, files))
    print("\n  [+] Архив создан")


def cmd_extract_zip(api: ApiClient, _username: str):
    archive = input("Путь к архиву: ").strip()
    target  = input("Куда распаковать: ").strip()
    data = _ok(api.extract_zip(archive, target))
    print(f"\n  [+] Распаковано файлов: {len(data.get('files', []))}")

def cmd_upload(api: ApiClient, _username: str):
    """
    Загрузка локального файла на сервер.
    Локальный файл должен быть доступен внутри контейнера клиента —
    например, через примонтированную папку /uploads.
    """
    local  = input("Путь к локальному файлу (например /uploads/note.txt): ").strip()
    remote = input("Путь на сервере (например docs/note.txt): ").strip()
    try:
        with open(local, "rb") as f:
            content = f.read()
    except OSError as e:
        print(f"\n[!] Не удалось прочитать {local}: {e}")
        return
    _ok(api.create_file(remote, content))
    print(f"\n  [+] Загружено ({len(content)} байт)")


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
    "8":  ("Сохранить JSON",       cmd_save_json),
    "9":  ("Загрузить JSON",       cmd_load_json),
    "10": ("Сохранить XML",        cmd_save_xml),
    "11": ("Загрузить XML",        cmd_load_xml),
    "12": ("Создать ZIP",          cmd_create_zip),
    "13": ("Распаковать ZIP",      cmd_extract_zip),
    "14": ("Журнал аудита",        cmd_audit),
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
            return                    # возвращаемся в главное меню
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