"""
HTTP-слой. Все эндпоинты - JSON in / JSON out.
Никакого HTML и инлайн-вставок пользовательских данных -> CWE-79 закрыт.
"""

import base64, binascii, functools
from flask import Flask, request, jsonify, g
from werkzeug.exceptions import HTTPException
from lxml import etree
from app import auth
from app.audit import log_event
from app.file_manager import (
    list_disks, create_file, read_file, update_file,
    delete_file, list_files,
)
from app.data_formats import save_json, load_json, save_xml, load_xml
from app.archive import create_zip, extract_zip
from app.db import fetch_all


app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024  # 16 МБ


def _client_ip() -> str:
    """
    Реальный IP клиента за nginx.
    nginx прокидывает X-Real-IP;
    fallback - remote_addr напрямую.
    """
    return (request.headers.get("X-Real-IP") or request.remote_addr or "unknown")


# Аутентификация
def require_auth(f):
    """Декоратор: требует заголовок Authorization: Bearer <token>."""
    @functools.wraps(f)
    def wrapper(*args, **kwargs):
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify(error="Требуется авторизация"), 401
        token = header[7:].strip()
        user = auth.resolve_session(token)
        if not user:
            return jsonify(error="Недействительный или истёкший токен"), 401
        g.user = user
        g.token = token
        return f(*args, **kwargs)
    return wrapper


def _decode_b64(value) -> bytes:
    """Строгий base64-декодер. Кидает binascii.Error на некорректный ввод."""
    return base64.b64decode(str(value or ""), validate=True)


@app.errorhandler(Exception)
def on_error(e):
    """CWE-209: наружу - обобщённое сообщение, детали - только в лог."""
    # HTTPException (404, 405, 400 и т.д.) должен обрабатываться Flask-ом,
    # иначе клиент получит 500 вместо настоящего кода ошибки.
    if isinstance(e, HTTPException):
        return e
    app.logger.exception("Unhandled error")
    return jsonify(error="Внутренняя ошибка сервера"), 500


@app.post("/api/register")
def register():
    data = request.get_json(silent=True) or {}
    try:
        auth.register_user(
            str(data.get("username") or ""),
            str(data.get("password") or ""),
        )
        return jsonify(status="ok"), 201
    except (ValueError, auth.AuthError) as e:
        return jsonify(error=str(e)), 400



# auth
@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    try:
        user = auth.authenticate(
            str(data.get("username") or ""),
            str(data.get("password") or ""),
            ip=_client_ip(),
        )
    except auth.RateLimitError as e:
        return jsonify(error=str(e)), 429
    except auth.AuthError as e:
        return jsonify(error=str(e)), 401

    token = auth.create_session(user["id"])
    return jsonify(token=token, username=user["username"])


@app.post("/api/logout")
@require_auth
def logout():
    auth.destroy_session(g.token)
    log_event(g.user["id"], None, "logout", "Выход из системы")
    return jsonify(status="ok")



# files
@app.get("/api/disks")
@require_auth
def api_disks():
    return jsonify(disks=list_disks())


@app.get("/api/files")
@require_auth
def api_files():
    return jsonify(files=list_files(g.user["id"]))


@app.post("/api/files")
@require_auth
def api_create_file():
    data = request.get_json(silent=True) or {}
    rel = str(data.get("path") or "")

    try:
        content = _decode_b64(data.get("content_b64"))
    except binascii.Error:
        return jsonify(error="Некорректный base64"), 400

    try:
        file_id = create_file(g.user["id"], rel, content)
        return jsonify(file_id=file_id), 201
    except (ValueError, FileExistsError) as e:
        return jsonify(error=str(e)), 400


@app.get("/api/files/<path:rel>")
@require_auth
def api_read_file(rel: str):
    try:
        data = read_file(g.user["id"], rel)
        return jsonify(content_b64=base64.b64encode(data).decode())
    except (ValueError, FileNotFoundError) as e:
        return jsonify(error=str(e)), 404


@app.put("/api/files/<path:rel>")
@require_auth
def api_update_file(rel: str):
    data = request.get_json(silent=True) or {}
    try:
        content = _decode_b64(data.get("content_b64"))
    except binascii.Error:
        return jsonify(error="Некорректный base64"), 400
    try:
        update_file(g.user["id"], rel, content)
        return jsonify(status="ok")
    except (ValueError, FileNotFoundError) as e:
        return jsonify(error=str(e)), 404


@app.delete("/api/files/<path:rel>")
@require_auth
def api_delete_file(rel: str):
    try:
        delete_file(g.user["id"], rel)
        return jsonify(status="ok")
    except (ValueError, FileNotFoundError) as e:
        return jsonify(error=str(e)), 404



# json, xml
@app.post("/api/json")
@require_auth
def api_save_json():
    data = request.get_json(silent=True) or {}
    try:
        save_json(g.user["id"], str(data.get("path") or ""), data.get("value"))
        return jsonify(status="ok"), 201
    except (ValueError, FileExistsError) as e:
        return jsonify(error=str(e)), 400


@app.get("/api/json/<path:rel>")
@require_auth
def api_load_json(rel: str):
    try:
        return jsonify(value=load_json(g.user["id"], rel))
    except (ValueError, FileNotFoundError) as e:
        return jsonify(error=str(e)), 404


@app.post("/api/xml")
@require_auth
def api_save_xml():
    data = request.get_json(silent=True) or {}
    xml_text = str(data.get("xml") or "")
    try:
        parser = etree.XMLParser(
            resolve_entities=False, no_network=True,
            huge_tree=False, load_dtd=False,
        )
        root = etree.fromstring(xml_text.encode("utf-8"), parser=parser)
    except etree.XMLSyntaxError as e:
        return jsonify(error=f"Некорректный XML: {e}"), 400
    try:
        save_xml(g.user["id"], str(data.get("path") or ""), root)
        return jsonify(status="ok"), 201
    except (ValueError, FileExistsError) as e:
        return jsonify(error=str(e)), 400


@app.get("/api/xml/<path:rel>")
@require_auth
def api_load_xml(rel: str):
    try:
        root = load_xml(g.user["id"], rel)
        return jsonify(xml=etree.tostring(root, encoding="unicode"))
    except (ValueError, FileNotFoundError) as e:
        return jsonify(error=str(e)), 404



# zip
@app.post("/api/zip")
@require_auth
def api_create_zip():
    data = request.get_json(silent=True) or {}
    try:
        fid = create_zip(
            g.user["id"],
            str(data.get("archive") or ""),
            list(data.get("files") or []),
        )
        return jsonify(file_id=fid), 201
    except (ValueError, FileNotFoundError, FileExistsError) as e:
        return jsonify(error=str(e)), 400


@app.post("/api/unzip")
@require_auth
def api_extract_zip():
    data = request.get_json(silent=True) or {}
    try:
        files = extract_zip(
            g.user["id"],
            str(data.get("archive") or ""),
            str(data.get("target") or ""),
        )
        return jsonify(files=files)
    except (ValueError, FileNotFoundError) as e:
        return jsonify(error=str(e)), 400



# health
@app.get("/api/health")
def health():
    return jsonify(status="ok")


# audit
@app.get("/api/audit")
@require_auth
def api_audit():
    """
    Журнал аудита пользователя.
    JOIN с users, чтобы видеть, кто сделал операцию
    (user_id хранится в operations, username - в users).

    Берём последние 100 записей (самые свежие), но выводим их
    в хронологическом порядке - от старых к новым.
    """
    rows = fetch_all(
        "SELECT * FROM ("
        "    SELECT o.timestamp, u.username, o.operation_type, o.details "
        "    FROM operations o "
        "    LEFT JOIN users u ON u.id = o.user_id "
        "    WHERE o.user_id = %s "
        "    ORDER BY o.timestamp DESC "
        "    LIMIT 100"
        ") AS last_ops "
        "ORDER BY timestamp ASC",
        (g.user["id"],),
    )
    # datetime не сериализуется jsonify по умолчанию - приводим к строке
    for r in rows:
        if r["timestamp"] is not None:
            r["timestamp"] = r["timestamp"].strftime("%Y-%m-%d %H:%M:%S")
    return jsonify(operations=rows)