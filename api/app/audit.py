"""
Журнал действий пользователей, пишется в таблицу operations
"""

from app.db import execute


# Белый список типов операций, должен совпадать с CHECK-констрейнтом в schema.sql
ALLOWED_OPERATIONS = {
    "create", "modify", "delete", "read", "login", "logout", "zip", "unzip",
}


def log_event(user_id: int | None, file_id: int | None, op_type: str, details: str = "", cur=None) -> None:
    """
    Запись события в журнал аудита.

    Если передан cur - используется внешняя транзакция (см. db.transaction),
    иначе открывается отдельное соединение.
    """

    if op_type not in ALLOWED_OPERATIONS:
        raise ValueError(f"Неизвестный тип операции: {op_type!r}")

    query = (
        "INSERT INTO operations (operation_type, file_id, user_id, details) "
        "VALUES (%s, %s, %s, %s)"
    )
    
    params = (op_type, file_id, user_id, str(details)[:500])

    if cur is not None:
        cur.execute(query, params)
    else:
        execute(query, params)