import pytest
from lxml import etree
from app.data_formats import load_xml

def test_load_xml_xxe_prevention(temp_storage_root, mocker):
    """Создание XML с попыткой XXE (CWE-611)"""
    user_id = 1
    xml_path = temp_storage_root / "users" / str(user_id) / "evil.xml"
    xml_path.parent.mkdir(parents=True)
    
    xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>"""
    xml_path.write_bytes(xxe_payload.encode("utf-8"))

    # мокаем read_file, чтобы он вернул наш зловредный XML
    mocker.patch("app.data_formats.read_file", return_value=xxe_payload.encode("utf-8"))

    # парсер должен проигнорировать сущность, не вызывая ошибку
    root = load_xml(user_id, "evil.xml")
    # проверяем, что содержимое /etc/passwd не подставилось
    assert "root:" not in etree.tostring(root).decode()
    assert root.text is None  # &xxe; не развернулся в текст