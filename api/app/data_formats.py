"""
Сериализация/десериализация JSON и XML.

Защиты:
  CWE-611 - XXE: lxml с resolve_entities=False, no_network=True
  CWE-776 - Billion Laughs: huge_tree=False
  CWE-502 - используем безопасный json, а не pickle
"""

import json
from lxml import etree
from app.file_manager import create_file, read_file


# JSON
def save_json(user_id: int, relative: str, obj) -> int:
    """Сохранить объект в JSON."""

    data = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")
    file_id = create_file(user_id, relative, data)

    return file_id


def load_json(user_id: int, relative: str):
    """Загрузить JSON из файла."""

    data = read_file(user_id, relative)

    return json.loads(data.decode("utf-8"))


# XML
def save_xml(user_id: int, relative: str, root: etree._Element) -> int:
    """Сохранить XML-дерево."""

    xml_bytes = etree.tostring(root, pretty_print=True, xml_declaration=True, encoding="UTF-8")
    file_id = create_file(user_id, relative, xml_bytes)

    return file_id


def load_xml(user_id: int, relative: str) -> etree._Element:
    """
    Безопасный парсинг XML
    Отключаем внешние сущности и сеть -> закрываем XXE (CWE-611) и Billion Laughs (CWE-776)
    """

    data = read_file(user_id, relative)

    parser = etree.XMLParser(
        resolve_entities=False,   # CWE-611
        no_network=True,          # CWE-611
        huge_tree=False,          # CWE-776
        dtd_validation=False,
        load_dtd=False,
    )

    return etree.fromstring(data, parser=parser)