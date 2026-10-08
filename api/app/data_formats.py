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
def save_json(user_id: int, path: str, obj) -> int:
    """Сохранить объект в JSON."""

    # ensure_ascii = False - позволяет сохранять Unicode (кириллицу)
    # indent - каждый уровень вложенности печается с двумя дополнительными пробелами
    data = json.dumps(obj, ensure_ascii=False, indent=2).encode("utf-8")

    file_id = create_file(user_id, path, data)

    return file_id


def load_json(user_id: int, path: str):
    """Загрузить JSON из файла."""

    data = read_file(user_id, path)

    return json.loads(data.decode("utf-8"))


# XML
def save_xml(user_id: int, path: str, user_folder: etree._Element) -> int:
    """Сохранить XML-дерево."""

    # pretty_print - читабельное отображение
    # xml_declaration - добавляет в начало XML строку <?xml version="1.0" encoding="UTF-8"?> для явного обозначения
    # формата xml, версии и кодировки
    xml_bytes = etree.tostring(user_folder, pretty_print=True, xml_declaration=True, encoding="UTF-8")

    file_id = create_file(user_id, path, xml_bytes)

    return file_id


def load_xml(user_id: int, path: str) -> etree._Element:
    """Загрузить XML из файла."""

    data = read_file(user_id, path)

    parser = etree.XMLParser(
        resolve_entities=False,   # CWE-611
        no_network=True,          # CWE-611
        huge_tree=False,          # CWE-776
        dtd_validation=False,
        load_dtd=False,           # CWE-611
    )

    return etree.fromstring(data, parser=parser)