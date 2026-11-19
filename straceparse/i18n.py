"""Локализация вывода"""

import os

from .locales import en, ru

DEFAULT_LANG = "en"
LANG_EN = "en"
LANG_RU = "ru"
LANGUAGES = (LANG_RU, LANG_EN)
ENV_VARS = ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE")

_CATALOG = {LANG_RU: ru.CATALOG, LANG_EN: en.CATALOG}


def lang_from_locale(value):
    """Превращает строку локали POSIX в поддерживаемый язык."""
    if not value:
        return DEFAULT_LANG
    for item in value.split(":"):
        item = item.strip()
        if not item:
            continue
        base = item.split(".", 1)[0].split("@", 1)[0].lower()
        if base in ("c", "posix"):
            return LANG_EN
        if base.startswith("ru"):
            return LANG_RU
        if base.startswith("en"):
            return LANG_EN
    return DEFAULT_LANG


def detect_lang(env=None):
    """Определяет язык по переменным локали"""
    env = os.environ if env is None else env
    for var in ENV_VARS:
        value = env.get(var)
        if value:
            return lang_from_locale(value)
    return DEFAULT_LANG


def resolve_lang(value=None):
    """auto/None -> по локали; ru/en -> явный выбор; прочее -> по локали."""
    if not value or value == "auto":
        return detect_lang()
    value = value.strip().lower()
    if value in _CATALOG:
        return value
    return lang_from_locale(value)


def prescan_argv(argv):
    for i, arg in enumerate(argv):
        if arg == "--lang" and i + 1 < len(argv):
            return argv[i + 1]
        if arg.startswith("--lang="):
            return arg.split("=", 1)[1]
    return None


_lang = detect_lang()


def get_lang():
    return _lang


def set_lang(lang):
    global _lang
    _lang = resolve_lang(lang)
    return _lang


def t(msg_id, **kwargs):
    """Строка каталога по ключу с подстановкой именованных аргументов."""
    template = _CATALOG[_lang].get(msg_id)
    if template is None:
        template = _CATALOG[DEFAULT_LANG].get(msg_id, msg_id)
    return template.format(**kwargs) if kwargs else template


def plural(n, one, few, many):
    n = abs(int(n))
    if _lang == LANG_RU:
        if n % 10 == 1 and n % 100 != 11:
            return one
        if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
            return few
        return many
    return one if n == 1 else many


def plural_word(n, key):
    """Слово из каталога (request, error, path, file, letter, candidate, process, call)."""
    one, few, many = _CATALOG[_lang]["plural"][key]
    return plural(n, one, few, many)
