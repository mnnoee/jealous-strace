"""Unit-тесты локализации (straceparse/i18n.py)."""

import re
import unittest

from straceparse import i18n
from straceparse.i18n import detect_lang, get_lang, lang_from_locale, plural_word, set_lang, t


class LocaleDetectTest(unittest.TestCase):
    def test_lc_all_c_is_english(self):
        self.assertEqual(detect_lang({"LC_ALL": "C"}), "en")

    def test_lc_all_ru_is_russian(self):
        self.assertEqual(detect_lang({"LC_ALL": "ru_RU"}), "ru")
        self.assertEqual(detect_lang({"LC_ALL": "ru_RU.UTF-8"}), "ru")

    def test_english_locale(self):
        self.assertEqual(detect_lang({"LANG": "en_US.UTF-8"}), "en")

    def test_posix_and_c_utf8_are_english(self):
        self.assertEqual(detect_lang({"LC_ALL": "POSIX"}), "en")
        self.assertEqual(detect_lang({"LANG": "C.UTF-8"}), "en")

    def test_lc_all_wins_over_lang(self):
        self.assertEqual(detect_lang({"LC_ALL": "C", "LANG": "ru_RU.UTF-8"}), "en")
        self.assertEqual(detect_lang({"LC_ALL": "ru_RU.UTF-8", "LANG": "en_US.UTF-8"}), "ru")

    def test_empty_lc_all_falls_through(self):
        self.assertEqual(detect_lang({"LC_ALL": "", "LC_MESSAGES": "", "LANG": "ru_RU.UTF-8"}), "ru")

    def test_no_locale_defaults_to_english(self):
        self.assertEqual(detect_lang({}), "en")

    def test_unknown_locale_defaults_to_english(self):
        self.assertEqual(detect_lang({"LANG": "de_DE.UTF-8"}), "en")

    def test_language_list(self):
        self.assertEqual(lang_from_locale("ru_RU:en_US"), "ru")
        self.assertEqual(lang_from_locale("en_US:ru_RU"), "en")


class TranslateTest(unittest.TestCase):
    def setUp(self):
        self._saved = get_lang()

    def tearDown(self):
        set_lang(self._saved)

    def test_russian(self):
        set_lang("ru")
        self.assertEqual(t("r.title"), "ОТЧЁТ ПО STRACE-ЛОГАМ")
        self.assertEqual(t("r.lines", n=7), "\nСтрок обработано: 7")

    def test_english(self):
        set_lang("en")
        self.assertEqual(t("r.title"), "STRACE LOG REPORT")
        self.assertEqual(t("r.lines", n=7), "\nLines processed: 7")

    def test_kwargs_name_and_key(self):
        # ключи каталога могут содержать поля name= и key= - не конфликтуют с t()
        set_lang("ru")
        self.assertEqual(
            t("sig.cookie", name="c", method="GET", uri="/", host="h"),
            "Secure-cookie «c» установлена по HTTP для GET / host=h. "
            "Кука помечена Secure, но соединение не HTTPS - браузер её не вернёт.",
        )
        self.assertIn("повторяется 2 раз", t("sig.repeated", key="a -> b", n=2))

    def test_plural_russian(self):
        set_lang("ru")
        self.assertEqual(plural_word(1, "request"), "запрос")
        self.assertEqual(plural_word(2, "request"), "запроса")
        self.assertEqual(plural_word(5, "request"), "запросов")
        self.assertEqual(plural_word(21, "request"), "запрос")

    def test_plural_english(self):
        set_lang("en")
        self.assertEqual(plural_word(1, "request"), "request")
        self.assertEqual(plural_word(2, "request"), "requests")
        self.assertEqual(plural_word(0, "request"), "requests")

    def test_all_catalogs_have_same_keys(self):
        self.assertEqual(set(i18n._CATALOG["ru"]), set(i18n._CATALOG["en"]))

    def test_english_catalog_has_no_cyrillic(self):
        for msg_id, value in i18n._CATALOG["en"].items():
            if msg_id == "plural":
                continue
            self.assertIsNone(re.search(r"[А-Яа-яЁё]", value), msg=msg_id)

    def test_no_em_dash_in_catalogs(self):
        for lang, catalog in i18n._CATALOG.items():
            for msg_id, value in catalog.items():
                if msg_id == "plural":
                    continue
                self.assertNotIn("\u2014", value, msg=msg_id + ":" + lang)

    def test_unknown_key_falls_back_to_itself(self):
        set_lang("en")
        self.assertEqual(t("no.such.key"), "no.such.key")


if __name__ == "__main__":
    unittest.main()
