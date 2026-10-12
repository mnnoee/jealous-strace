"""Диагностика WordPress: компоненты, ядро, тема, версии PHP/WP, тяжёлые плагины."""

import re
from collections import defaultdict

from .parse_utils import fmt_bytes


def classify_wp_component(path):
    """Определяет компонент WordPress по пути к файлу."""
    if '/plugins/' in path:
        return path.split('/plugins/')[1].split('/')[0]
    if '/themes/' in path:
        return f"theme: {path.split('/themes/')[1].split('/')[0]}"
    if '/wp-admin/' in path:
        return 'wp-admin'
    if '/wp-includes/' in path:
        return 'wp-includes'
    return 'other'


def maybe_wp_version(p, data):
    """Извлекает версию WordPress из содержимого version.php."""
    if p.wp_version:
        return
    try:
        txt = data.decode("utf-8", "replace")
        m = re.search(r"\$wp_version\s*=\s*['\"]([^'\"]+)['\"]", txt)
        if m:
            p.wp_version = m.group(1)
    except Exception:
        pass


def maybe_wp_abspath(p, path, data):
    """Извлекает ABSPATH из index.php / wp-load.php."""
    if p.wp_abspath:
        return
    try:
        txt = data.decode("utf-8", "replace")
        # из index.php: require( dirname( __FILE__ ) . '/wp-blog-header.php' );
        # из wp-load.php: define( 'ABSPATH', dirname(__FILE__) . '/' );
        if "ABSPATH" in txt:
            p.wp_abspath = path.rsplit("/", 1)[0] + "/"
        elif path.endswith("/index.php"):
            p.wp_abspath = path.rsplit("/", 1)[0] + "/"
    except Exception:
        pass


def maybe_php_version_from_cwd(p, args):
    """Определяет версию PHP по рабочей директории (getcwd)."""
    path_m = re.search(r'"([^"]*)"', args)
    if path_m and not p.wp_php_version_hint:
        cwd = path_m.group(1)
        m = re.search(r"php[-_]?(\d{2,3})", cwd, re.I)
        if m:
            v = m.group(1)
            if len(v) == 2:
                v = v[0] + "." + v[1]
            p.wp_php_version_hint = v


def detect_theme(p):
    """Определяет активную тему по файлам из wp-content/themes/."""
    if p.wp_active_theme:
        return
    for path in p.files:
        m = re.search(r"/wp-content/themes/([^/]+)/", path)
        if m:
            p.wp_active_theme = m.group(1)
            return
    for path in p.open_missing:
        m = re.search(r"/wp-content/themes/([^/]+)/", path)
        if m:
            p.wp_active_theme = m.group(1)
            return


def detect_php_version(p):
    """Определяет версию PHP из пути к бинарнику или рабочей директории."""
    if p.wp_php_version_hint:
        return
    # ищем в путях файлов и в open_missing
    all_paths = list(p.files.keys()) + list(p.open_missing.keys())
    for path in all_paths:
        m = re.search(r"php[-_]?(\d{2,3})", path, re.I)
        if m:
            v = m.group(1)
            if len(v) == 2:
                v = v[0] + "." + v[1]
            p.wp_php_version_hint = v
            return


def diagnose(p):
    """Комплексная диагностика WordPress: критические файлы, тема, версии."""
    if not p.wordpress:
        return []
    issues = []
    detect_theme(p)
    detect_php_version(p)

    # --- 1. Критические ядро-файлы WP ---
    critical_core = {
        "wp-blog-header.php": "точка входа WP (загружает wp-load.php)",
        "wp-load.php": "загрузчик WP (подключает wp-config.php)",
        "wp-config.php": "конфигурация (БД, ключи)",
        "wp-settings.php": "настройки окружения WP",
        "wp-includes/load.php": "базовые функции загрузки",
        "wp-includes/functions.php": "основной API",
        "wp-includes/plugin.php": "система хуков",
        "wp-includes/class-wp.php": "класс WP (роутинг)",
        "wp-includes/query.php": "WP_Query",
        "wp-includes/post.php": "работа с постами",
        "wp-includes/theme.php": "API тем",
        "wp-includes/template.php": "загрузка шаблонов",
        "wp-includes/user.php": "пользователи",
        "wp-includes/meta.php": "метаданные",
        "wp-includes/rewrite.php": "permalink-структура",
        "wp-includes/comment.php": "комментарии",
        "wp-includes/option.php": "API опций",
        "wp-includes/formatting.php": "форматирование",
        "wp-includes/capabilities.php": "роли и права",
        "wp-includes/taxonomy.php": "таксономии",
        "wp-includes/class-wp-error.php": "обработка ошибок",
    }

    missing_core = []
    for fname, desc in critical_core.items():
        full = (p.wp_abspath or "") + fname
        if full in p.open_missing or fname in p.open_missing:
            missing_core.append((fname, desc))
        # также проверяем по потерям в access/openat
        elif not any(path.endswith("/" + fname) or path.endswith("\\" + fname) for path in p.files):
            if not any(path.endswith("/" + fname) or path.endswith("\\" + fname) for path in p.open_missing):
                # файл вообще не упоминался — возможно, не добрались
                pass

    if missing_core:
        issues.append(("CRITICAL", "Отсутствуют критические файлы ядра WordPress:"))
        for fname, desc in missing_core:
            issues.append(("CRITICAL", f"  [!] {fname} — {desc}"))

    # --- 2. Файлы wp-content ---
    content_checks = {
        "db.php": "кастомный драйвер БД (drop-in)",
        "object-cache.php": "кастомный кэш объектов (drop-in)",
        "advanced-cache.php": "кэширование (drop-in)",
    }
    missing_content = []
    for fname, desc in content_checks.items():
        if fname in p.open_missing:
            missing_content.append((fname, desc))
    if missing_content:
        issues.append(("WARNING", "Отсутствуют drop-in файлы wp-content:"))
        for fname, desc in missing_content:
            issues.append(("WARNING", f"  [!] {fname} — {desc}"))

    # --- 3. Mu-plugins ---
    if "mu-plugins" in p.open_missing or any("mu-plugins" in path for path in p.open_missing):
        issues.append(("WARNING", "Отсутствует каталог mu-plugins (mu-плагины не загружены)"))

    # --- 4. Активная тема ---
    if p.wp_active_theme:
        base = (p.wp_abspath or "") + "wp-content/themes/" + p.wp_active_theme + "/"
        # Критические шаблоны темы
        theme_critical = {
            "index.php": "главный шаблон (fallback для всех запросов)",
            "functions.php": "функции темы (обязательный при активации)",
            "style.css": "метаданные темы",
            "header.php": "шапка страницы",
            "footer.php": "подвал страницы",
            "sidebar.php": "боковая панель",
        }
        # Шаблоны контента
        theme_content = {
            "front-page.php": "главная страница (статическая)",
            "home.php": "главная страница (посты)",
            "single.php": "одиночный пост",
            "page.php": "статическая страница",
            "archive.php": "архив",
            "search.php": "результаты поиска",
            "404.php": "страница «не найдено»",
        }

        missing_theme = []
        for fname, desc in theme_critical.items():
            fp = base + fname
            if fname in p.open_missing or fp in p.open_missing:
                missing_theme.append((fname, desc, "CRITICAL"))
        for fname, desc in theme_content.items():
            fp = base + fname
            if fname in p.open_missing or fp in p.open_missing:
                missing_theme.append((fname, desc, "ERROR"))

        if missing_theme:
            issues.append(("ERROR", f"Тема «{p.wp_active_theme}» — отсутствуют файлы шаблонов:"))
            for fname, desc, sev in missing_theme:
                issues.append((sev, f"  [!] {fname} — {desc}"))

        # Проверяем есть ли хотя бы один шаблон для вывода
        has_any_template = False
        for fname in ["index.php", "home.php", "front-page.php", "single.php", "page.php"]:
            fp = base + fname
            if fp in p.files:
                has_any_template = True
                break
        if not has_any_template and p.wp_active_theme:
            issues.append(("CRITICAL",
                f"Тема «{p.wp_active_theme}» не имеет ни одного шаблона для вывода! "
                "Страница не может быть отрисована."))
    else:
        issues.append(("WARNING", "Активная тема не определена (нет обращений к wp-content/themes/)"))

    # --- 5. Версия PHP ---
    if p.wp_php_version_hint:
        try:
            major, minor = map(int, p.wp_php_version_hint.split("."))
            if major < 7:
                issues.append(("ERROR",
                    f"PHP {p.wp_php_version_hint} — ЭТО КРИТИЧЕСКИ УСТАРЕВШАЯ ВЕРСИЯ! "
                    f"PHP {major}.{minor} не поддерживается с {2018 if major == 5 else 2021} года. "
                    f"Многие плагины и ядро WP требуют PHP 7.4+."))
            elif major == 7 and minor < 4:
                issues.append(("WARNING",
                    f"PHP {p.wp_php_version_hint} — рекомендуется обновить до PHP 7.4+"))
        except (ValueError, AttributeError):
            pass

    # --- 6. Версия WordPress ---
    if p.wp_version:
        try:
            parts = p.wp_version.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            if major < 5 and minor < 8:
                issues.append(("ERROR",
                    f"WordPress {p.wp_version} — КРИТИЧЕСКИ УСТАРЕВШАЯ ВЕРСИЯ! "
                    f"Содержит известные уязвимости. Рекомендуется обновление до 6.x"))
            elif major < 6:
                issues.append(("WARNING",
                    f"WordPress {p.wp_version} — устаревшая версия, рекомендуется обновление"))
        except (ValueError, IndexError):
            pass

    # --- 7. Языковые файлы ---
    missing_lang = []
    for path in p.open_missing:
        if "/languages/" in path and path.endswith(".mo"):
            missing_lang.append(path)
        elif "/languages/" in path and path.endswith(".php"):
            missing_lang.append(path)
    if missing_lang:
        issues.append(("WARNING", f"Отсутствуют языковые файлы ({len(missing_lang)}):"))
        for path in missing_lang[:5]:
            issues.append(("WARNING", f"  [!] {path}"))
        if len(missing_lang) > 5:
            issues.append(("WARNING", f"  ... и ещё {len(missing_lang) - 5}"))

    # --- 8. Общая статистика файлов ---
    total_missing = sum(p.open_missing.values())
    if total_missing > 20:
        issues.append(("WARNING",
            f"Всего {total_missing} обращений к несуществующим файлам — "
            "много ENOENT может замедлять загрузку."))

    # --- 9. Страница не отрисована (нет write с HTML) ---
    has_html_output = False
    for r in p.http_requests:
        if r.get("status") is not None:
            has_html_output = True
            break
    if not has_html_output and p.http_requests:
        issues.append(("CRITICAL",
            "HTTP-ответ не содержит статуса — страница не сформирована. "
            "Возможно, PHP-процесс завершился с ошибкой или по таймауту."))

    p.wp_detected_issues = issues
    return issues


def report_heavy_plugins(p, w):
    """Секция отчёта: компоненты, загрузившие больше всего байт."""
    if p.wordpress and p.files:
        plugin_bytes = defaultdict(int)
        plugin_files = defaultdict(set)
        plugin_access = defaultdict(int)
        for path, ops in p.files.items():
            comp = classify_wp_component(path)
            plugin_bytes[comp] += p.file_bytes[path].get("read", 0)
            plugin_files[comp].add(path)
            plugin_access[comp] += sum(ops.values())
        heavy = [(comp, b, plugin_access[comp], len(plugin_files[comp]))
                 for comp, b in plugin_bytes.items() if b > 100_000]
        if heavy:
            w("\n--- ТЯЖЁЛЫЕ ПЛАГИНЫ (по суммарному чтению) ---")
            for comp, b, acc, fc in sorted(heavy, key=lambda x: -x[1]):
                w(f"  {fmt_bytes(b):>8}  {comp}  ({acc} обращений, {fc} уникальных файлов)")
