"""Диагностика WordPress компоненты, ядро, тема, версии PHP/WP, тяжёлые плагины."""
# Переработать

import re
from collections import defaultdict

from .i18n import plural_word, t
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
        "wp-blog-header.php": t("wp.desc.blog_header"),
        "wp-load.php": t("wp.desc.load"),
        "wp-config.php": t("wp.desc.config"),
        "wp-settings.php": t("wp.desc.settings"),
        "wp-includes/load.php": t("wp.desc.includes_load"),
        "wp-includes/functions.php": t("wp.desc.includes_functions"),
        "wp-includes/plugin.php": t("wp.desc.includes_plugin"),
        "wp-includes/class-wp.php": t("wp.desc.includes_class_wp"),
        "wp-includes/query.php": t("wp.desc.includes_query"),
        "wp-includes/post.php": t("wp.desc.includes_post"),
        "wp-includes/theme.php": t("wp.desc.includes_theme"),
        "wp-includes/template.php": t("wp.desc.includes_template"),
        "wp-includes/user.php": t("wp.desc.includes_user"),
        "wp-includes/meta.php": t("wp.desc.includes_meta"),
        "wp-includes/rewrite.php": t("wp.desc.includes_rewrite"),
        "wp-includes/comment.php": t("wp.desc.includes_comment"),
        "wp-includes/option.php": t("wp.desc.includes_option"),
        "wp-includes/formatting.php": t("wp.desc.includes_formatting"),
        "wp-includes/capabilities.php": t("wp.desc.includes_capabilities"),
        "wp-includes/taxonomy.php": t("wp.desc.includes_taxonomy"),
        "wp-includes/class-wp-error.php": t("wp.desc.includes_class_wp_error"),
    }

    missing_core = []
    for fname, desc in critical_core.items():
        full = (p.wp_abspath or "") + fname
        if full in p.open_missing or fname in p.open_missing:
            missing_core.append((fname, desc))
        # также проверяем по потерям в access/openat
        elif not any(path.endswith("/" + fname) or path.endswith("\\" + fname) for path in p.files):
            if not any(path.endswith("/" + fname) or path.endswith("\\" + fname) for path in p.open_missing):
                # файл вообще не упоминался - возможно, не добрались
                pass

    if missing_core:
        issues.append(("CRITICAL", t("wp.missing_core")))
        for fname, desc in missing_core:
            issues.append(("CRITICAL", f"  [!] {fname} - {desc}"))

    # --- 2. Файлы wp-content ---
    content_checks = {
        "db.php": t("wp.desc.db"),
        "object-cache.php": t("wp.desc.object_cache"),
        "advanced-cache.php": t("wp.desc.advanced_cache"),
    }
    missing_content = []
    for fname, desc in content_checks.items():
        if fname in p.open_missing:
            missing_content.append((fname, desc))
    if missing_content:
        issues.append(("WARNING", t("wp.missing_content")))
        for fname, desc in missing_content:
            issues.append(("WARNING", f"  [!] {fname} - {desc}"))

    # --- 3. Mu-plugins ---
    if "mu-plugins" in p.open_missing or any("mu-plugins" in path for path in p.open_missing):
        issues.append(("WARNING", t("wp.no_mu")))

    # --- 4. Активная тема ---
    if p.wp_active_theme:
        base = (p.wp_abspath or "") + "wp-content/themes/" + p.wp_active_theme + "/"
        # Критические шаблоны темы
        theme_critical = {
            "index.php": t("wp.desc.index"),
            "functions.php": t("wp.desc.functions"),
            "style.css": t("wp.desc.style"),
            "header.php": t("wp.desc.header"),
            "footer.php": t("wp.desc.footer"),
            "sidebar.php": t("wp.desc.sidebar"),
        }
        # Шаблоны контента
        theme_content = {
            "front-page.php": t("wp.desc.front_page"),
            "home.php": t("wp.desc.home"),
            "single.php": t("wp.desc.single"),
            "page.php": t("wp.desc.page"),
            "archive.php": t("wp.desc.archive"),
            "search.php": t("wp.desc.search"),
            "404.php": t("wp.desc.404"),
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
            issues.append(("ERROR", t("wp.theme_missing", theme=p.wp_active_theme)))
            for fname, desc, sev in missing_theme:
                issues.append((sev, f"  [!] {fname} - {desc}"))

        # Проверяем есть ли хотя бы один шаблон для вывода
        has_any_template = False
        for fname in ["index.php", "home.php", "front-page.php", "single.php", "page.php"]:
            fp = base + fname
            if fp in p.files:
                has_any_template = True
                break
        if not has_any_template and p.wp_active_theme:
            issues.append(("CRITICAL",
                t("wp.theme_no_templates", theme=p.wp_active_theme)))
    else:
        issues.append(("WARNING", t("wp.no_theme")))

    # --- 5. Версия PHP ---
    if p.wp_php_version_hint:
        try:
            major, minor = map(int, p.wp_php_version_hint.split("."))
            if major < 7:
                issues.append(("ERROR",
                    t("wp.php_old", v=p.wp_php_version_hint, major=major, minor=minor,
                      year=2018 if major == 5 else 2021)))
            elif major == 7 and minor < 4:
                issues.append(("WARNING",
                    t("wp.php_recommend", v=p.wp_php_version_hint)))
        except (ValueError, AttributeError):
            pass

    # --- 6. Версия WordPress ---
    if p.wp_version:
        try:
            parts = p.wp_version.split(".")
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
            if major < 5 and minor < 8:
                issues.append(("ERROR", t("wp.wp_old", v=p.wp_version)))
            elif major < 6:
                issues.append(("WARNING", t("wp.wp_outdated", v=p.wp_version)))
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
        issues.append(("WARNING", t("wp.missing_lang", n=len(missing_lang))))
        for path in missing_lang[:5]:
            issues.append(("WARNING", f"  [!] {path}"))
        if len(missing_lang) > 5:
            issues.append(("WARNING", t("wp.more", n=len(missing_lang) - 5)))

    # --- 8. Общая статистика файлов ---
    total_missing = sum(p.open_missing.values())
    if total_missing > 20:
        issues.append(("WARNING",
            t("wp.enoent_many", n=total_missing)))

    # --- 9. Страница не отрисована (нет write с HTML) ---
    has_html_output = False
    for r in p.http_requests:
        if r.get("status") is not None:
            has_html_output = True
            break
    if not has_html_output and p.http_requests:
        issues.append(("CRITICAL", t("wp.no_status")))

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
            w(t("wp.heavy"))
            for comp, b, acc, fc in sorted(heavy, key=lambda x: -x[1]):
                w(t("wp.heavy_line", size=fmt_bytes(b), comp=comp, acc=acc, files=fc,
                    acc_word=plural_word(acc, "access"), files_word=plural_word(fc, "file")))
