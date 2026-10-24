"""All formatting and printing. No decisions, no API calls."""

from datetime import datetime

from verdict import VERDICT_CLEAN, VERDICT_MALICIOUS, VERDICT_SUSPICIOUS

NOT_SET = "(not set)"
LABEL_WIDTH = 14
DATE_FORMAT = "%Y-%m-%d %H:%M"
TIME_FORMAT = "%H:%M:%S"
STAT_KEYS = ("malicious", "suspicious", "harmless", "undetected")
EMPTY_VALUES = (None, "", [], {})
VERDICT_MARKERS = {
    VERDICT_MALICIOUS: "[!!]",
    VERDICT_SUSPICIOUS: "[! ]",
    VERDICT_CLEAN: "[ok]",
}
UNKNOWN_MARKER = "[??]"

MAX_LIST_ITEMS = 5
ENGINE_WIDTH = 28
CATEGORY_WIDTH = 12
ELLIPSIS = "..."
SIZE_UNITS = ("B", "KB", "MB", "GB", "TB")
BYTES_PER_UNIT = 1024
KIND_WIDTH = 8
VERDICT_WIDTH = 12
INDICATOR_WIDTH = 50

# ---------- formatters (return strings) ----------

def format_value(value):
    """Return the value as text, or a placeholder if it's missing/empty."""
    return NOT_SET if value in EMPTY_VALUES else str(value)


def format_timestamp(timestamp):
    """Format a Unix timestamp as a readable local date."""
    if not isinstance(timestamp, (int, float)):
        return NOT_SET
    return datetime.fromtimestamp(timestamp).strftime(DATE_FORMAT)


def format_stats(stats):
    """Format detection stats as 'malicious: 0  suspicious: 0 ...'."""
    stats = stats or {}
    return "  ".join(f"{key}: {stats.get(key) or 0}" for key in STAT_KEYS)

def truncate(text, width):
    """Shorten text to `width` characters, ending with '...' if cut."""
    text = format_value(text)
    return text if len(text) <= width else text[:width - len(ELLIPSIS)] + ELLIPSIS


def format_size(num_bytes):
    """Format a byte count as '1.5 MB'."""
    if not isinstance(num_bytes, (int, float)):
        return NOT_SET
    size = float(num_bytes)
    for unit in SIZE_UNITS:
        if size < BYTES_PER_UNIT or unit == SIZE_UNITS[-1]:
            return f"{int(size):,} {unit}" if unit == SIZE_UNITS[0] else f"{size:,.1f} {unit}"
        size /= BYTES_PER_UNIT


def format_list(values):
    """Format a list as 'a, b, c (+N more)'."""
    if not values:
        return NOT_SET
    shown = ", ".join(str(value) for value in values[:MAX_LIST_ITEMS])
    extra = len(values) - MAX_LIST_ITEMS
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def format_categories(categories):
    """VT categories are {engine: category}; show the unique category names."""
    if not isinstance(categories, dict):
        return NOT_SET
    return format_list(sorted(set(categories.values())))

# ---------- printers ----------

def print_header(title):
    print(f"\n=== {title} ===")


def print_info(message):
    print(f"[i] {message}")


def print_error(message):
    print(f"[!] {message}")


def print_fields(pairs):
    """Print aligned 'label: value' lines."""
    for label, value in pairs:
        print(f"  {label + ':':<{LABEL_WIDTH}} {format_value(value)}")


def print_menu(labels, requests_used, request_limit, exit_choice):
    """Print the main menu. `labels` maps choice -> label text."""
    print_header("Threat Intel CLI")
    print(f"Requests used this minute: {requests_used}/{request_limit}\n")
    for choice, label in labels.items():
        print(f"  {choice}. {label}")
    print(f"  {exit_choice}. Exit")


def print_verdict(verdict, indicator):
    marker = VERDICT_MARKERS.get(verdict, UNKNOWN_MARKER)
    print(f"\n{marker} {verdict}  {indicator}")

def print_poll_status(status):
    print(f"  ... status: {format_value(status)}")


def print_engines(engines):
    """Print a table of engines that flagged the indicator."""
    if not engines:
        print_info("No engine flagged this indicator.")
        return
    print(f"\n  {'Engine':<{ENGINE_WIDTH}} {'Category':<{CATEGORY_WIDTH}} Result")
    for engine in engines:
        name = truncate(engine.get("engine_name"), ENGINE_WIDTH)
        category = truncate(engine.get("category"), CATEGORY_WIDTH)
        print(f"  {name:<{ENGINE_WIDTH}} {category:<{CATEGORY_WIDTH}} {format_value(engine.get('result'))}")


def _print_report(indicator, verdict, fields, engines):
    """Shared layout: verdict line, fields, flagged engines."""
    print_verdict(verdict, indicator)
    print_fields(fields)
    print_engines(engines)


def print_ip_report(ip, attributes, verdict, engines):
    _print_report(ip, verdict, [
        ("Country", attributes.get("country")),
        ("Owner", attributes.get("as_owner")),
        ("Network", attributes.get("network")),
        ("Reputation", attributes.get("reputation")),
        ("Last analysis", format_timestamp(attributes.get("last_analysis_date"))),
        ("Detections", format_stats(attributes.get("last_analysis_stats"))),
    ], engines)


def print_domain_report(domain, attributes, verdict, engines):
    _print_report(domain, verdict, [
        ("Registrar", attributes.get("registrar")),
        ("Created", format_timestamp(attributes.get("creation_date"))),
        ("Categories", format_categories(attributes.get("categories"))),
        ("Reputation", attributes.get("reputation")),
        ("Last analysis", format_timestamp(attributes.get("last_analysis_date"))),
        ("Detections", format_stats(attributes.get("last_analysis_stats"))),
    ], engines)


def print_file_report(file_hash, attributes, verdict, engines):
    _print_report(file_hash, verdict, [
        ("Name", attributes.get("meaningful_name")),
        ("Other names", format_list(attributes.get("names"))),
        ("Type", attributes.get("type_description")),
        ("Size", format_size(attributes.get("size"))),
        ("SHA-256", attributes.get("sha256")),
        ("Detections", format_stats(attributes.get("last_analysis_stats"))),
    ], engines)


def print_url_report(url, analysis, verdict, engines):
    _print_report(url, verdict, [
        ("Detections", format_stats(analysis.get("stats"))),
    ], engines)

def print_countdown(seconds_left):
    """Overwrite the same line with the remaining seconds."""
    print(f"\r[i] Rate limit reached. Retrying in {seconds_left:>2}s (Ctrl+C to cancel)",
          end="", flush=True)


def end_line():
    print()


def print_history(entries):
    """Print this session's lookups as a table."""
    if not entries:
        print_info("No lookups yet in this session.")
        return
    print_header("Lookup history")
    print(f"  {'Time':<8}  {'Type':<{KIND_WIDTH}} {'Verdict':<{VERDICT_WIDTH}} Indicator")
    for entry in entries:
        cached = "  (cached)" if entry.from_cache else ""
        print(f"  {entry.checked_at.strftime(TIME_FORMAT)}  {entry.kind:<{KIND_WIDTH}} "
              f"{entry.verdict:<{VERDICT_WIDTH}} {truncate(entry.indicator, INDICATOR_WIDTH)}{cached}")