"""Interactive menu: asks, validates, decides. No HTTP, no formatting."""

import time
from getpass import getpass

import display
import validators
import verdict
from client import POLL_INTERVAL_SECONDS, REQUESTS_PER_WINDOW
from exceptions import AuthError, NotFoundError, RateLimitError, VirusTotalError
from history import HistoryEntry

EXIT_CHOICE = "0"
PROMPT = "> "
COUNTDOWN_TICK_SECONDS = 1

KIND_IP = "IP"
KIND_DOMAIN = "Domain"
KIND_HASH = "Hash"
KIND_URL = "URL"


class ThreatIntelCLI:
    """Interactive menu loop around a VirusTotalClient."""

    def __init__(self, client):
        self.client = client
        self.history = []
        self.cache = {}  # (kind, indicator) -> API data, so repeats cost no request
        self.menu = {
            "1": ("Look up an IP address", self.lookup_ip),
            "2": ("Look up a domain", self.lookup_domain),
            "3": ("Look up a file hash", self.lookup_hash),
            "4": ("Scan a URL", self.scan_url),
            "5": ("View lookup history", self.show_history),
        }

    def run(self):
        """Verify the key, then show the menu until the user chooses Exit."""
        if not self._ensure_valid_key():
            print("Goodbye!")
            return
        while True:
            labels = {choice: label for choice, (label, _) in self.menu.items()}
            display.print_menu(labels, self.client.requests_used(), REQUESTS_PER_WINDOW, EXIT_CHOICE)
            choice = input(PROMPT).strip()
            if choice == EXIT_CHOICE:
                print("Goodbye!")
                return
            option = self.menu.get(choice)
            if option is None:
                display.print_error(f"Invalid choice '{choice}'. Enter a number from the menu.")
                continue
            _, handler = option
            self._run_safely(handler)

    # ---------- menu actions ----------

    def lookup_ip(self):
        self._lookup(KIND_IP, "IP address", validators.parse_ip, "8.8.8.8",
                     self.client.get_ip_report, display.print_ip_report)

    def lookup_domain(self):
        self._lookup(KIND_DOMAIN, "Domain", validators.parse_domain, "example.com",
                     self.client.get_domain_report, display.print_domain_report)

    def lookup_hash(self):
        self._lookup(KIND_HASH, "File hash (MD5 / SHA-1 / SHA-256)", validators.parse_hash,
                     "44d88612fea8a8f36de82e1278abb02f",
                     self.client.get_file_report, display.print_file_report)

    def scan_url(self):
        url = self._ask_valid("URL", validators.parse_url, "https://example.com")
        if url is None:
            return
        analysis, from_cache = self._fetch_cached(KIND_URL, url, self._scan)
        if analysis is None:
            self._report_not_found(KIND_URL, url)
            return
        result = verdict.classify(analysis.get("stats"))
        self._record(KIND_URL, url, result, from_cache)
        display.print_url_report(url, analysis, result, verdict.flagged_engines(analysis.get("results")))

    def show_history(self):
        display.print_history(self.history)

    # ---------- shared flows ----------

    def _lookup(self, kind, prompt, parse, example, fetch, print_report):
        """Shared flow: ask, validate, fetch (or use cache), classify, record, print."""
        indicator = self._ask_valid(prompt, parse, example)
        if indicator is None:
            return
        attributes, from_cache = self._fetch_cached(kind, indicator, fetch)
        if attributes is None:
            self._report_not_found(kind, indicator)
            return
        result = verdict.classify(attributes.get("last_analysis_stats"), attributes.get("reputation"))
        self._record(kind, indicator, result, from_cache)
        engines = verdict.flagged_engines(attributes.get("last_analysis_results"))
        print_report(indicator, attributes, result, engines)

    def _scan(self, url):
        """Submit a URL and wait for its analysis to finish."""
        analysis_id = self._call_api(self.client.submit_url, url)
        display.print_info(f"Submitted. Checking every {POLL_INTERVAL_SECONDS}s (Ctrl+C to cancel)...")
        return self.client.wait_for_analysis(analysis_id, on_poll=display.print_poll_status)

    def _fetch_cached(self, kind, indicator, fetch):
        """Return (data, from_cache). data is None if VirusTotal has no record."""
        key = (kind, indicator)
        if key in self.cache:
            display.print_info("Shown from this session's cache (no request used).")
            return self.cache[key], True
        try:
            data = self._call_api(fetch, indicator)
        except NotFoundError:
            return None, False
        self.cache[key] = data
        return data, False

    def _call_api(self, function, *args):
        """Call the API; if our local rate limit is full, count down and retry once."""
        try:
            return function(*args)
        except RateLimitError as error:
            if not error.wait_seconds:
                raise  # server-side quota (maybe daily): waiting won't help
            self._wait_with_countdown(error.wait_seconds)
            return function(*args)

    def _wait_with_countdown(self, seconds):
        try:
            for seconds_left in range(seconds, 0, -1):
                display.print_countdown(seconds_left)
                time.sleep(COUNTDOWN_TICK_SECONDS)
        finally:
            display.end_line()

    def _record(self, kind, indicator, result, from_cache=False):
        self.history.append(HistoryEntry(kind, indicator, result, from_cache))

    def _report_not_found(self, kind, indicator):
        display.print_info(f"{indicator} was not found in VirusTotal.")
        self._record(kind, indicator, verdict.VERDICT_NOT_FOUND)

    # ---------- startup ----------

    def _ensure_valid_key(self):
        """Check the key; on rejection, let the user paste a new one. False = quit."""
        while True:
            try:
                self._call_api(self.client.check_api_key)
                display.print_info("API key accepted.")
                return True
            except AuthError:
                display.print_error("VirusTotal rejected the API key.")
                new_key = getpass("Paste a valid key (hidden, Enter to quit): ").strip()
                if not new_key:
                    return False
                self.client.set_api_key(new_key)
            except VirusTotalError as error:
                display.print_error(f"Could not verify the API key ({error}). Continuing anyway.")
                return True

    # ---------- safety net ----------

    def _run_safely(self, handler):
        """Run a menu action; any error returns to the menu with a clear message."""
        try:
            handler()
        except KeyboardInterrupt:
            print()
            display.print_info("Cancelled. Back to the menu.")
        except RateLimitError as error:
            self._report_rate_limit(error)
        except AuthError as error:
            display.print_error(f"{error} Get your key from your VirusTotal profile and restart.")
        except VirusTotalError as error:
            display.print_error(str(error))

    @staticmethod
    def _report_rate_limit(error):
        if error.wait_seconds:
            display.print_error(f"{error} Try again in {error.wait_seconds} seconds.")
        else:
            display.print_error(f"{error} This may be the daily quota; try again later.")

    # ---------- input helpers ----------

    @staticmethod
    def _ask(prompt):
        """Ask for input. Returns stripped text, or None if the user pressed Enter."""
        text = input(prompt).strip()
        return text or None

    def _ask_valid(self, prompt, parse, example):
        """Ask until `parse` accepts the input. Returns the parsed value, or None on Enter."""
        while True:
            text = self._ask(f"{prompt} (Enter to go back): ")
            if text is None:
                return None
            value = parse(text)
            if value is not None:
                return value
            display.print_error(f"'{text}' is not valid. Example: {example}")