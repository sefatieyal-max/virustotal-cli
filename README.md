# VirusTotal Threat Intel CLI

An interactive terminal tool that checks IP addresses, domains, file hashes and URLs against the [VirusTotal API v3](https://docs.virustotal.com/reference/overview) and gives a simple verdict: **MALICIOUS**, **SUSPICIOUS**, **CLEAN** or **NOT FOUND**.

## Requirements

- **Python 3.10+** (the code uses `match` / `case`)
- A free VirusTotal API key ([sign up](https://www.virustotal.com/gui/join-us), then copy the key from your profile)

## Setup

```bash
python -m venv .venv
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate

python -m pip install -r requirements.txt
```

## Authentication

The tool reads the key from the `VT_API_KEY` environment variable:

```powershell
# PowerShell
$env:VT_API_KEY="your-key-here"
```
```bash
# macOS / Linux
export VT_API_KEY="your-key-here"
```

If the variable is not set, the tool asks for the key with hidden input. On startup it checks the key with one request; if VirusTotal rejects it, you can paste a new one without restarting. The key is never printed or saved.

## Usage

```bash
python main.py
```

| Option | What it does |
|---|---|
| 1. Look up an IP address | IPv4 or IPv6: country, owner, network, reputation, detections |
| 2. Look up a domain | Registrar, creation date, categories, reputation, detections |
| 3. Look up a file hash | MD5 / SHA-1 / SHA-256: names, type, size, detections |
| 4. Scan a URL | Submits the URL, waits for the analysis, shows the result |
| 5. View lookup history | Everything checked in this session, with time and verdict |
| 0. Exit | |

Every report lists the engines that flagged the indicator, malicious first. Press **Enter** at any prompt to go back, and **Ctrl+C** to cancel the current action (or exit from the menu).

### Verdict rules

| Verdict | When |
|---|---|
| MALICIOUS | 3 or more engines say malicious |
| SUSPICIOUS | at least one malicious or suspicious detection, or a negative community reputation |
| CLEAN | no detections |
| NOT FOUND | VirusTotal has no record of the indicator |

## Project structure

| File | Responsibility |
|---|---|
| `main.py` | Entry point: reads the API key, starts the CLI, handles Ctrl+C |
| `cli.py` | Menu and user flow: asks, validates, decides. No HTTP, no formatting |
| `client.py` | All HTTP calls to VirusTotal. Never prints, never asks for input |
| `exceptions.py` | Custom exception hierarchy |
| `rate_limiter.py` | Client-side sliding-window rate limiter |
| `validators.py` | Pure input parsers: return a normalized value or `None` |
| `verdict.py` | Turns detection stats into a verdict |
| `display.py` | All formatting and printing |
| `history.py` | Immutable record of one lookup |
| `tests/` | pytest suite (no network needed) |

## Design decisions

- **One job per layer.** The client only talks HTTP, the CLI only runs the flow, display only prints. This keeps each part replaceable (e.g. swapping `requests` for another library touches only `client.py`) and testable on its own.
- **Custom exceptions.** HTTP errors are translated in one place (`_raise_for_error`) into `AuthError`, `NotFoundError`, `RateLimitError`, `ValidationError`, `NetworkError` and `AnalysisTimeoutError`, all under `VirusTotalError`. The CLI never sees `requests` exceptions. A 404 is treated as a valid result ("not found"), not a crash. Non-JSON responses (e.g. an HTML error page) are handled too.
- **Respecting the free-tier quota (4 requests/minute, 500/day).**
  - A client-side **sliding-window** rate limiter (a `deque` of `time.monotonic()` timestamps) blocks a request *before* it would exceed the limit. Unlike a counter reset every minute, it never allows a burst of more than 4 requests in any 60-second span.
  - When the local limit is reached, the CLI shows a countdown and retries once. If VirusTotal itself returns 429 (for example the daily quota), the tool does not retry and returns to the menu with a clear message.
  - The menu shows how many requests were used in the current minute.
  - A **session cache** keyed by `(type, normalized indicator)` means repeating a lookup costs no request.
- **Input validation before any request.** Every input is validated and normalized locally (e.g. IPv6 is shortened, hashes and domains are lowercased), so invalid input never wastes a request, and two spellings of the same indicator hit the same cache entry.
- **Async URL scans.** Submitting a URL returns an analysis id. The client polls every 15 seconds (or longer if the rate limiter requires it) for up to 120 seconds, reporting progress through a callback so the client itself never prints.
- **Secrets.** The key comes from an environment variable or hidden input, and is never printed or logged.

## Known limitations

- **Cache has no expiry.** Results stay cached for the whole session; a verdict that changes on VirusTotal during a long session will not be seen until restart. A TTL would fix this.
- **URL scans always submit a new scan** (1 request plus 2-4 polls). Fetching the existing report first (`GET /urls/{id}`) and scanning only if none exists would usually cost a single request.
- **The startup key check uses one request** out of the 4 per minute.
- **The rate limiter's state is in memory.** After a restart, or if the same key is used elsewhere, VirusTotal may still return 429; this is handled but not prevented.
- **The same file looked up by MD5 and then by SHA-256** is cached as two separate entries.

## Running the tests

```bash
python -m pytest -v
```

The suite runs in under a second and never touches the network:

- **Validators and verdict:** normal, boundary and invalid inputs (`parametrize`).
- **Rate limiter:** the clock is controlled with `unittest.mock.patch`, so no test waits.
- **Client:** VirusTotal responses (200, 401, 404, 429, HTML instead of JSON) are faked with the `responses` library.
- **CLI:** a `FakeClient` is injected to prove that the cache saves requests and that invalid input never reaches the API.
