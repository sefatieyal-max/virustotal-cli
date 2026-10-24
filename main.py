"""Entry point: reads the API key and starts the CLI."""

import os
import sys
from getpass import getpass

from cli import ThreatIntelCLI
from client import VirusTotalClient

API_KEY_ENV_VAR = "VT_API_KEY"
EXIT_SUCCESS = 0
EXIT_FAILURE = 1


def read_api_key():
    """Return the API key from the environment, or ask for it (hidden). None if empty."""
    key = os.environ.get(API_KEY_ENV_VAR, "").strip()
    if key:
        return key
    key = getpass(f"{API_KEY_ENV_VAR} is not set. Paste your VirusTotal API key (hidden): ")
    return key.strip() or None


def main():
    try:
        api_key = read_api_key()
        if api_key is None:
            print("No API key provided. Exiting.")
            return EXIT_FAILURE
        ThreatIntelCLI(VirusTotalClient(api_key)).run()
        return EXIT_SUCCESS
    except (KeyboardInterrupt, EOFError):
        print("\nGoodbye!")
        return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())