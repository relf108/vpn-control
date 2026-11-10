"""Read-only account-credit expiry checks; never expose the account credential."""

import datetime as dt
import getpass
import json
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

AUTH_URL = "https://api.mullvad.net/auth/v1/token"
ACCOUNT_URL = "https://api.mullvad.net/accounts/v1/accounts/me"
REFRESH_SECONDS = 6 * 60 * 60
RETRY_SECONDS = 5 * 60
MAX_RESPONSE = 65536


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward authentication material to a redirect destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def fetch_json(url, *, body=None, token=None):
    """Use fixed HTTPS endpoints, verified TLS, bounded reads, and no proxies."""
    if url not in (AUTH_URL, ACCOUNT_URL):
        raise ValueError("Unsupported Mullvad endpoint.")
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    if token is not None:
        headers["Authorization"] = "Bearer " + token
    request = urllib.request.Request(  # noqa: S310 - Endpoint allowlist above permits only Mullvad HTTPS.
        url, data=json.dumps(body).encode() if body is not None else None, headers=headers
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=5) as response:
        contents = response.read(MAX_RESPONSE + 1)
    if len(contents) > MAX_RESPONSE:
        raise ValueError("Oversized Mullvad response.")
    return json.loads(contents)


def normalize_account(value):
    """Accept the 16-digit account number, optionally grouped with whitespace."""
    number = "".join(value.split())
    if re.fullmatch(r"[0-9]{16}", number) is None:
        raise ValueError("Expected a 16-digit Mullvad account number.")
    return number


class AccountExpiryCache:
    """Cache safe expiry metadata, retry failures slowly, and retain stale dates.

    The credential is read from the explicit systemd credential copy only. The
    account number and access token never appear in responses, URLs, or logs.
    This helper cannot rotate keys, top up credit, or change VPN policy.
    """

    def __init__(self, credential=None, *, fetch=fetch_json, clock=time.monotonic, now=None):
        self.credential = credential
        self.fetch = fetch
        self.clock = clock
        self.now = now or (lambda: dt.datetime.now(dt.UTC))
        self.lock = threading.Lock()
        self.next_refresh = 0
        self.snapshot = {"state": "notConfigured", "expiry": None, "checkedAt": None, "stale": False}

    def __call__(self):
        with self.lock:
            if self.credential is None:
                return dict(self.snapshot)
            if self.clock() < self.next_refresh:
                return dict(self.snapshot)
            try:
                with Path(self.credential).open() as stream:
                    value = stream.read(257)
                if len(value) > 256:
                    raise ValueError("Invalid account credential file.")
                number = normalize_account(value)
                auth = self.fetch(AUTH_URL, body={"account_number": number})
                token = auth["access_token"]
                if not isinstance(token, str) or not token or len(token) > 4096 or not token.isascii():
                    raise ValueError("Invalid access token response.")
                if any(ord(character) < 33 or ord(character) > 126 for character in token):
                    raise ValueError("Invalid access token response.")
                account = self.fetch(ACCOUNT_URL, token=token)
                expiry = dt.datetime.fromisoformat(account["expiry"])
                if expiry.tzinfo is None:
                    raise ValueError("Account expiry must include a timezone.")
                self.snapshot = {
                    "state": "available",
                    "expiry": expiry.astimezone(dt.UTC).isoformat().replace("+00:00", "Z"),
                    "checkedAt": self.now().astimezone(dt.UTC).isoformat().replace("+00:00", "Z"),
                    "stale": False,
                }
                self.next_refresh = self.clock() + REFRESH_SECONDS
            except (OSError, ValueError, KeyError, TypeError, AttributeError):
                self.snapshot = {
                    **self.snapshot,
                    "state": "available" if self.snapshot["expiry"] is not None else "unavailable",
                    "stale": self.snapshot["expiry"] is not None,
                }
                self.next_refresh = self.clock() + RETRY_SECONDS
            return dict(self.snapshot)


def main():
    """Print a credential from a hidden prompt for root-owned runtime storage."""
    print(normalize_account(getpass.getpass("Mullvad account number: ")))


if __name__ == "__main__":
    main()
