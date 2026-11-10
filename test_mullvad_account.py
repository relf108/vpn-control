"""Expiry checks use synthetic account data, never actual provider requests."""

import datetime as dt
import json
import tempfile
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import patch

from mullvad_account import (
    ACCOUNT_URL,
    AUTH_URL,
    REFRESH_SECONDS,
    RETRY_SECONDS,
    AccountExpiryCache,
    NoRedirect,
    fetch_json,
)


class AccountTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.credential = Path(self.directory.name) / "account"
        self.credential.write_text("0000 0000 0000 0000\n")
        self.calls = []
        self.now = 100
        self.provider_failure = False
        self.expiry = "2027-01-24T12:00:00Z"

        def fetch(url, **kwargs):
            self.calls.append((url, kwargs))
            if self.provider_failure:
                raise urllib.error.URLError("synthetic provider failure")
            if url == AUTH_URL:
                return {"access_token": "synthetic-token"}
            return {"expiry": self.expiry, "id": "never-expose-account-id"}

        self.cache = AccountExpiryCache(
            self.credential,
            fetch=fetch,
            clock=lambda: self.now,
            now=lambda: dt.datetime(2026, 11, 10, tzinfo=dt.UTC),
        )

    def test_disabled_lookup_never_reads_files_or_calls_provider(self):
        cache = AccountExpiryCache(fetch=lambda *_: self.fail("Unexpected network call"))
        self.assertEqual(cache()["state"], "notConfigured")
        self.assertIsNone(cache()["expiry"])

    def test_returns_expiry_only_and_caches_success(self):
        result = self.cache()
        self.assertEqual(result["expiry"], self.expiry)
        self.assertEqual(result["checkedAt"], "2026-11-10T00:00:00Z")
        self.assertFalse(result["stale"])
        self.assertEqual(self.calls[0], (AUTH_URL, {"body": {"account_number": "0000000000000000"}}))
        self.assertEqual(self.calls[1], (ACCOUNT_URL, {"token": "synthetic-token"}))
        for secret in ("0000000000000000", "synthetic-token", "never-expose-account-id"):
            self.assertNotIn(secret, json.dumps(result))
        self.cache()
        self.assertEqual(len(self.calls), 2)
        self.now += REFRESH_SECONDS
        self.cache()
        self.assertEqual(len(self.calls), 4)

    def test_failure_keeps_a_clearly_stale_last_known_expiry(self):
        original = self.cache()
        self.now += REFRESH_SECONDS
        self.provider_failure = True
        failed = self.cache()
        self.assertEqual(failed["expiry"], original["expiry"])
        self.assertEqual(failed["checkedAt"], original["checkedAt"])
        self.assertTrue(failed["stale"])
        count = len(self.calls)
        self.cache()
        self.assertEqual(len(self.calls), count)
        self.now += RETRY_SECONDS
        self.cache()
        self.assertEqual(len(self.calls), count + 1)

    def test_first_failure_is_unknown_not_an_invented_expiry(self):
        self.provider_failure = True
        result = self.cache()
        self.assertEqual(result["state"], "unavailable")
        self.assertIsNone(result["expiry"])
        self.assertIsNone(result["checkedAt"])

    def test_invalid_or_missing_credential_never_reaches_provider(self):
        self.credential.write_text("invalid-private-value")
        self.assertEqual(self.cache()["state"], "unavailable")
        self.assertNotIn("invalid-private-value", json.dumps(self.cache()))
        self.assertEqual(self.calls, [])
        self.credential.unlink()
        self.now += RETRY_SECONDS
        self.assertEqual(self.cache()["state"], "unavailable")

    def test_expiry_must_have_a_timezone_and_may_be_in_the_past(self):
        self.expiry = "2026-01-01T00:00:00"
        self.assertIsNone(self.cache()["expiry"])
        self.now += RETRY_SECONDS
        self.expiry = "2020-01-01T12:00:00+02:00"
        self.assertEqual(self.cache()["expiry"], "2020-01-01T10:00:00Z")

    def test_redirects_and_unapproved_urls_cannot_leak_credentials(self):
        self.assertIsNone(NoRedirect().redirect_request(None, None, 302, "redirect", {}, "https://example.com"))
        with self.assertRaises(ValueError):
            fetch_json("https://example.com", token="synthetic-token")  # noqa: S106 - Synthetic test credential.

    def test_transport_bounds_response_and_uses_only_fixed_https_urls(self):
        with patch("urllib.request.build_opener") as build:
            response = build.return_value.open.return_value.__enter__.return_value
            response.read.return_value = b'{"expiry":"2027-01-24T12:00:00Z"}'
            self.assertEqual(fetch_json(ACCOUNT_URL, token="synthetic-token")["expiry"], self.expiry)  # noqa: S106 - Synthetic.
            request = build.return_value.open.call_args.args[0]
            self.assertEqual(request.full_url, ACCOUNT_URL)
            self.assertNotIn("synthetic-token", request.full_url)
            self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-token")
            self.assertEqual(build.return_value.open.call_args.kwargs["timeout"], 5)
            response.read.return_value = b"x" * 65537
            with self.assertRaises(ValueError):
                fetch_json(ACCOUNT_URL)


if __name__ == "__main__":
    unittest.main()
