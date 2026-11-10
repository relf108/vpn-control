"""Exercise authentication and HTTP boundaries with synthetic credentials only."""

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from argon2 import PasswordHasher

from vpn_api import COOKIE, SESSION_SECONDS, create_app


class ApiTests(unittest.TestCase):
    """No root, real profiles, or network access required."""

    @classmethod
    def setUpClass(cls):
        cls.credentials = {
            "username": "operator",
            "passwordHash": PasswordHasher(time_cost=1, memory_cost=8192).hash("synthetic-password"),
        }

    def setUp(self):
        self.now = 1000
        self.calls = []
        self.reply = {"ok": True, "message": "Completed safely."}
        self.config = {
            "publicOrigin": "https://192.0.2.1:8443",
            "socket": "/not/a/real/socket",
            "configuredRelayTitle": "Configured default",
            "relays": {"test": {"label": "Test region"}},
        }

        def backend(payload):
            self.calls.append(payload)
            return self.reply

        self.app = create_app(config=self.config, credentials=self.credentials, backend=backend, clock=lambda: self.now)
        self.client = self.app.test_client()
        self.csrf = ""

    def post(self, path, payload, *, origin=True, csrf=True):
        headers = {}
        if origin:
            headers["Origin"] = self.config["publicOrigin"]
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        return self.client.post("/api/v1/" + path, json=payload, headers=headers, base_url=self.config["publicOrigin"])

    def login(self):
        response = self.post("login", {"username": "operator", "password": "synthetic-password"})
        self.assertEqual(response.status_code, 200)
        self.csrf = response.json["csrfToken"]
        return response

    def get(self, path):
        return self.client.get("/api/v1/" + path, base_url=self.config["publicOrigin"])

    def test_unauthenticated_reads_and_writes_never_reach_controller(self):
        for path in ("status", "devices", "relays", "session"):
            self.assertEqual(self.get(path).status_code, 401)
        self.assertEqual(self.post("restore", {"targets": "all"}).status_code, 401)
        self.assertEqual(self.calls, [])

    def test_session_cookie_is_secure_and_not_javascript_readable(self):
        response = self.login()
        cookie = response.headers["Set-Cookie"]
        for flag in (COOKIE, "Secure", "HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertEqual(self.get("session").json["csrfToken"], self.csrf)
        self.assertEqual(self.get("status").headers["Cache-Control"], "no-store")

    def test_logout_revokes_server_side_session(self):
        self.login()
        old_cookie = self.client.get_cookie(COOKIE, domain="192.0.2.1").value
        self.assertEqual(self.post("logout", {}).status_code, 200)
        self.client.set_cookie(COOKIE, old_cookie, domain="192.0.2.1")
        self.assertEqual(self.get("session").status_code, 401)

    def test_session_expires(self):
        self.login()
        self.now += SESSION_SECONDS
        self.assertEqual(self.get("status").status_code, 401)

    def test_csrf_and_origin_required(self):
        self.login()
        self.assertEqual(self.post("restore", {"targets": "all"}, csrf=False).status_code, 403)
        self.assertEqual(self.post("restore", {"targets": "all"}, origin=False).status_code, 403)
        self.assertEqual(self.calls, [])

    def test_login_rejects_cross_origin_and_wrong_password(self):
        payload = {"username": "operator", "password": "incorrect"}
        self.assertEqual(self.post("login", payload, origin=False).status_code, 403)
        self.assertEqual(self.post("login", payload).status_code, 401)
        self.assertEqual(self.get("session").status_code, 401)

    def test_rate_limit_cannot_be_bypassed_with_forwarded_headers(self):
        for _ in range(5):
            self.assertEqual(self.post("login", {"username": "no", "password": "wrong"}).status_code, 401)
        self.assertEqual(self.post("login", {"username": "no", "password": "wrong"}).status_code, 429)
        self.now += 61
        self.login()

    def test_exact_action_schema_and_duration(self):
        self.login()
        for payload in (
            {"targets": "all", "minutes": True},
            {"targets": "all", "minutes": 999},
            {"targets": "all", "minutes": 15, "exec": "sh"},
            {"targets": ["all"], "minutes": 15},
            {"targets": [], "minutes": 15},
            {"targets": ["192.0.2.2,192.0.2.3"], "minutes": 15},
        ):
            self.assertEqual(self.post("bypass", payload).status_code, 400)
        self.assertEqual(self.calls, [])

    def test_selected_and_global_actions_use_constrained_protocol(self):
        self.login()
        self.assertEqual(self.post("bypass", {"targets": ["192.0.2.2"], "minutes": 15}).status_code, 200)
        self.assertEqual(self.calls[-1], {"action": "bypass", "targets": "192.0.2.2", "minutes": 15})
        self.assertEqual(self.post("restore", {"targets": "all"}).status_code, 200)
        self.assertEqual(self.calls[-1], {"action": "restore", "targets": "all"})

    def test_device_response_is_structured(self):
        self.login()
        self.reply = {"ok": True, "message": json.dumps([{"address": "192.0.2.2"}])}
        self.assertEqual(self.get("devices").json["devices"], [{"address": "192.0.2.2"}])

    def test_relay_allowlist_does_not_expose_secret_profile(self):
        self.login()
        self.assertEqual(self.get("relays").json["relays"][0]["id"], "configured")
        self.assertEqual(self.post("switch", {"relay": "unapproved"}).status_code, 400)
        self.assertEqual(self.post("switch", {"relay": "configured"}).status_code, 200)

    def test_failures_are_safe_and_not_successes(self):
        self.login()
        self.reply = {"ok": False, "message": "Privacy guards remain active."}
        self.assertEqual(self.get("status").status_code, 409)
        self.reply = {"secret": "never returned"}
        response = self.get("status")
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("never returned", response.text)

    def test_missing_or_invalid_credentials_fail_closed(self):
        for credentials in ({}, {"username": "operator", "passwordHash": "plaintext"}):
            with self.assertRaises(ValueError):
                create_app(config=self.config, credentials=credentials)

    def test_runtime_credentials_use_only_systemd_supplied_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "api-auth.json").write_text(json.dumps(self.credentials))
            config_path = root / "public-config.json"
            config_path.write_text(json.dumps(self.config))
            with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": directory, "VPN_API_CONFIG": str(config_path)}):
                app = create_app(backend=lambda _: self.reply)
                self.assertEqual(app.test_client().get("/api/v1/status").status_code, 401)
            (root / "api-auth.json").unlink()
            with patch.dict(os.environ, {"CREDENTIALS_DIRECTORY": directory}):
                with self.assertRaises(FileNotFoundError):
                    create_app(config=self.config)

    def test_oversized_body_rejected_before_controller(self):
        self.login()
        response = self.post("restore", {"targets": ["x" * 20000]})
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.calls, [])

    def test_non_ascii_csrf_is_rejected_without_internal_error(self):
        self.login()
        self.csrf = "invalid-\N{LATIN SMALL LETTER E WITH ACUTE}"
        self.assertEqual(self.post("restore", {"targets": "all"}).status_code, 403)


if __name__ == "__main__":
    unittest.main()
