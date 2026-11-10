"""Authenticated, same-origin HTTP adapter for the constrained VPN controller."""

import argparse
import getpass
import hmac
import json
import os
import secrets
import threading
import time
from pathlib import Path

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError
from flask import Flask, jsonify, request
from werkzeug.exceptions import HTTPException

from vpn_control import ALLOWED_MINUTES, MAX_TARGETS, client

COOKIE = "__Host-vpn-session"
SESSION_SECONDS = 8 * 60 * 60
MAX_SESSIONS = 128
MAX_RESPONSE = 262144


def create_app(*, config=None, credentials=None, backend=None, clock=time.monotonic):
    """Load public configuration and a runtime credential; fail closed if absent.

    Run one Gunicorn worker with threads: sessions, rate limits and action
    serialization are intentionally local to that worker. Restart logs users out.
    Tests inject synthetic credentials and a controller without network privileges.
    """
    if config is None:
        config = json.loads(Path(os.environ["VPN_API_CONFIG"]).read_text())
    if credentials is None:
        credentials = json.loads((Path(os.environ["CREDENTIALS_DIRECTORY"]) / "api-auth.json").read_text())
    if set(credentials) != {"username", "passwordHash"}:
        raise ValueError("Authentication file must contain username and passwordHash only.")
    username, password_hash = credentials["username"], credentials["passwordHash"]
    if not isinstance(username, str) or not 1 <= len(username) <= 128:
        raise ValueError("Invalid operator username.")
    if not isinstance(password_hash, str) or not password_hash.startswith("$argon2id$"):
        raise ValueError("Authentication requires an encoded Argon2id hash.")
    extract_parameters(password_hash)
    origin = config["publicOrigin"]
    if not isinstance(origin, str) or not origin.startswith("https://") or origin.endswith("/"):
        raise ValueError("publicOrigin must be an HTTPS origin without a trailing slash.")

    app = Flask(__name__)
    app.config.update(MAX_CONTENT_LENGTH=16384)
    hasher = PasswordHasher()
    sessions = {}
    attempts = []
    auth_lock = threading.Lock()
    action_lock = threading.Lock()
    backend = backend or (lambda payload: client(config["socket"], payload))

    def error(message, code):
        return jsonify(ok=False, message=message), code

    def current_session():
        token = request.cookies.get(COOKIE, "")
        now = clock()
        with auth_lock:
            expired = [key for key, value in sessions.items() if value["expires"] <= now]
            for key in expired:
                del sessions[key]
            return sessions.get(token)

    @app.before_request
    def authorize():
        if request.method == "POST" and request.headers.get("Origin") != origin:
            return error("Same-origin requests required.", 403)
        if request.path == "/api/v1/login" and request.method == "POST":
            return None
        session = current_session()
        if session is None:
            return error("Sign in required.", 401)
        if request.method not in {"GET", "HEAD"} and not hmac.compare_digest(
            request.headers.get("X-CSRF-Token", "").encode(), session["csrfToken"].encode()
        ):
            return error("Invalid CSRF token.", 403)
        return None

    @app.after_request
    def secure_headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none'"
        return response

    @app.errorhandler(HTTPException)
    def http_error(exception):
        return error(exception.name, exception.code)

    def body(keys):
        payload = request.get_json()
        if not isinstance(payload, dict) or set(payload) != set(keys):
            return None
        return payload

    @app.post("/api/v1/login")
    def login():
        payload = body({"username", "password"})
        if payload is None or not all(isinstance(value, str) for value in payload.values()):
            return error("Expected username and password.", 400)
        if len(payload["username"]) > 128 or len(payload["password"]) > 1024:
            return error("Invalid credentials.", 401)
        now = clock()
        # One operator endpoint: a global limit cannot be bypassed with forwarded
        # IP headers, and bounds expensive Argon2 work across all worker threads.
        with auth_lock:
            attempts[:] = [attempt for attempt in attempts if attempt > now - 60]
            if len(attempts) >= 5:
                return error("Too many login attempts. Retry in one minute.", 429)
            attempts.append(now)
        try:
            valid = hasher.verify(password_hash, payload["password"])
        except (VerificationError, InvalidHashError):
            valid = False
        if not valid or not hmac.compare_digest(payload["username"].encode(), username.encode()):
            return error("Invalid credentials.", 401)
        token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        with auth_lock:
            # Avoid keeping a caller's previous session after another login.
            sessions.pop(request.cookies.get(COOKIE, ""), None)
            expired = [key for key, value in sessions.items() if value["expires"] <= now]
            for key in expired:
                del sessions[key]
            if len(sessions) >= MAX_SESSIONS:
                return error("Session limit reached. Retry after existing sessions expire.", 429)
            sessions[token] = {"csrfToken": csrf, "expires": now + SESSION_SECONDS}
        response = jsonify(ok=True, csrfToken=csrf)
        response.set_cookie(
            COOKIE, token, max_age=SESSION_SECONDS, secure=True, httponly=True, samesite="Strict", path="/"
        )
        return response

    @app.get("/api/v1/session")
    def session_info():
        session = current_session()
        if session is None:
            return error("Sign in required.", 401)
        return jsonify(ok=True, csrfToken=session["csrfToken"])

    @app.post("/api/v1/logout")
    def logout():
        if body(set()) is None:
            return error("Expected an empty object.", 400)
        with auth_lock:
            sessions.pop(request.cookies.get(COOKIE, ""), None)
        response = jsonify(ok=True)
        response.delete_cookie(COOKIE, secure=True, httponly=True, samesite="Strict", path="/")
        return response

    def dispatch(payload):
        try:
            # Do not queue arbitrary numbers of slow relay changes. The backend
            # also serializes its own Unix-socket protocol.
            if not action_lock.acquire(blocking=False):
                return error("Another controller action is running. Retry shortly.", 409)
            try:
                response = backend(payload)
            finally:
                action_lock.release()
            if not isinstance(response, dict) or type(response.get("ok")) is not bool:
                raise ValueError("Invalid controller response.")
            message = response["message"]
            if not isinstance(message, str) or len(message) > MAX_RESPONSE:
                raise ValueError("Invalid controller message.")
            if not response["ok"]:
                return error(message, 409)
            if payload["action"] == "devices":
                devices = json.loads(message)
                if not isinstance(devices, list):
                    raise ValueError("Invalid device list.")
                return jsonify(ok=True, devices=devices)
            return jsonify(ok=True, message=message)
        except (OSError, ValueError, KeyError, TypeError):
            return error("VPN controller unavailable. Privacy guards remain active.", 503)

    @app.get("/api/v1/status")
    def status():
        return dispatch({"action": "status"})

    @app.get("/api/v1/devices")
    def devices():
        return dispatch({"action": "devices"})

    @app.get("/api/v1/relays")
    def relays():
        choices = [{"id": "configured", "label": config["configuredRelayTitle"]}]
        choices += sorted(
            [{"id": key, "label": value["label"]} for key, value in config["relays"].items()],
            key=lambda item: item["label"],
        )
        return jsonify(ok=True, relays=choices, durations=list(ALLOWED_MINUTES))

    def targets(payload):
        value = payload.get("targets")
        if value == "all":
            return "all"
        if isinstance(value, list) and 1 <= len(value) <= MAX_TARGETS:
            if all(isinstance(address, str) and "," not in address and address != "all" for address in value):
                return ",".join(value)
        return None

    @app.post("/api/v1/bypass")
    def bypass():
        payload = body({"targets", "minutes"})
        if payload is None or type(payload["minutes"]) is not int or payload["minutes"] not in ALLOWED_MINUTES:
            return error("Expected targets and duration of 5, 15, 30, or 60 minutes.", 400)
        selected = targets(payload)
        if selected is None:
            return error("Choose all or between 1 and 64 IPv4 addresses.", 400)
        return dispatch({"action": "bypass", "targets": selected, "minutes": payload["minutes"]})

    @app.post("/api/v1/restore")
    def restore():
        payload = body({"targets"})
        if payload is None or (selected := targets(payload)) is None:
            return error("Choose all or between 1 and 64 IPv4 addresses.", 400)
        return dispatch({"action": "restore", "targets": selected})

    @app.post("/api/v1/switch")
    def switch():
        payload = body({"relay"})
        if payload is None or not isinstance(payload["relay"], str):
            return error("Choose an approved relay.", 400)
        if payload["relay"] != "configured" and payload["relay"] not in config["relays"]:
            return error("Choose an approved relay.", 400)
        return dispatch({"action": "switch", "relay": payload["relay"]})

    return app


def password_main():
    """Print credential JSON from a hidden terminal prompt, never argv or Nix."""
    parser = argparse.ArgumentParser(description="Generate a runtime API authentication file on stdout.")
    parser.add_argument("--username", default="operator")
    args = parser.parse_args()
    password = getpass.getpass("New portal password: ")
    if len(password) < 12:
        parser.error("Use at least 12 characters.")
    if password != getpass.getpass("Confirm password: "):
        parser.error("Passwords do not match.")
    print(json.dumps({"username": args.username, "passwordHash": PasswordHasher().hash(password)}))


if __name__ == "__main__":
    password_main()
