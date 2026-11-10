"""Smoke-test the installed Gunicorn wrapper over loopback with fake credentials."""

import contextlib
import http.client
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from argon2 import PasswordHasher


def main():
    """Keep every fixture temporary and every listener on loopback."""
    with tempfile.TemporaryDirectory() as directory, socket.socket() as listener:
        root = Path(directory)
        credentials = root / "api-auth.json"
        credentials.write_text(
            json.dumps({"username": "operator", "passwordHash": PasswordHasher().hash("synthetic-password")})
        )
        credentials.chmod(0o600)
        config = root / "config.json"
        origin = "https://192.0.2.1:8443"
        config.write_text(
            json.dumps(
                {
                    "publicOrigin": origin,
                    "socket": str(root / "absent.sock"),
                    "configuredRelayTitle": "Synthetic default",
                    "relays": {},
                }
            )
        )
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        control_directory = root / "management-socket-must-not-exist"
        environment = {
            **os.environ,
            "CREDENTIALS_DIRECTORY": directory,
            "VPN_API_CONFIG": str(config),
            "XDG_RUNTIME_DIR": str(control_directory),
        }
        with (root / "server.log").open("w+") as log:
            process = subprocess.Popen(  # noqa: S603 - Nix supplies the installed wrapper; no shell or user commands.
                [sys.argv[1], "--bind", f"fd://{listener.fileno()}"],
                env=environment,
                pass_fds=(listener.fileno(),),
                stdout=log,
                stderr=log,
            )
            listener.close()

            def call(method, path, data=None, cookie="", csrf=""):
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
                try:
                    headers = {"Origin": origin, "Content-Type": "application/json", "Cookie": cookie}
                    headers["X-CSRF-Token"] = csrf
                    connection.request(
                        method, "/api/v1/" + path, json.dumps(data) if data is not None else None, headers
                    )
                    response = connection.getresponse()
                    return response.status, json.loads(response.read()), response.getheader("Set-Cookie", "")
                finally:
                    connection.close()

            def require(condition, label):
                if not condition:
                    raise RuntimeError(label)

            try:
                deadline = time.monotonic() + 10
                while True:
                    try:
                        code, _, _ = call("GET", "session")
                        break
                    except OSError:
                        if process.poll() is not None or time.monotonic() >= deadline:
                            raise RuntimeError("Installed API did not start.") from None
                        time.sleep(0.05)
                require(code == 401, "Unauthenticated session must be rejected.")
                require(not control_directory.exists(), "Unneeded Gunicorn management socket must stay disabled.")
                code, data, cookie = call("POST", "login", {"username": "operator", "password": "synthetic-password"})
                require(code == 200 and "HttpOnly" in cookie and "Secure" in cookie, "Secure login failed.")
                cookie = cookie.split(";", 1)[0]
                csrf = data["csrfToken"]
                require(call("POST", "restore", {"targets": "all"}, cookie)[0] == 403, "CSRF guard failed.")
                require(call("GET", "relays", cookie=cookie)[0] == 200, "Authenticated catalog failed.")
                code, account, _ = call("GET", "account", cookie=cookie)
                require(code == 200 and account["state"] == "notConfigured", "Optional account lookup failed.")
                require(set(account) == {"ok", "state", "expiry", "checkedAt", "stale"}, "Unsafe account response.")
                require(call("GET", "status", cookie=cookie)[0] == 503, "Missing controller must fail safely.")
                require(call("POST", "logout", {}, cookie, csrf)[0] == 200, "Logout failed.")
                require(call("GET", "session", cookie=cookie)[0] == 401, "Logout did not revoke session.")
                print("Installed API smoke passed: login, cookie, CSRF, catalog, fail-closed backend, logout.")
            finally:
                process.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=10)
                if process.poll() is None:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
