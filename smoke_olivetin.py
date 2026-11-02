"""Test generated OliveTin authentication, ACLs, forms, and argv in a private netns.

All controller executables are replaced with an argv-printing stub. This test
never connects to the privileged controller and never changes a live network.
"""

import argparse
import http.cookiejar
import json
import os
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path


def main() -> None:
    """Run the actual packaged portal using only temporary synthetic credentials."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--settings", type=Path, required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        environment = dict(os.environ, VPN_CONTROL_HOST_NETNS=os.readlink("/proc/self/ns/net"))
        result = subprocess.run(  # noqa: S603 - Fixed namespace wrapper, no shell.
            [  # noqa: S607
                "unshare",
                "--user",
                "--map-root-user",
                "--net",
                sys.executable,
                __file__,
                "--settings",
                str(args.settings),
            ],
            env=environment,
            check=False,
        )
        raise SystemExit(result.returncode)
    if not os.environ.get("VPN_CONTROL_HOST_NETNS") or os.environ["VPN_CONTROL_HOST_NETNS"] == os.readlink(
        "/proc/self/ns/net"
    ):
        raise SystemExit("Run as an ordinary user; this test creates an isolated namespace.")
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)  # noqa: S607
    settings = json.loads(args.settings.read_text())
    settings["ListenAddressSingleHTTPFrontend"] = "127.0.0.1:1337"
    settings["checkForUpdates"] = False
    password = secrets.token_urlsafe(32)
    argon = shutil.which("argon2")
    binary = shutil.which("OliveTin")
    if argon is None or binary is None:
        raise SystemExit("Use nix develop with libargon2 and olivetin-3k available.")
    hashed = subprocess.run(  # noqa: S603 - Trusted executable, synthetic password on stdin only.
        [argon, secrets.token_hex(16), "-id", "-t", "2", "-m", "16", "-p", "1", "-l", "32", "-e"],
        input=password,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    settings["authLocalUsers"]["users"] = [
        {"username": "test-operator", "usergroup": "vpn-operators", "password": hashed}
    ]
    for action in settings["actions"]:
        action["exec"] = [sys.executable, "-c", "import json,sys; print(json.dumps(sys.argv[1:]))", *action["exec"][1:]]
        action["execOnStartup"] = False
        action["execOnCron"] = []
    cookies = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(cookies))

    def api(method: str, data: dict) -> tuple[int, dict]:
        request = urllib.request.Request(
            "http://127.0.0.1:1337/api/" + method,
            data=json.dumps(data).encode(),
            headers={"Content-Type": "application/json"},
        )
        try:
            with opener.open(request, timeout=10) as response:
                return response.status, json.load(response)
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def action(name: str, arguments: dict) -> tuple[int, dict]:
        return api(
            "StartActionAndWait",
            {
                "actionId": name,
                "arguments": [{"name": key, "value": value} for key, value in arguments.items()],
            },
        )

    def check(label: str, condition: bool, response: object = "") -> None:
        if not condition:
            raise AssertionError(f"{label}: {response}")
        print("PASS:", label, flush=True)

    def output(response: dict) -> list:
        log = response.get("logEntry", response.get("log_entry", {}))
        return json.loads(log["output"])

    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        (root / "config.yaml").write_text(json.dumps(settings))
        with (root / "portal.log").open("w+") as logs:
            process = subprocess.Popen([binary, "-configdir", str(root)], stdout=logs, stderr=logs)  # noqa: S603
            try:
                for _ in range(100):
                    if process.poll() is not None:
                        raise RuntimeError("Portal exited during startup")
                    try:
                        api("Init", {})
                        break
                    except (urllib.error.URLError, ConnectionError):
                        time.sleep(0.05)
                status, data = action("restore-all", {})
                check("guest cannot execute actions", status >= 400, data)
                status, data = api("LocalUserLogin", {"username": "test-operator", "password": "incorrect"})
                check("wrong password cannot log in", status >= 400 or not data.get("success"), data)
                status, data = api("LocalUserLogin", {"username": "test-operator", "password": password})
                check(
                    "Argon2id local login succeeds",
                    status == 200 and data.get("success") is True and bool(list(cookies)),
                    data,
                )
                status, data = api("GetDashboard", {"title": "Home VPN gateway"})
                check("operator can view configured dashboard", status == 200 and "dashboard" in data, data)
                status, data = action("bypass-selected", {"targets": "192.168.0.50,10.77.0.2", "minutes": "5"})
                check(
                    "selected-device form preserves argv",
                    status == 200 and output(data) == ["bypass", "192.168.0.50,10.77.0.2", "5"],
                    data,
                )
                status, data = action("switch-relay", {"relay": "configured"})
                check(
                    "configured Melbourne default remains selectable",
                    status == 200 and output(data) == ["switch", "configured"],
                    data,
                )
                status, data = action("switch-relay", {"relay": "au-mel"})
                check(
                    "catalog region selection preserves region ID",
                    status == 200 and output(data) == ["switch", "au-mel"],
                    data,
                )
                for name, arguments in (
                    ("switch-relay", {"relay": "unapproved-relay"}),
                    ("bypass-selected", {"targets": "192.168.0.50;id", "minutes": "5"}),
                    ("bypass-all", {"minutes": "999"}),
                ):
                    status, data = action(name, arguments)
                    log = data.get("logEntry", data.get("log_entry", {}))
                    check(
                        "invalid form values cannot execute: " + name,
                        status >= 400 or log.get("blocked") or log.get("exitCode", log.get("exit_code", 0)) != 0,
                        data,
                    )
            except BaseException:
                logs.flush()
                logs.seek(0)
                print(logs.read().replace(password, "<redacted>").replace(hashed, "<redacted>"), file=sys.stderr)
                raise
            finally:
                process.terminate()
                process.wait(timeout=10)


if __name__ == "__main__":
    main()
