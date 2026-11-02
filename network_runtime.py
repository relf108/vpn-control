"""Exercise the real host firewall with WireGuard inside isolated user/net namespaces.

Usage: VPN_GATEWAY_FIXTURE=/path/to/public-firewall.json python3 network_runtime.py

The fixture contains the existing gateway's firewall and routing scripts, not keys.
No commands run against the host network namespace. No external servers are used.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import vpn_control as vpn
from test_vpn_control import configuration


def run(*args: str) -> str:
    """Run bounded validation commands without a shell."""
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=20).stdout  # noqa: S603


def inside(pid: int, *args: str) -> str:
    """Enter only a child network namespace created by this test."""
    return run("nsenter", "--target", str(pid), "--net", *args)


class FirewallRunner(vpn.Runner):
    """Expose non-secret firewall diagnostics only in this isolated test."""

    def run(self, *args: str, timeout: int = 15) -> str:
        try:
            return super().run(*args, timeout=timeout)
        except vpn.ControlError as error:
            if args[0] != "iptables" and isinstance(error.__cause__, subprocess.CalledProcessError):
                print(error.__cause__.stderr, file=sys.stderr)
            raise


HTTP_SERVER = """
from http.server import BaseHTTPRequestHandler, HTTPServer
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = self.client_address[0].encode()
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *args): pass
HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
"""

UDP_SERVER = """
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', 9999))
while True:
    data, client = s.recvfrom(8192)
    s.sendto(client[0].encode(), client)
"""

DNS_SERVER = """
import os, socket, socketserver, threading
class UDP(socketserver.BaseRequestHandler):
    def handle(self):
        data, reply = self.request
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        s.sendto(data, ('198.51.100.10', 9999))
        response = s.recv(8192)
        reply.sendto(LABEL.encode() + b':' + response, self.client_address)
        s.close()
class TCP(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.recv(8192)
        self.request.sendall(LABEL.encode())
udp = socketserver.ThreadingUDPServer(('0.0.0.0', PORT), UDP)
tcp = socketserver.ThreadingTCPServer(('0.0.0.0', PORT), TCP)
os.setgid(UID)
os.setuid(UID)
threading.Thread(target=tcp.serve_forever, daemon=True).start()
udp.serve_forever()
"""


def main() -> None:
    """Fail before any network changes unless already inside an isolated namespace."""
    if os.geteuid() != 0:
        environment = dict(os.environ, VPN_CONTROL_HOST_NETNS=os.readlink("/proc/self/ns/net"))
        result = subprocess.run(  # noqa: S603 - Fixed namespace wrapper, no shell.
            ["unshare", "--user", "--map-root-user", "--map-auto", "--net", sys.executable, __file__],  # noqa: S607
            env=environment,
            check=False,
        )
        raise SystemExit(result.returncode)
    host_namespace = os.environ.get("VPN_CONTROL_HOST_NETNS")
    if not host_namespace or host_namespace == os.readlink("/proc/self/ns/net"):
        raise SystemExit("Run as an ordinary user; this test creates its own isolated namespace.")
    fixture = json.loads(Path(os.environ["VPN_GATEWAY_FIXTURE"]).read_text())
    children = []

    def start(code: str, pid: int | None = None) -> subprocess.Popen:
        command = [sys.executable, "-u", "-c", code]
        if pid is not None:
            command = ["nsenter", "--target", str(pid), "--net", *command]
        process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)  # noqa: S603
        children.append(process)
        return process

    def namespace() -> int:
        process = subprocess.Popen(["unshare", "--net", sys.executable, "-c", "import time; time.sleep(300)"])  # noqa: S607
        children.append(process)
        # Wait for this process's new namespace, not a background Shell result.
        for _ in range(100):
            if os.readlink(f"/proc/{process.pid}/ns/net") != os.readlink("/proc/self/ns/net"):
                inside(process.pid, "ip", "link", "set", "lo", "up")
                return process.pid
            time.sleep(0.01)
        raise RuntimeError("Child namespace did not start")

    def pair(host: str, peer: str, pid: int) -> None:
        run("ip", "link", "add", host, "type", "veth", "peer", "name", peer)
        run("ip", "link", "set", peer, "netns", str(pid))
        run("ip", "link", "set", host, "up")
        inside(pid, "ip", "link", "set", peer, "up")

    def check(label: str, condition: bool) -> None:
        if not condition:
            for command in (
                ("ipset", "save"),
                ("ip", "-4", "rule", "show"),
                ("iptables-save", "-c"),
                (
                    "sysctl",
                    "net.ipv4.conf.all.rp_filter",
                    "net.ipv4.conf.enp2s0.rp_filter",
                    "net.ipv4.conf.all.src_valid_mark",
                ),
            ):
                print(run(*command), file=sys.stderr)
            print("client route:", inside(client, "ip", "route", "get", "198.51.100.10"), file=sys.stderr)
            print(
                "marked route:",
                run(
                    "ip",
                    "route",
                    "get",
                    "198.51.100.10",
                    "from",
                    "192.168.0.50",
                    "iif",
                    "enp2s0",
                    "mark",
                    vpn.BYPASS_MARK,
                ),
                file=sys.stderr,
            )
            raise AssertionError(label)
        print("PASS:", label, flush=True)

    def fetch(pid: int | None = None, address: str = "198.51.100.10", port: int = 18080) -> str:
        command = [
            "curl",
            "--noproxy",
            "*",
            "--silent",
            "--fail",
            "--connect-timeout",
            "1",
            "--max-time",
            "2",
            f"http://{address}:{port}",
        ]
        try:
            return inside(pid, *command) if pid else run(*command)
        except subprocess.CalledProcessError:
            return "blocked"

    def dns(pid: int, tcp: bool = False, port: int = 53) -> str:
        code = """
import socket
s = socket.socket(socket.AF_INET, TYPE)
s.settimeout(3)
s.connect(('192.168.0.100', PORT))
s.send(b'test')
print(s.recv(8192).decode())
""".replace("TYPE", "socket.SOCK_STREAM" if tcp else "socket.SOCK_DGRAM").replace("PORT", str(port))
        return inside(pid, sys.executable, "-c", code).strip()

    try:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cfg = configuration(root)
            cfg.update({"protectedDNSUser": "12345", "bypassDNSUser": "12346"})
            router, client, remote = namespace(), namespace(), namespace()
            run("ip", "link", "set", "lo", "up")
            run("ip", "link", "add", "enp2s0", "type", "bridge")
            run("ip", "address", "add", "192.168.0.100/24", "dev", "enp2s0")
            run("ip", "link", "set", "enp2s0", "up")
            for host, peer, pid, address in (
                ("to-router", "lan0", router, "192.168.0.1/24"),
                ("to-client", "eth0", client, "192.168.0.50/24"),
            ):
                pair(host, peer, pid)
                run("ip", "link", "set", host, "master", "enp2s0")
                inside(pid, "ip", "address", "add", address, "dev", peer)
            pair("home-underlay", "eth0", remote)
            run("ip", "address", "add", "192.0.2.1/24", "dev", "home-underlay")
            inside(remote, "ip", "address", "add", "192.0.2.2/24", "dev", "eth0")
            inside(router, "ip", "address", "add", "198.51.100.10/32", "dev", "lo")
            inside(client, "ip", "route", "add", "default", "via", "192.168.0.100")
            run("ip", "route", "add", "default", "via", "192.168.0.1")

            keys = [run("wg", "genkey").strip() for _ in range(4)]
            keyfiles = []
            public = []
            for index, key in enumerate(keys):
                path = root / f"key-{index}"
                path.write_text(key)
                path.chmod(0o600)
                keyfiles.append(str(path))
                public.append(
                    subprocess.run(
                        ["wg", "pubkey"],  # noqa: S607
                        input=key,
                        text=True,
                        capture_output=True,
                        check=True,
                    ).stdout.strip()
                )
            for name, pid, address, key_index, peer_index, endpoint, allowed, port in (
                ("wg-mullvad", None, "10.64.1.2/32", 0, 1, "192.168.0.1:51820", "0.0.0.0/0", "51820"),
                ("wg-provider", router, "10.64.1.1/32", 1, 0, "192.168.0.100:51820", "10.64.1.2/32", "51820"),
                ("wg-home", None, "10.77.0.1/24", 2, 3, "192.0.2.2:51821", "10.77.0.2/32", "51821"),
                ("wg-client", remote, "10.77.0.2/24", 3, 2, "192.0.2.1:51821", "0.0.0.0/0", "51821"),
            ):

                def command(*args: str, namespace_pid: int | None = pid) -> str:
                    return inside(namespace_pid, *args) if namespace_pid else run(*args)

                command("ip", "link", "add", name, "type", "wireguard")
                command("ip", "address", "add", address, "dev", name)
                command(
                    "wg",
                    "set",
                    name,
                    "private-key",
                    keyfiles[key_index],
                    "listen-port",
                    port,
                    "fwmark",
                    vpn.WAN_MARK,
                    "peer",
                    public[peer_index],
                    "endpoint",
                    endpoint,
                    "allowed-ips",
                    allowed,
                )
                command("ip", "link", "set", name, "up")
            inside(router, "ip", "route", "add", "10.64.1.2/32", "dev", "wg-provider")
            inside(remote, "ip", "route", "add", "default", "dev", "wg-client")
            run("sysctl", "-qw", "net.ipv4.ip_forward=1")
            run("sysctl", "-qw", "net.ipv4.conf.all.src_valid_mark=1")
            run(
                "sysctl",
                "-qw",
                "net.ipv4.conf.all.send_redirects=0",
                "net.ipv4.conf.default.send_redirects=0",
                "net.ipv4.conf.enp2s0.send_redirects=0",
            )
            firewall = root / "firewall.sh"
            firewall.write_text(fixture["firewall"])
            routing = root / "routing.sh"
            routing.write_text(fixture["routing"])
            run("bash", "-e", str(firewall))
            run("bash", "-e", str(routing))
            run("ip", "route", "add", "default", "dev", "wg-mullvad", "table", "51821", "metric", "10")
            vpn.install_firewall(cfg, FirewallRunner())
            before = [line for line in run("iptables-save").splitlines() if not line.startswith("#")]
            vpn.install_firewall(cfg, FirewallRunner())
            check(
                "firewall reload is idempotent",
                [line for line in run("iptables-save").splitlines() if not line.startswith("#")] == before,
            )
            controller = vpn.Controller(cfg)
            config_file = root / "controller.json"
            config_file.write_text(json.dumps(cfg))
            daemon = subprocess.Popen(  # noqa: S603 - Run the application under test, not user input.
                [sys.executable, vpn.__file__, "--config", str(config_file), "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
            )
            children.append(daemon)
            for _ in range(100):
                if Path(cfg["socket"]).exists():
                    break
                if daemon.poll() is not None:
                    raise RuntimeError(daemon.stderr.read().decode())
                time.sleep(0.02)
            check("controller socket starts with mode 0660", Path(cfg["socket"]).stat().st_mode & 0o777 == 0o660)

            start("PORT=18080\n" + HTTP_SERVER, router)
            start("PORT=18082\n" + HTTP_SERVER)
            start(UDP_SERVER, router)
            start("PORT=53\nUID=12345\nLABEL='protected'\n" + DNS_SERVER)
            start("PORT=5354\nUID=12346\nLABEL='bypass'\n" + DNS_SERVER)
            for _ in range(100):
                if fetch(client) == "10.64.1.2":
                    break
                time.sleep(0.02)
            check("LAN internet initially uses real WireGuard", fetch(client) == "10.64.1.2")
            check("home peer internet initially uses Mullvad interface", fetch(remote) == "10.64.1.2")
            check("gateway initially protected", fetch() == "10.64.1.2")
            check("protected client DNS uses protected resolver/tunnel", dns(client) == "protected:10.64.1.2")
            controller.bypass("192.168.0.50", 5)
            check("selected LAN device uses ISP", fetch(client) == "192.168.0.100")
            check("unselected home peer stays protected", fetch(remote) == "10.64.1.2")
            check("selected device DNS uses bypass resolver/ISP", dns(client) == "bypass:192.168.0.100")
            check("selected device TCP DNS uses bypass resolver", dns(client, tcp=True) == "bypass")
            controller.restore("192.168.0.50")
            check("individual restore returns to tunnel", fetch(client) == "10.64.1.2")
            controller.bypass("all", 5)
            check("global bypass includes gateway", fetch() == "192.168.0.100")
            check("global bypass includes home peer", fetch(remote) == "192.168.0.100")
            # Main resolver's UID remains protected even when its host bypasses.
            protected_dns_source = run(
                sys.executable,
                "-c",
                """
import os, socket
os.setgid(12345)
os.setuid(12345)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(b'protected resolver', ('198.51.100.10', 9999))
print(s.recv(8192).decode())
""",
            )
            check("normal DNS resolver stays protected during host bypass", protected_dns_source.strip() == "10.64.1.2")
            controller.restore("all")
            controller.replace_entries({"192.168.0.50": 4}, time.monotonic())
            check("short-lived bypass starts", fetch(client) == "192.168.0.100")
            persistent_dns = inside(
                client,
                sys.executable,
                "-c",
                """
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.connect(('192.168.0.100', 53))
s.send(b'first')
print(s.recv(8192).decode())
time.sleep(4)
s.send(b'after expiry')
print(s.recv(8192).decode())
""",
            )
            check(
                "persistent UDP DNS socket recovers after kernel expiry",
                persistent_dns.splitlines() == ["bypass:192.168.0.100", "protected:10.64.1.2"],
            )
            check("kernel expiry restores protected route", fetch(client) == "10.64.1.2")
            try:
                dns(client, port=5354)
            except subprocess.CalledProcessError:
                check("expired device cannot directly use bypass DNS", True)
            else:
                check("expired device cannot directly use bypass DNS", False)
            run("ip", "link", "set", "wg-mullvad", "down")
            check("provider failure blocks protected LAN traffic", fetch(client) == "blocked")
            check("provider failure blocks protected home internet", fetch(remote) == "blocked")
            check(
                "home VPN still reaches LAN services during provider failure",
                fetch(remote, "192.168.0.100", 18082) == "10.77.0.2",
            )
            check(
                "public incoming replies retain ordinary WAN routing",
                fetch(router, "192.168.0.100", 18082) == "192.168.0.1",
            )
            controller.bypass("192.168.0.50,10.77.0.2", 5)
            result = fetch(client)
            check("explicit LAN bypass works with provider down", result == "192.168.0.100")
            check("explicit home peer bypass works with provider down", fetch(remote) == "192.168.0.100")
            check("bypassed DNS works with provider down", dns(client) == "bypass:192.168.0.100")
            result = vpn.client(cfg["socket"], {"action": "restore", "targets": "all"})
            check("unprivileged socket protocol restores all protection", result["ok"])
            result = vpn.client(cfg["socket"], {"action": "install-firewall"})
            check("socket protocol rejects privileged arbitrary actions", not result["ok"])
            controller.replace_entries({"192.168.0.50": 3}, time.monotonic())
            daemon.terminate()
            daemon.wait(timeout=5)
            check("explicit bypass survives controller exit until its deadline", fetch(client) == "192.168.0.100")
            time.sleep(3)
            check("controller crash cannot extend bypass past kernel expiry", fetch(client) == "blocked")
            check(
                "both WireGuard identities stay unchanged",
                run("wg", "show", "wg-home", "public-key").strip() == public[2],
            )
    finally:
        for child in reversed(children):
            child.terminate()
        for child in children:
            child.wait(timeout=5)


if __name__ == "__main__":
    main()
