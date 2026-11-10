"""Constrain portal actions to timed IPv4 bypasses and approved Mullvad relays."""

# Standalone application. No shell commands or user-selected executables.
# ruff: noqa: CPY001, INP001, T201

import argparse
import base64
import configparser
import contextlib
import io
import ipaddress
import json
import logging
import os
import shlex
import socket
import socketserver
import subprocess
import tempfile
import time
from pathlib import Path

SET_NAME = "vpn-bypass"
STAGING_SET = "vpn-bypass-next"
MAX_MESSAGE = 16384
MAX_TARGETS = 64
ALLOWED_MINUTES = (5, 15, 30, 60)
WAN_MARK = "0x51822"
BYPASS_MARK = "0x51823"
KEY_BYTES = 32
IPV4_HOST_PREFIX = 32
MIN_NETWORK_PREFIX = 24
MAX_PORT = 65535
LOGGER = logging.getLogger(__name__)


class ControlError(Exception):
    """A safe error suitable for display in the portal."""


class Runner:
    """Run trusted executables with bounded runtimes and sanitized errors."""

    def run(self, *args: str, timeout: int = 15, empty_ok: bool = False) -> str:
        """Return stdout without exposing stderr or WireGuard credentials."""
        try:
            result = subprocess.run(  # noqa: S603 - No shell; executables come from the Nix wrapper.
                args,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode and not (
                empty_ok and result.returncode == 1 and "0 flow entries have been deleted" in result.stderr
            ):
                raise subprocess.CalledProcessError(result.returncode, args)
        except (OSError, subprocess.SubprocessError) as error:
            msg = f"{args[0]} operation failed; non-bypassed traffic remains protected."
            raise ControlError(msg) from error
        else:
            return result.stdout


def load_config(path: Path) -> dict:
    """Load immutable configuration and validate its network boundaries."""
    config = json.loads(path.read_text())
    for name in ("lanNetwork", "homeNetwork"):
        if ipaddress.IPv4Network(config[name]).prefixlen < MIN_NETWORK_PREFIX:
            msg = "Configured client networks must be /24 or smaller."
            raise ControlError(msg)
    for name in ("hostAddress", "homeAddress"):
        ipaddress.IPv4Address(config[name])
    return config


class Controller:
    """Manage expiring kernel state without changing Nix or persistent VPN files."""

    def __init__(self, config: dict, runner: Runner | None = None) -> None:
        """Bind immutable gateway settings and a bounded command runner."""
        self.config = config
        self.runner = runner or Runner()
        self.networks = [ipaddress.IPv4Network(config[key]) for key in ("lanNetwork", "homeNetwork")]
        self.dns_sources = None

    def reconcile_dns(self, *, force: bool = False) -> None:
        """Clear stale DNS NAT mappings on policy changes and kernel expiry.

        Packet filters enforce expiry even if this housekeeping is unavailable.
        Housekeeping lets a client's existing UDP socket recover immediately.
        """
        current = set(self.entries())
        sources = current.symmetric_difference(self.dns_sources or set())
        if force or self.dns_sources is None:
            sources.update([str(network) for network in self.networks] + ["127.0.0.1"])
        for source in sorted(sources):
            for protocol in ("udp", "tcp"):
                self.runner.run(
                    "conntrack",
                    "-D",
                    "-f",
                    "ipv4",
                    "-p",
                    protocol,
                    "--src",
                    source,
                    "--dport",
                    "53",
                    empty_ok=True,
                )
        self.dns_sources = current

    def entries(self) -> dict[str, int]:
        """Read remaining kernel lifetimes, never wall-clock deadlines."""
        result = {}
        for line in self.runner.run("ipset", "save", SET_NAME).splitlines():
            fields = shlex.split(line)
            if fields[:2] != ["add", SET_NAME]:
                continue
            if "timeout" not in fields:
                msg = "Refusing an unbounded bypass entry."
                raise ControlError(msg)
            seconds = int(fields[fields.index("timeout") + 1])
            if seconds > 0:
                result[fields[2]] = seconds
        return result

    def targets(self, text: str) -> list[str]:
        """Accept exact client IPv4 addresses, never networks or shell expressions."""
        if text.startswith("["):
            try:
                values = json.loads(text)
            except ValueError as error:
                msg = "Invalid device selection."
                raise ControlError(msg) from error
            if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
                msg = "Choose client IPv4 addresses only."
                raise ControlError(msg)
        else:
            values = text.split(",")
        if not 1 <= len(values) <= MAX_TARGETS:
            msg = "Choose between 1 and 64 client IPv4 addresses."
            raise ControlError(msg)
        result = []
        for value in values:
            try:
                address = ipaddress.IPv4Address(value.strip())
            except ipaddress.AddressValueError as error:
                msg = "Use comma-separated client IPv4 addresses only."
                raise ControlError(msg) from error
            if not any(
                address in network and address not in (network.network_address, network.broadcast_address)
                for network in self.networks
            ):
                msg = "Client address is outside the configured LAN and home VPN networks."
                raise ControlError(msg)
            if str(address) == self.config["homeAddress"]:
                msg = "Select the gateway's LAN address, not its home VPN address."
                raise ControlError(msg)
            result.append(str(address))
        return sorted(set(result))

    def replace_entries(self, entries: dict[str, int], observed_at: float) -> None:
        """Publish a bypass set atomically; timeout zero is never allowed."""
        self.runner.run(
            "ipset", "create", STAGING_SET, "hash:net", "family", "inet", "timeout", "0", "maxelem", "1024", "-exist"
        )
        self.runner.run("ipset", "flush", STAGING_SET)
        for address, seconds in entries.items():
            remaining = int(seconds - (time.monotonic() - observed_at))
            if remaining > 0:
                self.runner.run("ipset", "add", STAGING_SET, address, "timeout", str(remaining))
        self.runner.run("ipset", "swap", STAGING_SET, SET_NAME)
        self.runner.run("ipset", "destroy", STAGING_SET)

    def bypass(self, targets: str, minutes: int) -> str:
        """Create bounded bypasses while leaving both tunnels up."""
        if minutes not in ALLOWED_MINUTES:
            msg = "Duration must be 5, 15, 30, or 60 minutes."
            raise ControlError(msg)
        observed_at = time.monotonic()
        seconds = minutes * 60
        if targets == "all":
            entries = {str(network): seconds for network in self.networks}
            entries["127.0.0.1"] = seconds
        else:
            addresses = self.targets(targets)
            entries = self.entries()
            if any(str(network) in entries for network in self.networks):
                msg = "Global bypass is active. Restore all before editing individual devices."
                raise ControlError(msg)
            entries.update(dict.fromkeys(addresses, seconds))
            if self.config["hostAddress"] in addresses:
                entries["127.0.0.1"] = seconds
        self.replace_entries(entries, observed_at)
        self.reconcile_dns()
        return (
            f"Bypass enabled for {targets}, at most {minutes} minutes. "
            "Internet traffic uses the home ISP. Home VPN stays on."
        )

    def restore(self, targets: str) -> str:
        """Restore-all also cancels every individual lease."""
        if targets == "all":
            self.runner.run("ipset", "flush", SET_NAME)
        else:
            addresses = self.targets(targets)
            observed_at = time.monotonic()
            entries = self.entries()
            if any(str(network) in entries for network in self.networks):
                msg = "Global bypass is active. Use Restore all."
                raise ControlError(msg)
            for address in addresses:
                entries.pop(address, None)
            if self.config["hostAddress"] in addresses:
                entries.pop("127.0.0.1", None)
            self.replace_entries(entries, observed_at)
        self.reconcile_dns()
        return "Protection restored. Existing internet connections may need to reconnect. Home VPN remains on."

    def relay(self, name: str) -> dict:
        """Resolve only approved relay IDs or the original configured profile."""
        if name == "configured":
            parser = configparser.ConfigParser(interpolation=None)
            parser.read(self.config["profile"])
            try:
                result = {"publicKey": parser["Peer"]["PublicKey"], "endpoint": parser["Peer"]["Endpoint"]}
            except KeyError as error:
                msg = "Configured Mullvad profile is unavailable."
                raise ControlError(msg) from error
        else:
            try:
                result = self.config["relays"][name]
            except KeyError as error:
                msg = "Choose an approved Mullvad relay."
                raise ControlError(msg) from error
        try:
            if len(base64.b64decode(result["publicKey"], validate=True)) != KEY_BYTES:
                raise ValueError  # noqa: TRY301 - Convert invalid metadata to one safe error below.
            host, port = result["endpoint"].rsplit(":", 1)
            ipaddress.IPv4Address(host)
            if not 1 <= int(port) <= MAX_PORT:
                raise ValueError  # noqa: TRY301 - Convert invalid metadata to one safe error below.
        except (ValueError, KeyError) as error:
            msg = "Relay has an invalid public key or IPv4 endpoint."
            raise ControlError(msg) from error
        return result

    def sync(self, contents: str) -> None:
        """Pass a private snapshot through a temporary mode-0600 file."""
        descriptor, name = tempfile.mkstemp(dir=self.config["runtimeDirectory"], prefix="wg-")
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write(contents)
            self.runner.run("wg", "syncconf", self.config["mullvadInterface"], name)
        finally:
            Path(name).unlink(missing_ok=True)

    def switch(self, name: str) -> str:
        """Change only the outbound peer; verify its exit or roll back."""
        relay = self.relay(name)
        interface = self.config["mullvadInterface"]
        original = self.runner.run("wg", "showconf", interface)
        parser = configparser.ConfigParser(interpolation=None)
        parser.optionxform = str
        parser.read_string(original)
        if set(parser.sections()) != {"Interface", "Peer"}:
            msg = "Expected exactly one Mullvad peer; no changes made."
            raise ControlError(msg)
        # Preserve interface identity, listener, fwmark, and optional PSK.
        parser["Peer"]["PublicKey"] = relay["publicKey"]
        parser["Peer"]["Endpoint"] = relay["endpoint"]
        parser["Peer"]["AllowedIPs"] = "0.0.0.0/0"
        parser["Peer"]["PersistentKeepalive"] = "1"
        changed = io.StringIO()
        parser.write(changed)
        try:
            self.sync(changed.getvalue())
            # Bind a tunnel source IP, not a device name. This still verifies
            # Mullvad when the gateway's own LAN address is deliberately bypassed.
            addresses = json.loads(self.runner.run("ip", "-j", "-4", "address", "show", "dev", interface))
            source = addresses[0]["addr_info"][0]["local"]
            response = json.loads(
                self.runner.run(
                    "curl",
                    "--noproxy",
                    "*",
                    "--silent",
                    "--show-error",
                    "--fail",
                    "--max-time",
                    "15",
                    "--retry",
                    "2",
                    "--retry-delay",
                    "1",
                    "--interface",
                    source,
                    "https://am.i.mullvad.net/json",
                    timeout=50,
                )
            )
            if response.get("mullvad_exit_ip") is not True:
                msg = "New relay did not verify as a Mullvad exit."
                raise ControlError(msg)  # noqa: TRY301 - Verification failure must run rollback.
            self.runner.run("wg", "set", interface, "peer", relay["publicKey"], "persistent-keepalive", "25")
        except (ControlError, ValueError, KeyError, IndexError, AttributeError, TypeError, OSError) as error:
            try:
                self.sync(original)
            except (ControlError, OSError):
                msg = (
                    "Relay switch and rollback failed. "
                    "Non-bypassed internet remains fail-closed; check Mullvad locally."
                )
                raise ControlError(msg) from error
            msg = (
                "Relay switch failed; previous peer restored. Non-bypassed internet remains fail-closed if unavailable."
            )
            raise ControlError(msg) from error
        return (
            f"Mullvad relay switched to {name}; verified exit {response.get('ip', 'unknown')}. "
            "Home VPN was not changed."
        )

    def lan_candidates(self) -> dict[str, tuple[str, str]]:
        """Read public neighbour observations without sending network probes."""
        candidates = {}
        try:
            neighbours = json.loads(
                self.runner.run("ip", "-j", "-4", "neigh", "show", "dev", self.config["lanInterface"])
            )
            for neighbour in neighbours:
                states = neighbour.get("state", [])
                if neighbour.get("lladdr") and not {"FAILED", "INCOMPLETE"}.intersection(states):
                    candidates[neighbour.get("dst", "")] = ("LAN", "/".join(states).lower() or "observed")
        except (ControlError, ValueError, TypeError, AttributeError):
            pass
        return candidates

    def home_candidates(self) -> dict[str, tuple[str, str]]:
        """List configured exact home peer IPs and recent public handshake state."""
        candidates = {}
        try:
            handshakes = {}
            for line in self.runner.run("wg", "show", self.config["homeInterface"], "latest-handshakes").splitlines():
                peer, timestamp = line.split()
                handshakes[peer] = int(timestamp)
            for line in self.runner.run("wg", "show", self.config["homeInterface"], "allowed-ips").splitlines():
                peer, allowed = line.split(maxsplit=1)
                recent = handshakes.get(peer, 0) > time.time() - 180
                for value in allowed.replace(",", " ").split():
                    try:
                        network = ipaddress.IPv4Network(value)
                    except ValueError:
                        continue
                    if network.prefixlen == IPV4_HOST_PREFIX:
                        candidates[str(network.network_address)] = (
                            "home VPN",
                            "recent handshake" if recent else "configured peer",
                        )
        except (ControlError, ValueError):
            pass
        return candidates

    def device_name(self, address: str, lookup_deadline: float) -> str:
        """Prefer declarative labels; bound total time spent in hostname lookup."""
        name = self.config.get("deviceNames", {}).get(address, "")
        if not name and time.monotonic() < lookup_deadline:
            try:
                resolved = self.runner.run("getent", "hosts", address, timeout=1).split()
                name = resolved[1] if len(resolved) > 1 else ""
            except ControlError:
                pass
        name = "".join(char for char in name[:80] if char.isalnum() or char in " ._-")
        return name or ("Gateway" if address == self.config["hostAddress"] else "")

    def devices(self) -> list[dict]:
        """Discover candidates, not trusted identities or guaranteed connectivity.

        Configured home peers and active bypasses remain selectable offline.
        Hostname lookup is best-effort; discovery never scans client networks.
        """
        candidates = self.lan_candidates() | self.home_candidates()
        candidates[self.config["hostAddress"]] = ("gateway", "local")
        entries = self.entries()
        for address in entries:
            if "/" not in address and address != "127.0.0.1":
                candidates.setdefault(address, ("bypass", "not recently observed"))
        devices = []
        lookup_deadline = time.monotonic() + 3
        for address, (source, state) in sorted(candidates.items()):
            try:
                self.targets(address)
            except ControlError:
                continue
            if source == "LAN" and ipaddress.IPv4Address(address) not in self.networks[0]:
                continue
            if source == "home VPN" and ipaddress.IPv4Address(address) not in self.networks[1]:
                continue
            name = self.device_name(address, lookup_deadline)
            seconds = entries.get(address, 0)
            suffix = f" · bypass ≤{seconds}s" if seconds else ""
            devices.append(
                {
                    "address": address,
                    "title": f"{name + ' · ' if name else ''}{address} · {source} ({state}){suffix}",
                    "source": source,
                    "state": state,
                    "bypassSeconds": seconds,
                }
            )
        return devices

    def status(self) -> str:
        """Report live lifetimes and public peer data, never private credentials."""
        entries = self.entries()
        lines = ["IPv4 policy: protected unless listed below. Untunnelled IPv6 stays blocked."]
        lines += [f"  {address}: bypass for at most {seconds}s" for address, seconds in sorted(entries.items())]
        if not entries:
            lines.append("No active bypasses.")
        observations = [
            (
                "Home VPN peers (public keys and allowed addresses):",
                ["wg", "show", self.config["homeInterface"], "allowed-ips"],
            ),
            ("Mullvad peer and endpoint:", ["wg", "show", self.config["mullvadInterface"], "endpoints"]),
            (
                "Recent LAN neighbors (IP/MAC, not a trusted device identity):",
                ["ip", "-4", "neigh", "show", "dev", self.config["lanInterface"]],
            ),
        ]
        for title, command in observations:
            lines.append(title)
            try:
                lines.append(self.runner.run(*command).strip())
            except ControlError:
                lines.append("Unavailable (interface may be down).")
        try:
            exit_info = json.loads(
                self.runner.run(
                    "curl",
                    "--ipv4",
                    "--noproxy",
                    "*",
                    "--silent",
                    "--fail",
                    "--max-time",
                    "3",
                    "https://am.i.mullvad.net/json",
                    timeout=5,
                )
            )
            lines.append(
                f"Gateway observed public IPv4: {exit_info.get('ip', 'unknown')}; "
                f"Mullvad verified: {exit_info.get('mullvad_exit_ip') is True}."
            )
        except (ControlError, ValueError, AttributeError):
            lines.append("Gateway public-IP check unavailable; this does not enable WAN fallback.")
        lines.append(
            "Check public IP from each selected client separately; the observation above is for the gateway only."
        )
        return "\n".join(lines)

    def dispatch(self, request: dict) -> str:
        """Expose a typed protocol, not a general privileged command runner."""
        action = request.get("action")
        if action == "status" and set(request) == {"action"}:
            return self.status()
        if action == "devices" and set(request) == {"action"}:
            return json.dumps(self.devices())
        if (
            action == "bypass"
            and set(request) == {"action", "targets", "minutes"}
            and isinstance(request["targets"], str)
            and type(request["minutes"]) is int
        ):
            return self.bypass(request["targets"], request["minutes"])
        if action == "restore" and set(request) == {"action", "targets"} and isinstance(request["targets"], str):
            return self.restore(request["targets"])
        if action == "switch" and set(request) == {"action", "relay"} and isinstance(request["relay"], str):
            return self.switch(request["relay"])
        msg = "Unknown or invalid portal action."
        raise ControlError(msg)


def firewall_rules(config: dict) -> list[tuple[str, str, list[str]]]:
    """Build dedicated chains. Existing privacy guards remain in place."""
    lan, home = config["lanInterface"], config["homeInterface"]
    rules = []

    def add(table: str, chain: str, *args: str) -> None:
        rules.append((table, chain, list(args)))

    # Reverse-path checks run after PREROUTING but before FORWARD. ISP replies
    # need the main-table exemption even while the private table is unreachable.
    add(
        "mangle",
        "vpn-bypass-in",
        "-i",
        lan,
        "-m",
        "conntrack",
        "--ctdir",
        "REPLY",
        "-j",
        "MARK",
        "--set-mark",
        WAN_MARK,
    )
    for interface, network in ((lan, config["lanNetwork"]), (home, config["homeNetwork"])):
        add(
            "mangle",
            "vpn-bypass-in",
            "-i",
            interface,
            "-s",
            network,
            "-m",
            "set",
            "--match-set",
            SET_NAME,
            "src",
            "-j",
            "MARK",
            "--set-mark",
            BYPASS_MARK,
        )
        add(
            "filter",
            "vpn-bypass-fwd",
            "-i",
            interface,
            "-s",
            network,
            "-o",
            lan,
            "-m",
            "mark",
            "--mark",
            BYPASS_MARK,
            "-m",
            "set",
            "--match-set",
            SET_NAME,
            "src",
            "-j",
            "ACCEPT",
        )
        for protocol in ("udp", "tcp"):
            add(
                "nat",
                "vpn-bypass-dns",
                "-i",
                interface,
                "-s",
                network,
                "-m",
                "set",
                "--match-set",
                SET_NAME,
                "src",
                "-m",
                "addrtype",
                "--dst-type",
                "LOCAL",
                "-p",
                protocol,
                "--dport",
                "53",
                "-j",
                "REDIRECT",
                "--to-ports",
                "5354",
            )
    add("mangle", "vpn-bypass-out", "-m", "mark", "--mark", WAN_MARK, "-j", "RETURN")
    add("mangle", "vpn-bypass-out", "-m", "conntrack", "--ctdir", "REPLY", "-j", "RETURN")
    for network in (config["lanNetwork"], config["homeNetwork"], "127.0.0.0/8", "224.0.0.0/4", "255.255.255.255/32"):
        add("mangle", "vpn-bypass-out", "-d", network, "-j", "RETURN")
    # The ordinary resolver must stay protected even when the gateway itself is
    # bypassed. Only the second resolver is allowed to send DNS over the ISP.
    add(
        "mangle",
        "vpn-bypass-out",
        "-m",
        "owner",
        "--uid-owner",
        config.get("protectedDNSUser", "adguardhome"),
        "-j",
        "RETURN",
    )
    add(
        "mangle",
        "vpn-bypass-out",
        "-m",
        "owner",
        "--uid-owner",
        config.get("bypassDNSUser", "vpn-bypass-dns"),
        "-j",
        "MARK",
        "--set-mark",
        BYPASS_MARK,
    )
    add("mangle", "vpn-bypass-out", "-m", "mark", "--mark", BYPASS_MARK, "-j", "RETURN")
    add(
        "mangle", "vpn-bypass-out", "-m", "set", "--match-set", SET_NAME, "src", "-j", "MARK", "--set-mark", BYPASS_MARK
    )
    add(
        "nat",
        "vpn-bypass-nat",
        "-o",
        lan,
        "!",
        "-d",
        config["lanNetwork"],
        "-m",
        "mark",
        "--mark",
        BYPASS_MARK,
        "-j",
        "MASQUERADE",
    )
    for protocol in ("udp", "tcp"):
        add(
            "nat",
            "vpn-bypass-local",
            "-m",
            "set",
            "--match-set",
            SET_NAME,
            "src",
            "-m",
            "addrtype",
            "--dst-type",
            "LOCAL",
            "-p",
            protocol,
            "--dport",
            "53",
            "-j",
            "REDIRECT",
            "--to-ports",
            "5354",
        )
        # Old DNS NAT state must never bypass the per-packet expiry check.
        add(
            "filter",
            "vpn-bypass-dns-in",
            "-p",
            protocol,
            "--dport",
            "5354",
            "-m",
            "set",
            "--match-set",
            SET_NAME,
            "src",
            "-j",
            "ACCEPT",
        )
        add("filter", "vpn-bypass-dns-in", "-p", protocol, "--dport", "5354", "-j", "REJECT")
    return rules


def install_firewall(config: dict, runner: Runner) -> None:
    """Install declarative hooks without clearing live timed leases."""
    runner.run("ipset", "create", SET_NAME, "hash:net", "family", "inet", "timeout", "0", "maxelem", "1024", "-exist")
    rules = firewall_rules(config)
    chains = sorted({(table, chain) for table, chain, _ in rules})
    for table in ("mangle", "nat", "filter"):
        lines = [f"*{table}"]
        # Declaring an existing user chain flushes it in the atomic transaction,
        # even with --noflush; built-in chains and privacy guards are retained.
        lines += [f":{chain} - [0:0]" for chain_table, chain in chains if chain_table == table]
        # iptables-restore is not a shell: single-quoted tokens (notably '!')
        # remain literal. All fields here are fixed tokens or trusted Nix settings.
        lines += [" ".join(["-A", chain, *args]) for rule_table, chain, args in rules if rule_table == table]
        lines.append("COMMIT")
        descriptor, name = tempfile.mkstemp(prefix="vpn-firewall-")
        try:
            with os.fdopen(descriptor, "w") as handle:
                handle.write("\n".join(lines) + "\n")
            runner.run("iptables-restore", "--wait", "--noflush", name)
        finally:
            Path(name).unlink(missing_ok=True)
    hooks = [
        ("mangle", "PREROUTING", ["-j", "vpn-bypass-in"]),
        ("mangle", "OUTPUT", ["-j", "vpn-bypass-out"]),
        ("mangle", "homelab-vpn-mark", ["-m", "mark", "--mark", BYPASS_MARK, "-j", "RETURN"]),
        ("nat", "PREROUTING", ["-j", "vpn-bypass-dns"]),
        ("nat", "OUTPUT", ["-j", "vpn-bypass-local"]),
        ("nat", "POSTROUTING", ["-j", "vpn-bypass-nat"]),
        ("filter", "FORWARD", ["-j", "vpn-bypass-fwd"]),
        ("filter", "INPUT", ["-j", "vpn-bypass-dns-in"]),
    ]
    for table, chain, args in hooks:
        try:
            runner.run("iptables", "-w", "-t", table, "-C", chain, *args)
        except ControlError:
            runner.run("iptables", "-w", "-t", table, "-I", chain, "1", *args)
    priority = str(config["rulePriority"])
    existing = [line for line in runner.run("ip", "-4", "rule", "show").splitlines() if line.startswith(priority + ":")]
    if existing and (len(existing) != 1 or f"fwmark {BYPASS_MARK} lookup main" not in existing[0]):
        msg = "Bypass routing priority is occupied by another policy."
        raise ControlError(msg)
    if not existing:
        runner.run("ip", "-4", "rule", "add", "priority", priority, "fwmark", BYPASS_MARK, "table", "main")


def serve(config: dict) -> None:
    """Serve a restricted Unix socket; kernel timeouts outlive this process."""
    controller = Controller(config)
    controller.reconcile_dns(force=True)

    class Server(socketserver.UnixStreamServer):
        def service_actions(self) -> None:
            try:
                controller.reconcile_dns()
            except ControlError:
                LOGGER.warning("DNS NAT housekeeping failed; kernel bypass expiry and DNS access checks remain active.")

    class Handler(socketserver.StreamRequestHandler):
        def handle(self) -> None:
            self.connection.settimeout(5)
            try:
                data = self.rfile.readline(MAX_MESSAGE + 1)
                if len(data) > MAX_MESSAGE or not data.endswith(b"\n"):
                    msg = "Request too large or incomplete."
                    raise ControlError(msg)  # noqa: TRY301 - Protocol errors share the safe response below.
                request = json.loads(data)
                if not isinstance(request, dict):
                    msg = "Expected an action object."
                    raise ControlError(msg)  # noqa: TRY301 - Protocol errors share the safe response below.
                response = {"ok": True, "message": controller.dispatch(request)}
            except ControlError as error:
                response = {"ok": False, "message": str(error)}
            except (ValueError, TypeError, OSError, KeyError, configparser.Error):
                response = {
                    "ok": False,
                    "message": "Action failed; invalid state or request. Privacy guards remain active.",
                }
            with contextlib.suppress(BrokenPipeError, TimeoutError):
                self.wfile.write(json.dumps(response).encode() + b"\n")

    path = Path(config["socket"])
    path.unlink(missing_ok=True)
    with Server(str(path), Handler) as server:
        path.chmod(0o660)
        server.serve_forever()


def client(path: str, request: dict) -> dict:
    """Send one allowlisted action to the privileged controller."""
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(70)
        connection.connect(path)
        connection.sendall(json.dumps(request).encode() + b"\n")
        with connection.makefile("rb") as stream:
            return json.loads(stream.readline(262144))


def main() -> None:
    """Run service/installation entry points or an unprivileged portal client."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=Path("/etc/vpn-control.json"))
    parser.add_argument("--socket", default="/run/vpn-control/control.sock")
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("serve", "install-firewall", "status", "devices"):
        sub.add_parser(action)
    bypass_parser = sub.add_parser("bypass")
    bypass_parser.add_argument("targets")
    bypass_parser.add_argument("minutes", type=int, choices=ALLOWED_MINUTES)
    sub.add_parser("restore").add_argument("targets")
    sub.add_parser("switch").add_argument("relay")
    args = parser.parse_args()
    try:
        if args.action in ("serve", "install-firewall"):
            config = load_config(args.config)
            if args.action == "serve":
                serve(config)
            else:
                install_firewall(config, Runner())
            return
        request = {"action": args.action}
        for key in ("targets", "minutes", "relay"):
            if hasattr(args, key):
                request[key] = getattr(args, key)
        response = client(args.socket, request)
        print(response["message"])
        if not response["ok"]:
            raise SystemExit(1)
    except (ControlError, OSError, ValueError):
        parser.exit(1, "VPN control unavailable or invalid configuration. No automatic WAN fallback was enabled.\n")


if __name__ == "__main__":
    main()
