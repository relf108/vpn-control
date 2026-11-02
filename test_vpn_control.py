"""Rootless controller tests: expiry, scope isolation, rollback, and command safety."""

import base64
import json
import stat
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

import update_catalog
import vpn_control as vpn


def configuration(root: Path) -> dict:
    """Return synthetic public settings and disposable profile paths."""
    return {
        "lanInterface": "enp2s0",
        "homeInterface": "wg-home",
        "mullvadInterface": "wg-mullvad",
        "lanNetwork": "192.168.0.0/24",
        "homeNetwork": "10.77.0.0/24",
        "hostAddress": "192.168.0.100",
        "homeAddress": "10.77.0.1",
        "profile": str(root / "profile.conf"),
        "runtimeDirectory": str(root),
        "rulePriority": 10903,
        "socket": str(root / "control.sock"),
        "relays": {"test-relay": {"publicKey": base64.b64encode(b"r" * 32).decode(), "endpoint": "192.0.2.1:51820"}},
    }


class FakeRunner:
    """Model ipset swaps and sensitive WireGuard files without privileged commands."""

    def __init__(self) -> None:
        self.calls = []
        self.sets = {vpn.SET_NAME: {}}
        self.snapshots = []
        self.fail_add = False
        self.verify = True
        self.original = (
            "[Interface]\nPrivateKey = "
            + base64.b64encode(b"s" * 32).decode()
            + "\nFwMark = 0x51822\nListenPort = 12345\n[Peer]\nPublicKey = "
            + base64.b64encode(b"p" * 32).decode()
            + "\nEndpoint = 192.0.2.2:51820\nAllowedIPs = 0.0.0.0/0\n"
        )

    def run(self, *args: str, timeout: int = 15, empty_ok: bool = False) -> str:
        """Record argv and implement only operations used by these tests."""
        self.calls.append(args)
        if args[:2] == ("ipset", "save"):
            return "\n".join(f"add {args[2]} {address} timeout {ttl}" for address, ttl in self.sets[args[2]].items())
        if args[:2] == ("ipset", "create"):
            self.sets.setdefault(args[2], {})
        if args[:2] == ("ipset", "flush"):
            self.sets[args[2]] = {}
        if args[:2] == ("ipset", "add"):
            if self.fail_add:
                raise vpn.ControlError("Synthetic ipset failure")
            self.sets[args[2]][args[3]] = int(args[5])
        if args[:2] == ("ipset", "swap"):
            self.sets[args[2]], self.sets[args[3]] = self.sets[args[3]], self.sets[args[2]]
        if args[:2] == ("ipset", "destroy"):
            del self.sets[args[2]]
        if args[:2] == ("wg", "showconf"):
            return self.original
        if args[:2] == ("wg", "syncconf"):
            path = Path(args[3])
            if stat.S_IMODE(path.stat().st_mode) != 0o600:
                raise AssertionError("Snapshot must be private")
            self.snapshots.append(path.read_text())
        if args[:3] == ("ip", "-j", "-4"):
            return '[{"addr_info":[{"local":"10.64.1.2"}]}]'
        if args[0] == "curl":
            return json.dumps({"mullvad_exit_ip": self.verify, "ip": "198.51.100.1"})
        return ""


class ControllerTests(unittest.TestCase):
    """Check all portal actions against state and argument-boundary regressions."""

    def setUp(self) -> None:
        """Create disposable state; never touch live WireGuard or networking."""
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = configuration(self.root)
        self.runner = FakeRunner()
        self.controller = vpn.Controller(self.config, self.runner)

    def test_selected_bypass_does_not_add_other_clients(self) -> None:
        """Only requested source addresses receive a bounded bypass."""
        self.controller.bypass("192.168.0.50,10.77.0.2", 5)
        entries = self.runner.sets[vpn.SET_NAME]
        self.assertEqual(set(entries), {"192.168.0.50", "10.77.0.2"})
        self.assertTrue(all(0 < value <= 300 for value in entries.values()))
        self.assertFalse(any("wg-home" in args for args in self.runner.calls))

    def test_global_bypass_replaces_individual_leases(self) -> None:
        """Global expiry never silently falls back to an older per-client lease."""
        self.controller.bypass("192.168.0.50", 60)
        self.controller.bypass("all", 5)
        self.assertEqual(set(self.runner.sets[vpn.SET_NAME]), {"192.168.0.0/24", "10.77.0.0/24", "127.0.0.1"})
        with self.assertRaises(vpn.ControlError):
            self.controller.restore("192.168.0.50")
        with self.assertRaises(vpn.ControlError):
            self.controller.bypass("10.77.0.2", 15)
        self.controller.restore("all")
        self.assertEqual(self.runner.sets[vpn.SET_NAME], {})

    def test_individual_restore_preserves_other_clients(self) -> None:
        """One device's restore cannot clear a different device's lease."""
        self.controller.bypass("192.168.0.50,10.77.0.2", 5)
        self.controller.restore("10.77.0.2")
        self.assertEqual(set(self.runner.sets[vpn.SET_NAME]), {"192.168.0.50"})

    def test_gateway_bypass_handles_loopback_dns(self) -> None:
        """The host's localhost resolver follows its selected bypass lifetime."""
        self.controller.bypass("192.168.0.100", 5)
        self.assertIn("127.0.0.1", self.runner.sets[vpn.SET_NAME])
        self.controller.restore("192.168.0.100")
        self.assertEqual(self.runner.sets[vpn.SET_NAME], {})

    def test_rejects_external_networks_and_command_injection(self) -> None:
        """Portal text cannot become shell commands or arbitrary network grants."""
        for text in (
            "",
            "1.1.1.1",
            "192.168.0.0/24",
            "192.168.0.0",
            "192.168.0.255",
            "10.77.0.1",
            "::1",
            "all; id",
            "$(id)",
            "192.168.0.50,id",
        ):
            with self.subTest(text=text), self.assertRaises(vpn.ControlError):
                self.controller.bypass(text, 5)
        for minutes in (0, -1, 1, 1440):
            with self.assertRaises(vpn.ControlError):
                self.controller.bypass("all", minutes)
        self.assertEqual(self.runner.calls, [])

    def test_atomic_publish_failure_retains_previous_policy(self) -> None:
        """A failed staging update never broadens the active kernel set."""
        self.controller.bypass("192.168.0.50", 5)
        before = self.runner.sets[vpn.SET_NAME].copy()
        self.runner.fail_add = True
        with self.assertRaises(vpn.ControlError):
            self.controller.bypass("10.77.0.2", 5)
        self.assertEqual(self.runner.sets[vpn.SET_NAME], before)

    def test_expired_entries_never_become_permanent(self) -> None:
        """A lifetime of zero must not be passed to ipset add."""
        self.controller.replace_entries({"192.168.0.50": 1}, time.monotonic() - 2)
        self.assertEqual(self.runner.sets[vpn.SET_NAME], {})
        self.assertFalse(any(args[:2] == ("ipset", "add") for args in self.runner.calls))

    def test_existing_lifetimes_are_not_extended_by_slow_operations(self) -> None:
        """Rebuilding a set accounts for time spent staging it."""
        with patch.object(vpn.time, "monotonic", return_value=110):
            self.controller.replace_entries({"192.168.0.50": 20}, observed_at=100)
        self.assertEqual(self.runner.sets[vpn.SET_NAME]["192.168.0.50"], 10)

    def test_protocol_rejects_unknown_fields_actions_and_types(self) -> None:
        """Only typed operations, not general root commands, cross the socket."""
        for request in (
            {"action": "install-firewall"},
            {"action": "status", "exec": "id"},
            {"action": "bypass", "targets": "all", "minutes": "5"},
            {"action": "bypass", "targets": ["all"], "minutes": 5},
            {"action": "bypass", "targets": "all", "minutes": True},
        ):
            with self.subTest(request=request), self.assertRaises(vpn.ControlError):
                self.controller.dispatch(request)
        self.assertEqual(self.runner.calls, [])

    def test_switch_verifies_relay_preserves_identity_and_cleans_secrets(self) -> None:
        """Live server changes never replace home VPN or persistent profiles."""
        message = self.controller.switch("test-relay")
        self.assertIn("198.51.100.1", message)
        self.assertEqual(len(self.runner.snapshots), 1)
        self.assertIn("PrivateKey = " + base64.b64encode(b"s" * 32).decode(), self.runner.snapshots[0])
        self.assertIn("FwMark = 0x51822", self.runner.snapshots[0])
        self.assertFalse(any("wg-home" in args for args in self.runner.calls))
        self.assertEqual(list(self.root.iterdir()), [])
        curl = next(args for args in self.runner.calls if args[0] == "curl")
        self.assertEqual(curl[curl.index("--interface") + 1], "10.64.1.2")

    def test_failed_switch_restores_previous_peer(self) -> None:
        """An unverified exit restores the complete original WireGuard snapshot."""
        self.runner.verify = False
        with self.assertRaisesRegex(vpn.ControlError, "previous peer restored"):
            self.controller.switch("test-relay")
        self.assertEqual(self.runner.snapshots[-1], self.runner.original)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_unapproved_relay_does_not_touch_wireguard(self) -> None:
        """Arbitrary relay endpoints and keys cannot enter privileged commands."""
        with self.assertRaises(vpn.ControlError):
            self.controller.switch("$(id)")
        self.assertEqual(self.runner.calls, [])

    def test_dns_housekeeping_clears_only_dns_and_not_other_connections(self) -> None:
        """Mode changes clear TCP/UDP DNS tuples without resetting home VPN or SSH."""
        self.controller.bypass("192.168.0.50", 5)
        self.runner.calls.clear()
        self.runner.sets[vpn.SET_NAME].clear()
        self.controller.reconcile_dns()
        calls = [args for args in self.runner.calls if args[0] == "conntrack"]
        self.assertEqual(len(calls), 2)
        for args in calls:
            self.assertEqual(args[-2:], ("--dport", "53"))
            self.assertIn("192.168.0.50", args)

    def test_status_never_reads_private_keys(self) -> None:
        """Status commands expose only explicit public WireGuard fields."""
        self.controller.status()
        wg = [args for args in self.runner.calls if args[0] == "wg"]
        self.assertEqual([args[-1] for args in wg], ["allowed-ips", "endpoints"])

    def test_catalog_covers_all_snapshot_regions_with_valid_public_data(self) -> None:
        """Every versioned region is a valid selectable relay, including Melbourne."""
        catalog = json.loads(Path(__file__).with_name("regions.json").read_text())
        self.assertEqual(catalog["regionCount"], len(catalog["regions"]))
        self.assertIn("au-mel", catalog["regions"])
        self.assertIn("Australia / Melbourne", catalog["regions"]["au-mel"]["label"])
        self.config["relays"] = catalog["regions"]
        for name in catalog["regions"]:
            self.assertEqual(self.controller.relay(name), catalog["regions"][name])

    def test_configured_default_keeps_original_profile_and_peer(self) -> None:
        """Enabling the controller cannot replace the existing Melbourne identity."""
        profile = Path(self.config["profile"])
        profile.write_text(self.runner.original)
        self.assertEqual(self.runner.calls, [])
        original = self.controller.relay("configured")
        self.assertEqual(original["endpoint"], "192.0.2.2:51820")
        self.controller.switch("configured")
        self.assertEqual(profile.read_text(), self.runner.original)

    def test_catalog_refresh_ignores_inactive_and_non_wireguard_relays(self) -> None:
        """Catalog maintenance only adds active public WireGuard regions."""
        key = self.config["relays"]["test-relay"]["publicKey"]
        row = {
            "active": True,
            "type": "wireguard",
            "hostname": "au-mel-wg-002",
            "pubkey": key,
            "ipv4_addr_in": "192.0.2.2",
            "country_name": "Australia",
            "city_name": "Melbourne",
        }
        result = update_catalog.catalog(
            [
                row,
                row | {"hostname": "au-mel-wg-001", "ipv4_addr_in": "192.0.2.1"},
                row | {"hostname": "gb-lon-wg-001", "active": False},
                row | {"hostname": "gb-lon-ovpn-001", "type": "openvpn"},
            ],
            "2026-11-02",
        )
        self.assertEqual(result["regionCount"], 1)
        self.assertEqual(result["activeWireGuardRelays"], 2)
        self.assertEqual(result["regions"]["au-mel"]["endpoint"], "192.0.2.1:51820")

    def test_firewall_limits_forwarding_and_checks_dns_expiry(self) -> None:
        """Direct forwarding requires both a bypass mark and live set membership."""
        rules = vpn.firewall_rules(self.config)
        incoming = [args for _, chain, args in rules if chain == "vpn-bypass-in"]
        self.assertIn("REPLY", incoming[0])
        self.assertEqual(incoming[0][-1], vpn.WAN_MARK)
        forwarding = [args for table, chain, args in rules if table == "filter" and chain == "vpn-bypass-fwd"]
        self.assertEqual(len(forwarding), 2)
        for args in forwarding:
            self.assertIn(vpn.BYPASS_MARK, args)
            self.assertIn("--match-set", args)
            self.assertEqual(args[args.index("-o") + 1], "enp2s0")
        dns = [args for _, chain, args in rules if chain == "vpn-bypass-dns-in"]
        self.assertEqual([args[-1] for args in dns], ["ACCEPT", "REJECT", "ACCEPT", "REJECT"])
        output = [args for _, chain, args in rules if chain == "vpn-bypass-out"]
        protected = next(i for i, args in enumerate(output) if "adguardhome" in args)
        bypassed = next(i for i, args in enumerate(output) if "vpn-bypass-dns" in args)
        self.assertLess(protected, bypassed)


if __name__ == "__main__":
    unittest.main()
