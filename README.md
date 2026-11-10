# vpn-control

Private, authenticated HTTP API and constrained controller for an **existing
NixOS WireGuard gateway**. The separate [Flutter dashboard](https://github.com/relf108/vpn-control-web)
provides the UI. Neither service should be exposed to the public internet.

## Features and safety

- Discover recent LAN neighbours, exact incoming WireGuard peer addresses, and
  offline devices with active bypasses. Discovery is passive, not a subnet scan.
- Bypass selected devices or the whole network for 5, 15, 30, or 60 minutes.
  Restore selected devices or all devices early.
- Kernel ipset timeouts enforce expiry even when the API or controller stops.
- Keep both WireGuard interfaces running. Protected traffic fails closed if
  Mullvad fails. Untunnelled IPv6 remains blocked in every mode.
- Change approved Mullvad relays live, verify the exit, and roll back on failure.
  Restarting Mullvad restores the original configured peer.
- Preserve AdGuard filtering for protected and bypassed DNS.

**Bypass deliberately exposes selected internet traffic to your home ISP and
uses your home public IP.** Global bypass includes the server and replaces
individual timers. Restore all before changing individual bypasses.

Device names, neighbour entries, and recent handshakes are not trusted identities
or connectivity guarantees. Use DHCP reservations. NATed clients behind one VPN
peer cannot be selected separately. Check public IP and DNS from each client;
gateway status reports the gateway's observed exit only.

## Flake installation

Both flakes export `nixosModules.default`, `packages.<system>.default`, checks,
a formatter, and a development shell for x86_64-linux and aarch64-linux.

```nix
{
  inputs.vpn-control.url = "github:relf108/vpn-control";
  inputs.vpn-control.inputs.nixpkgs.follows = "nixpkgs";
  inputs.vpn-control-web.url = "github:relf108/vpn-control-web";
  inputs.vpn-control-web.inputs.nixpkgs.follows = "nixpkgs";

  # Add both inputs' nixosModules.default to the host's modules list.
  # In a host module:
  services.homelab-vpn-control = {
    enable = true;
    profileFile = "/var/lib/wireguard/wg-mullvad.conf";
    credentialsFile = "/var/lib/vpn-control/api-auth.json";
    publicOrigin = "https://192.168.0.100:8443";
    configuredRelayTitle = "Melbourne (configured default)";
    deviceNames."192.168.0.50" = "Living room TV";
  };
  services.homelab-vpn-web.enable = true;
}
```

Interface/network defaults are `enp2s0`, `192.168.0.0/24`, `192.168.0.100`,
`wg-home`, `10.77.0.0/24`, `10.77.0.1`, and `wg-mullvad`. Override these through
module options. Keep frontend/API ports, host address, networks and public origin
consistent when overriding defaults. The API always binds to loopback.

### Existing gateway contract

This module is not a general-purpose VPN appliance. It requires an existing
`homelab-vpn-routing.service`, iptables (not native nftables), routing table
`51821`, marks `0x51821` (protected) and `0x51822` (WAN replies/tunnel transport),
the `homelab-vpn-mark`, `homelab-vpn-post`, `homelab-vpn-forward` privacy guards,
and an unreachable backup route. It reserves mark `0x51823` and priority `10903`.
AdGuard Home must use declarative settings. Bypass DNS uses port `5354` and a
loopback-only admin UI on `3001`. Review firewall integration before deploying.

### Explicit runtime secrets; no evaluation-time loading

The previous module expected an OliveTin YAML file and hardcoded the WireGuard
profile location. Version 0.2 replaces that YAML with a small JSON file and makes
both paths explicit options. It never imports `secrets.nix`, discovers credentials,
downloads keys, or copies secret contents into the Nix store.

Provision **on the target machine**, before starting the API:

```sh
sudo install -d -m 0700 /var/lib/vpn-control
sudo sh -c 'umask 077; vpn-control-password --username operator > /var/lib/vpn-control/api-auth.json'
```

For the first deployment, run the helper from `nix run github:relf108/vpn-control#password`
instead of the installed `vpn-control-password`. The helper prompts twice with
terminal echo disabled. Do not put a password in command arguments or shell
history. JSON contains only `username` and an encoded Argon2id `passwordHash`.
The file must be root-owned, mode `0600`; keep a secure backup or provision it with
your existing secret manager. A missing/invalid file fails closed, without any
anonymous fallback. Restart `vpn-control-api` after credential rotation.

Nix receives the **string path**, not contents. systemd `LoadCredential` gives
only the unprivileged API a runtime credential copy. The privileged controller
alone reads the existing private outbound profile when restoring the configured
relay. Live relay changes use short-lived mode-0600 snapshots under `/run`, always
removed after use. Persistent profiles and incoming peers are never rewritten.
Keep WireGuard profiles backed up separately; this project does not provision them.

The frontend receives no secrets. Login creates a Secure, HttpOnly,
SameSite=Strict cookie and an in-memory CSRF token. Sessions expire after eight
hours, logout revokes them server-side, and API restart invalidates all sessions.
Five login attempts per minute are allowed globally. Run the supplied single-worker,
threaded Gunicorn wrapper; do not add workers without shared session/rate-limit state.
The tested Gunicorn 26 wrapper disables its separate management socket; systemd
owns process lifecycle, and the HTTP adapter remains unprivileged.

### Optional account-credit expiry

To show when VPN access needs renewing, configure an explicit target-host secret:

```nix
services.homelab-vpn-control.mullvadAccountFile = "/var/lib/vpn-control/mullvad-account";
```

Provision that root-owned, mode-0600 file on the target through your secret manager,
or use the installed hidden-prompt helper:

```sh
sudo sh -c 'umask 077; vpn-control-account-credential > /var/lib/vpn-control/mullvad-account'
```

The flake also exports `packages.<system>.account-credential` for `nix run` before
installation. Restart the API after provisioning/rotating the systemd credential.
This is the **account number**, not a WireGuard key. Keep it out of Nix values,
Git, URLs, command arguments, and the frontend. The default `null` disables lookup
and requires no additional file. Invalid credentials or provider errors never
change routing, disable privacy guards, or prevent ordinary VPN control requests.

The API reads the optional systemd credential, obtains an in-memory access token,
and queries Mullvad's account expiry endpoint over verified HTTPS. Redirects and
environment proxies are disabled. Only expiry/check timestamps and cache state
leave the API. Successful checks are cached for six hours; failures retry after
five minutes. A previous expiry remains explicitly marked stale on refresh failure.
If the provider is unreachable through the current route, lookup fails safely;
it never enables an ISP bypass to obtain account data.

`GET /api/v1/account` requires login and returns `state` (`available`,
`notConfigured`, or `unavailable`), `expiry`, `checkedAt`, and `stale`. No account
ID, account number, or access token is returned. The dashboard shows whole calendar
years/months/days remaining, with month-end clamping, and opens the fixed Mullvad
account page in a new tab for top-ups. It never renews automatically or rotates keys.

### Private HTTPS

Open `https://192.168.0.100:8443` from the LAN or incoming home VPN. The frontend
module serves local Flutter assets and proxies `/api/*` through Caddy. It restricts
source networks and opens the port only on the configured interfaces. Trust
Caddy's internal CA on clients. Never forward this port from your router.

## HTTP API

All endpoints live under `/api/v1`. No CORS is enabled. Every POST requires
`Origin` matching `publicOrigin`; authenticated POSTs also require
`X-CSRF-Token` returned by login or session lookup. Use HTTPS and a cookie jar for
non-browser clients. There is no unauthenticated network controller endpoint.

| Method | Path | JSON body / response |
| --- | --- | --- |
| POST | `/login` | `{ "username": "operator", "password": "..." }`; returns `csrfToken` and cookie |
| GET | `/session` | Returns `csrfToken` for the current session |
| POST | `/logout` | `{}`; revokes session |
| GET | `/status` | Safe human-readable status in `message` |
| GET | `/devices` | Structured `devices` list with address/title/source/state/bypassSeconds |
| GET | `/relays` | Approved `relays` with id/label, plus allowed `durations` |
| POST | `/bypass` | `{ "targets": ["192.168.0.50"], "minutes": 15 }`, or targets `"all"` |
| POST | `/restore` | `{ "targets": ["192.168.0.50"] }`, or targets `"all"` |
| POST | `/switch` | `{ "relay": "configured" }`, or an approved catalog ID |

Responses include `ok`. Errors include `message`. Status codes distinguish invalid
input (400), authentication (401), CSRF/origin (403), controller conflict (409),
rate/session limits (429), and controller unavailable (503). Extra fields, invalid
durations, and arbitrary commands/relay endpoints are rejected. Client lists
contain at most 64 addresses, validated again by the privileged controller.

The root/membership-restricted CLI and Unix socket remain available:

```sh
sudo vpn-control status
sudo vpn-control devices
sudo vpn-control bypass 192.168.0.50,10.77.0.2 15
sudo vpn-control restore all
sudo vpn-control switch configured
```

Membership in `vpn-control` grants VPN control, not just read access. Never proxy
`/run/vpn-control/control.sock` directly to unauthenticated network clients.

## Development

```sh
nix develop
ruff check .
ruff format --check .
python3 -m unittest discover -v
nix flake check
```

Tests use synthetic profiles and credentials, without production network changes.
`network_runtime.py` contains the migrated gateway integration harness. Start it
as an ordinary user: it creates its own user/network namespaces and refuses the
host network namespace. It validates WireGuard routing, DNS isolation, timed
bypass expiry and controller failure against the host's public firewall fixture:

```sh
# Build tests/vpn_gateway_fixture.nix from the server repo with its pinned nixpkgs.
# Then run from this repository's development shell:
VPN_GATEWAY_FIXTURE=/nix/store/...-vpn-gateway-fixture.json python3 network_runtime.py
```

The host needs user namespaces, UID/GID mapping helpers, and the required kernel
network modules. The fixture contains routing/firewall scripts only, not private
keys. The obsolete OliveTin smoke test has been removed; the HTTP boundary is
covered by `test_api_runtime.py` and the Flutter repository owns UI tests.
Refresh public catalog metadata with `python3 update_catalog.py`, then review the
diff before deployment. Review staged source before publishing; ignore rules and
explicit build file sets are guards, not secret scanners.
