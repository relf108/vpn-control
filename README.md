# vpn-control

A small, privileged controller behind an unprivileged OliveTin portal. It adds
timed outbound-VPN bypasses to an **existing NixOS WireGuard gateway**. It never
stops the incoming home VPN.

This is an initial implementation, not a general-purpose VPN appliance. Test on
your gateway before making it the only route to your network. Do not expose the
portal publicly.

## Features

- Bypass all clients, or a comma-separated list of LAN/WireGuard client IPv4s.
- Choose 5, 15, 30, or 60 minutes; restore all or individual clients early.
- Kernel `ipset` timeouts end bypass even if OliveTin or the controller crashes.
- Keep both WireGuard interfaces running. Protected traffic still fails closed
  when the outbound tunnel fails; only explicit bypasses use the ISP.
- Select any active region in the versioned Mullvad catalog. Verify the new exit and restore the
  previous peer if verification fails. Neither private keys nor home peers change.
- Show active bypass lifetimes, public peer data, LAN neighbors, and the gateway's
  observed public IPv4. Verify each client's public IP separately.
- Keep existing AdGuard filters for both modes. Protected clients use the existing
  resolver; bypassed DNS queries go to a second AdGuard instance using Quad9 DoH
  over the ISP. The normal resolver stays pinned to the VPN even if its host bypasses.
- Keep untunnelled IPv6 blocked in every mode.

The first UI uses IP-address entry, not automatic device identity or a discovered
device checklist. Use router DHCP reservations. A remote WireGuard peer counts as
one client; devices NATed behind that peer cannot be selected separately.

**Bypass deliberately exposes selected internet traffic to your home ISP and uses
your home public IP. The home tunnel still encrypts remote traffic as far as home,
but home-to-internet traffic no longer passes through Mullvad.**

## Declarative installation

The flake exports `nixosModules.default`, `packages.<system>.default`, unit-test
checks, a formatter, and a development shell for x86_64-linux and aarch64-linux.
`flake.lock` pins development/build dependencies. The module uses the host's
`pkgs`, so follow the host's nixpkgs input when installing into a flake.

Example after publishing this repository:

```nix
{
  inputs.vpn-control.url = "github:OWNER/vpn-control";
  inputs.vpn-control.inputs.nixpkgs.follows = "nixpkgs";

  outputs = { nixpkgs, vpn-control, ... }: {
    nixosConfigurations.gateway = nixpkgs.lib.nixosSystem {
      modules = [
        ./configuration.nix
        vpn-control.nixosModules.default
        {
          services.homelab-vpn-control = {
            enable = true;
            lanInterface = "enp2s0";
            lanNetwork = "192.168.0.0/24";
            hostAddress = "192.168.0.100";
            homeInterface = "wg-home";
            homeNetwork = "10.77.0.0/24";
            homeAddress = "10.77.0.1";
            mullvadInterface = "wg-mullvad";
            credentialsFile = "/run/secrets/olivetin-users.yaml";
            # Leave relays unset to offer every region from the pinned catalog.
          };
        }
      ];
    };
  };
}
```

For a non-flake NixOS configuration, import a pinned public revision:

```nix
let
  portal = builtins.getFlake "github:OWNER/vpn-control/FULL_COMMIT_SHA";
in {
  imports = [ portal.nixosModules.default ];
  services.homelab-vpn-control.enable = true;
}
```

During local development, `builtins.getFlake "path:/absolute/path/to/vpn-control"`
also works with ordinary impure `nix-instantiate` / non-flake NixOS evaluation.
Replace the development path with an immutable GitHub revision before relying on
remote reproducibility. No GitHub repository is created or published by this code.

### Gateway prerequisites

The module currently integrates with the following existing gateway contract:

- `homelab-vpn-routing.service`, routing table `51821`, and marks `0x51821`
  (protected traffic) / `0x51822` (ordinary WAN replies and tunnel transport).
- `homelab-vpn-mark`, `homelab-vpn-post`, and `homelab-vpn-forward` privacy guards,
  plus an unreachable backup default in table `51821`.
- `wg-quick-wg-home` and `wg-quick-wg-mullvad`, or the configured interface names.
  Incoming WireGuard has per-peer AllowedIPs; outgoing WireGuard has one peer and
  an IPv4 tunnel address. The host's main default route leads to the ISP router.
- The existing main-LAN and home-VPN forwarding policies, IPv6 bypass guards,
  and disabled ICMP redirects. Client networks must be /24 or smaller.
- Declarative `services.adguardhome.settings`, with `mutableSettings = false`.
- Recent nixpkgs with the `olivetin-3k` package. Legacy OliveTin is not used.

It adds mark `0x51823`, routing-rule priority `10903`, and dedicated `vpn-bypass-*`
chains. Do not reuse those identifiers for another policy. It sets
`net.ipv4.conf.all.src_valid_mark = 1` so reverse-path checks honor reply marks.

This module does **not** replace or create the underlying VPN gateway. An unrelated
NixOS host needs that gateway contract first. Interface/subnet defaults are examples,
not hardware discovery. Host relay choices belong in the consuming configuration;
the public project contains no account, client key, or host-specific default selection.

### Regions and the configured default

The catalog snapshot currently covers **91 active regions** (526 active WireGuard
servers, retrieved 2026-11-02). Each region selects one deterministic active server;
the displayed label includes its hostname. The first/default choice always restores
the peer in the existing private profile. On this gateway that is Melbourne; enabling
the portal never switches it to another country. `configuredRelayTitle` customizes
that choice's label without reading private data into Nix.

The catalog works without a live metadata API, including when Mullvad is down.
It is a reviewed source snapshot, not a claim that an old pinned revision always
matches the current network. Maintainers can refresh it before publishing an update:

```sh
python3 update_catalog.py
nix flake check
git diff -- regions.json
```

Commit the reviewed public catalog, then update the consuming flake revision.
`relays` can replace the catalog with a custom attribute set containing `publicKey`,
`endpoint`, and optional `label`; leave it unset to keep all regions available.

### Secrets and portability

All service definitions, firewall integration, DNS/filter policy, UI actions, and
approved relay metadata are Nix configuration. Temporary bypasses and live server
choices are intentional runtime state, not configuration-file edits.

Keep these outside Git and outside source paths copied into the Nix store:

- `/var/lib/wireguard/wg-home.conf`, `home.key`, and `wg-mullvad.conf`: the gateway's
  existing identity/profile secret material. Restore these securely, or provision
  them with a secret-management module. This project does not generate identities.
- `/var/lib/vpn-control/olivetin-users.yaml` (default), or `credentialsFile`:
  root-owned mode 0600 YAML loaded through systemd credentials.
- Caddy's CA private state, if preserving trust across reinstalls. If it is not
  restored, the new CA must be trusted again on each client.

Credential file shape:

```yaml
authLocalUsers:
  users:
    - username: operator
      usergroup: vpn-operators
      password: '$argon2id$v=19$REPLACE_WITH_A_REAL_ENCODED_HASH'
```

OliveTin 3k needs **Argon2id**, not bcrypt or plaintext. Generate an encoded hash
locally, without putting the password in command arguments or shell history:

```sh
nix shell nixpkgs#libargon2 nixpkgs#openssl
read -rsp 'Portal password: ' password; printf '\n'
printf '%s' "$password" | argon2 "$(openssl rand -base64 16)" -id -t 4 -m 16 -p 6 -l 32 -e
unset password
```

Use a secret manager such as sops-nix/agenix to provision the YAML declaratively,
or securely restore the external secret file with the rest of the host's secrets.
Do not use `builtins.readFile` on it or interpolate its contents into Nix. A missing
credential file prevents OliveTin from starting; there is no anonymous fallback.

Reinstalling on the same hardware needs the Nix configuration, this pinned flake,
and those external secrets. DNS caches and logs are disposable. Reboot clears all
bypasses. Restarting the outbound interface restores the server from its original
profile; portal-selected relay changes do not rewrite that secret profile.

The package build uses an explicit source allowlist. `.gitignore` is an additional
guard, not a secret scanner. Review `git diff --cached` before publishing; never
force-add credentials or packet captures. There are no real credentials or private
keys in the public-project sources; tests generate ephemeral keys or synthetic data.

## Portal access

Open `https://HOST_LAN_ADDRESS:8443` from the LAN or incoming home VPN. Caddy binds
only the configured LAN IPv4 and rejects source addresses outside those two
networks. OliveTin itself listens on loopback `127.0.0.1:1337`. Do not forward 8443
at the router.

Caddy uses an internal CA. Securely copy its public root certificate from the
server and install it as a trusted CA on your clients. On iOS, install the profile
and enable full trust under Certificate Trust Settings. Never distribute the CA's
private key. Do not bypass certificate warnings for routine password login.

All actions require the `vpn-operators` group. The web process cannot run arbitrary
root commands: it can only send typed requests over a restricted Unix socket. The
controller has `CAP_NET_ADMIN`, read-only profile access, and no general sudo rule.

Global bypass replaces individual timers. Restore-all cancels every bypass.
Individual edits are rejected while global bypass is active, so there is no hidden
global rule overriding a device's restore button. Connections may need to reconnect
when their public IP changes. DNS NAT housekeeping removes stale DNS tuples on
mode changes and expiry; per-packet DNS access checks enforce expiry even if that
housekeeping stops. A controller outage can briefly delay DNS recovery, not extend
the privacy exception.

Both AdGuard instances load the same declarative filters and filtering options.
Their downloaded filter caches and query logs are separate, so list refresh timing
can differ. UI-only edits to the second instance are overwritten on restart.

## Validation

```sh
nix flake check
nix build
nix develop -c python3 -m unittest discover -v
nix develop -c ruff check .
nix develop -c ruff format --check .
```

The consuming NixOS configuration exposes
`config.system.build.vpnControlConfigChecks` to validate its generated bypass AdGuard
configuration and Caddy configuration without deployment. For a non-flake host:

```sh
nix-build '<nixpkgs/nixos>' -I nixos-config=/path/to/configuration.nix \
  -A config.system.build.vpnControlConfigChecks --no-out-link
```

`network_runtime.py` tests the actual gateway's public firewall/routing scripts
with real WireGuard links, LAN and remote clients, fake upstream servers, kernel
expiry, DNS routing, controller death, and provider failure. It automatically
creates isolated user/network namespaces; it refuses direct root execution and
never changes the host network. It requires subordinate UID mappings, user
namespaces, WireGuard/ipset kernel support, `conntrack`, `nsenter`, and `sysctl`.

Supply a JSON fixture containing only `firewall` and `routing` script strings:

```sh
VPN_GATEWAY_FIXTURE=/path/to/public-gateway-fixture.json \
  nix develop -c python3 network_runtime.py
```

This optional integration test is separate from rootless flake unit checks.
`smoke_olivetin.py --settings /path/to/generated-olivetin-settings.json` additionally
tests the actual OliveTin login/ACLs and form argument templates in a private netns.
It replaces controller commands with harmless argv-printing stubs and uses disposable
credentials, never real portal credentials.

Production rollout still needs LAN/remote access checks, a bypass expiry check,
DNS checks, IPv6 bypass checks, and verification from an external client. Keep a
LAN SSH session open; do not activate networking changes for the first time over
your only remote management path.
