{
  config,
  lib,
  pkgs,
  ...
}:
let
  cfg = config.services.homelab-vpn-control;
  package = import ./default.nix { inherit pkgs; };
  command = "${package}/bin/vpn-control";
  runtime = "/run/vpn-control";
  controllerConfig = pkgs.writeText "vpn-control.json" (
    builtins.toJSON {
      inherit (cfg)
        lanInterface
        homeInterface
        mullvadInterface
        lanNetwork
        homeNetwork
        hostAddress
        homeAddress
        relays
        deviceNames
        ;
      profile = cfg.profileFile;
      rulePriority = 10903;
      runtimeDirectory = runtime;
      socket = "${runtime}/control.sock";
    }
  );
  apiConfig = pkgs.writeText "vpn-control-api.json" (
    builtins.toJSON {
      mullvadAccountEnabled = cfg.mullvadAccountFile != null;
      inherit (cfg) publicOrigin configuredRelayTitle relays;
      socket = "${runtime}/control.sock";
    }
  );
  yaml = pkgs.formats.yaml { };
  mainDNS = config.services.adguardhome.settings;
  bypassDNS = yaml.generate "vpn-bypass-adguard.yaml" (
    mainDNS
    // {
      http.address = "127.0.0.1:3001";
      dns = mainDNS.dns // {
        bind_hosts = [ "0.0.0.0" ];
        port = 5354;
        upstream_dns = [ "https://dns.quad9.net/dns-query" ];
        bootstrap_dns = [ "9.9.9.9" ];
        fallback_dns = [ ];
      };
      dhcp.enabled = false;
    }
  );
  runtimePath = path: lib.hasPrefix "/" path && !lib.hasPrefix "/nix/store/" path;
in
{
  options.services.homelab-vpn-control = {
    enable = lib.mkEnableOption "private API controls for the homelab VPN gateway";
    lanInterface = lib.mkOption {
      type = lib.types.str;
      default = "enp2s0";
    };
    homeInterface = lib.mkOption {
      type = lib.types.str;
      default = "wg-home";
    };
    mullvadInterface = lib.mkOption {
      type = lib.types.str;
      default = "wg-mullvad";
    };
    lanNetwork = lib.mkOption {
      type = lib.types.str;
      default = "192.168.0.0/24";
    };
    homeNetwork = lib.mkOption {
      type = lib.types.str;
      default = "10.77.0.0/24";
    };
    hostAddress = lib.mkOption {
      type = lib.types.str;
      default = "192.168.0.100";
    };
    homeAddress = lib.mkOption {
      type = lib.types.str;
      default = "10.77.0.1";
    };
    profileFile = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/wireguard/${cfg.mullvadInterface}.conf";
      description = "Absolute runtime path to the existing private outbound profile; never read during evaluation.";
    };
    credentialsFile = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/vpn-control/api-auth.json";
      description = "Absolute runtime path to root-owned JSON with username and passwordHash (Argon2id). Passed through systemd LoadCredential, never imported into Nix.";
    };
    mullvadAccountFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      description = "Optional absolute runtime path to a root-owned 0600 file containing the Mullvad account number. Loaded only by the API through systemd credentials for read-only expiry checks. Never a Nix path or store file.";
    };
    apiPort = lib.mkOption {
      type = lib.types.port;
      default = 1337;
    };
    publicOrigin = lib.mkOption {
      type = lib.types.str;
      default = "https://${cfg.hostAddress}:8443";
      description = "Exact HTTPS origin serving the frontend and /api; required on all POST requests.";
    };
    configuredRelayTitle = lib.mkOption {
      type = lib.types.str;
      default = "Original configured server";
    };
    deviceNames = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
    };
    relays = lib.mkOption {
      type = lib.types.attrsOf (
        lib.types.submodule (
          { name, ... }: {
            options = {
              publicKey = lib.mkOption { type = lib.types.str; };
              endpoint = lib.mkOption { type = lib.types.str; };
              label = lib.mkOption {
                type = lib.types.str;
                default = name;
              };
            };
          }
        )
      );
      default = (builtins.fromJSON (builtins.readFile ./regions.json)).regions;
      description = "Reviewed public relay catalog. No account tokens or private keys.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = config.networking.firewall.enable && !config.networking.nftables.enable;
        message = "vpn-control requires the existing iptables gateway firewall.";
      }
      {
        assertion = config.services.adguardhome.enable && !config.services.adguardhome.mutableSettings;
        message = "vpn-control requires declarative AdGuard Home settings to share filtering policy.";
      }
      {
        assertion = config.systemd.services ? homelab-vpn-routing;
        message = "vpn-control needs the existing homelab-vpn-routing and privacy-guard contract; see README.";
      }
      {
        assertion =
          runtimePath cfg.credentialsFile
          && runtimePath cfg.profileFile
          && (cfg.mullvadAccountFile == null || runtimePath cfg.mullvadAccountFile);
        message = "vpn-control credential/profile options must be absolute runtime paths outside /nix/store.";
      }
    ];

    environment.systemPackages = [ package ];
    environment.etc."vpn-control.json".source = controllerConfig;
    system.build.vpnControlConfigChecks =
      pkgs.runCommand "vpn-control-config-checks"
        {
          nativeBuildInputs = [
            config.services.adguardhome.package
            pkgs.caddy
          ];
        }
        ''
          export HOME="$TMPDIR"
          cp ${bypassDNS} bypass-dns.yaml
          chmod u+w bypass-dns.yaml
          mkdir -p "$TMPDIR/dns-check"
          AdGuardHome --work-dir "$TMPDIR/dns-check" --config "$PWD/bypass-dns.yaml" --check-config
          sed "s|/var/log/caddy/|$TMPDIR/|g" ${config.services.caddy.configFile} > Caddyfile
          caddy validate --adapter caddyfile --config "$PWD/Caddyfile"
          mkdir "$out"
          touch "$out/passed"
        '';
    boot.kernelModules = [
      "ip_set"
      "ip_set_hash_net"
      "xt_set"
      "xt_owner"
    ];
    boot.kernel.sysctl."net.ipv4.conf.all.src_valid_mark" = 1;

    users.groups.vpn-control = { };
    users.groups.vpn-control-api = { };
    users.users.vpn-control-api = {
      isSystemUser = true;
      group = "vpn-control-api";
      extraGroups = [ "vpn-control" ];
    };
    users.groups.vpn-bypass-dns = { };
    users.users.vpn-bypass-dns = {
      isSystemUser = true;
      group = "vpn-bypass-dns";
    };
    # Stable UID before firewall.service starts: owner-based DNS isolation.
    users.groups.adguardhome = { };
    users.users.adguardhome = {
      isSystemUser = true;
      group = "adguardhome";
    };
    systemd.services.adguardhome.serviceConfig.User = "adguardhome";
    systemd.tmpfiles.rules = [ "d /var/lib/vpn-control 0700 root root -" ];

    networking.firewall.extraCommands = lib.mkAfter ''
      ${command} --config ${controllerConfig} install-firewall
    '';
    # Never remove these hooks on stop. Kernel expiry enforces fail-closed policy.
    systemd.services.vpn-control = {
      description = "Constrained VPN controller (kernel-enforced bypass expiry)";
      wantedBy = [ "multi-user.target" ];
      requires = [ "homelab-vpn-routing.service" ];
      after = [ "homelab-vpn-routing.service" ];
      serviceConfig = {
        ExecStart = "${command} --config ${controllerConfig} serve";
        User = "root";
        Group = "vpn-control";
        RuntimeDirectory = "vpn-control";
        RuntimeDirectoryMode = "0750";
        UMask = "0077";
        Restart = "on-failure";
        CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_NETLINK"
          "AF_INET"
          "AF_INET6"
        ];
        ReadOnlyPaths = [ cfg.profileFile ];
      };
    };
    systemd.services.vpn-control-api = {
      description = "Private authenticated VPN HTTP API";
      wantedBy = [ "multi-user.target" ];
      requires = [ "vpn-control.service" ];
      after = [ "vpn-control.service" ];
      environment.VPN_API_CONFIG = apiConfig;
      serviceConfig = {
        ExecStart = "${package}/bin/vpn-control-api --bind 127.0.0.1:${toString cfg.apiPort}";
        LoadCredential = [
          "api-auth.json:${cfg.credentialsFile}"
        ]
        ++ lib.optional (cfg.mullvadAccountFile != null) "mullvad-account:${cfg.mullvadAccountFile}";
        User = "vpn-control-api";
        Group = "vpn-control-api";
        UMask = "0077";
        Restart = "on-failure";
        CapabilityBoundingSet = [ ];
        NoNewPrivileges = true;
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
        ];
        InaccessiblePaths = [
          "/var/lib/wireguard"
          cfg.profileFile
        ];
      };
    };
    systemd.services.vpn-bypass-dns = {
      description = "AdGuard DNS for explicitly bypassed clients only";
      wantedBy = [ "multi-user.target" ];
      requires = [ "firewall.service" ];
      after = [
        "firewall.service"
        "network.target"
      ];
      preStart = ''
        cp --force ${bypassDNS} "$STATE_DIRECTORY/AdGuardHome.yaml"
        chmod 600 "$STATE_DIRECTORY/AdGuardHome.yaml"
      '';
      serviceConfig = {
        ExecStart = "${lib.getExe config.services.adguardhome.package} --no-check-update --work-dir /var/lib/vpn-bypass-dns --config /var/lib/vpn-bypass-dns/AdGuardHome.yaml";
        User = "vpn-bypass-dns";
        Group = "vpn-bypass-dns";
        StateDirectory = "vpn-bypass-dns";
        UMask = "0077";
        Restart = "on-failure";
        NoNewPrivileges = true;
        CapabilityBoundingSet = [ ];
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];
      };
    };
  };
}
