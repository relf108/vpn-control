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
        ;
      profile = "/var/lib/wireguard/${cfg.mullvadInterface}.conf";
      rulePriority = 10903;
      runtimeDirectory = runtime;
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
  duration = {
    name = "minutes";
    title = "Duration";
    rejectNull = true;
    default = "15";
    choices =
      map
        (n: {
          title = "${toString n} minutes";
          value = toString n;
        })
        [
          5
          15
          30
          60
        ];
  };
  addresses = {
    name = "targets";
    title = "IPv4 addresses, separated by commas (use reserved DHCP addresses)";
    type = "regex:[0-9.]+(,[0-9.]+)*";
    rejectNull = true;
  };
  action = id: title: args: arguments: {
    inherit id title arguments;
    exec = [ command ] ++ args;
    timeout = 75;
    maxConcurrent = 1;
  };
in
{
  options.services.homelab-vpn-control = {
    enable = lib.mkEnableOption "private OliveTin controls for the homelab VPN gateway";
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
    credentialsFile = lib.mkOption {
      type = lib.types.str;
      default = "/var/lib/vpn-control/olivetin-users.yaml";
      description = "Root-owned runtime YAML containing OliveTin Argon2id users; never a Nix store path.";
    };
    configuredRelayTitle = lib.mkOption {
      type = lib.types.str;
      default = "Original configured server";
      description = "Label for the existing peer; enabling the portal never changes that default.";
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
      description = "Approved relay public keys and literal IPv4:port endpoints. The original configured relay is always available.";
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
        message = "vpn-control needs the existing homelab-vpn-routing service and privacy-guard contract; see README.";
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
          # Validate the real routes/TLS policy, redirecting only filesystem logs to
          # the build sandbox. Never write production logs or CA state during checks.
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
    # Kernel rp_filter must honor the same marks as NixOS's --validmark check.
    boot.kernel.sysctl."net.ipv4.conf.all.src_valid_mark" = 1;

    users.groups.vpn-control = { };
    users.groups.vpn-bypass-dns = { };
    users.users.vpn-bypass-dns = {
      isSystemUser = true;
      group = "vpn-bypass-dns";
    };
    # Preallocate the normally dynamic user so owner-based DNS isolation has a
    # stable UID before firewall.service starts. DynamicUser can use static users.
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
    # Never remove these hooks in extraStopCommands. Without explicit timed set
    # membership the old privacy guards still reject direct forwarding.
    networking.firewall.interfaces.${cfg.lanInterface}.allowedTCPPorts = [ 8443 ];
    networking.firewall.interfaces.${cfg.homeInterface}.allowedTCPPorts = [ 8443 ];

    systemd.services.vpn-control = {
      description = "Constrained VPN portal controller (kernel-enforced bypass expiry)";
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
        ReadOnlyPaths = [ "/var/lib/wireguard" ];
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

    services.olivetin = {
      enable = true;
      # stateVersion 23.11 otherwise selects the vulnerable legacy package.
      package = pkgs.olivetin-3k;
      extraConfigFiles = [ cfg.credentialsFile ];
      settings = {
        ListenAddressSingleHTTPFrontend = "127.0.0.1:1337";
        authRequireGuestsToLogin = true;
        authLocalUsers.enabled = true;
        defaultPermissions = {
          view = false;
          exec = false;
          logs = false;
          kill = false;
        };
        defaultPolicy = {
          showDiagnostics = false;
          showLogList = false;
          showVersionNumber = false;
        };
        accessControlLists = [
          {
            name = "vpn-operators";
            matchUsergroups = [ "vpn-operators" ];
            addToEveryAction = true;
            permissions = {
              view = true;
              exec = true;
              logs = true;
              kill = false;
            };
          }
        ];
        actions = [
          (action "bypass-all" "Bypass ALL devices — uses home ISP"
            [ "bypass" "all" "{{ .Arguments.minutes }}" ]
            [ duration ]
          )
          (action "bypass-selected" "Bypass selected devices — uses home ISP"
            [ "bypass" "{{ .Arguments.targets }}" "{{ .Arguments.minutes }}" ]
            [ addresses duration ]
          )
          (action "restore-all" "Restore protection for ALL devices" [ "restore" "all" ] [ ])
          (action "restore-selected" "Restore protection for selected devices"
            [ "restore" "{{ .Arguments.targets }}" ]
            [ addresses ]
          )
          (action "switch-relay" "Change Mullvad server"
            [ "switch" "{{ .Arguments.relay }}" ]
            [
              {
                name = "relay";
                title = "Approved server (connection resets return to configured default)";
                rejectNull = true;
                default = "configured";
                choices = [
                  {
                    title = cfg.configuredRelayTitle;
                    value = "configured";
                  }
                ]
                ++ lib.sort (a: b: a.title < b.title) (
                  lib.mapAttrsToList (name: relay: {
                    title = relay.label;
                    value = name;
                  }) cfg.relays
                );
              }
            ]
          )
          (
            (action "vpn-status" "Refresh VPN status" [ "status" ] [ ])
            // {
              execOnStartup = true;
              execOnCron = [ "* * * * *" ];
            }
          )
        ];
        dashboards = [
          {
            title = "Home VPN gateway";
            acls = [ "vpn-operators" ];
            contents = [
              {
                type = "display";
                title = "Bypass exposes selected internet traffic to your home ISP. Home VPN stays on. IPv6 stays blocked. Global bypass replaces all individual timers.";
              }
              { title = "Bypass ALL devices — uses home ISP"; }
              { title = "Bypass selected devices — uses home ISP"; }
              { title = "Restore protection for ALL devices"; }
              { title = "Restore protection for selected devices"; }
              { title = "Change Mullvad server"; }
              { title = "Refresh VPN status"; }
              {
                type = "stdout-most-recent-execution";
                title = "vpn-status";
              }
            ];
          }
        ];
      };
    };
    systemd.services.olivetin = {
      requires = [ "vpn-control.service" ];
      after = [ "vpn-control.service" ];
      serviceConfig.SupplementaryGroups = [ "vpn-control" ];
    };

    services.caddy.enable = true;
    services.caddy.virtualHosts."https://${cfg.hostAddress}:8443".extraConfig = ''
      bind ${cfg.hostAddress}
      tls internal
      @outside not remote_ip ${cfg.lanNetwork} ${cfg.homeNetwork}
      respond @outside 403
      reverse_proxy 127.0.0.1:1337
    '';
  };
}
