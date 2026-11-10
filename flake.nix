{
  description = "Private authenticated API for an existing NixOS WireGuard VPN gateway";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      eachSystem = nixpkgs.lib.genAttrs systems;
    in
    {
      nixosModules.default = import ./module.nix;
      packages = eachSystem (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = import ./default.nix { inherit pkgs; };
          password = pkgs.writeShellScriptBin "vpn-control-password" ''
            exec ${self.packages.${system}.default}/bin/vpn-control-password "$@"
          '';
          account-credential = pkgs.writeShellScriptBin "vpn-control-account-credential" ''
            exec ${self.packages.${system}.default}/bin/vpn-control-account-credential "$@"
          '';
        }
      );
      checks = eachSystem (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
          styleSource = pkgs.lib.fileset.toSource {
            root = ./.;
            fileset = pkgs.lib.fileset.unions [
              ./default.nix
              ./flake.nix
              ./module.nix
              ./pyproject.toml
              ./vpn_control.py
              ./vpn_api.py
              ./mullvad_account.py
              ./test_mullvad_account.py
              ./test_vpn_api.py
              ./test_api_runtime.py
              ./test_vpn_control.py
              ./network_runtime.py
              ./update_catalog.py
            ];
          };
        in
        {
          controller = self.packages.${system}.default;
          style =
            pkgs.runCommand "vpn-control-style"
              {
                nativeBuildInputs = [
                  pkgs.ruff
                  pkgs.nixfmt
                ];
              }
              ''
                cd ${styleSource}
                ruff check --no-cache .
                ruff format --check --no-cache .
                nixfmt --check default.nix flake.nix module.nix
                mkdir "$out"
              '';
        }
      );
      devShells = eachSystem (
        system:
        let
          pkgs = import nixpkgs { inherit system; };
        in
        {
          default = pkgs.mkShell {
            packages = with pkgs; [
              python3
              (python3.withPackages (ps: [
                ps.flask
                ps.gunicorn
                ps.argon2-cffi
              ]))
              ruff
              nixfmt
              iptables
              ipset
              iproute2
              wireguard-tools
              curl
              conntrack-tools
              util-linux
              procps
            ];
          };
        }
      );
      formatter = eachSystem (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
