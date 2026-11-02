{
  description = "Private OliveTin controls for an existing NixOS WireGuard VPN gateway";

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
              ./test_vpn_control.py
              ./network_runtime.py
              ./smoke_olivetin.py
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
              libargon2
              olivetin-3k
            ];
          };
        }
      );
      formatter = eachSystem (system: nixpkgs.legacyPackages.${system}.nixfmt);
    };
}
