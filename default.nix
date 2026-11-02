{ pkgs }:
pkgs.stdenvNoCC.mkDerivation {
  pname = "vpn-control";
  version = "0.1.0";
  # Never copy credentials, captures, or other local files into a build input.
  src = pkgs.lib.fileset.toSource {
    root = ./.;
    fileset = pkgs.lib.fileset.unions [
      ./vpn_control.py
      ./test_vpn_control.py
      ./pyproject.toml
      ./regions.json
      ./update_catalog.py
    ];
  };
  nativeBuildInputs = [ pkgs.makeWrapper ];
  doCheck = true;
  checkPhase = ''
    ${pkgs.python3}/bin/python3 -m unittest discover -v
  '';
  installPhase = ''
    install -Dm755 vpn_control.py "$out/libexec/vpn_control.py"
    makeWrapper ${pkgs.python3}/bin/python3 "$out/bin/vpn-control" \
      --add-flags "$out/libexec/vpn_control.py" \
      --prefix PATH : ${
        pkgs.lib.makeBinPath [
          pkgs.iproute2
          pkgs.iptables
          pkgs.ipset
          pkgs.wireguard-tools
          pkgs.curl
          pkgs.conntrack-tools
        ]
      }
  '';
  meta = {
    description = "Constrained OliveTin controls for an existing WireGuard gateway";
    license = pkgs.lib.licenses.mit;
    platforms = pkgs.lib.platforms.linux;
    mainProgram = "vpn-control";
  };
}
