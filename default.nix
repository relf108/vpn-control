{ pkgs }:
let
  python = pkgs.python3.withPackages (ps: [
    ps.flask
    ps.gunicorn
    ps.argon2-cffi
  ]);
in
pkgs.stdenvNoCC.mkDerivation {
  pname = "vpn-control";
  version = "0.3.0";
  # Never copy credentials, captures, or other local files into a build input.
  src = pkgs.lib.fileset.toSource {
    root = ./.;
    fileset = pkgs.lib.fileset.unions [
      ./vpn_control.py
      ./vpn_api.py
      ./mullvad_account.py
      ./test_mullvad_account.py
      ./test_vpn_api.py
      ./test_api_runtime.py
      ./test_vpn_control.py
      ./pyproject.toml
      ./regions.json
      ./update_catalog.py
    ];
  };
  nativeBuildInputs = [ pkgs.makeWrapper ];
  doCheck = true;
  checkPhase = ''
    ${python}/bin/python3 -m unittest discover -v
  '';
  installPhase = ''
    install -Dm755 vpn_control.py "$out/libexec/vpn_control.py"
    install -Dm644 vpn_api.py "$out/libexec/vpn_api.py"
    install -Dm644 mullvad_account.py "$out/libexec/mullvad_account.py"
    makeWrapper ${python}/bin/python3 "$out/bin/vpn-control-account-credential" \
      --add-flags "$out/libexec/mullvad_account.py"
    makeWrapper ${python}/bin/python3 "$out/bin/vpn-control-password" \
      --add-flags "$out/libexec/vpn_api.py"
    makeWrapper ${python}/bin/gunicorn "$out/bin/vpn-control-api" \
      --add-flags "--no-control-socket --workers 1 --worker-class gthread --threads 4 --timeout 90 --limit-request-line 4096 --limit-request-fields 30 'vpn_api:create_app()'" \
      --set PYTHONPATH "$out/libexec"
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
          pkgs.getent
        ]
      }
  '';
  doInstallCheck = true;
  installCheckPhase = ''
    "$out/bin/vpn-control-api" --version
    "$out/bin/vpn-control-password" --help
    "$out/bin/vpn-control" --help
    ${python}/bin/python3 test_api_runtime.py "$out/bin/vpn-control-api"
  '';
  meta = {
    description = "Private authenticated API and constrained controller for an existing WireGuard gateway";
    license = pkgs.lib.licenses.mit;
    platforms = pkgs.lib.platforms.linux;
    mainProgram = "vpn-control";
  };
}
