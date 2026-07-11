{
  description = "Higgs trust-first network configuration system";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      supportedSystems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = nixpkgs.lib.genAttrs supportedSystems;
    in
    {
      packages = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
          cleanSrc = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              type != "socket"
              && !(pkgs.lib.hasInfix "/.higgs" path)
              && !(pkgs.lib.hasInfix "/.public-test" path)
              && !(pkgs.lib.hasInfix "/build" path)
              && !(pkgs.lib.hasInfix "/dist" path)
              && !(pkgs.lib.hasSuffix "/result" path);
          };
          higgs = pkgs.buildGoModule {
            pname = "higgs";
            version = self.shortRev or "dirty";
            src = cleanSrc;
            vendorHash = "sha256-NoOelMKfFmgXd/CRitCSct7dFf7Nrq14jCWtEsbghUo=";

            subPackages = [ "app/higgs" ];

            ldflags = [
              "-s"
              "-w"
              "-X main.buildCommit=${self.shortRev or "unknown"}"
              "-X main.buildDescribe=${self.shortRev or "dirty"}"
              "-X main.buildDirty=${if self ? rev then "false" else "true"}"
              "-X main.buildTime=unknown"
            ];

            meta = {
              description = "Trust-first network configuration control plane";
              homepage = "https://github.com/Catofes/higgs";
              license = pkgs.lib.licenses.mit;
              mainProgram = "higgs";
              platforms = pkgs.lib.platforms.linux;
            };
          };
        in
        {
          default = higgs;
          higgs = higgs;
        });

      devShells = forAllSystems (system:
        let
          pkgs = nixpkgs.legacyPackages.${system};
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.bird2
              pkgs.go
              pkgs.gopls
              pkgs.iproute2
              pkgs.iptables
              pkgs.nftables
              pkgs.strongswan
              pkgs.wireguard-tools
            ];
          };
        });
    };
}
