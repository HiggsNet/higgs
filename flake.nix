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
          higgsnet = pkgs.buildGoModule {
            pname = "higgsnet";
            version = self.shortRev or "dirty";
            src = cleanSrc;
            vendorHash = "sha256-NoOelMKfFmgXd/CRitCSct7dFf7Nrq14jCWtEsbghUo=";

            subPackages = [ "app/higgs" "app/higgs-services" ];

            ldflags = [
              "-s"
              "-w"
              "-X main.buildCommit=${self.shortRev or "unknown"}"
              "-X main.buildDescribe=${self.shortRev or "dirty"}"
              "-X main.buildDirty=${if self ? rev then "false" else "true"}"
              "-X main.buildTime=unknown"
            ];

            postInstall = ''
              mv $out/bin/higgs $out/bin/higgsnet
            '';

            meta = {
              description = "Trust-first network configuration control plane";
              homepage = "https://github.com/Catofes/higgs";
              license = pkgs.lib.licenses.mit;
              mainProgram = "higgsnet";
              platforms = pkgs.lib.platforms.linux;
            };
          };
        in
        {
          default = higgsnet;
          higgsnet = higgsnet;
          # Keep the old flake attribute as a compatibility alias.
          higgs = higgsnet;
        });

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.higgsnet;
        in
        {
          options.services.higgsnet = {
            enable = lib.mkEnableOption "Higgs mesh daemon";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.default";
              description = "Higgs package to run.";
            };

            configFile = lib.mkOption {
              type = lib.types.str;
              default = "/etc/higgs/config.yaml";
              description = "Path to the Higgs configuration file.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.higgsnet = {
              description = "Higgs mesh daemon";
              wantedBy = [ "multi-user.target" ];
              wants = [ "network-online.target" ];
              after = [ "network-online.target" "strongswan.service" ];
              environment.HIGGS_CONFIG = cfg.configFile;
              path = with pkgs; [
                bird2
                iproute2
                iptables
                nftables
                strongswan
              ];
              serviceConfig = {
                Type = "simple";
                User = "root";
                Group = "root";
                ExecStart = "${lib.getExe cfg.package} daemon";
                Restart = "on-failure";
                RestartSec = 2;
                TimeoutStopSec = 30;
                RuntimeDirectory = "higgs";
                RuntimeDirectoryMode = "0700";
                UMask = "0077";
                LimitNOFILE = 65536;
              };
            };
          };
        };

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
