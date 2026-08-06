{
  description = "Photon trust-first network configuration system";

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
          version = pkgs.lib.removeSuffix "\n" (builtins.readFile ./VERSION);
          cleanSrc = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              type != "socket"
              && !(pkgs.lib.hasInfix "/.photon" path)
              && !(pkgs.lib.hasInfix "/.public-test" path)
              && !(pkgs.lib.hasInfix "/build" path)
              && !(pkgs.lib.hasInfix "/dist" path)
              && !(pkgs.lib.hasSuffix "/result" path);
          };
          photon = pkgs.buildGoModule {
            pname = "photon";
            inherit version;
            src = cleanSrc;
            vendorHash = "sha256-v0SzEL0agW+0qwx4mvoOW0JSemkaAm5FgCpg7zHfsxs=";

            subPackages = [ "app/photon" "app/photon-services" ];
            # Unit and root smoke tests are run explicitly by CI/Make targets.
            # Nix packaging only needs to compile the installable binaries.
            doCheck = false;

            ldflags = [
              "-X main.buildCommit=${self.shortRev or "unknown"}"
              "-X main.buildDescribe=${self.shortRev or "dirty"}"
              "-X main.buildDirty=${if self ? rev then "false" else "true"}"
              "-X main.buildTime=unknown"
            ];

            meta = {
              description = "Trust-first network configuration control plane";
              homepage = "https://github.com/Catofes/photon";
              license = pkgs.lib.licenses.mit;
              mainProgram = "photon";
              platforms = pkgs.lib.platforms.linux;
            };
          };
        in
        {
          default = photon;
          photon = photon;
        });

      nixosModules.default = { config, lib, pkgs, ... }:
        let
          cfg = config.services.photon;
        in
        {
          options.services.photon = {
            enable = lib.mkEnableOption "Photon mesh daemon";

            package = lib.mkOption {
              type = lib.types.package;
              default = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
              defaultText = lib.literalExpression "self.packages.\${pkgs.stdenv.hostPlatform.system}.default";
              description = "Photon package to run.";
            };

            configFile = lib.mkOption {
              type = lib.types.str;
              default = "/etc/photon/config.yaml";
              description = "Path to the Photon configuration file.";
            };
          };

          config = lib.mkIf cfg.enable {
            systemd.services.photon = {
              description = "Photon mesh daemon";
              wantedBy = [ "multi-user.target" ];
              wants = [ "network-online.target" ];
              after = [ "network-online.target" "strongswan.service" ];
              environment.PHOTON_CONFIG = cfg.configFile;
              path = with pkgs; [
                bird2
                iproute2
                iputils
                ipset
                iptables
                nftables
                procps
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
                RuntimeDirectory = "photon";
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
              pkgs.ipset
              pkgs.iptables
              pkgs.nftables
              pkgs.strongswan
              pkgs.wireguard-tools
            ];
          };
        });
    };
}
