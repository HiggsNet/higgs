(import
  (
    let
      lock = builtins.fromJSON (builtins.readFile ./flake.lock);
      nixpkgs = lock.nodes.nixpkgs.locked;
    in
    fetchTarball {
      url = "https://github.com/NixOS/nixpkgs/archive/${nixpkgs.rev}.tar.gz";
      sha256 = nixpkgs.narHash;
    }
  )
  { }
).callPackage
  (
    { buildGoModule, lib }:
    let
      cleanSrc = lib.cleanSourceWith {
        src = ./.;
        filter = path: type:
          type != "socket"
          && !(lib.hasInfix "/.higgs" path)
          && !(lib.hasInfix "/.public-test" path)
          && !(lib.hasInfix "/build" path)
          && !(lib.hasInfix "/dist" path)
          && !(lib.hasSuffix "/result" path);
      };
    in
    buildGoModule {
      pname = "higgs";
      version = "dirty";
      src = cleanSrc;
      vendorHash = "sha256-NoOelMKfFmgXd/CRitCSct7dFf7Nrq14jCWtEsbghUo=";
      subPackages = [ "app/higgs" "app/higgs-services" ];
      ldflags = [
        "-s"
        "-w"
        "-X main.buildCommit=unknown"
        "-X main.buildDescribe=dirty"
        "-X main.buildDirty=true"
        "-X main.buildTime=unknown"
      ];
      meta = {
        description = "Trust-first network configuration control plane";
        homepage = "https://github.com/Catofes/higgs";
        license = lib.licenses.mit;
        mainProgram = "higgs";
        platforms = lib.platforms.linux;
      };
    }
  )
  { }
