{
  description = "pinentry-touchid (kitten fork) — pinentry that uses macOS Touch ID";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs =
    { nixpkgs, flake-utils, ... }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        version = "0.1.1";
        releaseApp = pkgs.writeShellApplication {
          name = "release";
          runtimeInputs = with pkgs; [ gh jq zip git ];
          text = ''exec bash ${./scripts/release.sh} "$@"'';
        };
      in
      {
        packages = rec {
          default = prebuilt;

          # Pre-built variant (default): fetch the Developer ID-signed .app and
          # wrap its inner binary with pinentry-mac on PATH. Enforced Touch ID
          # needs a signature the sandbox can't make — hence prebuilt vs unsigned.
          prebuilt = pkgs.stdenvNoCC.mkDerivation {
            pname = "pinentry-touchid";
            inherit version;

            src = pkgs.fetchurl {
              url = "https://github.com/kitten/pinentry-touchid/releases/download/v${version}/pinentry-touchid-macos.zip";
              # Printed by `nix run .#release` — replace after publishing v0.1.1.
              hash = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
            };

            nativeBuildInputs = [
              pkgs.unzip
              pkgs.makeWrapper
            ];

            # Pre-signed: don't strip/rewrite, or the signature + profile break.
            dontBuild = true;
            dontFixup = true;

            unpackPhase = "unzip -q $src";

            installPhase = ''
              mkdir -p $out/Applications $out/bin
              cp -R pinentry-touchid.app $out/Applications/
              makeWrapper \
                $out/Applications/pinentry-touchid.app/Contents/MacOS/pinentry-touchid \
                $out/bin/pinentry-touchid \
                --prefix PATH : ${pkgs.pinentry_mac}/bin
            '';

            meta = with pkgs.lib; {
              description = "Pinentry that uses macOS Touch ID (kitten fork)";
              homepage = "https://github.com/kitten/pinentry-touchid";
              license = licenses.asl20;
              platforms = platforms.darwin;
              mainProgram = "pinentry-touchid";
            };
          };

          # Unsigned variant: the reproducible build entrypoint. Not usable as-is
          # (the entitlement isn't authorized until signed); scripts/release.sh
          # signs it and publishes it as the artifact `prebuilt` fetches.
          unsigned = pkgs.buildGoModule {
            pname = "pinentry-touchid-unsigned";
            inherit version;

            src = ./.;
            vendorHash = "sha256-v3JtUk94/javwhtUsPUFV9EwFfaixZpb4AqKpCEaZp4=";
            proxyVendor = true;
            doCheck = false;
            subPackages = [ "." ];
            ldflags = [
              "-s"
              "-w"
              "-X main.version=${version}"
            ];

            patchPhase = ''
              substituteInPlace go.mod \
                --replace-fail "=> ./go-assuan" "=> $src/go-assuan"
            '';

            # Reshape the binary into a .app with Info.plist + profile, ready to sign.
            postInstall = ''
              app=$out/Applications/pinentry-touchid.app
              mkdir -p $app/Contents/MacOS
              mv $out/bin/pinentry-touchid $app/Contents/MacOS/pinentry-touchid
              rmdir $out/bin || true
              install -m444 ${./assets/Info.plist} $app/Contents/Info.plist
              install -m444 ${./assets/pinentry-touchid.provisionprofile} $app/Contents/embedded.provisionprofile
            '';

            meta = with pkgs.lib; {
              description = "pinentry-touchid (unsigned .app, for local Developer ID signing)";
              homepage = "https://github.com/kitten/pinentry-touchid";
              license = licenses.asl20;
              platforms = platforms.darwin;
            };
          };
        };

        apps.release = {
          type = "app";
          program = "${releaseApp}/bin/release";
        };

        devShells.default = pkgs.mkShell {
          packages = with pkgs; [
            go
            gopls
            gotools
          ];
          shellHook = ''
            unset GOPATH GOROOT
          '';
        };
      }
    );
}
