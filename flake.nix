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
      in
      {
        packages.default = pkgs.buildGoModule rec {
          pname = "pinentry-touchid";
          version = "kitten";
          vendorHash = "sha256-v3JtUk94/javwhtUsPUFV9EwFfaixZpb4AqKpCEaZp4=";
          proxyVendor = true;

          doCheck = false;
          src = ./.;
          subPackages = [ "." ];

          buildInputs = [ pkgs.makeBinaryWrapper ];
          nativeBuildInputs = [ pkgs.pinentry_mac pkgs.darwin.sigtool ];
          ldflags = [
            "-s"
            "-w"
            "-X main.version=${version}"
          ];

          patchPhase = ''
            substituteInPlace go.mod \
              --replace-fail "=> ./go-assuan" "=> $src/go-assuan"
          '';

          postInstall = ''
            wrapProgram $out/bin/pinentry-touchid \
              --prefix PATH : ${pkgs.pinentry_mac}/bin
          '';

          # Sign the wrapped binary (the launcher execv's into it, entitlements re-evaluate at exec).
          postFixup = ''
            codesign -f -s - \
              --identifier sh.kitten.pinentry-touchid \
              --entitlements ${./entitlements.plist} \
              $out/bin/.pinentry-touchid-wrapped
          '';

          meta = with pkgs.lib; {
            description = "Pinentry that uses macOS Touch ID (kitten fork)";
            homepage = "https://github.com/kitten/pinentry-touchid";
            license = licenses.asl20;
            platforms = platforms.darwin;
            mainProgram = "pinentry-touchid";
          };
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
