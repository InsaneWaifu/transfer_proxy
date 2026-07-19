{
  description = "A Minecraft protocol transfer proxy";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        transfer_proxy = pkgs.rustPlatform.buildRustPackage {
          pname = "transfer_proxy";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
        };
      in
      {
        packages = {
          transfer_proxy = transfer_proxy;
          default = transfer_proxy;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ transfer_proxy ];
          packages = with pkgs; [
            rustc
            cargo
            clippy
            rustfmt
          ];
        };
      }
    ) // {
      nixosModules.default = import ./nix/transfer_proxy.nix {inherit self;};
    };
}
