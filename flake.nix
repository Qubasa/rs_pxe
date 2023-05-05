{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    nix-fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

  };

  outputs = { self, nixpkgs, utils, nix-fenix}:
    utils.lib.eachDefaultSystem (system:
      let
        overlays = [ nix-fenix.overlays.default ];
        pkgs = import nixpkgs { inherit system; inherit overlays; };
        fenix = nix-fenix.packages.${system};
        target64 = fenix.minimal.toolchain;
        myrust = with fenix; fenix.combine [
          (latest.withComponents [
            "rust-src"
            "rustc"
            "rustfmt"
            "llvm-tools-preview"
            "cargo"
            "clippy"
          ])
          target64
        ];

        buildDeps = with pkgs; [
          myrust
        ]  ++ (with pkgs.llvmPackages_latest; [
          lld
          llvm
        ]);
      in
      rec {
        packages.default = (pkgs.makeRustPlatform {
          cargo = myrust;
          rustc = myrust;
        }).buildRustPackage {
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          pname = "pxe-rs";
          version = "0.1.0";
        };

        defaultPackage = packages.default;

        apps.default = utils.lib.mkApp {
          drv = self.defaultPackage."${system}";
        };

        devShell = with pkgs; mkShell {
          buildInputs = buildDeps;
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
          shellHook = ''
            export PATH=$PATH:~/.cargo/bin
          '';
        };
      });
}
