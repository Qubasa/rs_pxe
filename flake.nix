{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    utils.url = "github:numtide/flake-utils";
    nix-fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

    nix-pre-commit-hooks = {
      url = "github:cachix/pre-commit-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    smoltcp = {
      url = "github:luis-hebendanz/smoltcp/pxe_2";
      flake = false;
    };
    smolapps = {
      url = "github:luis-hebendanz/smolapps";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, utils, nix-fenix, smoltcp, smolapps, nix-pre-commit-hooks, ... }:
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

        buildDir = pkgs.symlinkJoin {
          name = "build";
          paths = [ self ];
          postBuild = ''
            rm -rf $out/external/smoltcp
            rm -rf $out/external/smolapps
            ln -sf ${smoltcp} $out/external/smoltcp
            ln -sf ${smolapps} $out/external/smolapps
          '';
        };
        buildDeps = with pkgs; [
          myrust
        ] ++ (with pkgs.llvmPackages_latest; [
          lld
        ]);

        runtimeDeps = with pkgs; [
          qemu
          cargo-watch
          rust-analyzer-nightly
          pixiecore
          dhcpcd
          dhcp
        ];
      in
      rec {

        checks = {
          pre-commit-check = nix-pre-commit-hooks.lib.${system}.run {
            src = buildDir;
            hooks = {
              nixpkgs-fmt.enable = true;
              rustfmt.enable = true;
              shellcheck.enable = true;
            };
          };
        };

        packages.default = (pkgs.makeRustPlatform {
          cargo = myrust;
          rustc = myrust;
        }).buildRustPackage {
          src = buildDir;
          cargoLock.lockFile = ./Cargo.lock;
          pname = "pxe-rs";
          #nativeBuildInputs = [ pkgs.breakpointHook ];
          version = "0.1.0";
        };

        defaultPackage = packages.default;

        apps.default = utils.lib.mkApp {
          drv = self.defaultPackage."${system}";
        };

        devShell = with pkgs; mkShell {
          buildInputs = buildDeps ++ runtimeDeps;
          RUST_SRC_PATH = rustPlatform.rustLibSrc;
          shellHook = ''
            export PATH=$PATH:~/.cargo/bin
            export RUST_ANALYZER=${pkgs.rust-analyzer-nightly}/bin/rust-analyzer
            ${self.checks.${system}.pre-commit-check.shellHook}
          '';
        };
      });
}
