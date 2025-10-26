{
  description = "OCaml + Rust dev env using opam.export with opam-nix";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    opam-nix.url = "github:tweag/opam-nix";
    rust-overlay.url = "github:oxalica/rust-overlay";
    opam-repository.url = "github:ocaml/opam-repository";
    opam-repository.flake = false;
    o1-opam-repository.url = "github:o1-labs/opam-repository";
    o1-opam-repository.flake = false;
  };

  inputs.opam-nix.inputs.nixpkgs.follows = "nixpkgs";
  inputs.opam-nix.inputs.opam-repository.follows = "opam-repository";

  outputs = { self, nixpkgs, flake-utils, opam-nix, rust-overlay
    , opam-repository, o1-opam-repository }@inputs:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ rust-overlay.overlays.default ];
        };

        rust = pkgs.rust-bin.stable."1.82.0".default;

        # Repository configuration
        repos = [ opam-repository.outPath o1-opam-repository.outPath ];

        # Import OCaml dependencies from opam.export
        opamLib = opam-nix.lib.${system};
        parsedExport = opamLib.importOpam ./opam.export;

        # Remove problematic packages that might conflict
        implicit-deps =
          builtins.removeAttrs (opamLib.opamListToQuery parsedExport.installed)
          [ "check_opam_switch" ];

        # LSP support - must match project's OCaml 4.14 version
        lsp-packages = with implicit-deps; {
          dune-rpc = "3.6.2";
          dyn = "3.6.2";
          fiber = "3.6.2";
          chrome-trace = "3.6.2";
          ocaml-lsp-server = "1.15.1-4.14";
          ocamlc-loc = "3.6.2";
          ocaml-system = "4.14.2";
          ocamlformat-rpc-lib = "0.22.4";
          omd = "1.3.2";
          ordering = "3.6.2";
          pp = "1.1.2";
          ppx_yojson_conv_lib = "v0.15.0";
          xdg = dune;
        };

        # Custom overlay for package fixes
        package-overlay = self: super: {
          # Fix PostgreSQL dependencies
          caqti-driver-postgresql = super.caqti-driver-postgresql.overrideAttrs
            (old: {
              buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.postgresql ];
            });

          # Fix SQLite dependencies  
          caqti-driver-sqlite3 = super.caqti-driver-sqlite3.overrideAttrs
            (old: {
              buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.sqlite ];
            });

          # Fix OpenSSL dependencies
          conf-pkg-config = super.conf-pkg-config.overrideAttrs (old: {
            buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.pkg-config ];
          });

          # Fix core_unix_gettid linking error in Core library
          core = super.core.overrideAttrs (old: {
            postPatch = ''
              # Find and patch unix_stubs.c to add the missing core_unix_gettid function
              for stubs_file in src/unix_stubs.c linux_ext/src/unix_stubs.c; do
                if [ -f "$stubs_file" ]; then
                  echo "Adding core_unix_gettid to $stubs_file"
                  cat >> "$stubs_file" << 'EOF'

              /* Missing function in core v0.14.1 - added by Nix overlay */
              value core_unix_gettid(value unit) {
                return Val_long(syscall(SYS_gettid));
              }
              EOF
                  break
                fi
              done

              # Ensure the necessary includes are present in unix_stubs.c
              for stubs_file in src/unix_stubs.c linux_ext/src/unix_stubs.c; do
                if [ -f "$stubs_file" ]; then
                  # Add the necessary includes at the top if not already present
                  if ! grep -q "sys/syscall.h" "$stubs_file"; then
                    sed -i '1i#include <sys/syscall.h>' "$stubs_file"
                  fi
                  break
                fi
              done
            '';
            buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.glibc ];
          });

          # Also fix any packages that depend on core and might have the same issue
          async = super.async.overrideAttrs (old: {
            buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.glibc ];
          });

          cohttp-async = super.cohttp-async.overrideAttrs (old: {
            buildInputs = (old.buildInputs or [ ]) ++ [ pkgs.glibc ];
            preBuild = ''
              export NIX_CFLAGS_LINK="$NIX_CFLAGS_LINK -lpthread"
            '';
          });
        };

        # Create the package scope
        scope =
          opamLib.applyOverlays (opamLib.__overlays ++ [ package-overlay ])
          (opamLib.defsToScope pkgs { }
            (opamLib.queryToDefs repos implicit-deps));
        lsp-scope =
          opamLib.applyOverlays (opamLib.__overlays ++ [ package-overlay ])
          (opamLib.defsToScope pkgs { }
            (opamLib.queryToDefs repos (lsp-packages // implicit-deps)));

        # Filter only the derivations we need
        scopePkgs = builtins.filter (x: pkgs.lib.isDerivation x)
          (builtins.attrValues scope);

      in {
        formatter = pkgs.nixfmt-classic;
        devShells.default = pkgs.mkShell {
          inputsFrom = scopePkgs;

          buildInputs = [
            # Rust toolchain
            rust

            # System dependencies
            pkgs.pkg-config
            pkgs.openssl
            pkgs.postgresql
            pkgs.sqlite
            pkgs.openssl_3

            # OCaml tools from scope
            scope.dune
            scope.ocaml
            scope.ocamlfind

            # For some reason, introducing ocaml-lsp-server to scope breaks the build
            # This is due to some Ocaml dependencies introduced by ocaml-lsp-server.
            # So we add it as a separate input, i.e. only executable is imported.
            lsp-scope.ocaml-lsp-server
          ] ++ scopePkgs;

          shellHook = ''
            echo "✅ OCaml: $(ocamlc -version)" >&2
            echo "✅ Dune:  $(dune --version)" >&2
            echo "✅ Rust:  $(rustc --version)" >&2
            echo "✅ LSP:   $(ocamllsp --version 2>&1 | head -1)" >&2
            echo "🔧 Ready for development!" >&2
          '';
        };

        packages.default = scope;
      });
}
