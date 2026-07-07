{
  description = "My TLS implementation flake";

  inputs.nixpkgs.url = "https://flakehub.com/f/NixOS/nixpkgs/0"; # stable Nixpkgs

  outputs =
    { self, nixpkgs, ... }@inputs:
    let
      inherit (nixpkgs) lib;

      supportedSystems = [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      forEachSupportedSystem =
        f:
        lib.genAttrs supportedSystems (
          system:
          let
            pkgs = import nixpkgs { inherit system; };
          in
          f pkgs
        );

      nativeBuildInputs =
        pkgs: with pkgs; [
          cmake
          ninja
          pkg-config
        ];

      runtimeInputs =
        pkgs: with pkgs; [
          gmp
          nettle
          jsoncpp
          spdlog
          fmt
        ];

      testInputs =
        pkgs: with pkgs; [
          catch2_3
        ];

      devInputs =
        pkgs:
        with pkgs;
        [
          clang-tools
          cmake-lint
          codespell
          cppcheck
          lcov
          neocmakelsp
          nixfmt
        ]
        ++ lib.optionals (!stdenv.hostPlatform.isDarwin) [ gdb ];

      mkPackage =
        {
          pkgs,
          withTests ? false,
        }:
        pkgs.stdenv.mkDerivation {
          pname = if withTests then "custom-tls-check" else "custom-tls";
          version = "0.1";
          src = self;

          nativeBuildInputs = nativeBuildInputs pkgs;
          buildInputs = runtimeInputs pkgs ++ lib.optionals withTests (testInputs pkgs);

          cmakeFlags = [
            "-DBUILD_TESTING=${if withTests then "ON" else "OFF"}"
          ];

          doCheck = withTests;

          checkPhase = lib.optionalString withTests ''
            runHook preCheck
            ctest --output-on-failure --no-tests=error
            runHook postCheck
          '';

          installPhase = lib.optionalString withTests ''
            mkdir -p $out
            touch $out/check-passed
          '';
        };
    in
    {
      packages = forEachSupportedSystem (pkgs: {
        default = mkPackage { inherit pkgs; };
      });

      checks = forEachSupportedSystem (pkgs: {
        default = mkPackage {
          inherit pkgs;
          withTests = true;
        };
      });

      devShells = forEachSupportedSystem (pkgs: {
        default = pkgs.mkShell {
          packages = nativeBuildInputs pkgs ++ runtimeInputs pkgs ++ testInputs pkgs ++ devInputs pkgs;
        };
      });

      formatter = forEachSupportedSystem (pkgs: pkgs.nixfmt);
    };
}
