{
  description = "Logos Keycard signer: a bare Keycard's accounts, and the hashes it signs once its PIN opens it.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      lib = nixpkgs.lib;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];
      # x86_64-windows is a cross target the builder understands, never a host.
      targets = systems ++ [ "x86_64-windows" ];

      # The crate's simulator setup, staged beside the SDK source its manifest names, built
      # without the module.
      setup = pkgs:
        let
          src = pkgs.runCommand "keycard-simulator-setup-src" { } ''
            mkdir -p $out
            cp -r ${./rust-lib} $out/rust-lib
            cp -r ${logos-module-builder.packages.${pkgs.stdenv.hostPlatform.system}.rust-sdk-src} $out/logos-rust-sdk-src
          '';
        in
        pkgs.rustPlatform.buildRustPackage {
          pname = "keycard-simulator-setup";
          version = "0.1.0";
          inherit src;
          sourceRoot = "keycard-simulator-setup-src/rust-lib";
          cargoLock = {
            lockFile = ./rust-lib/Cargo.lock;
            allowBuiltinFetchGit = true;
          };
          buildNoDefaultFeatures = true;
          buildFeatures = [ "simulator" ];
          cargoBuildFlags = [ "--bin" "keycard-simulator-setup" ];
          doCheck = false;
        };

      # A Keycard in software for the tests: the Keycard applet built from its source, 4.0 and
      # the last 3.x, in jCardSim, served over TCP by sim/KeycardSim.java. Two changes make the
      # applet run there: 4.0's scratch EC keys live in ordinary memory, since jCardSim 3.0.5 has
      # no transient ones, and jCardSim's RSA without padding takes a block as long as its
      # modulus, as a card does, which 4.0's BIP340 arithmetic needs.
      simulator = system:
        let
          pkgs = import nixpkgs { inherit system; };
          jdk = pkgs.jdk8;
          applet40 = pkgs.fetchFromGitHub {
            owner = "status-im";
            repo = "status-keycard";
            rev = "c1f85d607a2e89fe2f85f6a7bab661dc1118dc3e";
            hash = "sha256-LakIUsSsMfny6xr43PZQpfp0M7LuLzt9CDRXo+EPTb4=";
          };
          applet32 = pkgs.fetchFromGitHub {
            owner = "status-im";
            repo = "status-keycard";
            rev = "731314fb92ab3a8da697bfdd7397950ed39c4da8";
            hash = "sha256-vHBf/kH+jzAkXCz3swQas4KA4SG4plYTNB1ZSmmdsfw=";
          };
          jcardsim = pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/status-im/jcardsim/e1e351a5adebf203e36eec57d608ebaa6a9c55fb/jcardsim-3.0.5-SNAPSHOT.jar";
            hash = "sha256-/zzlaN8OWlnEFjfAYQIh9EXIpcSmtrRORC5uXxRRsDE=";
          };
          cipher = pkgs.fetchurl {
            url = "https://raw.githubusercontent.com/status-im/jcardsim/e1e351a5adebf203e36eec57d608ebaa6a9c55fb/src/main/java/com/licel/jcardsim/crypto/AsymmetricCipherImpl.java";
            hash = "sha256-9rvk5txvBl0W4LF0dK/JmYdmpSxzN8lluehHG7OqBrU=";
          };
          kit = pkgs.stdenv.mkDerivation {
            pname = "keycard-simulator-cards";
            version = "0.1.0";
            dontUnpack = true;
            nativeBuildInputs = [ jdk ];
            buildPhase = ''
              runHook preBuild
              cp ${cipher} AsymmetricCipherImpl.java
              chmod u+w AsymmetricCipherImpl.java
              substituteInPlace AsymmetricCipherImpl.java \
                --replace-fail "import org.bouncycastle." "import com.licel.jcardsim.bouncycastle." \
                --replace-fail "makeTransientByteArray((short) engine.getInputBlockSize()," \
                  "makeTransientByteArray((short) (algorithm == ALG_RSA_NOPAD ? Math.max(engine.getInputBlockSize(), engine.getOutputBlockSize()) : engine.getInputBlockSize()),"
              mkdir -p src40 patches 40 32 bridge
              cp ${applet40}/src/main/java/im/status/keycard/*.java src40/
              chmod u+w src40/*.java
              substituteInPlace src40/SECP256k1.java src40/SecureChannelV2.java \
                --replace-fail "KeyBuilder.TYPE_EC_FP_PRIVATE_TRANSIENT_DESELECT" "KeyBuilder.TYPE_EC_FP_PRIVATE"
              javac="javac -nowarn -source 1.8 -target 1.8"
              $javac -cp ${jcardsim} -d patches AsymmetricCipherImpl.java
              $javac -cp ${jcardsim}:${applet40}/keycard-math/keycard-math.jar -d 40 src40/*.java
              $javac -cp ${jcardsim} -d 32 ${applet32}/src/main/java/im/status/keycard/*.java
              cp ${./sim/KeycardSim.java} KeycardSim.java
              $javac -cp ${jcardsim} -d bridge KeycardSim.java
              runHook postBuild
            '';
            installPhase = ''
              runHook preInstall
              mkdir -p $out
              cp -r patches 40 32 bridge $out/
              cp ${jcardsim} $out/jcardsim.jar
              cp ${applet40}/keycard-math/keycard-math.jar $out/
              runHook postInstall
            '';
          };
        in
        pkgs.writeShellApplication {
          name = "keycard-simulator";
          runtimeInputs = [ jdk (setup pkgs) ];
          text = ''
            # keycard-simulator <port> [4.0|3.2]: a Keycard on 127.0.0.1:<port>, set up with PIN
            # 123456 and the BIP39 test phrase's key, serving until stopped.
            port=''${1:?usage: keycard-simulator <port> [4.0|3.2]}
            version=''${2:-4.0}
            case "$version" in
              4.0) applet=${kit}/40:${kit}/keycard-math.jar ;;
              3.2) applet=${kit}/32 ;;
              *) echo "keycard-simulator: no applet $version" >&2; exit 2 ;;
            esac
            java -noverify -cp "${kit}/patches:${kit}/jcardsim.jar:$applet:${kit}/bridge" KeycardSim "$port" &
            card=$!
            trap 'kill "$card" 2>/dev/null || true' EXIT INT TERM
            for _ in $(seq 1 100); do
              if keycard-simulator-setup "127.0.0.1:$port" --fresh 2>/dev/null; then
                wait "$card"
                exit $?
              fi
              sleep 0.2
            done
            keycard-simulator-setup "127.0.0.1:$port" --fresh
          '';
        };
    in
    {
      packages = lib.genAttrs targets (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system}
        // lib.optionalAttrs (builtins.elem system systems) { simulator = simulator system; });
    };
}
