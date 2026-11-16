{
  description = "Independent OMBP start app and rootless Podman access gateways";
  inputs.nixpkgs.url = "github:NixOS/nixpkgs/5adc50831c259f87faeb09ddf930d43597197473";
  # 26.11 no longer supports Intel Darwin. Keep every other system on the existing pin.
  inputs.nixpkgs-intel.url = "github:NixOS/nixpkgs/e0c84f9d0ad137f076dc957494f5b39885597d4f";
  outputs = { self, nixpkgs, nixpkgs-intel }: let
    inherit (nixpkgs) lib;
    linuxSystems = [ "x86_64-linux" "aarch64-linux" ];
    darwinSystems = [ "aarch64-darwin" "x86_64-darwin" ];
    eachLinux = lib.genAttrs linuxSystems;
    eachDarwin = lib.genAttrs darwinSystems;
    exports = env: lib.concatStringsSep "\n" (lib.mapAttrsToList (name: value: "export ${name}=${lib.escapeShellArg value}") env);
    source = lib.cleanSourceWith {
      src = self;
      filter = path: _type: !(builtins.elem (baseNameOf path) [
        ".quality-coverage" ".coverage" "__pycache__" "result"
      ]);
    };
    syntax = pkgs: python: pkgs.runCommand "ombp-start-syntax" { nativeBuildInputs = [ python pkgs.nodejs_24 ]; } ''
      export PYTHONPYCACHEPREFIX="$TMPDIR/bytecode"
      python3 -m compileall -q ${source}
      node --check ${source}/ui.js
      if [ -e ${source}/viewer.js ]; then node --check ${source}/viewer.js; fi
      bash -n ${source}/vm/provision.sh
      touch "$out"
    '';
    # Linux: the rootless container runtime, used directly on Linux hosts and as the macOS VM's guest runtime.
    linux = system: let
      pkgs = nixpkgs.legacyPackages.${system};
      # Only CPU emulation is needed. The pinned static GnuTLS/nettle link fails
      # on aarch64; its TLS/LUKS support belongs to system/tools QEMU, not this interpreter.
      scannerEmulator = (pkgs.pkgsStatic.qemu-user.override {
        hostCpuTargets = [ "x86_64-linux-user" ];
      }).overrideAttrs (old: {
        # QEMU's automatic -static-pie conflicts with the static toolchain's startup
        # objects: the resulting ET_DYN faults in musl __init_libc before main.
        # Deliberately use non-PIE ET_EXEC for this guest-only interpreter. Its own
        # executable mapping loses PIE ASLR; container privileges and other binaries'
        # ASLR remain unchanged. No host emulator or privileged container is added.
        configureFlags = builtins.filter (flag: flag != "--enable-gnutls") old.configureFlags
          ++ [ "--disable-gnutls" "--disable-pie" ];
        postInstall = (old.postInstall or "") + ''
          if [ ! -x "$out/bin/qemu-x86_64" ]; then
            echo "Static scanner interpreter was not installed" >&2
            exit 1
          fi
          export LC_ALL=C
          ${pkgs.binutils}/bin/readelf -h "$out/bin/qemu-x86_64" \
            | grep -Eq 'Type:[[:space:]]+EXEC' || {
              echo "Scanner interpreter must be a non-PIE ET_EXEC" >&2
              exit 1
            }
          if ${pkgs.binutils}/bin/readelf -l "$out/bin/qemu-x86_64" | grep -q INTERP \
            || ${pkgs.binutils}/bin/readelf -d "$out/bin/qemu-x86_64" | grep -q NEEDED; then
            echo "Scanner interpreter must be statically linked without a loader" >&2
            exit 1
          fi
          # A static ELF can still have broken startup relocations: execute the
          # native interpreter, not a target program, before accepting this output.
          ${pkgs.coreutils}/bin/timeout 15 "$out/bin/qemu-x86_64" --version || {
            echo "Scanner interpreter failed its native startup check" >&2
            exit 1
          }
        '';
      });
      python = pkgs.python3.withPackages (ps: [ ps.fusepy ps.mitmproxy ]);
      testPython = pkgs.python3.withPackages (ps: [ ps.fusepy ps.mitmproxy ps.aiohttp ps.coverage ]);
      # Keep OMBP's 720x480 minimum non-fatal, give the nested desktop the full host allocation,
      # stop busy clients overflowing libwayland's 4 KiB connection buffer, and let the browser
      # display and Zenity pickers maximize (keeping address bars and buttons) instead of fullscreening.
      weston = pkgs.weston.overrideAttrs (old: {
        patches = (old.patches or [ ]) ++ [ ./weston-min-size.patch ./weston-frameless.patch ./weston-client-buffer.patch
                                            ./weston-kiosk-maximize.patch ];
      });
      # The sandbox has no /etc/fonts: include fontconfig's own conf.d so generic families (monospace,
      # sans-serif) resolve; without them WebKit cannot lay out OMBP's xterm terminal and it stays blank.
      fonts = pkgs.writeText "ombp-fonts.conf" ''
        <?xml version="1.0"?>
        <!DOCTYPE fontconfig SYSTEM "urn:fontconfig:fonts.dtd">
        <fontconfig>
          <include>${pkgs.makeFontsConf { fontDirectories = [ pkgs.dejavu_fonts ]; }}</include>
          <include ignore_missing="yes">${pkgs.fontconfig.out}/etc/fonts/conf.d</include>
        </fontconfig>
      '';
      fusermount = pkgs.writeShellScriptBin "fusermount" ''
        for helper in /run/wrappers/bin/fusermount /usr/bin/fusermount /usr/bin/fusermount3; do
          if [ -x "$helper" ]; then exec "$helper" "$@"; fi
        done
        echo "A host setuid fusermount or fusermount3 helper is required" >&2
        exit 1
      '';
      # OMBP finds browsers by these names; each opens the browser in its own nested desktop window.
      browser = pkgs.runCommand "ombp-sandbox-browser" { } ''
        mkdir -p "$out/bin" "$out/libexec"
        { echo "#!${python}/bin/python3"; cat ${./browser.py}; } > "$out/libexec/ombp-browser"
        chmod +x "$out/libexec/ombp-browser"
        for name in google-chrome-stable google-chrome chromium chromium-browser chrome brave-browser; do
          ln -s "$out/libexec/ombp-browser" "$out/bin/$name"
        done
      '';
      # rfd's Zenity fallback drops the directory; start unspecified sandbox pickers at the host gateway.
      dialog = pkgs.writeShellScriptBin "zenity" ''
        file_selection=false
        for arg in "$@"; do
          case "$arg" in
            --file-selection) file_selection=true ;;
            --filename|--filename=*) exec ${pkgs.zenity}/bin/zenity "$@" ;;
          esac
        done
        if "$file_selection"; then
          exec ${pkgs.zenity}/bin/zenity --filename=/host/ "$@"
        fi
        exec ${pkgs.zenity}/bin/zenity "$@"
      '';
      # Everyday CLI tools for the AI inside the sandbox; files and network still pass the gateways.
      basicToolPaths = with pkgs; [
        glib.bin procps psmisc util-linux findutils gnugrep gnused gawk diffutils patch file which less
        gnutar gzip bzip2 xz zstd unzip zip curl wget jq ripgrep fd rsync tree gnumake bc strace lsof
        # zenity: OMBP's file/folder pickers fall back to it without a desktop portal.
        ncurses libnotify dialog
      ];
      languageServerPaths = with pkgs; [
        marksman emmet-language-server typescript-language-server typescript
        vscode-langservers-extracted nil nixd jdt-language-server
      ];
      basicTools = pkgs.buildEnv {
        name = "ombp-sandbox-basic-tools";
        paths = basicToolPaths;
        pathsToLink = [ "/bin" ];
      };
      tools = pkgs.buildEnv {
        name = "ombp-sandbox-tools";
        paths = basicToolPaths ++ languageServerPaths;
        pathsToLink = [ "/bin" ];
      };
      # Installed-mode packages, built only on Linux (directly or inside the macOS VM). Unfree evaluation
      # stays restricted to these named, default-off selections.
      unfreePkgs = import nixpkgs {
        inherit system;
        config.allowUnfreePredicate = package:
          lib.elem (lib.getName package) [ "obsidian" "intelephense" "terraform" "kotlin-lsp" ];
      };
      optionalTools = (import ./tool-packages.nix { inherit pkgs unfreePkgs; })
        // (import ./language-packages.nix { pkgs = unfreePkgs; });
      packageOutputs = {
        package-basic-tools = basicTools;
        package-chromium = pkgs.chromium;
        package-obsidian = unfreePkgs.obsidian;
        package-gh = pkgs.gh;
        package-ssh = pkgs.openssh;
      } // lib.mapAttrs' (id: package: lib.nameValuePair ("package-" + id) package) optionalTools;
      runtimeInputs = [ python fusermount pkgs.nix pkgs.podman pkgs.dbus pkgs.gnome-keyring pkgs.libsecret ];
      # Everything the container runtime needs, whichever display it uses.
      containerEnv = {
        FUSE_LIBRARY_PATH = "${lib.getLib pkgs.fuse}/lib/libfuse.so.2";
        START_APP_PYTHON = "${python}/bin/python3";
        START_APP_DBUS = "${pkgs.dbus}/bin/dbus-run-session";
        START_APP_CERTUTIL = "${pkgs.nssTools}/bin/certutil";
        START_APP_KEYRING = "${pkgs.gnome-keyring}/bin/gnome-keyring-daemon";
        START_APP_MESA = "${pkgs.mesa}";
        START_APP_SHELL = "${pkgs.bashInteractive}/bin/bash";
        START_APP_COREUTILS = "${pkgs.coreutils}/bin";
        START_APP_FONTCONFIG = "${fonts}";
        START_APP_PODMAN = "${pkgs.podman}/bin";
        START_APP_GH = "${pkgs.gh}/bin";
        START_APP_OPENSSH = "${pkgs.openssh}/bin";
        START_APP_CHROMIUM = "${pkgs.chromium}/bin/chromium";
        START_APP_BROWSER_NAMES = "${browser}/bin";
        START_APP_TOOLS = "${tools}/bin";
        START_APP_ZENITY = "${dialog}/bin/zenity";
      };
      # A Linux host nests OMBP's desktop in its own Wayland session through Weston.
      hostEnv = containerEnv // { START_APP_WESTON = "${weston}/bin/weston"; };
      # The macOS VM has no host Wayland session: headless Sway (software rendering) with wayvnc per display.
      guestEnv = containerEnv // {
        START_APP_SWAY = "${pkgs.sway-unwrapped}/bin/sway";
        START_APP_WAYVNC = "${pkgs.wayvnc}/bin/wayvnc";
      } // lib.optionalAttrs (system == "aarch64-linux") {
        # The locked Sonar CLI scanner is amd64-only. Registration is guest-only,
        # with a fixed interpreter FD; the sandbox never receives privileged APIs.
        START_APP_QEMU_X86_64 = "${scannerEmulator}/bin/qemu-x86_64";
      };
    in { inherit pkgs python testPython runtimeInputs hostEnv guestEnv packageOutputs; };
    # macOS host: the controller, website gateway, file broker and viewer; Linux execution stays in the VM.
    darwin = system: let
      pkgs = (if system == "x86_64-darwin" then nixpkgs-intel else nixpkgs).legacyPackages.${system};
      # Keep the same Lima protocol/template version with Intel's supported stdenv.
      lima = if system == "x86_64-darwin" then
        pkgs.callPackage "${nixpkgs}/pkgs/by-name/li/lima/package.nix" { inherit lima; }
      else pkgs.lima;
      python = pkgs.python3.withPackages (ps: [ ps.mitmproxy ps.aiohttp ]);
      testPython = pkgs.python3.withPackages (ps: [ ps.mitmproxy ps.aiohttp ps.coverage ]);
      limaTemplate = pkgs.writeText "ombp-lima-template.json" (builtins.toJSON (import ./vm/lima-template.nix));
      runtimeInputs = [ python pkgs.nix lima pkgs.openssh ];
      hostEnv = {
        START_APP_PYTHON = "${python}/bin/python3";
        START_APP_LIMACTL = "${lima}/bin/limactl";
        START_APP_OPENSSH = "${pkgs.openssh}/bin";
        START_APP_LIMA_TEMPLATE = "${limaTemplate}";
        START_APP_CACERT = "${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt";
        # The pinned noVNC package's websockify tests fail on Darwin; the viewer serves only its static tree.
        START_APP_NOVNC = "${pkgs.novnc.src}";
      };
    in { inherit pkgs python testPython runtimeInputs hostEnv; };
    launcher = pkgs: runtimeInputs: env: python: pkgs.writeShellApplication {
      name = "ombp-start";
      inherit runtimeInputs;
      text = ''
        ${exports env}
        exec ${python}/bin/python3 ${source}/app.py "$@"
      '';
    };
  in {
    checks = eachLinux (system: let inherit (linux system) pkgs python; in { syntax = syntax pkgs python; })
      // eachDarwin (system: let inherit (darwin system) pkgs python; in { syntax = syntax pkgs python; });
    packages = eachLinux (system: let inherit (linux system) pkgs python runtimeInputs hostEnv guestEnv packageOutputs; in {
      default = launcher pkgs runtimeInputs hostEnv python;
      # The macOS controller deploys these sources into its VM and builds this there: the guest supervisor.
      guest-runtime = pkgs.writeShellApplication {
        name = "ombp-guest";
        inherit runtimeInputs;
        text = ''
          ${exports guestEnv}
          exec ${python}/bin/python3 ${source}/vm/guest.py "$@"
        '';
      };
    } // packageOutputs) // eachDarwin (system: let
      inherit (darwin system) pkgs python runtimeInputs hostEnv;
      controller = launcher pkgs runtimeInputs hostEnv python;
    in {
      default = pkgs.symlinkJoin {
        name = "ombp-start";
        paths = [ controller ];
        postBuild = ''
          mkdir -p "$out/Applications/OMBP Start.app/Contents/MacOS"
          ln -s ${controller}/bin/ombp-start "$out/Applications/OMBP Start.app/Contents/MacOS/ombp-start"
          cat > "$out/Applications/OMBP Start.app/Contents/Info.plist" <<'PLIST'
          <?xml version="1.0" encoding="UTF-8"?>
          <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
          <plist version="1.0"><dict>
            <key>CFBundleExecutable</key><string>ombp-start</string>
            <key>CFBundleIdentifier</key><string>dev.udvikler.ombp-start</string>
            <key>CFBundleName</key><string>OMBP Start</string>
            <key>CFBundlePackageType</key><string>APPL</string>
            <key>CFBundleShortVersionString</key><string>0.1.0</string>
            <key>CFBundleVersion</key><string>0.1.0</string>
            <key>LSMinimumSystemVersion</key><string>15.0</string>
            <key>LSUIElement</key><true/>
          </dict></plist>
          PLIST
        '';
      };
    });
    devShells = eachLinux (system: let inherit (linux system) pkgs testPython runtimeInputs hostEnv guestEnv; in {
      default = pkgs.mkShell ({ packages = [ testPython ] ++ builtins.tail runtimeInputs; } // hostEnv // guestEnv);
    }) // eachDarwin (system: let inherit (darwin system) pkgs testPython runtimeInputs hostEnv; in {
      # GNU cp is test-only here: the private-installation tests need its reflink/ownership flags,
      # while installation itself runs in the Linux guest. The shipped controller does not include it.
      default = pkgs.mkShell ({
        packages = [ testPython pkgs.coreutils ] ++ builtins.tail runtimeInputs;
        START_APP_COREUTILS = "${pkgs.coreutils}/bin";
      } // hostEnv);
    });
  };
}
