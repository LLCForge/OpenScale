# OpenScale package for Nix (#317, ADR-0091). Builds from this checkout;
# nothing is fetched from a project server. Use with:
#
#   nix-build -E 'with import <nixpkgs> {}; callPackage ./deploy/nix/package.nix {}'
#
# vendorHash is the NAR hash of `go mod vendor` for the current
# go.mod/go.sum (computed 2026-10-30). After a dependency change set it to
# lib.fakeHash, build once and copy the "got:" value Nix prints (the usual
# buildGoModule procedure). The embedded panel is whatever
# internal/panel/web/dist holds: build it first (`pnpm --dir panel build`)
# if this machine should serve the panel; a headless server does not need
# it.
{
  lib,
  buildGoModule,
  go_1_26,
}:

let
  root = ../..;
  version = lib.strings.trim (builtins.readFile (root + "/VERSION"));
in
(buildGoModule.override { go = go_1_26; }) {
  pname = "openscale";
  inherit version;

  # Only what the Go build needs: never keys, network folders or the
  # competitor clones that may sit in a working copy.
  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/go.mod")
      (root + "/go.sum")
      (root + "/VERSION")
      (root + "/cmd")
      (root + "/tools")
      (lib.fileset.difference (root + "/internal") (
        lib.fileset.fileFilter (
          f: lib.hasSuffix ".key" f.name || lib.hasSuffix ".passphrase" f.name || f.name == "network.json"
        ) (root + "/internal")
      ))
    ];
  };

  vendorHash = "sha256-j/KW4ubqIYNGcu328TRu/M5Xcvm8hTSKp9gQDHaTKFc=";

  subPackages = [
    "cmd/openscale"
    "cmd/releaseverify"
  ];

  env.CGO_ENABLED = "0";
  # buildGoModule already adds -trimpath; the rest matches scripts/release.sh.
  ldflags = [
    "-s"
    "-w"
    "-buildid="
    "-X github.com/openscale/openscale/internal/version.Version=${version}"
    "-X github.com/openscale/openscale/internal/version.Build=nix"
  ];

  # The tests bind loopback sockets and expect writable home directories;
  # they run in CI (go test ./...) instead of the Nix sandbox.
  doCheck = false;

  # The daemon runs ip and nft only from the system folders (F-125), on
  # NixOS /run/current-system/sw/bin; the NixOS module adds iproute2 and
  # nftables to environment.systemPackages.
  postInstall = ''
    mv $out/bin/releaseverify $out/bin/openscale-release-verify
  '';

  meta = {
    description = "Personal, single-owner WireGuard mesh VPN";
    mainProgram = "openscale";
    platforms = lib.platforms.linux ++ lib.platforms.freebsd ++ lib.platforms.openbsd;
    # ADR-0010 has not chosen a license yet.
    license = lib.licenses.unfree;
  };
}
