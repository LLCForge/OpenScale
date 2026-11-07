# Changelog

All notable changes to OpenScale. Versions follow `MAJOR.MINOR.PATCH` with a minor number from 0 to 9 (`1.9` is followed by `2.0`); betas carry `-beta.N`.

## v1.0.0-beta.2

**Upgrade order:** update the coordinator first, then every device, and only then sign documents that use the new fields (device icons, IP ranges in groups, support rules). Signing them raises the network's minimum client version to `1.0.0-beta.2`; older devices would drop off the network.

### New
- **Automatic updates.** The coordinator distributes signed releases over the tunnel and can follow this repository's releases; devices verify every release themselves and install it in rings (`ring-canary` → `ring-early` → everyone). A rollback anywhere stops the rollout. The tunnel stays up during the update.
- **English and Turkish panel**, switchable in Settings, on the sign-in page and in the setup wizard.
- **macOS app**: menu bar icon, native panel window, launchd service, `.dmg`.
- **Linux tray** (StatusNotifierItem) and **Wayland remote desktop** (xdg-desktop-portal and PipeWire).
- **Network locations**: shares of your devices appear automatically under *Network locations* in Windows Explorer.
- **Windows tray flyout**, *Send to → OpenScale* in Explorer, accept files from a notification, Start menu and desktop shortcuts, no consent prompt at sign-in.
- **Remote desktop**: multiple monitors, a second admin can join as a viewer.
- **SFTP file browser** next to the SSH terminal.
- **Remote support toolbox**: processes, services, event logs and disks of a device, read only, with the user's consent.
- **Troubleshooting wizard** and **flight recorder** for intermittent drops.
- **Sealed connection candidates**: the coordinator no longer sees how devices reach each other.
- **Birthday-scan NAT traversal** for symmetric NATs, bounded and opt-out.
- **Privilege separation**: network documents and release manifests are parsed in an unprivileged helper process.
- Device icons, IP/CIDR ranges in groups, IoT and camera isolation for devices behind a subnet router, device retirement wizard, name suggestions, `openscale prompt`, `openscale forward`, resumable setup.
- Packages and recipes for immutable Linux (Silverblue, MicroOS, SteamOS), AppArmor and SELinux profiles, pfSense/OPNsense, MikroTik RouterOS, Home Assistant OS, Qubes OS; FreeBSD and macOS release archives.

### Fixed
- MagicDNS could not be configured on Windows.
- The Linux device service refused to start on Ubuntu because of the system's own `/usr/bin/ld.so`.
- A Tailscale firewall rule on the same machine silently dropped tunnel traffic; OpenScale now detects it and prints the fix.
- The panel window used a placeholder icon instead of the app icon.

### Known limits
- Releases built without the owner's release key are published unsigned and are never installed automatically.
- The macOS app, the Linux tray and Wayland support, and the new platform packages have not been tested on real hardware yet.

## v1.0.0-beta.1

First public beta: the trust core (root key, signed network document, enrollment, revocation), coordinator, mesh tunnel with NAT traversal and relay, exit nodes with kill switch, MagicDNS and DNS protection, packet filter, remote desktop, SSH, end-to-end file transfer, the web panel and the Windows desktop app.
