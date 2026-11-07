# NixOS module for OpenScale (#317, ADR-0091). Mirrors the hardened units
# in deploy/linux: the device runs as root with only CAP_NET_ADMIN and
# CAP_NET_RAW; the coordinator runs as its own user with no capabilities.
# Neither unit starts before the machine has joined: the service refuses
# to start until the state directory holds a key and a signed document.
#
#   imports = [ /path/to/openscale/deploy/nix/module.nix ];
#   services.openscale.device.enable = true;
#
# Join once (as root): openscale invite-join --state-dir /var/lib/openscale/device --code @invite.txt
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.openscale;
  hardening = {
    NoNewPrivileges = true;
    ProtectSystem = "strict";
    ProtectHome = true;
    PrivateTmp = true;
    ProtectKernelModules = true;
    ProtectKernelLogs = true;
    ProtectControlGroups = true;
    ProtectClock = true;
    ProtectHostname = true;
    RestrictNamespaces = true;
    RestrictRealtime = true;
    RestrictSUIDSGID = true;
    LockPersonality = true;
    MemoryDenyWriteExecute = true;
    SystemCallArchitectures = "native";
    UMask = "0077";
    Restart = "on-failure";
    RestartSec = 5;
  };
in
{
  options.services.openscale = {
    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./package.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./package.nix { }";
      description = "OpenScale package.";
    };

    device = {
      enable = lib.mkEnableOption "the OpenScale device (tunnel and, if the document says so, exit node)";
      stateDir = lib.mkOption {
        type = lib.types.path;
        default = "/var/lib/openscale/device";
        description = "Device keys and signed document. With memoryState this is a tmpfs.";
      };
      memoryState = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Keep the device state in memory only (ADR-0092): the state
          directory is a tmpfs, so the keys are gone at every reboot and
          the machine must join again with an invite (inviteFile).
        '';
      };
      inviteFile = lib.mkOption {
        type = lib.types.nullOr lib.types.path;
        default = null;
        description = ''
          Invite code file (outside the Nix store) used to join when the
          state directory is empty. Required with memoryState.
        '';
      };
      interface = lib.mkOption {
        type = lib.types.strMatching "[A-Za-z0-9_.-]{1,15}";
        default = "OpenScale";
        description = "Tunnel interface name.";
      };
      listenPort = lib.mkOption {
        type = lib.types.port;
        default = 41821;
        description = "WireGuard UDP port.";
      };
      openFirewall = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Open listenPort (UDP) in the NixOS firewall.";
      };
      extraArgs = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = "Extra arguments for `openscale up`.";
      };
    };

    coordinator = {
      enable = lib.mkEnableOption "the OpenScale coordinator";
      listenPort = lib.mkOption {
        type = lib.types.port;
        default = 41820;
        description = "Coordinator UDP port.";
      };
      openFirewall = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = "Open listenPort (UDP) in the NixOS firewall.";
      };
    };
  };

  config = lib.mkMerge [
    (lib.mkIf (cfg.device.enable || cfg.coordinator.enable) {
      # ip and nft are run from the system profile only (F-125).
      environment.systemPackages = [
        cfg.package
        pkgs.iproute2
        pkgs.nftables
      ];
      systemd.tmpfiles.rules = [ "d /var/lib/openscale 0755 root root -" ];
    })

    (lib.mkIf cfg.device.enable {
      assertions = [
        {
          assertion = !cfg.device.memoryState || cfg.device.inviteFile != null;
          message = "services.openscale.device.memoryState needs inviteFile: a memory-only device joins at every boot.";
        }
      ];
      boot.kernelModules = [ "tun" ];
      networking.firewall.allowedUDPPorts = lib.mkIf cfg.device.openFirewall [ cfg.device.listenPort ];
      # Keep NetworkManager away from the tunnel interface (#309).
      networking.networkmanager.unmanaged = [ "interface-name:${cfg.device.interface}" ];

      fileSystems = lib.mkIf cfg.device.memoryState {
        ${cfg.device.stateDir} = {
          device = "tmpfs";
          fsType = "tmpfs";
          options = [
            "mode=0700"
            "size=8m"
            "nosuid"
            "nodev"
            "noexec"
          ];
        };
      };
      systemd.tmpfiles.rules = lib.mkIf (!cfg.device.memoryState) [
        "d ${cfg.device.stateDir} 0700 root root -"
      ];

      systemd.services.openscale-device = {
        description = "OpenScale device (tunnel and exit node)";
        after = [
          "network-online.target"
          "time-sync.target"
        ];
        wants = [ "network-online.target" ];
        wantedBy = [ "multi-user.target" ];
        path = [ cfg.package ];
        unitConfig.RequiresMountsFor = [ cfg.device.stateDir ];
        preStart = lib.optionalString (cfg.device.inviteFile != null) ''
          if [ ! -f ${cfg.device.stateDir}/device.key ] || [ ! -f ${cfg.device.stateDir}/anchor.json ]; then
            echo "Cihaz ağa katılmamış; davet koduyla katılınıyor. Onay kodu aşağıda; paneldan onaylayın."
            openscale invite-join --state-dir ${cfg.device.stateDir} --code @${cfg.device.inviteFile}
          fi
        '';
        serviceConfig = hardening // {
          Type = "simple";
          ExecCondition = lib.mkIf (cfg.device.inviteFile == null) "${pkgs.coreutils}/bin/test -f ${cfg.device.stateDir}/anchor.json";
          ExecStart = lib.escapeShellArgs (
            [
              "${cfg.package}/bin/openscale"
              "up"
              "--state-dir"
              cfg.device.stateDir
              "--listen-port"
              (toString cfg.device.listenPort)
              "--interface"
              cfg.device.interface
            ]
            ++ cfg.device.extraArgs
          );
          CapabilityBoundingSet = [
            "CAP_NET_ADMIN"
            "CAP_NET_RAW"
          ];
          AmbientCapabilities = [
            "CAP_NET_ADMIN"
            "CAP_NET_RAW"
          ];
          ReadWritePaths = [ cfg.device.stateDir ];
          DeviceAllow = [ "/dev/net/tun rw" ];
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
            "AF_NETLINK"
            "AF_UNIX"
          ];
          # invite-join waits for the owner's approval.
          TimeoutStartSec = lib.mkIf (cfg.device.inviteFile != null) "30min";
        };
      };
    })

    (lib.mkIf cfg.coordinator.enable {
      users.users.openscale = {
        isSystemUser = true;
        group = "openscale";
        home = "/var/lib/openscale";
      };
      users.groups.openscale = { };
      networking.firewall.allowedUDPPorts = lib.mkIf cfg.coordinator.openFirewall [ cfg.coordinator.listenPort ];
      systemd.tmpfiles.rules = [ "d /var/lib/openscale/coordinator 0700 openscale openscale -" ];

      systemd.services.openscale-coordinator = {
        description = "OpenScale coordinator";
        after = [
          "network-online.target"
          "time-sync.target"
        ];
        wants = [ "network-online.target" ];
        wantedBy = [ "multi-user.target" ];
        serviceConfig = hardening // {
          # READY=1 follows once the WireGuard device is up (F-149).
          Type = "notify";
          NotifyAccess = "main";
          User = "openscale";
          Group = "openscale";
          # Not started before `openscale coordinator keygen` and the
          # signed document exist.
          ExecCondition = "${pkgs.coreutils}/bin/test -f /var/lib/openscale/coordinator/coordinator.key";
          ExecStart = lib.escapeShellArgs [
            "${cfg.package}/bin/openscale"
            "coordinator"
            "run"
            "--state-dir"
            "/var/lib/openscale/coordinator"
            "--listen-port"
            (toString cfg.coordinator.listenPort)
          ];
          # Only for the optional TCP transport on :443 (ADR-0032).
          CapabilityBoundingSet = [ "CAP_NET_BIND_SERVICE" ];
          AmbientCapabilities = [ "CAP_NET_BIND_SERVICE" ];
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          LimitNOFILE = 4096;
          # Resource limits (#484), as in deploy/linux.
          MemoryHigh = "384M";
          MemoryMax = "512M";
          Environment = [ "GOMEMLIMIT=320MiB" ];
          TasksMax = 256;
          CPUWeight = 50;
          IOWeight = 50;
          ReadWritePaths = [ "/var/lib/openscale/coordinator" ];
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
            "AF_UNIX"
          ];
          PrivateDevices = true;
        };
      };
    })
  ];
}
