# OpenScale on MikroTik RouterOS 7 (#889, docs/routeros.md).
# NOT TESTED ON A REAL ROUTER. Read docs/routeros.md first, paste the
# blocks one by one in a terminal (WinBox / SSH) and check each result.
#
# Assumptions (change them to match your router):
#   disk            usb1 (container files need a USB/NVMe disk, not the
#                   internal flash)
#   container net   172.31.250.0/30: router .1, container .2
#   LAN             192.168.88.0/24 on bridge "bridge" (RouterOS default)
#   WAN list        WAN (RouterOS default interface list)
#   UDP port        41821
#
# Step 0, once: enable the container mode. The router asks for a power
# button press or a cold reboot to confirm (RouterOS 7.13+):
#   /system/device-mode/update container=yes

# 1. A veth for the container and a small bridge on the router side.
/interface/veth/add name=veth-openscale address=172.31.250.2/30 gateway=172.31.250.1
/interface/bridge/add name=br-openscale
/interface/bridge/port/add bridge=br-openscale interface=veth-openscale
/ip/address/add address=172.31.250.1/30 interface=br-openscale

# 2. The container reaches the internet through the router.
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.31.250.0/30 out-interface-list=WAN comment="openscale: konteyner internete"

# 3. Direct connections from other devices: forward the WireGuard port.
#    Without it the device still works through relays (slower).
/ip/firewall/nat/add chain=dstnat action=dst-nat in-interface-list=WAN protocol=udp dst-port=41821 to-addresses=172.31.250.2 to-ports=41821 comment="openscale: wireguard"
/ip/firewall/filter/add chain=forward action=accept protocol=udp dst-address=172.31.250.2 dst-port=41821 connection-nat-state=dstnat comment="openscale: wireguard" place-before=0

# 4. Persistent state and the invite (copy invite.txt to usb1/openscale-secrets/openscale-invite first).
/container/mounts/add name=openscale-state src=/usb1/openscale-state dst=/var/lib/openscale
/container/mounts/add name=openscale-secrets src=/usb1/openscale-secrets dst=/run/secrets
/container/envs/add name=openscale key=OPENSCALE_LISTEN_PORT value=41821
/container/envs/add name=openscale key=OPENSCALE_HOSTNAME value=mikrotik
/container/envs/add name=openscale key=OPENSCALE_ROUTER_ROLE value=device

# 5. Import the image built with deploy/routeros/Dockerfile (copy the tar to usb1 first).
/container/config/set tmpdir=/usb1/tmp
/container/add file=/usb1/openscale-routeros-arm64.tar interface=veth-openscale root-dir=/usb1/openscale-root mounts=openscale-state,openscale-secrets envs=openscale hostname=openscale logging=yes start-on-boot=yes
#    Wait until /container/print shows the container "stopped" (extracted), then:
/container/start [find where hostname=openscale]
#    The 4-digit approval code appears in /log/print where topics~"container"; approve it in the panel.

# 6. The router itself reaches the private network through the container
#    (100.80.0.0/16 is the default overlay range; use your network's range).
/ip/route/add dst-address=100.80.0.0/16 gateway=172.31.250.2 comment="openscale: özel ağ"

# 7a. Subnet router role (other devices reach the LAN through this router):
#     - in the panel give this device the subnet 192.168.88.0/24
#     - set the role variable and restart the container:
#   /container/envs/set [find where name=openscale and key=OPENSCALE_ROUTER_ROLE] value=router
#   /container/stop [find where hostname=openscale]
#   /container/start [find where hostname=openscale]
#     - let the container reach the LAN (the reply comes back through the
#       masquerade inside the container, so no route back is needed):
#   /ip/firewall/filter/add chain=forward action=accept src-address=172.31.250.2 out-interface=bridge comment="openscale: alt ağ" place-before=0

# 7b. Exit node role (other devices send their internet traffic here):
#     - in the panel give this device the exit node role
#     - OPENSCALE_ROUTER_ROLE=router as in 7a; step 2 already masquerades
#       the container's traffic to the WAN.

# Removing everything:
#   /container/stop [find where hostname=openscale]
#   /container/remove [find where hostname=openscale]
#   /container/mounts/remove [find where name~"openscale"]
#   /container/envs/remove [find where name=openscale]
#   /ip/route/remove [find where comment~"openscale"]
#   /ip/firewall/nat/remove [find where comment~"openscale"]
#   /ip/firewall/filter/remove [find where comment~"openscale"]
#   /ip/address/remove [find where interface=br-openscale]
#   /interface/bridge/port/remove [find where interface=veth-openscale]
#   /interface/bridge/remove [find where name=br-openscale]
#   /interface/veth/remove [find where name=veth-openscale]
