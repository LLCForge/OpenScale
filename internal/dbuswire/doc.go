// Package dbuswire is OpenScale's small D-Bus client (ADR-0039, ADR-0234).
// It speaks just enough of the D-Bus Specification for the Linux tray
// (StatusNotifierItem, com.canonical.dbusmenu, desktop notifications) and
// the Wayland remote desktop portal (xdg-desktop-portal ScreenCast and
// RemoteDesktop), without a third-party module (ADR-0002):
//
//   - transport: unix:path= and unix:abstract= addresses from
//     DBUS_SESSION_BUS_ADDRESS, else $XDG_RUNTIME_DIR/bus; every other
//     transport (tcp, nonce-tcp, launchd, autolaunch) is refused;
//   - authentication: SASL EXTERNAL with the process's uid, optional
//     NEGOTIATE_UNIX_FD so a method return can carry file descriptors
//     (the portal's PipeWire remote);
//   - wire format: both byte orders on receive, little endian on send,
//     the types y b n q i u x t d s o g h a ( ) { } v;
//   - messages: method call, method return, error and signal, serial
//     matching with a context deadline, Hello, RequestName, AddMatch;
//   - exported objects: a handler table per path and interface with
//     org.freedesktop.DBus.Introspectable, org.freedesktop.DBus.Properties
//     and org.freedesktop.DBus.Peer built in.
//
// Everything read from the bus is untrusted. A message is at most
// MaxMessageSize bytes (1 MiB, far below the specification's 128 MiB),
// containers nest at most 32 deep each and 64 in total, a message decodes
// to at most maxValues values, strings must be valid UTF-8 without NUL,
// padding must be zero and every name and path is checked. A message that
// breaks a rule closes the connection; a handler never sees it.
package dbuswire
