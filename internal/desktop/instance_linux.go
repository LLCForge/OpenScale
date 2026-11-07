//go:build linux

package desktop

// maxSunPath is sizeof(sockaddr_un.sun_path) on Linux.
const maxSunPath = 108
