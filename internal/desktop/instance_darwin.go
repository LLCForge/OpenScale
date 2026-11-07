//go:build darwin

package desktop

// maxSunPath is sizeof(sockaddr_un.sun_path) on macOS.
const maxSunPath = 104
