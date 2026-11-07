//go:build unix

package usagehist

func linuxBatteryForTest(dir string) Battery { return linuxBattery(dir) }
