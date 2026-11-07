//go:build !unix

package usagehist

func linuxBatteryForTest(string) Battery { return Battery{} }
