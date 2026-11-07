// Command fakecli stands in for openscale in the PowerShell module tests: it
// appends its arguments to $FAKECLI_LOG as one JSON line and prints canned
// --json answers. It never touches the system or the network.
package main

import (
	"encoding/json"
	"fmt"
	"os"
)

func main() {
	args := os.Args[1:]
	if p := os.Getenv("FAKECLI_LOG"); p != "" {
		f, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err == nil {
			line, _ := json.Marshal(args)
			_, _ = f.Write(append(line, '\n'))
			_ = f.Close()
		}
	}
	if os.Getenv("FAKECLI_FAIL") == "1" {
		fmt.Fprintln(os.Stderr, "hata: servise ulaşılamadı (yönetici gerekir)")
		os.Exit(1)
	}
	if len(args) == 0 {
		os.Exit(2)
	}
	switch args[0] {
	case "status":
		fmt.Println(`{"schema":1,"running":true,"peers":[{"name":"nas","online":true,"ipv4":"100.64.0.2"},{"name":"tv","online":false,"ipv4":"100.64.0.3"}]}`)
	case "set":
		fmt.Println(`{"prefs":[{"key":"exit-node","value":"ev-sunucu"}]}`)
	case "send":
		fmt.Println("Gönderildi: nas")
	default:
		os.Exit(2)
	}
}
