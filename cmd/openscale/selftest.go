package main

import (
	"fmt"
	"os"

	"github.com/openscale/openscale/internal/trust"
)

// selfTestExitCode is EX_SOFTWARE: the program itself is broken.
const selfTestExitCode = 70

// cryptoSelfTestOrExit runs the cryptographic known answer tests (#531)
// and stops the program when one fails: no command, service or
// coordinator may use primitives that give wrong answers. The tests take
// about a millisecond and use only public vectors.
func cryptoSelfTestOrExit() {
	if _, err := trust.CryptoSelfTest(); err != nil {
		fmt.Fprintf(os.Stderr, "openscale: %v\nProgram dosyası bozuk veya kurcalanmış olabilir; imzalı sürümden yeniden kurun.\n", err)
		os.Exit(selfTestExitCode)
	}
}
