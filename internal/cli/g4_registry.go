package cli

import "sync"

// Command registry for commands added from their own files with init()
// (G4 and later work), so the shared command table in cli.go changes by
// one line only. Registered commands come after the static table: a
// static command with the same leading words wins.

var commandRegistry struct {
	sync.Mutex
	list []command
}

// registerCommands adds commands; call it from init().
func registerCommands(cmds ...command) {
	commandRegistry.Lock()
	defer commandRegistry.Unlock()
	commandRegistry.list = append(commandRegistry.list, cmds...)
}

// registeredCommands returns a copy of the registered commands.
func registeredCommands() []command {
	commandRegistry.Lock()
	defer commandRegistry.Unlock()
	return append([]command(nil), commandRegistry.list...)
}
