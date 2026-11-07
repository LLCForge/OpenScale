package cli

import (
	"fmt"
	"slices"
	"strings"

	"github.com/openscale/openscale/internal/service"
)

// Shell completion (#227). The scripts ask the program itself for the
// next words ("openscale completion --list -- <words so far>"), so they
// never go stale when commands change. Only command names and a few
// fixed values are completed; nothing is read from the network or the
// state directory.

const completionUsage = "Kullanım: openscale completion bash|zsh|fish|powershell\n" +
	"  bash:       source <(openscale completion bash)\n" +
	"  zsh:        openscale completion zsh > \"${fpath[1]}/_openscale\"\n" +
	"  fish:       openscale completion fish > ~/.config/fish/completions/openscale.fish\n" +
	"  PowerShell: openscale completion powershell | Out-String | Invoke-Expression  (kalıcı: $PROFILE dosyasına ekleyin)"

func cmdCompletion(env *Env, args []string) error {
	if len(args) > 0 && args[0] == "--list" {
		words := args[1:]
		if len(words) > 0 && words[0] == "--" {
			words = words[1:]
		}
		for _, w := range completionWords(words) {
			fmt.Fprintln(env.Stdout, w)
		}
		return nil
	}
	if len(args) != 1 {
		fmt.Fprintln(env.Stderr, completionUsage)
		return usageError("bir kabuk adı yazın")
	}
	script, ok := completionScripts[strings.ToLower(args[0])]
	if !ok {
		fmt.Fprintln(env.Stderr, completionUsage)
		return usageError("bilinmeyen kabuk %q", args[0])
	}
	fmt.Fprint(env.Stdout, script)
	return nil
}

// completionWords returns the candidates for the word after words.
func completionWords(words []string) []string {
	var out []string
	add := func(s ...string) { out = append(out, s...) }
	if len(words) == 0 {
		add("help", "version")
	}
	for _, c := range commands() {
		parts := strings.Fields(c.name)
		switch {
		case len(words) < len(parts) && slices.Equal(parts[:len(words)], words):
			add(parts[len(words)])
		case len(words) >= len(parts) && slices.Equal(words[:len(parts)], parts):
			add(argumentWords(c.name, words[len(parts):])...)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// argumentWords completes the arguments of a known command.
func argumentWords(name string, rest []string) []string {
	last := ""
	if len(rest) > 0 {
		last = rest[len(rest)-1]
	}
	switch {
	case name == "set":
		keys := service.PrefKeys()
		for i, k := range keys {
			keys[i] = k + "="
		}
		return keys
	case name == "get":
		return service.PrefKeys()
	case name == "completion" && len(rest) == 0:
		return []string{"bash", "zsh", "fish", "powershell"}
	case name == "log level" && len(rest) == 0:
		return []string{"debug", "info", "warn", "error"}
	case strings.HasPrefix(name, "service ") && name != "service run":
		if last == "--role" || last == "-role" {
			return []string{"device", "coordinator"}
		}
		return []string{"--role"}
	case name == "configtest" || name == "config validate":
		if last == "--for" || last == "-for" {
			return []string{"up", "coordinator"}
		}
	}
	return nil
}

var completionScripts = map[string]string{
	"bash": `# openscale bash completion
_openscale() {
	local cur="${COMP_WORDS[COMP_CWORD]}"
	local IFS=$'\n'
	COMPREPLY=($(compgen -W "$("${COMP_WORDS[0]}" completion --list -- "${COMP_WORDS[@]:1:COMP_CWORD-1}" 2>/dev/null)" -- "$cur"))
}
complete -o default -F _openscale openscale
`,
	"zsh": `#compdef openscale
# openscale zsh completion
_openscale() {
	local -a candidates
	candidates=("${(@f)$(${words[1]} completion --list -- ${words[2,CURRENT-1]} 2>/dev/null)}")
	compadd -a candidates
}
compdef _openscale openscale
`,
	"fish": `# openscale fish completion
function __openscale_complete
	set -l tokens (commandline -opc)
	$tokens[1] completion --list -- $tokens[2..-1] 2>/dev/null
end
complete -c openscale -f -a '(__openscale_complete)'
`,
	"powershell": `# openscale PowerShell completion
Register-ArgumentCompleter -Native -CommandName openscale, openscale.exe -ScriptBlock {
	param($wordToComplete, $commandAst, $cursorPosition)
	$elements = @($commandAst.CommandElements | ForEach-Object { $_.ToString() })
	$exe = $elements[0]
	$words = @($elements | Select-Object -Skip 1)
	if ($wordToComplete -ne '' -and $words.Count -gt 0) { $words = @($words | Select-Object -First ($words.Count - 1)) }
	& $exe completion --list -- @words 2>$null | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
		[System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
	}
}
`,
}
