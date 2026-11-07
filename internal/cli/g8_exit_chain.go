package cli

import (
	"fmt"
	"strings"

	"github.com/openscale/openscale/internal/trust"
)

// Signed two-hop exit (#618, ADR-0222): the owner names an entry exit node
// whose members' internet traffic leaves through a second exit node. The
// chain is signed into the document with the root key.

func cmdExitChain(env *Env, args []string) error {
	if len(args) == 0 {
		return usageError("alt komut gerekli: set, clear veya show")
	}
	switch args[0] {
	case "set":
		fs := newFlagSet(env, "exit chain set")
		common := addEditFlags(fs)
		entry := fs.String("entry", "", "giriş çıkış düğümü (üyelerin seçtiği)")
		final := fs.String("final", "", "son çıkış düğümü (internete çıkan)")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *entry == "" || *final == "" {
			return usageError("--entry ve --final gerekli")
		}
		fmt.Fprintln(env.Stdout, "Not: exit_chains alanını eski istemciler reddeder; imzalamadan önce bütün cihazları güncelleyip min_client_version değerini yükseltin.")
		return runEdit(env, common, func(doc *trust.Document) error { return doc.SetExitChain(*entry, *final) })
	case "clear":
		fs := newFlagSet(env, "exit chain clear")
		common := addEditFlags(fs)
		entry := fs.String("entry", "", "zinciri kaldırılacak giriş düğümü")
		if err := parseFlags(fs, args[1:]); err != nil {
			return err
		}
		if *entry == "" {
			return usageError("--entry gerekli")
		}
		return runEdit(env, common, func(doc *trust.Document) error { return doc.SetExitChain(*entry, "") })
	case "show":
		doc, err := loadDocument(env, args[1:], "exit chain show")
		if err != nil || doc == nil {
			return err
		}
		if len(doc.ExitChains) == 0 {
			fmt.Fprintln(env.Stdout, "Çift sıçramalı çıkış zinciri yok.")
			return nil
		}
		lines := make([]string, 0, len(doc.ExitChains))
		for _, c := range doc.ExitChains {
			lines = append(lines, c.Entry+" → "+c.Final)
		}
		fmt.Fprintln(env.Stdout, "Çift sıçramalı çıkış zincirleri:\n  "+strings.Join(lines, "\n  "))
		return nil
	}
	return usageError("bilinmeyen alt komut %q; set, clear veya show", args[0])
}
