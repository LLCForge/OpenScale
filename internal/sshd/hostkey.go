package sshd

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"

	"golang.org/x/crypto/ssh"

	"github.com/openscale/openscale/internal/securefile"
)

const maxHostKeySize = 16 << 10

// LoadOrCreateHostKey loads the Ed25519 host key at path, generating and
// storing a new one (owner-only permissions, never overwriting) when the
// file does not exist. On POSIX systems a key file readable by others is
// refused.
func LoadOrCreateHostKey(path string) (ssh.Signer, error) {
	data, err := securefile.ReadPrivate(path, maxHostKeySize)
	if err == nil {
		return parseHostKey(data)
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("sshd: host anahtarı okunamadı: %w", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sshd: host anahtarı üretilemedi: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "openscale-host")
	if err != nil {
		return nil, fmt.Errorf("sshd: host anahtarı kodlanamadı: %w", err)
	}
	pemBytes := pem.EncodeToMemory(block)
	if err := securefile.WriteNew(path, pemBytes); err != nil {
		if errors.Is(err, fs.ErrExist) {
			// Another process created it first; use that key.
			data, rerr := securefile.ReadPrivate(path, maxHostKeySize)
			if rerr != nil {
				return nil, fmt.Errorf("sshd: host anahtarı okunamadı: %w", rerr)
			}
			return parseHostKey(data)
		}
		return nil, fmt.Errorf("sshd: host anahtarı kaydedilemedi: %w", err)
	}
	return ssh.NewSignerFromKey(priv)
}

func parseHostKey(data []byte) (ssh.Signer, error) {
	signer, err := ssh.ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("sshd: host anahtarı çözümlenemedi: %w", err)
	}
	if signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return nil, errors.New("sshd: host anahtarı Ed25519 olmalı")
	}
	return signer, nil
}
