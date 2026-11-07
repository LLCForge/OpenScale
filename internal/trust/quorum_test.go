package trust

import (
	"bytes"
	"crypto/rand"
	"errors"
	"testing"
)

var quorumPassphrases = [][]byte{
	[]byte("kuzey yıldızı mavi kapı 47"),
	[]byte("turuncu bisiklet nehir 1923"),
	[]byte("sessiz fener kumsal yedi"),
	[]byte("kırmızı balkon fırtına 88"),
	[]byte("gece treni zeytin ağacı"),
}

func TestQuorumBackupThreeOfFive(t *testing.T) {
	f := newFixture(t)
	holders := []string{"ayse", "mehmet", "banka", "avukat", "ev"}
	qb, err := SealQuorum(f.rootPriv, holders, quorumPassphrases, 3, testArgon2, rand.Reader)
	if err != nil {
		t.Fatalf("SealQuorum: %v", err)
	}
	if len(qb.Copies) != 10 {
		t.Fatalf("copies = %d, want C(5,3) = 10", len(qb.Copies))
	}
	data, err := MarshalQuorumBackup(qb)
	if err != nil {
		t.Fatal(err)
	}
	qb, err = UnmarshalQuorumBackup(data)
	if err != nil {
		t.Fatalf("UnmarshalQuorumBackup: %v", err)
	}
	// Every 3-subset opens it.
	for _, s := range subsets(5, 3) {
		m := map[int][]byte{}
		for _, i := range s {
			m[i] = quorumPassphrases[i]
		}
		priv, err := qb.OpenQuorum(m)
		if err != nil {
			t.Fatalf("subset %v: %v", s, err)
		}
		if !bytes.Equal(priv, f.rootPriv) {
			t.Fatalf("subset %v: wrong key", s)
		}
	}
	// Four holders work too.
	if _, err := qb.OpenQuorum(map[int][]byte{0: quorumPassphrases[0], 1: quorumPassphrases[1], 3: quorumPassphrases[3], 4: quorumPassphrases[4]}); err != nil {
		t.Fatal(err)
	}
	// Two holders do not.
	if _, err := qb.OpenQuorum(map[int][]byte{0: quorumPassphrases[0], 1: quorumPassphrases[1]}); !errors.Is(err, ErrQuorumNotMet) {
		t.Fatalf("two holders: %v", err)
	}
	// A wrong passphrase fails.
	if _, err := qb.OpenQuorum(map[int][]byte{0: quorumPassphrases[0], 1: quorumPassphrases[1], 2: []byte("yanlış parola ama uzun 123")}); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("wrong passphrase: %v", err)
	}
	// Swapping holders' passphrases fails (indices are bound).
	if _, err := qb.OpenQuorum(map[int][]byte{0: quorumPassphrases[1], 1: quorumPassphrases[0], 2: quorumPassphrases[2]}); !errors.Is(err, ErrWrongPassphrase) {
		t.Fatalf("swapped passphrases: %v", err)
	}
}

func TestQuorumBackupRejections(t *testing.T) {
	f := newFixture(t)
	if _, err := SealQuorum(f.rootPriv, []string{"a", "b"}, quorumPassphrases[:2], 1, testArgon2, rand.Reader); err == nil {
		t.Error("threshold 1 accepted")
	}
	if _, err := SealQuorum(f.rootPriv, []string{"a", "b", "c", "d", "e", "f", "g"}, append(quorumPassphrases, quorumPassphrases...)[:7], 3, testArgon2, rand.Reader); err == nil {
		t.Error("7 holders accepted")
	}
	if _, err := SealQuorum(f.rootPriv, []string{"a", "b"}, [][]byte{quorumPassphrases[0], quorumPassphrases[0]}, 2, testArgon2, rand.Reader); err == nil {
		t.Error("shared passphrase accepted")
	}
	if _, err := SealQuorum(f.rootPriv, []string{"a", "b"}, [][]byte{quorumPassphrases[0], []byte("kısa")}, 2, testArgon2, rand.Reader); err == nil {
		t.Error("weak passphrase accepted")
	}
	if _, err := SealQuorum(f.rootPriv, []string{"a", "a"}, quorumPassphrases[:2], 2, testArgon2, rand.Reader); err == nil {
		t.Error("duplicate holder accepted")
	}
	qb, err := SealQuorum(f.rootPriv, []string{"a", "b", "c"}, quorumPassphrases[:3], 2, testArgon2, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	qb.Copies = qb.Copies[:2]
	data, _ := MarshalQuorumBackup(qb)
	if _, err := UnmarshalQuorumBackup(data); err == nil {
		t.Error("missing copy accepted")
	}
	if binomial(5, 3) != 10 || binomial(6, 3) != 20 || len(subsets(6, 3)) != 20 {
		t.Error("binomial/subsets mismatch")
	}
}
