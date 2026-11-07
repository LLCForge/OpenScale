package trust

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

// Cryptographic known answer tests (#531). Before any key is used, every
// primitive OpenScale relies on is run once on a published test vector:
// a miscompiled, wrongly linked or tampered implementation then fails
// here, with no secret involved, instead of producing keys or
// signatures nobody else can verify. The vectors are public constants:
//
//	SHA-256            FIPS 180-2, message "abc"
//	Ed25519            RFC 8032 section 7.1, test 1 (also verified)
//	X25519             RFC 7748 section 6.1 (both directions)
//	ChaCha20-Poly1305  RFC 8439 section 2.8.2 (seal, open and a forged tag)
//	Argon2id           reference implementation vector, t=3 m=256 KiB p=2
//
// The Argon2id vector is the small one of the reference test suite, so the
// whole set runs in a few milliseconds at every start.

// ErrSelfTest is returned when a known answer test fails. Nothing that
// needs cryptography may continue after it.
var ErrSelfTest = errors.New("kriptografik öz sınama başarısız")

type katCase struct {
	name string
	run  func() error
}

var katCases = []katCase{
	{"SHA-256", katSHA256},
	{"Ed25519", katEd25519},
	{"X25519", katX25519},
	{"ChaCha20-Poly1305", katChaCha20Poly1305},
	{"Argon2id", katArgon2id},
}

// KnownAnswerTests runs every test and returns the names that passed, or
// an error naming the first one that failed.
func KnownAnswerTests() ([]string, error) {
	passed := make([]string, 0, len(katCases))
	for _, c := range katCases {
		if err := c.run(); err != nil {
			return passed, fmt.Errorf("%w: %s: %v", ErrSelfTest, c.name, err)
		}
		passed = append(passed, c.name)
	}
	return passed, nil
}

var cryptoSelfTest struct {
	once   sync.Once
	passed []string
	err    error
}

// CryptoSelfTest runs the known answer tests once per process and returns
// the cached result afterwards.
func CryptoSelfTest() ([]string, error) {
	cryptoSelfTest.once.Do(func() {
		cryptoSelfTest.passed, cryptoSelfTest.err = KnownAnswerTests()
	})
	return cryptoSelfTest.passed, cryptoSelfTest.err
}

func mustHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("trust: bad known answer constant")
	}
	return b
}

func katSHA256() error {
	want := mustHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
	got := sha256.Sum256([]byte("abc"))
	if !bytes.Equal(got[:], want) {
		return errors.New("özet beklenen değer değil")
	}
	return nil
}

func katEd25519() error {
	seed := mustHex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	wantPub := mustHex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
	wantSig := mustHex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
	priv := ed25519.NewKeyFromSeed(seed)
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, wantPub) {
		return errors.New("açık anahtar beklenen değer değil")
	}
	sig := ed25519.Sign(priv, nil)
	if !bytes.Equal(sig, wantSig) {
		return errors.New("imza beklenen değer değil")
	}
	if !ed25519.Verify(pub, nil, sig) {
		return errors.New("geçerli imza reddedildi")
	}
	bad := bytes.Clone(sig)
	bad[0] ^= 1
	if ed25519.Verify(pub, nil, bad) {
		return errors.New("bozuk imza kabul edildi")
	}
	return nil
}

func katX25519() error {
	alicePriv := mustHex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
	alicePub := mustHex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
	bobPriv := mustHex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
	bobPub := mustHex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
	shared := mustHex("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
	curve := ecdh.X25519()
	a, err := curve.NewPrivateKey(alicePriv)
	if err != nil {
		return err
	}
	b, err := curve.NewPrivateKey(bobPriv)
	if err != nil {
		return err
	}
	if !bytes.Equal(a.PublicKey().Bytes(), alicePub) || !bytes.Equal(b.PublicKey().Bytes(), bobPub) {
		return errors.New("açık anahtar beklenen değer değil")
	}
	ab, err := a.ECDH(b.PublicKey())
	if err != nil {
		return err
	}
	ba, err := b.ECDH(a.PublicKey())
	if err != nil {
		return err
	}
	if !bytes.Equal(ab, shared) || !bytes.Equal(ba, shared) {
		return errors.New("ortak sır beklenen değer değil")
	}
	return nil
}

func katChaCha20Poly1305() error {
	key := mustHex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
	nonce := mustHex("070000004041424344454647")
	aad := mustHex("50515253c0c1c2c3c4c5c6c7")
	plain := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	want := mustHex("d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116" +
		"1ae10b594f09e26a7e902ecbd0600691")
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return err
	}
	sealed := aead.Seal(nil, nonce, plain, aad)
	if !bytes.Equal(sealed, want) {
		return errors.New("şifreli metin beklenen değer değil")
	}
	opened, err := aead.Open(nil, nonce, sealed, aad)
	if err != nil || !bytes.Equal(opened, plain) {
		return errors.New("geçerli şifreli metin açılamadı")
	}
	forged := bytes.Clone(sealed)
	forged[len(forged)-1] ^= 1
	if _, err := aead.Open(nil, nonce, forged, aad); err == nil {
		return errors.New("bozuk doğrulama etiketi kabul edildi")
	}
	return nil
}

func katArgon2id() error {
	want := mustHex("4668d30ac4187e6878eedeacf0fd83c5a0a30db2cc16ef0b")
	got := argon2.IDKey([]byte("password"), []byte("somesalt"), 3, 256, 2, uint32(len(want)))
	if !bytes.Equal(got, want) {
		return errors.New("türetilen anahtar beklenen değer değil")
	}
	return nil
}
