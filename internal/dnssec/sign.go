package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"math/big"
)

// Signing exists for tests and local tools that build signed zones (the
// resolver tests sign fake zones with freshly generated keys); OpenScale
// itself never signs DNS data.

// NewDNSKEY encodes pub as a DNSKEY of algorithm alg.
func NewDNSKEY(pub crypto.PublicKey, alg uint8, flags uint16) (DNSKEY, error) {
	k := DNSKEY{Flags: flags, Protocol: 3, Algorithm: alg}
	switch p := pub.(type) {
	case ed25519.PublicKey:
		if alg != AlgED25519 {
			return DNSKEY{}, ErrUnsupportedAlgorithm
		}
		k.PublicKey = append([]byte(nil), p...)
	case *ecdsa.PublicKey:
		var curve elliptic.Curve
		switch alg {
		case AlgECDSAP256SHA256:
			curve = elliptic.P256()
		case AlgECDSAP384SHA384:
			curve = elliptic.P384()
		default:
			return DNSKEY{}, ErrUnsupportedAlgorithm
		}
		if p.Curve != curve {
			return DNSKEY{}, ErrUnsupportedAlgorithm
		}
		e, err := p.ECDH()
		if err != nil {
			return DNSKEY{}, err
		}
		k.PublicKey = e.Bytes()[1:] // drop the 0x04 prefix
	case *rsa.PublicKey:
		if alg != AlgRSASHA256 && alg != AlgRSASHA512 {
			return DNSKEY{}, ErrUnsupportedAlgorithm
		}
		e := big.NewInt(int64(p.E)).Bytes()
		if len(e) > 255 {
			return DNSKEY{}, ErrMalformed
		}
		k.PublicKey = append([]byte{byte(len(e))}, e...)
		k.PublicKey = append(k.PublicKey, p.N.Bytes()...)
	default:
		return DNSKEY{}, ErrUnsupportedAlgorithm
	}
	return k, nil
}

// Sign fills sig.Signature with priv's signature over rrset. sig must
// carry every other field (algorithm, key tag, signer, times, labels).
func Sign(sig RRSIG, rrset []RR, priv crypto.Signer) (RRSIG, error) {
	data, err := signedData(sig, rrset)
	if err != nil {
		return RRSIG{}, err
	}
	switch k := priv.(type) {
	case ed25519.PrivateKey:
		sig.Signature = ed25519.Sign(k, data)
	case *ecdsa.PrivateKey:
		var h []byte
		size := 32
		switch sig.Algorithm {
		case AlgECDSAP256SHA256:
			s := sha256.Sum256(data)
			h = s[:]
		case AlgECDSAP384SHA384:
			s := sha512.Sum384(data)
			h, size = s[:], 48
		default:
			return RRSIG{}, ErrUnsupportedAlgorithm
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, h)
		if err != nil {
			return RRSIG{}, err
		}
		out := make([]byte, 2*size)
		r.FillBytes(out[:size])
		s.FillBytes(out[size:])
		sig.Signature = out
	case *rsa.PrivateKey:
		var err error
		switch sig.Algorithm {
		case AlgRSASHA256:
			h := sha256.Sum256(data)
			sig.Signature, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, h[:])
		case AlgRSASHA512:
			h := sha512.Sum512(data)
			sig.Signature, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA512, h[:])
		default:
			return RRSIG{}, ErrUnsupportedAlgorithm
		}
		if err != nil {
			return RRSIG{}, err
		}
	default:
		return RRSIG{}, errors.New("dnssec: unsupported private key")
	}
	return sig, nil
}
