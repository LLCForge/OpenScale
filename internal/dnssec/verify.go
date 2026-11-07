package dnssec

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"math/big"
	"time"
)

// SignatureSkew is the clock difference tolerated at both ends of a
// signature's validity period.
const SignatureSkew = 5 * time.Minute

// RSA key sizes accepted (RFC 3110; Go refuses less than 1024 bits).
const (
	minRSABits = 1024
	maxRSABits = 4096
)

// TimeValid reports whether now lies within the signature's validity
// period, compared in serial number arithmetic (RFC 4034 3.1.5, RFC 1982).
func (s RRSIG) TimeValid(now time.Time) bool {
	n := uint32(now.Unix())
	skew := uint32(SignatureSkew / time.Second)
	if int32(s.Expiration-s.Inception) <= 0 {
		return false
	}
	return int32(n+skew-s.Inception) >= 0 && int32(s.Expiration+skew-n) >= 0
}

// ValidUntil returns the expiration time nearest to now.
func (s RRSIG) ValidUntil(now time.Time) time.Time {
	n := uint32(now.Unix())
	return now.Add(time.Duration(int32(s.Expiration-n)) * time.Second)
}

// VerifyRRSIG checks that key made sig over rrset at time now: the key
// must be a usable zone key with the signature's algorithm and key tag,
// the owner must lie in the signer's zone and the signature must be in
// its validity period.
func VerifyRRSIG(sig RRSIG, key DNSKEY, rrset []RR, now time.Time) error {
	if !SupportedAlgorithm(sig.Algorithm) {
		return ErrUnsupportedAlgorithm
	}
	if !key.usable() || key.Algorithm != sig.Algorithm || key.KeyTag() != sig.KeyTag {
		return ErrKeyMismatch
	}
	if len(rrset) == 0 || !IsSubdomain(rrset[0].Name, sig.SignerName) || rrset[0].Class != uint16(1) {
		return ErrRRset
	}
	if !sig.TimeValid(now) {
		return ErrSignatureTime
	}
	data, err := signedData(sig, rrset)
	if err != nil {
		return err
	}
	return verifySignature(sig.Algorithm, key.PublicKey, data, sig.Signature)
}

func verifySignature(alg uint8, pub, data, sig []byte) error {
	switch alg {
	case AlgRSASHA256, AlgRSASHA512:
		k, err := parseRSAKey(pub)
		if err != nil {
			return err
		}
		if alg == AlgRSASHA256 {
			h := sha256.Sum256(data)
			err = rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig)
		} else {
			h := sha512.Sum512(data)
			err = rsa.VerifyPKCS1v15(k, crypto.SHA512, h[:], sig)
		}
		if err != nil {
			return ErrBadSignature
		}
		return nil
	case AlgECDSAP256SHA256, AlgECDSAP384SHA384:
		curve, size := elliptic.P256(), 32
		var h []byte
		if alg == AlgECDSAP256SHA256 {
			s := sha256.Sum256(data)
			h = s[:]
		} else {
			curve, size = elliptic.P384(), 48
			s := sha512.Sum384(data)
			h = s[:]
		}
		if len(pub) != 2*size || len(sig) != 2*size {
			return ErrBadSignature
		}
		k, err := ecdsa.ParseUncompressedPublicKey(curve, append([]byte{4}, pub...))
		if err != nil {
			return ErrBadSignature
		}
		r := new(big.Int).SetBytes(sig[:size])
		s := new(big.Int).SetBytes(sig[size:])
		if !ecdsa.Verify(k, h, r, s) {
			return ErrBadSignature
		}
		return nil
	case AlgED25519:
		if len(pub) != ed25519.PublicKeySize || len(sig) != ed25519.SignatureSize {
			return ErrBadSignature
		}
		if !ed25519.Verify(ed25519.PublicKey(pub), data, sig) {
			return ErrBadSignature
		}
		return nil
	}
	return ErrUnsupportedAlgorithm
}

// parseRSAKey reads an RFC 3110 public key.
func parseRSAKey(b []byte) (*rsa.PublicKey, error) {
	if len(b) < 3 {
		return nil, ErrBadSignature
	}
	elen, off := int(b[0]), 1
	if elen == 0 {
		elen, off = int(b[1])<<8|int(b[2]), 3
	}
	if elen == 0 || elen > 4 || off+elen >= len(b) {
		return nil, ErrBadSignature
	}
	var e uint64
	for _, c := range b[off : off+elen] {
		e = e<<8 | uint64(c)
	}
	if e < 3 || e > 1<<31-1 || e&1 == 0 {
		return nil, ErrBadSignature
	}
	n := new(big.Int).SetBytes(b[off+elen:])
	if bits := n.BitLen(); bits < minRSABits || bits > maxRSABits {
		return nil, ErrBadSignature
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// ComputeDS returns the digest of key under owner (RFC 4034 5.1.4).
func ComputeDS(owner string, key DNSKEY, digestType uint8) (DS, error) {
	w, err := nameWire(owner)
	if err != nil {
		return DS{}, err
	}
	data := append(w, key.Rdata()...)
	d := DS{KeyTag: key.KeyTag(), Algorithm: key.Algorithm, DigestType: digestType}
	switch digestType {
	case DigestSHA256:
		h := sha256.Sum256(data)
		d.Digest = h[:]
	case DigestSHA384:
		h := sha512.Sum384(data)
		d.Digest = h[:]
	default:
		return DS{}, ErrUnsupportedAlgorithm
	}
	return d, nil
}

// Matches reports whether ds names key under owner.
func (d DS) Matches(owner string, key DNSKEY) bool {
	if !d.Supported() || d.KeyTag != key.KeyTag() || d.Algorithm != key.Algorithm {
		return false
	}
	c, err := ComputeDS(owner, key, d.DigestType)
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(c.Digest, d.Digest) == 1
}
