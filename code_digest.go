package authentication

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

// KeyedDigest derives the one-time code's HMAC-SHA-256 storage representation
// without exposing its bytes. key is a trusted independently generated 32-byte
// digest key; the all-zero value is invalid. binding is an exact 1..4096-byte
// canonical scope owned by the consuming workflow (tenant, purpose, subject or
// destination, challenge and relevant versions). It must be injective and must
// include the retained key version. No key, binding or derived state is retained.
//
// Framing is the literal domain "authentication-one-time-code-digest-v1", NUL,
// a big-endian uint32 binding length, binding, a big-endian uint16 code length,
// and the original exact code bytes. Recovery codes use a different domain.
// Zero code/key and invalid binding return a zero digest and ErrInvalidProof.
// The result is sensitive correlation data, not a bearer, authenticated proof
// or consumption result; never log it. Compare through hmac.Equal in the
// authoritative bounded-attempt transaction. Key rotation, scope policy,
// challenge expiry and one-time state remain owned by the consumer. This pure
// bounded operation owns no IO and is safe for concurrent calls when input
// buffers are not concurrently modified. Copies of the code retain its secret;
// release them after use. Go provides no complete secret-erasure guarantee.
func (c OneTimeCode) KeyedDigest(key [32]byte, binding []byte) ([32]byte, error) {
	return keyedCodeDigest(c.secret, key, binding, "authentication-one-time-code-digest-v1")
}

// KeyedDigest derives the recovery code's HMAC-SHA-256 storage representation.
// It has the same key, binding, ownership, bounds and error contract as
// OneTimeCode.KeyedDigest, but uses "authentication-recovery-code-digest-v1"
// as its type-specific domain. It does not consume, verify account authority,
// issue a recovery proof or expose code bytes. No IO or state is retained.
func (c RecoveryCode) KeyedDigest(key [32]byte, binding []byte) ([32]byte, error) {
	return keyedCodeDigest(c.secret, key, binding, "authentication-recovery-code-digest-v1")
}

func keyedCodeDigest(secret func() string, key [32]byte, binding []byte, domain string) ([32]byte, error) {
	if secret == nil || key == ([32]byte{}) || len(binding) < 1 || len(binding) > 4096 {
		return [32]byte{}, ErrInvalidProof
	}
	h := hmac.New(sha256.New, key[:])
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte{0})
	var scopeLength [4]byte
	binary.BigEndian.PutUint32(scopeLength[:], uint32(len(binding)))
	_, _ = h.Write(scopeLength[:])
	_, _ = h.Write(binding)
	code := []byte(secret())
	defer clear(code)
	var codeLength [2]byte
	binary.BigEndian.PutUint16(codeLength[:], uint16(len(code)))
	_, _ = h.Write(codeLength[:])
	_, _ = h.Write(code)
	var digest [32]byte
	h.Sum(digest[:0])
	return digest, nil
}
