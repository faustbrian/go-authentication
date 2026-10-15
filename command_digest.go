package authentication

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"unicode/utf8"
)

// CommandDigest derives the opaque code's identity-command-v1 secret binding
// without exposing its bytes. This is distinct from KeyedDigest's challenge
// storage profile. Supply the coordinator's trusted nonzero versioned 32-byte
// fingerprint key and exact canonical 1..4096-byte UTF-8 field path. The owning
// command schema must validate its code profile and full context before use.
// No normalization, key selection, workflow, authentication or consumption runs.
//
// Framing is the ASCII domain "identity-command-secret-v1" (without NUL),
// big-endian uint32 field-path byte length, exact path bytes, big-endian uint64
// code byte length and original exact code bytes. The coordinator replaces the
// secret with this HMAC-SHA-256 value in its deterministic command encoding;
// it owns the outer fingerprint, stored key version and retained-key recovery.
// This value is sensitive correlation data, not a proof, bearer or attempt
// result. Never log it or expose an unbounded digest oracle to untrusted users.
//
// Zero code/key or invalid path returns a zero digest and ErrInvalidProof.
// Pure bounded computation retains no inputs and owns no IO or goroutines.
// Immutable code copies may be used concurrently; discard them after terminal
// use. Temporary mutable code bytes are cleared, but complete secret erasure
// of Go's immutable storage or cryptographic state cannot be guaranteed.
func (c OneTimeCode) CommandDigest(key [32]byte, fieldPath string) ([32]byte, error) {
	if c.secret == nil || key == ([32]byte{}) || len(fieldPath) == 0 || len(fieldPath) > 4096 || !utf8.ValidString(fieldPath) {
		return [32]byte{}, ErrInvalidProof
	}
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write([]byte("identity-command-secret-v1"))
	var lengths [8]byte
	binary.BigEndian.PutUint32(lengths[:4], uint32(len(fieldPath)))
	_, _ = mac.Write(lengths[:4])
	_, _ = mac.Write([]byte(fieldPath))
	code := []byte(c.secret())
	defer clear(code)
	binary.BigEndian.PutUint64(lengths[:], uint64(len(code)))
	_, _ = mac.Write(lengths[:])
	_, _ = mac.Write(code)
	var digest [32]byte
	mac.Sum(digest[:0])
	return digest, nil
}
