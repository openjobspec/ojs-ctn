// Package inclusion verifies RFC 6962-style Merkle inclusion proofs
// against a CTN signed tree head (STH). It is the auditor's
// counterpart to the CTN server's "give me a proof for entry N at
// tree size T" endpoint.
//
// Why this matters for OJS: signed CTN entries are only trustworthy
// to the extent that an auditor can confirm the entry was actually
// committed to the immutable log — i.e., that the tree head a
// witness co-signed actually contains the entry. Without inclusion
// proofs an operator can only verify that *something* was signed by
// the log, not that *their* entry is in it.
//
// Reference:
//   Laurie, Langley, Kasper, "Certificate Transparency", RFC 6962
//   §2.1.1 (Merkle Tree) and §2.1.2 (Merkle Audit Paths).
//   https://datatracker.ietf.org/doc/html/rfc6962
//
// Hashing convention (RFC 6962):
//   leaf:     h(0x00 || leaf_data)
//   internal: h(0x01 || left || right)
//
// We use SHA-256, matching every other CTN component.
package inclusion

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
)

// HashLeaf returns the RFC 6962 leaf hash for the given canonical
// entry bytes. Callers MUST canonicalise (e.g. via jcs) before
// hashing — the log and the verifier disagreeing on canonical form
// would silently break inclusion.
func HashLeaf(canonical []byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(canonical)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// HashChildren returns the RFC 6962 internal-node hash.
func HashChildren(left, right [32]byte) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left[:])
	h.Write(right[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Verify checks a Merkle audit path. Returns nil iff
// path applied to leafHash produces expectedRoot at the given
// (leafIndex, treeSize). leafIndex is 0-based; treeSize is the total
// number of leaves in the tree (the STH's tree_size).
//
// The algorithm is the standard RFC 6962 §2.1.2 walk: at each level
// we look at the lowest bit of the running index to decide whether
// the sibling is on the left or right, then ascend until the index
// covers the whole subtree. This generalises cleanly to non-power-of-2
// trees, which CTN is in steady state.
func Verify(leafIndex, treeSize uint64, leafHash [32]byte, path [][32]byte, expectedRoot [32]byte) error {
	if leafIndex >= treeSize {
		return fmt.Errorf("inclusion: leafIndex %d >= treeSize %d", leafIndex, treeSize)
	}
	if treeSize == 0 {
		return errors.New("inclusion: empty tree")
	}
	cur := leafHash
	idx := leafIndex
	last := treeSize - 1
	pi := 0
	for last > 0 {
		if pi >= len(path) && (idx&1 == 1 || idx != last) {
			return fmt.Errorf("inclusion: proof too short at level (have %d steps)", len(path))
		}
		switch {
		case idx&1 == 1:
			// Right child: sibling on left.
			if pi >= len(path) {
				return errors.New("inclusion: proof exhausted (need left sibling)")
			}
			cur = HashChildren(path[pi], cur)
			pi++
		case idx != last:
			// Left child with a real right sibling.
			cur = HashChildren(cur, path[pi])
			pi++
		default:
			// Left child at the rightmost edge with no right sibling
			// at this level — promote unchanged.
		}
		idx >>= 1
		last >>= 1
	}
	if pi != len(path) {
		return fmt.Errorf("inclusion: extra %d unused steps in proof", len(path)-pi)
	}
	if !bytes.Equal(cur[:], expectedRoot[:]) {
		return fmt.Errorf("inclusion: computed root %x != expected %x", cur, expectedRoot)
	}
	return nil
}
