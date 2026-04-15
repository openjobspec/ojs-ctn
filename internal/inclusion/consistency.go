// Consistency-proof verification per RFC 6962 §2.1.4.
//
// A consistency proof shows that the Merkle tree at size m (older
// STH) is a *prefix* of the tree at size n (newer STH) — i.e. that
// the log only ever appended, never rewrote history. This is the
// auditor's primary defence against a malicious or compromised log
// operator silently retconning entries.
//
// Reference:
//   Crosby & Wallach, "Efficient Data Structures for Tamper-Evident
//   Logging", USENIX Security 2009.
//   RFC 6962 §2.1.4 — Merkle Consistency Proofs.

package inclusion

import (
	"bytes"
	"errors"
	"fmt"
)

// VerifyConsistency checks an RFC 6962 consistency proof connecting
// an older root oldRoot at oldSize to a newer root newRoot at
// newSize. Returns nil iff the proof is valid.
//
// The algorithm walks the proof bottom-up, tracking two parallel
// hashes: oldHash (must terminate at oldRoot) and newHash (must
// terminate at newRoot). At each level the sibling consumed depends
// on whether the old subtree is left- or right-aligned within the
// new tree at that level — see RFC 6962 §2.1.4 for the formal
// description; this implementation follows the well-tested CT
// reference algorithm.
func VerifyConsistency(oldSize, newSize uint64, oldRoot, newRoot [32]byte, proof [][32]byte) error {
	switch {
	case oldSize > newSize:
		return fmt.Errorf("inclusion: oldSize %d > newSize %d", oldSize, newSize)
	case oldSize == newSize:
		if len(proof) != 0 {
			return errors.New("inclusion: equal sizes require empty proof")
		}
		if !bytes.Equal(oldRoot[:], newRoot[:]) {
			return errors.New("inclusion: equal sizes but roots differ")
		}
		return nil
	case oldSize == 0:
		// Empty old tree: any new tree is consistent.
		if len(proof) != 0 {
			return errors.New("inclusion: oldSize=0 requires empty proof")
		}
		return nil
	}

	// Walk node = oldSize-1 (rightmost leaf of the old tree) and
	// last = newSize-1 up the tree, dropping all-right-edge ancestors
	// at the bottom — they're identical in old and new trees, so the
	// proof omits them.
	node := oldSize - 1
	last := newSize - 1
	for node&1 == 1 {
		node >>= 1
		last >>= 1
	}

	pi := 0
	var oldH, newH [32]byte
	if node > 0 {
		// The first proof element is the "seed" hash that's the same
		// in both trees at this level.
		if pi >= len(proof) {
			return errors.New("inclusion: consistency proof too short (no seed)")
		}
		oldH = proof[pi]
		newH = proof[pi]
		pi++
	} else {
		// node == 0 means oldSize is a power of two: the seed is
		// just oldRoot itself. Per RFC 6962 §2.1.2 the first proof
		// element MUST be omitted when it equals the previous root,
		// but the reference RFC 6962 §2.1.4 generator includes it.
		// Accept both forms for interoperability.
		oldH = oldRoot
		newH = oldRoot
		if pi < len(proof) && bytes.Equal(proof[pi][:], oldRoot[:]) {
			pi++
		}
	}

	for node > 0 {
		if pi >= len(proof) {
			return errors.New("inclusion: consistency proof too short")
		}
		switch {
		case node&1 == 1:
			// Right child at this level: sibling is on the left in
			// both trees.
			oldH = HashChildren(proof[pi], oldH)
			newH = HashChildren(proof[pi], newH)
			pi++
		case node < last:
			// Left child with a real right sibling in the new tree;
			// in the old tree this level had no right neighbour at
			// the top of the old subtree, so only newH consumes.
			newH = HashChildren(newH, proof[pi])
			pi++
		default:
			// Promote unchanged on the rightmost edge.
		}
		node >>= 1
		last >>= 1
	}

	for last > 0 {
		if pi >= len(proof) {
			return errors.New("inclusion: consistency proof too short (top levels)")
		}
		newH = HashChildren(newH, proof[pi])
		pi++
		last >>= 1
	}

	if pi != len(proof) {
		return fmt.Errorf("inclusion: %d unused proof steps", len(proof)-pi)
	}
	if !bytes.Equal(oldH[:], oldRoot[:]) {
		return fmt.Errorf("inclusion: computed old root %x != %x", oldH, oldRoot)
	}
	if !bytes.Equal(newH[:], newRoot[:]) {
		return fmt.Errorf("inclusion: computed new root %x != %x", newH, newRoot)
	}
	return nil
}
