package inclusion

import (
	"crypto/rand"
	"strings"
	"testing"
)

// consistencyProof is the reference RFC 6962 §2.1.4 proof generator
// used only by tests, mirroring the Google CT model implementation.
func consistencyProof(leaves [][32]byte, m int) [][32]byte {
	n := len(leaves)
	if m == 0 || m > n {
		return nil
	}
	if m == n {
		return [][32]byte{}
	}
	return subproof(leaves, m, n, true)
}

// subproof returns the consistency proof for the prefix of the first
// `m` leaves out of the first `n`. atRoot indicates whether the
// caller is at the root of the current tree (per RFC 6962).
func subproof(leaves [][32]byte, m, n int, atRoot bool) [][32]byte {
	if m == n {
		if atRoot {
			return nil
		}
		return [][32]byte{treeRoot(leaves[:n])}
	}
	k := largestPow2LessThan(n)
	if m <= k {
		return append(subproof(leaves[:k], m, k, false), treeRoot(leaves[k:n]))
	}
	return append(subproof(leaves[k:n], m-k, n-k, false), treeRoot(leaves[:k]))
}

func TestConsistency_HappyPaths(t *testing.T) {
	// Test grid: every (m, n) with 1 <= m <= n for n in {1..16}.
	for n := 1; n <= 16; n++ {
		leaves := mkLeaves(n)
		newRoot, leafHashes := buildTree(leaves)
		for m := 1; m <= n; m++ {
			oldRoot := treeRoot(leafHashes[:m])
			proof := consistencyProof(leafHashes, m)
			if err := VerifyConsistency(uint64(m), uint64(n), oldRoot, newRoot, proof); err != nil {
				t.Errorf("m=%d n=%d: %v (proof len=%d)", m, n, err, len(proof))
			}
		}
	}
}

func TestConsistency_EmptyOldTreeRequiresEmptyProof(t *testing.T) {
	leaves := mkLeaves(4)
	root, _ := buildTree(leaves)
	if err := VerifyConsistency(0, 4, [32]byte{}, root, nil); err != nil {
		t.Errorf("empty-old should accept any new with empty proof: %v", err)
	}
	if err := VerifyConsistency(0, 4, [32]byte{}, root, [][32]byte{{}}); err == nil {
		t.Error("non-empty proof should be rejected when oldSize=0")
	}
}

func TestConsistency_EqualSizes(t *testing.T) {
	leaves := mkLeaves(7)
	root, _ := buildTree(leaves)
	if err := VerifyConsistency(7, 7, root, root, nil); err != nil {
		t.Errorf("equal sizes: %v", err)
	}
	other := root
	other[0] ^= 0xff
	if err := VerifyConsistency(7, 7, root, other, nil); err == nil {
		t.Error("equal sizes with mismatched roots must fail")
	}
}

func TestConsistency_RejectsOldGtNew(t *testing.T) {
	if err := VerifyConsistency(5, 3, [32]byte{}, [32]byte{}, nil); err == nil {
		t.Error("oldSize > newSize must fail")
	}
}

func TestConsistency_RejectsTamperedProof(t *testing.T) {
	leaves := mkLeaves(8)
	newRoot, leafHashes := buildTree(leaves)
	oldRoot := treeRoot(leafHashes[:5])
	proof := consistencyProof(leafHashes, 5)
	if len(proof) == 0 {
		t.Fatal("expected non-empty proof for m=5,n=8")
	}
	proof[0][0] ^= 0xff
	err := VerifyConsistency(5, 8, oldRoot, newRoot, proof)
	if err == nil || !strings.Contains(err.Error(), "computed") {
		t.Errorf("tampered proof should fail with computed-mismatch, got %v", err)
	}
}

func TestConsistency_RejectsTruncated(t *testing.T) {
	leaves := mkLeaves(8)
	newRoot, leafHashes := buildTree(leaves)
	oldRoot := treeRoot(leafHashes[:3])
	proof := consistencyProof(leafHashes, 3)
	if len(proof) < 2 {
		t.Skip("need a multi-step proof")
	}
	short := proof[:len(proof)-1]
	if err := VerifyConsistency(3, 8, oldRoot, newRoot, short); err == nil {
		t.Error("truncated proof must fail")
	}
}

func TestConsistency_RejectsExtraSteps(t *testing.T) {
	leaves := mkLeaves(8)
	newRoot, leafHashes := buildTree(leaves)
	oldRoot := treeRoot(leafHashes[:5])
	proof := consistencyProof(leafHashes, 5)
	var extra [32]byte
	_, _ = rand.Read(extra[:])
	long := append(proof, extra)
	if err := VerifyConsistency(5, 8, oldRoot, newRoot, long); err == nil {
		t.Error("overlong proof must fail")
	}
}
