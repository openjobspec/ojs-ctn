package inclusion

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"
)

// Reference RFC 6962 tree builder used only by tests. We want the
// production verifier in inclusion.go to be the smaller, audited
// surface; the builder lives here.

func buildTree(leaves [][]byte) (root [32]byte, leafHashes [][32]byte) {
	leafHashes = make([][32]byte, len(leaves))
	for i, l := range leaves {
		leafHashes[i] = HashLeaf(l)
	}
	root = treeRoot(leafHashes)
	return
}

func treeRoot(leaves [][32]byte) [32]byte {
	switch len(leaves) {
	case 0:
		var z [32]byte
		copy(z[:], sha256.New().Sum(nil))
		return z
	case 1:
		return leaves[0]
	}
	k := largestPow2LessThan(len(leaves))
	return HashChildren(treeRoot(leaves[:k]), treeRoot(leaves[k:]))
}

// largestPow2LessThan returns the largest power of two strictly less
// than n. RFC 6962 §2.1: split point for n leaves is the largest
// power of two < n.
func largestPow2LessThan(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// inclusionProof returns the audit path for leafIndex within leaves.
func inclusionProof(leaves [][32]byte, leafIndex int) [][32]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := largestPow2LessThan(len(leaves))
	if leafIndex < k {
		return append(inclusionProof(leaves[:k], leafIndex), treeRoot(leaves[k:]))
	}
	return append(inclusionProof(leaves[k:], leafIndex-k), treeRoot(leaves[:k]))
}

func mkLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		out[i] = []byte(fmt.Sprintf("entry-%04d", i))
	}
	return out
}

func TestVerify_PowerOfTwo(t *testing.T) {
	leaves := mkLeaves(8)
	root, leafHashes := buildTree(leaves)
	for i := 0; i < 8; i++ {
		path := inclusionProof(leafHashes, i)
		if err := Verify(uint64(i), 8, leafHashes[i], path, root); err != nil {
			t.Fatalf("leaf %d: %v", i, err)
		}
	}
}

func TestVerify_NonPowerOfTwo(t *testing.T) {
	for _, n := range []int{1, 3, 5, 7, 9, 13, 17, 33} {
		t.Run(fmt.Sprintf("n=%d", n), func(t *testing.T) {
			leaves := mkLeaves(n)
			root, leafHashes := buildTree(leaves)
			for i := 0; i < n; i++ {
				path := inclusionProof(leafHashes, i)
				if err := Verify(uint64(i), uint64(n), leafHashes[i], path, root); err != nil {
					t.Fatalf("leaf %d/%d: %v", i, n, err)
				}
			}
		})
	}
}

func TestVerify_RejectsTamperedRoot(t *testing.T) {
	leaves := mkLeaves(8)
	root, leafHashes := buildTree(leaves)
	root[0] ^= 0xff
	path := inclusionProof(leafHashes, 3)
	err := Verify(3, 8, leafHashes[3], path, root)
	if err == nil || !strings.Contains(err.Error(), "computed root") {
		t.Errorf("expected root mismatch, got %v", err)
	}
}

func TestVerify_RejectsWrongLeafHash(t *testing.T) {
	leaves := mkLeaves(8)
	root, leafHashes := buildTree(leaves)
	path := inclusionProof(leafHashes, 3)
	bad := HashLeaf([]byte("not the right entry"))
	if err := Verify(3, 8, bad, path, root); err == nil {
		t.Error("expected verification failure on wrong leaf hash")
	}
}

func TestVerify_RejectsWrongIndex(t *testing.T) {
	leaves := mkLeaves(8)
	root, leafHashes := buildTree(leaves)
	path := inclusionProof(leafHashes, 3)
	if err := Verify(2, 8, leafHashes[3], path, root); err == nil {
		t.Error("expected failure when index doesn't match path")
	}
}

func TestVerify_RejectsTruncatedProof(t *testing.T) {
	leaves := mkLeaves(8)
	root, leafHashes := buildTree(leaves)
	path := inclusionProof(leafHashes, 5)
	short := path[:len(path)-1]
	if err := Verify(5, 8, leafHashes[5], short, root); err == nil {
		t.Error("expected failure on truncated proof")
	}
}

func TestVerify_RejectsExtraSteps(t *testing.T) {
	leaves := mkLeaves(8)
	root, leafHashes := buildTree(leaves)
	path := inclusionProof(leafHashes, 5)
	var extra [32]byte
	_, _ = rand.Read(extra[:])
	long := append(path, extra)
	if err := Verify(5, 8, leafHashes[5], long, root); err == nil {
		t.Error("expected failure on overlong proof")
	}
}

func TestVerify_SingleLeafTree(t *testing.T) {
	leaves := mkLeaves(1)
	root, leafHashes := buildTree(leaves)
	if err := Verify(0, 1, leafHashes[0], nil, root); err != nil {
		t.Errorf("single-leaf verification failed: %v", err)
	}
}

func TestVerify_RejectsIndexOutOfRange(t *testing.T) {
	leaves := mkLeaves(4)
	root, _ := buildTree(leaves)
	if err := Verify(4, 4, [32]byte{}, nil, root); err == nil {
		t.Error("expected leafIndex>=treeSize rejection")
	}
}

func TestVerify_RejectsEmptyTree(t *testing.T) {
	if err := Verify(0, 0, [32]byte{}, nil, [32]byte{}); err == nil {
		t.Error("expected empty-tree rejection")
	}
}
