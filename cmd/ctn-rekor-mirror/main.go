// Command ctn-rekor-mirror is the M5/P3 sliver that copies CTN entries
// into a Sigstore Rekor instance (or any compatible transparency log).
//
// Why mirror to Rekor? The Conformance Trust Network is its own log,
// but Rekor is the de-facto industry standard. Mirroring gives us:
//
//   - A second independent witness for free (Rekor is operated by the
//     Linux Foundation, not by openjobspec.org).
//   - Discoverability: tooling that already searches Rekor (cosign,
//     gitsign, sget) finds CTN entries without learning a new API.
//   - A migration path if CTN ever needs to step back to "secondary log"
//     status — the canonical record exists in Rekor.
//
// What this binary does (P3 sliver):
//
//   - Polls the source CTN's `/v1/log/head` every -interval.
//   - For every entry sequence_number > last_mirrored, GETs the entry,
//     formats a Rekor "hashedrekord-like" proposal and POSTs it.
//   - Records the resulting Rekor UUID alongside the CTN entry id in
//     a state file so a restart is idempotent.
//
// What it does NOT do (parking lot for P3 follow-up):
//
//   - Real PEM key conversion for canonical Rekor v0.0.1 hashedrekord
//     bodies (we ship a CTN-shaped body that Rekor accepts as a
//     `intoto` blob; full hashedrekord support requires PEM marshalling
//     of the ed25519 public key — feasible but out of scope here).
//   - Inclusion-proof verification on the Rekor side (P4).
//   - Backfill of the entire CTN history on first run beyond a -from
//     sequence cursor.
package main

import (
	"fmt"
	"os"
)

const version = "0.1.0-p3"

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	switch os.Args[1] {
	case "run":
		if err := runCmd(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "ctn-rekor-mirror run:", err)
			os.Exit(1)
		}
	case "version":
		fmt.Println("ctn-rekor-mirror", version)
	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: ctn-rekor-mirror <run|version> [flags]")
}
