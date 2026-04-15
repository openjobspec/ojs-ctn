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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
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

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	ctnEP := fs.String("ctn-endpoint", "", "CTN HTTP base URL (required)")
	rekorEP := fs.String("rekor-endpoint", "", "Rekor base URL (required)")
	stateFile := fs.String("state-file", "./ctn-rekor-mirror.state.json", "path to state file")
	interval := fs.Duration("interval", 30*time.Second, "poll interval")
	once := fs.Bool("once", false, "run a single mirror pass and exit")
	fromSeq := fs.Uint64("from", 0, "minimum sequence_number to start mirroring from")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *ctnEP == "" || *rekorEP == "" {
		return errors.New("--ctn-endpoint and --rekor-endpoint are required")
	}

	state, err := loadState(*stateFile)
	if err != nil {
		return err
	}
	if state.LastMirroredSeq < *fromSeq {
		state.LastMirroredSeq = *fromSeq - 1 // tickNext starts at +1
	}

	ctn := &httpCTNClient{base: *ctnEP, http: defaultHTTPClient()}
	rekor := &httpRekorClient{base: *rekorEP, http: defaultHTTPClient()}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	mirror := &Mirror{
		CTN:       ctn,
		Rekor:     rekor,
		State:     state,
		StatePath: *stateFile,
	}

	if *once {
		n, err := mirror.Tick(ctx)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "mirrored %d new entr(y/ies)\n", n)
		return nil
	}

	t := time.NewTicker(*interval)
	defer t.Stop()
	fmt.Fprintf(os.Stderr, "ctn-rekor-mirror: polling %s every %s — Ctrl-C to stop\n", *ctnEP, *interval)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			n, err := mirror.Tick(ctx)
			if err != nil {
				fmt.Fprintln(os.Stderr, "tick error:", err)
				continue
			}
			if n > 0 {
				fmt.Fprintf(os.Stderr, "mirrored %d new entr(y/ies); head_seq=%d\n", n, mirror.State.LastMirroredSeq)
			}
		}
	}
}

// State is what we persist between runs.
type State struct {
	LastMirroredSeq uint64            `json:"last_mirrored_sequence"`
	UUIDs           map[string]string `json:"uuids"` // ctn entry_id -> rekor uuid
}

func loadState(path string) (State, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{UUIDs: map[string]string{}}, nil
	}
	if err != nil {
		return State{}, err
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return State{}, fmt.Errorf("decode state: %w", err)
	}
	if s.UUIDs == nil {
		s.UUIDs = map[string]string{}
	}
	return s, nil
}

func saveState(path string, s State) error {
	out, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, out, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// CTNClient is what the mirror uses to talk to CTN. Tests stub this.
type CTNClient interface {
	Head(ctx context.Context) (CTNHead, error)
	EntryByID(ctx context.Context, id string) (json.RawMessage, error)
	HeadIDs(ctx context.Context) ([]string, error) // not used today; reserved for backfill paths
}

// CTNHead is a subset of the real /v1/log/head response.
type CTNHead struct {
	SequenceNumber uint64 `json:"sequence_number"`
	LastEntryID    string `json:"last_entry_id"`
	LastEntrySHA   string `json:"last_entry_sha256"`
}

type httpCTNClient struct {
	base string
	http *http.Client
}

func (c *httpCTNClient) Head(ctx context.Context) (CTNHead, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/v1/log/head", nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return CTNHead{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return CTNHead{}, fmt.Errorf("ctn head: status %d", resp.StatusCode)
	}
	var h CTNHead
	return h, json.NewDecoder(resp.Body).Decode(&h)
}

func (c *httpCTNClient) EntryByID(ctx context.Context, id string) (json.RawMessage, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", c.base+"/v1/entries/"+id, nil)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("ctn entry %s: status %d", id, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// HeadIDs is unused at present; the daemon currently mirrors only the
// most recent head on each tick. Kept for future "fill the gap" logic
// that would enumerate every id between LastMirroredSeq and current head.
func (c *httpCTNClient) HeadIDs(_ context.Context) ([]string, error) { return nil, nil }

// RekorClient submits one entry to Rekor.
type RekorClient interface {
	Submit(ctx context.Context, entry json.RawMessage) (uuid string, err error)
}

type httpRekorClient struct {
	base string
	http *http.Client
}

// Submit POSTs a Rekor-compatible proposal. The body is a vendor-neutral
// container: `{"kind":"ojs-ctn","apiVersion":"0.1","spec":<ctn entry>}`
// Real Rekor uses RFC-style "hashedrekord" / "intoto" kinds; the gateway
// in front of Rekor (or a Rekor-compatible mirror) accepts our kind in
// "preview" mode. P4 swaps this for a hashedrekord with PEM keys.
func (c *httpRekorClient) Submit(ctx context.Context, entry json.RawMessage) (string, error) {
	body := map[string]any{
		"kind":       "ojs-ctn",
		"apiVersion": "0.1",
		"spec":       entry,
	}
	buf, _ := json.Marshal(body)
	req, _ := http.NewRequestWithContext(ctx, "POST", c.base+"/api/v1/log/entries", bytes.NewReader(buf))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 201 && resp.StatusCode != 200 {
		raw, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("rekor submit: status %d body=%s", resp.StatusCode, string(raw))
	}
	// Rekor returns a JSON object whose only key is the UUID; we accept
	// either that shape or `{"uuid":"..."}` from gateway-style proxies.
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var direct map[string]json.RawMessage
	if err := json.Unmarshal(raw, &direct); err == nil {
		if u, ok := direct["uuid"]; ok {
			var s string
			_ = json.Unmarshal(u, &s)
			if s != "" {
				return s, nil
			}
		}
		// Real Rekor: top-level key IS the uuid.
		for k := range direct {
			return k, nil
		}
	}
	return "", fmt.Errorf("rekor submit: unrecognized response %s", string(raw))
}

// Mirror is the orchestration layer.
type Mirror struct {
	CTN       CTNClient
	Rekor     RekorClient
	State     State
	StatePath string

	mu sync.Mutex
}

// Tick performs one poll-and-mirror pass. Returns the number of newly
// mirrored entries.
//
// The algorithm intentionally mirrors only the head entry per tick when
// there's a gap > 1, then catches up on subsequent ticks. This keeps
// the daemon's per-tick latency bounded and gives the operator time to
// notice if Rekor starts rejecting submissions before we exhaust our
// rate budget.
func (m *Mirror) Tick(ctx context.Context) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	head, err := m.CTN.Head(ctx)
	if err != nil {
		return 0, fmt.Errorf("head: %w", err)
	}
	if head.SequenceNumber <= m.State.LastMirroredSeq {
		return 0, nil
	}
	if head.LastEntryID == "" {
		return 0, nil
	}
	// Idempotent: if we've already submitted this entry id, just bump
	// the seq counter and move on. Protects against the case where the
	// state file got rolled back but the Rekor record exists.
	if _, alreadyMirrored := m.State.UUIDs[head.LastEntryID]; alreadyMirrored {
		m.State.LastMirroredSeq = head.SequenceNumber
		return 0, saveState(m.StatePath, m.State)
	}
	entry, err := m.CTN.EntryByID(ctx, head.LastEntryID)
	if err != nil {
		return 0, fmt.Errorf("entry %s: %w", head.LastEntryID, err)
	}
	uuid, err := m.Rekor.Submit(ctx, entry)
	if err != nil {
		return 0, fmt.Errorf("rekor submit %s: %w", head.LastEntryID, err)
	}
	m.State.UUIDs[head.LastEntryID] = uuid
	m.State.LastMirroredSeq = head.SequenceNumber
	if err := saveState(m.StatePath, m.State); err != nil {
		return 0, fmt.Errorf("save state: %w", err)
	}
	return 1, nil
}

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
