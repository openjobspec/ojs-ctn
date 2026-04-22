package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStateFileBytesAndModeCharacterization(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	state := State{
		LastMirroredSeq: 99,
		UUIDs: map[string]string{
			"e2": "u2",
			"e1": "u1",
		},
	}
	if err := saveState(path, state); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n" +
		"  \"last_mirrored_sequence\": 99,\n" +
		"  \"uuids\": {\n" +
		"    \"e1\": \"u1\",\n" +
		"    \"e2\": \"u2\"\n" +
		"  }\n" +
		"}"
	if string(got) != want {
		t.Fatalf("state bytes:\n got %q\nwant %q", got, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatalf("state mode = %o, want 600", info.Mode().Perm())
	}
	if _, err := os.Stat(path + ".tmp"); !os.IsNotExist(err) {
		t.Fatalf("temporary state file remains: %v", err)
	}
}

func TestStateReplacementFailurePreservesOriginalBytes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	original := State{LastMirroredSeq: 1, UUIDs: map[string]string{"e1": "u1"}}
	if err := saveState(path, original); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}

	err = saveState(path, State{LastMirroredSeq: 2, UUIDs: map[string]string{"e2": "u2"}})
	if err == nil {
		t.Fatal("saveState unexpectedly succeeded")
	}
	after, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("failed replacement changed state:\n before %q\n after %q", before, after)
	}
}

func TestHTTPCTNClientCharacterization(t *testing.T) {
	var requests []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests = append(requests, r.Method+" "+r.URL.Path)
		switch r.URL.Path {
		case "/v1/log/head":
			_, _ = io.WriteString(w, `{"sequence_number":7,"last_entry_id":"e7","last_entry_sha256":"sha"}`)
		case "/v1/entries/e7":
			_, _ = io.WriteString(w, `{"entry_id":"e7","report":{"a":1}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	client := &httpCTNClient{base: server.URL, http: server.Client()}

	head, err := client.Head(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if head != (CTNHead{SequenceNumber: 7, LastEntryID: "e7", LastEntrySHA: "sha"}) {
		t.Fatalf("head = %+v", head)
	}
	entry, err := client.EntryByID(context.Background(), "e7")
	if err != nil {
		t.Fatal(err)
	}
	if string(entry) != `{"entry_id":"e7","report":{"a":1}}` {
		t.Fatalf("entry = %q", entry)
	}
	if strings.Join(requests, ",") != "GET /v1/log/head,GET /v1/entries/e7" {
		t.Fatalf("requests = %v", requests)
	}
}

func TestHTTPClientStatusErrorsGolden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/log/head" {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()
	client := &httpCTNClient{base: server.URL, http: server.Client()}

	if _, err := client.Head(context.Background()); err == nil || err.Error() != "ctn head: status 502" {
		t.Fatalf("Head error = %v", err)
	}
	if _, err := client.EntryByID(context.Background(), "missing"); err == nil || err.Error() != "ctn entry missing: status 404" {
		t.Fatalf("EntryByID error = %v", err)
	}
}

func TestHTTPRekorClientRequestAndResponses(t *testing.T) {
	var gotMethod, gotPath, gotContentType string
	var gotBody []byte
	response := `{"uuid":"rekor-1"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, response)
	}))
	defer server.Close()
	client := &httpRekorClient{base: server.URL, http: server.Client()}

	uuid, err := client.Submit(context.Background(), json.RawMessage(`{"entry_id":"e1"}`))
	if err != nil {
		t.Fatal(err)
	}
	if uuid != "rekor-1" {
		t.Fatalf("uuid = %q", uuid)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/v1/log/entries" || gotContentType != "application/json" {
		t.Fatalf("request = %s %s Content-Type=%q", gotMethod, gotPath, gotContentType)
	}
	wantBody := `{"apiVersion":"0.1","kind":"ojs-ctn","spec":{"entry_id":"e1"}}`
	if string(gotBody) != wantBody {
		t.Fatalf("body = %q, want %q", gotBody, wantBody)
	}

	response = `{"rekor-2":{"logIndex":1}}`
	uuid, err = client.Submit(context.Background(), json.RawMessage(`{}`))
	if err != nil || uuid != "rekor-2" {
		t.Fatalf("top-level UUID = %q, %v", uuid, err)
	}

	response = `[]`
	if _, err := client.Submit(context.Background(), json.RawMessage(`{}`)); err == nil ||
		err.Error() != "rekor submit: unrecognized response []" {
		t.Fatalf("unrecognized response error = %v", err)
	}
}

func TestMirrorSaveFailurePreservesFileAndCurrentStateSemantics(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	initial := State{LastMirroredSeq: 1, UUIDs: map[string]string{"e1": "u1"}}
	if err := saveState(path, initial); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".tmp", 0700); err != nil {
		t.Fatal(err)
	}

	mirror := &Mirror{
		CTN: &stubCTN{
			heads:   []CTNHead{{SequenceNumber: 2, LastEntryID: "e2"}},
			entries: map[string]json.RawMessage{"e2": json.RawMessage(`{"entry_id":"e2"}`)},
		},
		Rekor:     &stubRekor{},
		State:     initial,
		StatePath: path,
	}
	if _, err := mirror.Tick(context.Background()); err == nil || !strings.HasPrefix(err.Error(), "save state: ") {
		t.Fatalf("Tick error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(after, before) {
		t.Fatalf("failed Tick changed state file:\n before %q\n after %q", before, after)
	}
	if mirror.State.LastMirroredSeq != 2 || mirror.State.UUIDs["e2"] != "rekor-uuid-1" {
		t.Fatalf("in-memory failure semantics changed: %+v", mirror.State)
	}
}

func TestRunCmdOnceGoldenOutputAndState(t *testing.T) {
	ctn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/log/head":
			_, _ = io.WriteString(w, `{"sequence_number":3,"last_entry_id":"e3"}`)
		case "/v1/entries/e3":
			_, _ = io.WriteString(w, `{"entry_id":"e3"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer ctn.Close()
	rekor := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"uuid":"rekor-3"}`)
	}))
	defer rekor.Close()
	statePath := filepath.Join(t.TempDir(), "state.json")

	stderr := captureMirrorStderr(t, func() {
		err := runCmd([]string{
			"-ctn-endpoint", ctn.URL,
			"-rekor-endpoint", rekor.URL,
			"-state-file", statePath,
			"-once",
		})
		if err != nil {
			t.Fatal(err)
		}
	})
	if stderr != "mirrored 1 new entr(y/ies)\n" {
		t.Fatalf("stderr = %q", stderr)
	}
	stateBytes, err := os.ReadFile(statePath)
	if err != nil {
		t.Fatal(err)
	}
	want := "{\n  \"last_mirrored_sequence\": 3,\n  \"uuids\": {\n    \"e3\": \"rekor-3\"\n  }\n}"
	if string(stateBytes) != want {
		t.Fatalf("state = %q, want %q", stateBytes, want)
	}
}

func captureMirrorStderr(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
	fn()
	_ = writer.Close()
	os.Stderr = original
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	return strings.ReplaceAll(string(output), "\r\n", "\n")
}
