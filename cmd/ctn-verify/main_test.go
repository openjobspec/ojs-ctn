package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRunValidationOrder(t *testing.T) {
	tests := []struct {
		name        string
		endpoint    string
		entryID     string
		trustFile   string
		allowAnyKey bool
		want        string
	}{
		{name: "endpoint first", want: "-endpoint required"},
		{name: "entry id second", endpoint: "https://ctn.example", want: "-entry-id required"},
		{name: "trust third", endpoint: "https://ctn.example", entryID: "entry-1", want: "-trust-file required (or pass -allow-any-key for dev)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.endpoint, tt.entryID, tt.trustFile, time.Second, 0, tt.allowAnyKey)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("run error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestLoadTrustCharacterization(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    string
	}{
		{name: "invalid json", content: "not json", want: "parse trust file: invalid character 'o' in literal null (expecting 'u')"},
		{name: "invalid base64", content: `{"key":"***"}`, want: `decode pubkey for "key": illegal base64 data at input byte 0`},
		{name: "wrong size", content: `{"key":"YQ=="}`, want: `pubkey for "key" is 1 bytes, want 32`},
		{name: "empty", content: `{}`, want: "trust file is empty"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "trust.json")
			if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := loadTrust(path, false)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("loadTrust error = %v, want %q", err, tt.want)
			}
		})
	}

	trust, err := loadTrust("", true)
	if err != nil || len(trust) != 0 {
		t.Fatalf("allow-any trust = %v, %v", trust, err)
	}
}

func TestCanonicalizeGolden(t *testing.T) {
	got, err := canonicalize(json.RawMessage("{\n \"z\":2, \"nested\":{\"z\":false,\"a\":true}, \"a\":1\n}"))
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":1,"nested":{"a":true,"z":false},"z":2}`
	if string(got) != want {
		t.Fatalf("canonical = %q, want %q", got, want)
	}
}

func TestRunGoldenRequestAndSignatureVerification(t *testing.T) {
	fixture := newVerifyFixture(t)
	var gotMethod, gotPath, gotUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotUserAgent = r.Header.Get("User-Agent")
		_, _ = w.Write(fixture.response)
	}))
	defer server.Close()

	if err := run(server.URL+"/", fixture.entryID, fixture.trustFile, time.Second, 0, false); err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/entries/"+fixture.entryID {
		t.Fatalf("request = %s %s", gotMethod, gotPath)
	}
	if gotUserAgent != "ctn-verify/"+version {
		t.Fatalf("User-Agent = %q", gotUserAgent)
	}
}

func TestRunAllowAnyKeyWarningGolden(t *testing.T) {
	fixture := newVerifyFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture.response)
	}))
	defer server.Close()

	stderr := captureStderr(t, func() {
		if err := run(server.URL, fixture.entryID, "", time.Second, 0, true); err != nil {
			t.Fatal(err)
		}
	})
	want := "ctn-verify: WARNING -allow-any-key set; signature NOT cryptographically verified against a trusted key\n"
	if stderr != want {
		t.Fatalf("stderr = %q, want %q", stderr, want)
	}
}

func TestRunVerificationErrorsGolden(t *testing.T) {
	fixture := newVerifyFixture(t)
	var entry Entry
	if err := json.Unmarshal(fixture.response, &entry); err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name      string
		mutate    func(*Entry)
		response  []byte
		entryID   string
		want      string
		freshness time.Duration
	}{
		{
			name:    "entry id mismatch",
			entryID: fixture.entryID,
			mutate:  func(e *Entry) { e.EntryID = "other" },
			want:    `entry id mismatch: requested "entry-1", got "other"`,
		},
		{
			name:     "empty report",
			entryID:  fixture.entryID,
			response: []byte(`{"entry_id":"entry-1"}`),
			want:     "entry has empty report",
		},
		{
			name:    "digest mismatch",
			entryID: fixture.entryID,
			mutate:  func(e *Entry) { e.ReportSHA256 = "bad" },
			want:    `report_sha256 mismatch: declared "bad", computed "fb34b05e6a0f0d1b0b352aa9ad714d4c429b25c9dd865280a88be07597015a07"`,
		},
		{
			name:    "unknown key",
			entryID: fixture.entryID,
			mutate:  func(e *Entry) { e.SubmitterKeyID = "unknown" },
			want:    `submitter key "unknown" not in trust file`,
		},
		{
			name:    "invalid signature encoding",
			entryID: fixture.entryID,
			mutate:  func(e *Entry) { e.SubmitterSignature = "***" },
			want:    "decode signature: illegal base64 data at input byte 0",
		},
		{
			name:    "invalid signature",
			entryID: fixture.entryID,
			mutate: func(e *Entry) {
				e.SubmitterSignature = base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
			},
			want: "signature verification FAILED",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := tt.response
			if response == nil {
				candidate := entry
				tt.mutate(&candidate)
				var err error
				response, err = json.Marshal(candidate)
				if err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(response)
			}))
			defer server.Close()
			runErr := run(server.URL, tt.entryID, fixture.trustFile, time.Second, tt.freshness, false)
			if runErr == nil || runErr.Error() != tt.want {
				t.Fatalf("run error = %v, want %q", runErr, tt.want)
			}
		})
	}
}

func TestRunHTTPErrorGolden(t *testing.T) {
	fixture := newVerifyFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, " denied \n")
	}))
	defer server.Close()
	err := run(server.URL, fixture.entryID, fixture.trustFile, time.Second, 0, false)
	if err == nil || err.Error() != "server returned 403: denied" {
		t.Fatalf("run error = %v", err)
	}
}

func TestCommandGoldenOutputAndExit(t *testing.T) {
	fixture := newVerifyFixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(fixture.response)
	}))
	defer server.Close()

	bin := filepath.Join(t.TempDir(), "ctn-verify")
	build := exec.Command("go", "build", "-o", bin, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, output)
	}

	tests := []struct {
		name       string
		args       []string
		exitCode   int
		wantStdout string
		wantStderr string
	}{
		{name: "version", args: []string{"version"}, wantStdout: "ctn-verify 0.1.0\n"},
		{name: "validation failure", exitCode: 1, wantStderr: "ctn-verify: -endpoint required\n"},
		{
			name: "verified",
			args: []string{
				"-endpoint", server.URL,
				"-entry-id", fixture.entryID,
				"-trust-file", fixture.trustFile,
			},
			wantStdout: "OK\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := exec.Command(bin, tt.args...)
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			err := cmd.Run()
			gotExit := 0
			if err != nil {
				gotExit = err.(*exec.ExitError).ExitCode()
			}
			if gotExit != tt.exitCode || stdout.String() != tt.wantStdout || stderr.String() != tt.wantStderr {
				t.Fatalf("exit/stdout/stderr = %d/%q/%q, want %d/%q/%q",
					gotExit, stdout.String(), stderr.String(), tt.exitCode, tt.wantStdout, tt.wantStderr)
			}
		})
	}
}

type verifyFixture struct {
	entryID   string
	trustFile string
	response  []byte
}

func newVerifyFixture(t *testing.T) verifyFixture {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	publicKey := ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)
	report := json.RawMessage(`{"a":1,"nested":{"a":true,"z":false},"z":2}`)
	canonical, err := canonicalize(report)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(report)
	entry := Entry{
		EntryID:            "entry-1",
		LoggedAt:           time.Now().UTC(),
		ReportSHA256:       hex.EncodeToString(digest[:]),
		Report:             report,
		SubmitterSignature: base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), canonical)),
		SubmitterKeyID:     "key-1",
		SequenceNumber:     1,
	}
	response, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	trustBytes, err := json.Marshal(map[string]string{
		"key-1": base64.StdEncoding.EncodeToString(publicKey),
	})
	if err != nil {
		t.Fatal(err)
	}
	trustFile := filepath.Join(t.TempDir(), "trust.json")
	if err := os.WriteFile(trustFile, trustBytes, 0600); err != nil {
		t.Fatal(err)
	}
	return verifyFixture{entryID: entry.EntryID, trustFile: trustFile, response: response}
}

func captureStderr(t *testing.T, fn func()) string {
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
