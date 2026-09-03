package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
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

	sigalgpkg "github.com/openjobspec/ojs-ctn/internal/sigalg"
)

func TestRunValidationOrder(t *testing.T) {
	tests := []struct {
		name       string
		endpoint   string
		keyID      string
		seedFile   string
		reportPath string
		dryRun     bool
		want       string
	}{
		{name: "key id first", want: "-key-id required"},
		{name: "seed file second", keyID: "key", want: "-seed-file required"},
		{name: "report third", keyID: "key", seedFile: "seed", want: "-report required (use - for stdin)"},
		{name: "endpoint fourth", keyID: "key", seedFile: "seed", reportPath: "report", want: "-endpoint required (or use -dry-run)"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.endpoint, tt.keyID, tt.seedFile, tt.reportPath, "ed25519", time.Second, tt.dryRun)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("run error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRunDryRunGoldenAlgorithms(t *testing.T) {
	seedFile, reportFile, seed := writeSigningInputs(t)
	canonical := []byte(`{"a":1,"nested":{"a":true,"z":false},"z":2}`)

	for _, algorithm := range []string{"", "ed25519", "ml-dsa-65", "hybrid"} {
		t.Run(algorithm, func(t *testing.T) {
			stdout := captureStdout(t, func() {
				if err := run("", "key-1", seedFile, reportFile, algorithm, time.Second, true); err != nil {
					t.Fatal(err)
				}
			})

			wantSignature := expectedSignature(t, algorithm, seed, canonical)
			wantBody, err := json.Marshal(map[string]any{
				"report":              json.RawMessage(canonical),
				"submitter_signature": base64.StdEncoding.EncodeToString(wantSignature),
				"submitter_key_id":    "key-1",
			})
			if err != nil {
				t.Fatal(err)
			}
			want := string(wantBody) + "\n"
			if stdout != want {
				t.Fatalf("stdout mismatch:\n got %q\nwant %q", stdout, want)
			}
		})
	}
}

func TestRunHTTPGoldenRequestAndOutput(t *testing.T) {
	seedFile, reportFile, _ := writeSigningInputs(t)
	var gotMethod, gotPath, gotContentType, gotUserAgent string
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotContentType = r.Header.Get("Content-Type")
		gotUserAgent = r.Header.Get("User-Agent")
		gotBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "{\"entry_id\":\"entry-1\"}\n")
	}))
	defer server.Close()

	stdout := captureStdout(t, func() {
		if err := run(server.URL+"/", "key-1", seedFile, reportFile, "ed25519", time.Second, false); err != nil {
			t.Fatal(err)
		}
	})

	if gotMethod != http.MethodPost || gotPath != "/v1/submissions" {
		t.Fatalf("request = %s %s", gotMethod, gotPath)
	}
	if gotContentType != "application/json" || gotUserAgent != "ctn-submit/"+version {
		t.Fatalf("headers: Content-Type=%q User-Agent=%q", gotContentType, gotUserAgent)
	}
	var submission struct {
		Report             json.RawMessage `json:"report"`
		SubmitterSignature string          `json:"submitter_signature"`
		SubmitterKeyID     string          `json:"submitter_key_id"`
	}
	if err := json.Unmarshal(gotBody, &submission); err != nil {
		t.Fatal(err)
	}
	if string(submission.Report) != `{"a":1,"nested":{"a":true,"z":false},"z":2}` ||
		submission.SubmitterKeyID != "key-1" {
		t.Fatalf("submission = %s", gotBody)
	}
	if stdout != "{\"entry_id\":\"entry-1\"}\n\n" {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestRunHTTPErrorGolden(t *testing.T) {
	seedFile, reportFile, _ := writeSigningInputs(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		_, _ = io.WriteString(w, "  rejected by policy \n")
	}))
	defer server.Close()

	err := run(server.URL, "key-1", seedFile, reportFile, "ed25519", time.Second, false)
	if err == nil || err.Error() != "server returned 418: rejected by policy" {
		t.Fatalf("run error = %v", err)
	}
}

func TestReadReportStdinLimit(t *testing.T) {
	original := os.Stdin
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = reader
	t.Cleanup(func() {
		os.Stdin = original
		_ = reader.Close()
	})

	input := bytes.Repeat([]byte("x"), (4<<20)+17)
	go func() {
		_, _ = writer.Write(input)
		_ = writer.Close()
	}()
	got, err := readReport("-")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 4<<20 || !bytes.Equal(got, input[:4<<20]) {
		t.Fatalf("stdin bytes = %d, want %d-byte prefix", len(got), 4<<20)
	}
}

func TestCommandGoldenVersionAndFailure(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "ctn-submit")
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
		{name: "version", args: []string{"version"}, exitCode: 0, wantStdout: "ctn-submit 0.1.0\n"},
		{name: "validation failure", exitCode: 1, wantStderr: "ctn-submit: -key-id required\n"},
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

func writeSigningInputs(t *testing.T) (seedFile, reportFile string, seed []byte) {
	t.Helper()
	seed = make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	seedFile = filepath.Join(t.TempDir(), "seed.bin")
	if err := os.WriteFile(seedFile, seed, 0600); err != nil {
		t.Fatal(err)
	}
	reportFile = filepath.Join(t.TempDir(), "report.json")
	report := "{\n \"z\": 2,\n \"nested\": {\"z\": false, \"a\": true},\n \"a\": 1\n}\n"
	if err := os.WriteFile(reportFile, []byte(report), 0600); err != nil {
		t.Fatal(err)
	}
	return seedFile, reportFile, seed
}

func expectedSignature(t *testing.T, algorithm string, seed, canonical []byte) []byte {
	t.Helper()
	switch algorithm {
	case "", "ed25519":
		return ed25519.Sign(ed25519.NewKeyFromSeed(seed), canonical)
	case "ml-dsa-65":
		_, privateKey, err := sigalgpkg.GenerateMLDSA65Key(seed)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := sigalgpkg.SignMLDSA65(privateKey, canonical)
		if err != nil {
			t.Fatal(err)
		}
		return signature
	case "hybrid":
		edSignature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), canonical)
		_, privateKey, err := sigalgpkg.GenerateMLDSA65Key(seed)
		if err != nil {
			t.Fatal(err)
		}
		pqSignature, err := sigalgpkg.SignMLDSA65(privateKey, canonical)
		if err != nil {
			t.Fatal(err)
		}
		signature, err := sigalgpkg.EncodeHybridSig(edSignature, pqSignature)
		if err != nil {
			t.Fatal(err)
		}
		return signature
	default:
		t.Fatalf("unsupported test algorithm %q", algorithm)
		return nil
	}
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	original := os.Stdout
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = writer
	fn()
	_ = writer.Close()
	os.Stdout = original
	output, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	_ = reader.Close()
	return strings.ReplaceAll(string(output), "\r\n", "\n")
}
