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
)

func TestRunValidationOrder(t *testing.T) {
	tests := []struct {
		name     string
		endpoint string
		entryID  string
		keyID    string
		seedFile string
		want     string
	}{
		{name: "endpoint first", want: "-endpoint required"},
		{name: "entry id second", endpoint: "https://ctn.example", want: "-entry-id required"},
		{name: "key id third", endpoint: "https://ctn.example", entryID: "entry-1", want: "-witness-key-id required"},
		{name: "seed fourth", endpoint: "https://ctn.example", entryID: "entry-1", keyID: "witness-1", want: "-seed-file required"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := run(tt.endpoint, tt.entryID, tt.keyID, tt.seedFile, time.Second, false)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("run error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestRunDryRunGoldenSignatureAndRequest(t *testing.T) {
	seedFile, seed := writeWitnessSeed(t)
	entryID := "entry-1"
	report := json.RawMessage("{\n \"z\":2, \"nested\":{\"z\":false,\"a\":true}, \"a\":1\n}")
	response, err := json.Marshal(Entry{
		EntryID:            entryID,
		Report:             report,
		SubmitterKeyID:     "submitter",
		SubmitterSignature: "signature",
	})
	if err != nil {
		t.Fatal(err)
	}
	var gotMethod, gotPath, gotUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		gotUserAgent = r.Header.Get("User-Agent")
		_, _ = w.Write(response)
	}))
	defer server.Close()

	stdout := captureStdout(t, func() {
		if err := run(server.URL+"/", entryID, "witness-1", seedFile, time.Second, true); err != nil {
			t.Fatal(err)
		}
	})

	canonical := []byte(`{"a":1,"nested":{"a":true,"z":false},"z":2}`)
	signature := ed25519.Sign(ed25519.NewKeyFromSeed(seed), canonical)
	wantBody, err := json.Marshal(map[string]string{
		"witness_key_id":    "witness-1",
		"witness_signature": base64.StdEncoding.EncodeToString(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	if stdout != string(wantBody)+"\n" {
		t.Fatalf("stdout = %q, want %q", stdout, string(wantBody)+"\n")
	}
	if gotMethod != http.MethodGet || gotPath != "/v1/entries/"+entryID ||
		gotUserAgent != "ctn-witness/"+version {
		t.Fatalf("GET = %s %s User-Agent=%q", gotMethod, gotPath, gotUserAgent)
	}
}

func TestRunPostGoldenRequestAndOutput(t *testing.T) {
	seedFile, _ := writeWitnessSeed(t)
	entryID := "entry-1"
	entryResponse := []byte(`{"entry_id":"entry-1","report":{"b":2,"a":1},"submitter_key_id":"submitter","submitter_signature":"signature"}`)
	var methods, paths, userAgents []string
	var postContentType string
	var postBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		methods = append(methods, r.Method)
		paths = append(paths, r.URL.Path)
		userAgents = append(userAgents, r.Header.Get("User-Agent"))
		if r.Method == http.MethodGet {
			_, _ = w.Write(entryResponse)
			return
		}
		postContentType = r.Header.Get("Content-Type")
		postBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, "{\"entry_id\":\"entry-1\"}\n")
	}))
	defer server.Close()

	stdout := captureStdout(t, func() {
		if err := run(server.URL+"/", entryID, "witness-1", seedFile, time.Second, false); err != nil {
			t.Fatal(err)
		}
	})

	if strings.Join(methods, ",") != "GET,POST" ||
		strings.Join(paths, ",") != "/v1/entries/entry-1,/v1/entries/entry-1/witness" {
		t.Fatalf("requests = %v %v", methods, paths)
	}
	if userAgents[0] != "ctn-witness/"+version || userAgents[1] != "ctn-witness/"+version ||
		postContentType != "application/json" {
		t.Fatalf("headers = User-Agent %v, Content-Type %q", userAgents, postContentType)
	}
	var cosignature map[string]string
	if err := json.Unmarshal(postBody, &cosignature); err != nil {
		t.Fatal(err)
	}
	if cosignature["witness_key_id"] != "witness-1" || cosignature["witness_signature"] == "" {
		t.Fatalf("cosignature = %s", postBody)
	}
	if stdout != "{\"entry_id\":\"entry-1\"}\n\n" {
		t.Fatalf("stdout = %q", stdout)
	}
}

func TestRunTransportAndEntryErrorsGolden(t *testing.T) {
	seedFile, _ := writeWitnessSeed(t)
	tests := []struct {
		name       string
		getStatus  int
		getBody    string
		postStatus int
		postBody   string
		want       string
	}{
		{name: "get status", getStatus: http.StatusNotFound, getBody: " missing \n", want: "get entry: server returned 404: missing"},
		{name: "decode entry", getStatus: http.StatusOK, getBody: "not json", want: "decode entry: invalid character 'o' in literal null (expecting 'u')"},
		{name: "empty report", getStatus: http.StatusOK, getBody: `{"entry_id":"entry-1"}`, want: "entry has empty report"},
		{name: "canonicalize", getStatus: http.StatusOK, getBody: `{"entry_id":"entry-1","report":invalid}`, want: "decode entry: invalid character 'i' looking for beginning of value"},
		{
			name:       "post status",
			getStatus:  http.StatusOK,
			getBody:    `{"entry_id":"entry-1","report":{"a":1}}`,
			postStatus: http.StatusConflict,
			postBody:   " duplicate \n",
			want:       "server returned 409: duplicate",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet {
					w.WriteHeader(tt.getStatus)
					_, _ = io.WriteString(w, tt.getBody)
					return
				}
				w.WriteHeader(tt.postStatus)
				_, _ = io.WriteString(w, tt.postBody)
			}))
			defer server.Close()
			err := run(server.URL, "entry-1", "witness-1", seedFile, time.Second, false)
			if err == nil || err.Error() != tt.want {
				t.Fatalf("run error = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestCommandGoldenOutputAndExit(t *testing.T) {
	seedFile, _ := writeWitnessSeed(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, `{"entry_id":"entry-1","report":{"a":1}}`)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"status":"cosigned"}`)
	}))
	defer server.Close()

	bin := filepath.Join(t.TempDir(), "ctn-witness")
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
		{name: "version", args: []string{"version"}, wantStdout: "ctn-witness 0.1.0\n"},
		{name: "validation failure", exitCode: 1, wantStderr: "ctn-witness: -endpoint required\n"},
		{
			name: "cosigned",
			args: []string{
				"-endpoint", server.URL,
				"-entry-id", "entry-1",
				"-witness-key-id", "witness-1",
				"-seed-file", seedFile,
			},
			wantStdout: "{\"status\":\"cosigned\"}\n",
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

func writeWitnessSeed(t *testing.T) (string, []byte) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	path := filepath.Join(t.TempDir(), "seed.bin")
	if err := os.WriteFile(path, seed, 0600); err != nil {
		t.Fatal(err)
	}
	return path, seed
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
