package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

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
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	var direct map[string]json.RawMessage
	if err := json.Unmarshal(raw, &direct); err == nil {
		if encodedUUID, ok := direct["uuid"]; ok {
			var uuid string
			_ = json.Unmarshal(encodedUUID, &uuid)
			if uuid != "" {
				return uuid, nil
			}
		}
		for uuid := range direct {
			return uuid, nil
		}
	}
	return "", fmt.Errorf("rekor submit: unrecognized response %s", string(raw))
}
