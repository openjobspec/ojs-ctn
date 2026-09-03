package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
)

type witnessClient struct {
	httpClient *http.Client
}

func (c witnessClient) getEntry(ctx context.Context, endpoint, entryID string) ([]byte, error) {
	url := strings.TrimRight(endpoint, "/") + "/v1/entries/" + entryID
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "ctn-witness/"+version)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("get entry: %w", err)
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("get entry: server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func (c witnessClient) postCosignature(ctx context.Context, endpoint, entryID string, body []byte) ([]byte, error) {
	url := strings.TrimRight(endpoint, "/") + "/v1/entries/" + entryID + "/witness"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ctn-witness/"+version)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("post cosignature: %w", err)
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode/100 != 2 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
	}
	return responseBody, nil
}
