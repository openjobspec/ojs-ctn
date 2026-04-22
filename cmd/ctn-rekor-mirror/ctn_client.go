package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

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
	var head CTNHead
	return head, json.NewDecoder(resp.Body).Decode(&head)
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
// most recent head on each tick. It remains because it is part of the
// exported CTNClient contract.
func (c *httpCTNClient) HeadIDs(_ context.Context) ([]string, error) { return nil, nil }
