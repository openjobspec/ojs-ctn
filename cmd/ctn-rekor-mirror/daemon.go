package main

import (
	"context"
	"fmt"
	"io"
	"time"
)

func runDaemon(ctx context.Context, mirror *Mirror, ctnEndpoint string, interval time.Duration, stderr io.Writer) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	fmt.Fprintf(stderr, "ctn-rekor-mirror: polling %s every %s — Ctrl-C to stop\n", ctnEndpoint, interval)
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			count, err := mirror.Tick(ctx)
			if err != nil {
				fmt.Fprintln(stderr, "tick error:", err)
				continue
			}
			if count > 0 {
				fmt.Fprintf(stderr, "mirrored %d new entr(y/ies); head_seq=%d\n", count, mirror.State.LastMirroredSeq)
			}
		}
	}
}
