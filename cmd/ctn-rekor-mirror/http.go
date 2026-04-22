package main

import (
	"net/http"
	"time"
)

func defaultHTTPClient() *http.Client {
	return &http.Client{Timeout: 10 * time.Second}
}
