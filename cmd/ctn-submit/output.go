package main

import (
	"fmt"
	"io"
)

func writeSubmissionOutput(output io.Writer, body []byte) error {
	_, _ = fmt.Fprintln(output, string(body))
	return nil
}
