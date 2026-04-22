package main

import (
	"fmt"
	"io"
)

func writeWitnessOutput(output io.Writer, body []byte) {
	_, _ = fmt.Fprintln(output, string(body))
}
