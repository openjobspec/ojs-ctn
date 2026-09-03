package main

import (
	"fmt"
	"io"
)

func writeAllowAnyKeyWarning(output io.Writer) {
	_, _ = fmt.Fprintln(output, "ctn-verify: WARNING -allow-any-key set; signature NOT cryptographically verified against a trusted key")
}

func writeVerificationSuccess(output io.Writer) {
	_, _ = fmt.Fprintln(output, "OK")
}
