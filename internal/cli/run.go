package cli

import (
	"fmt"
	"io"
)

// Handler is the program entrypoint for CLI execution.
//
// It is set by the main package (wired in init) so tests can call Run without
// forking processes while keeping the actual implementation out of this package.
var Handler func(args []string, stdout, stderr io.Writer) int

func Run(args []string, stdout, stderr io.Writer) int {
	if Handler == nil {
		fmt.Fprintln(stderr, "internal error: cli handler not configured")
		return 1
	}
	return Handler(args, stdout, stderr)
}
