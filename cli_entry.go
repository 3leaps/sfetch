package main

import (
	"os"

	"github.com/3leaps/sfetch/internal/cli"
)

func init() {
	cli.Handler = run
}

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
