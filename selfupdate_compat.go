package main

import "github.com/3leaps/sfetch/internal/selfupdate"

func computeSelfUpdatePath(dir string) (string, error) {
	return selfupdate.ComputeTargetPath(dir)
}
