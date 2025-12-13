package main

import "github.com/3leaps/sfetch/internal/verify"

func detectChecksumType(filename string) string {
	return verify.DetectChecksumType(filename)
}

func detectChecksumAlgorithm(filename, defaultAlgo string) string {
	return verify.DetectChecksumAlgorithm(filename, defaultAlgo)
}

func formatSize(bytes int64) string {
	return verify.FormatSize(bytes)
}
