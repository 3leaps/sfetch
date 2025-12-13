package verify

import (
	"strings"

	"github.com/3leaps/sfetch/internal/model"
)

// FindChecksumSignature looks for a signature over the checksum file (Workflow A).
// It searches for assets matching the ChecksumSigCandidates patterns.
// Returns the signature asset and the corresponding checksum asset name, or nil if not found.
func FindChecksumSignature(assets []model.Asset, cfg *model.RepoConfig) (*model.Asset, string) {
	for _, candidate := range cfg.ChecksumSigCandidates {
		for i := range assets {
			if assets[i].Name == candidate {
				checksumName := strings.TrimSuffix(candidate, ".minisig")
				checksumName = strings.TrimSuffix(checksumName, ".asc")
				checksumName = strings.TrimSuffix(checksumName, ".sig")
				return &assets[i], checksumName
			}
		}
	}
	return nil, ""
}
