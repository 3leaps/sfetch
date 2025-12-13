package main

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
)

//go:embed configs/update/sfetch.json
var embeddedUpdateTargetJSON []byte

type UpdateTargetSource struct {
	Type         string `json:"type"`
	APIBase      string `json:"apiBase,omitempty"`
	DownloadBase string `json:"downloadBase,omitempty"`
}

type UpdateTargetRepo struct {
	ID string `json:"id"`
}

type UpdateTargetVersioning struct {
	Comparator string `json:"comparator,omitempty"`
}

type UpdateTargetConfig struct {
	Schema     string                 `json:"schema"`
	Version    int                    `json:"version"`
	Source     UpdateTargetSource     `json:"source"`
	Repo       UpdateTargetRepo       `json:"repo"`
	Versioning UpdateTargetVersioning `json:"versioning,omitempty"`
	RepoConfig RepoConfig             `json:"repoConfig"`
}

var (
	updateTargetOnce sync.Once
	updateTarget     *UpdateTargetConfig
	updateTargetErr  error
)

func loadEmbeddedUpdateTarget() (*UpdateTargetConfig, error) {
	updateTargetOnce.Do(func() {
		if len(embeddedUpdateTargetJSON) == 0 {
			updateTargetErr = errors.New("embedded update target config is empty")
			return
		}
		var cfg UpdateTargetConfig
		if err := json.Unmarshal(embeddedUpdateTargetJSON, &cfg); err != nil {
			updateTargetErr = fmt.Errorf("parse embedded update target config: %w", err)
			return
		}
		if err := validateUpdateTargetConfig(&cfg); err != nil {
			updateTargetErr = err
			return
		}
		updateTarget = &cfg
	})
	return updateTarget, updateTargetErr
}

func validateUpdateTargetConfig(cfg *UpdateTargetConfig) error {
	var problems []string

	if strings.TrimSpace(cfg.Schema) == "" {
		problems = append(problems, "schema: missing")
	}
	if cfg.Version < 1 {
		problems = append(problems, fmt.Sprintf("version: must be >= 1 (got %d)", cfg.Version))
	}
	if strings.TrimSpace(cfg.Source.Type) == "" {
		problems = append(problems, "source.type: missing")
	}
	if cfg.Source.Type != "github" {
		problems = append(problems, fmt.Sprintf("source.type: unsupported %q (supported: github)", cfg.Source.Type))
	}
	if strings.TrimSpace(cfg.Repo.ID) == "" {
		problems = append(problems, "repo.id: missing")
	}

	// RepoConfig must be explicit for self-update; the binary should not rely on
	// inference defaults to locate/verify its own release artifacts.
	if strings.TrimSpace(cfg.RepoConfig.BinaryName) == "" {
		problems = append(problems, "repoConfig.binaryName: missing")
	}
	if len(cfg.RepoConfig.AssetPatterns) == 0 {
		problems = append(problems, "repoConfig.assetPatterns: missing/empty")
	}
	if len(cfg.RepoConfig.ArchiveExtensions) == 0 {
		problems = append(problems, "repoConfig.archiveExtensions: missing/empty")
	}
	if len(cfg.RepoConfig.ChecksumSigCandidates) == 0 {
		problems = append(problems, "repoConfig.checksumSigCandidates: missing/empty")
	}

	if len(problems) > 0 {
		return fmt.Errorf("invalid embedded update target config:\n- %s", strings.Join(problems, "\n- "))
	}
	return nil
}
