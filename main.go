package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/3leaps/sfetch/pkg/update"
	"github.com/jedisct1/go-minisign"
)

const (
	defaultAPIBase  = "https://api.github.com"
	defaultCDNBase  = "https://github.com"
	defaultCacheDir = "~/.cache/sfetch"
	maxCommandError = 512
)

func githubToken() string {
	if tok := strings.TrimSpace(os.Getenv("SFETCH_GITHUB_TOKEN")); tok != "" {
		return tok
	}
	return strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
}

func httpGetWithAuth(url string) (*http.Response, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("sfetch/%s", version))
	if tok := githubToken(); tok != "" && strings.Contains(url, "github.com") {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return client.Do(req)
}

var (
	version   = "dev"
	buildTime = "unknown"
	gitCommit = "unknown"
)

// self-update target is defined via embedded update-target config (see update_target.go).

// Verification workflows
const (
	workflowA        = "A"        // Checksum-level signature (SHA256SUMS.minisig)
	workflowB        = "B"        // Per-asset signature (asset.tar.gz.minisig)
	workflowC        = "C"        // Checksum-only (no signature available)
	workflowInsecure = "insecure" // No verification (--insecure flag)
)

// Trust levels for provenance records
const (
	trustHigh   = "high"   // Signature + checksum verified
	trustMedium = "medium" // Signature only (no checksum)
	trustLow    = "low"    // Checksum only (no signature)
	trustNone   = "none"   // No verification (--insecure)
)

// Minisign key format constants
// Public key: "RW" + 54 base64 chars = 56 total (42 bytes: 2 algo + 8 keyid + 32 pubkey)
// Secret key (unencrypted): 212 chars, starts with "RWQAAEIy"
// Secret key (encrypted):   212 chars, starts with "RWRTY0Iy"
// Signature: 140+ chars (4 lines total)
const (
	minisignPubkeyLen    = 56
	minisignSecretkeyLen = 212
)

// minisignPubkeyRegex matches a valid minisign public key line (with or without comment header)
var minisignPubkeyRegex = regexp.MustCompile(`^RW[A-Za-z0-9+/]{54}$`)

// Embedded trust anchors for self-verification and transparency.
// Users can compare these against keys published at:
//   - https://github.com/3leaps/sfetch/releases (sfetch-minisign.pub)
//   - scripts/install-sfetch.sh (SFETCH_MINISIGN_PUBKEY)
//
// Changing these keys requires updating both this file and install-sfetch.sh.
const (
	EmbeddedMinisignPubkey = "RWTAoUJ007VE3h8tbHlBCyk2+y0nn7kyA4QP34LTzdtk8M6A2sryQtZC"
	EmbeddedMinisignKeyID  = "3leaps/sfetch release signing key"
)

// minisignSecretkeyPrefixes are known prefixes for secret key files
var minisignSecretkeyPrefixes = []string{
	"RWQAAEIy", // unencrypted secret key
	"RWRTY0Iy", // encrypted secret key
}

//go:embed inference-rules.json
var defaultInferenceRulesJSON []byte

// InferenceRules drive tie-breaking for smart asset selection. If rule volume grows,
// we may externalize user overrides (e.g., ~/.config/sfetch) while keeping embedded
// defaults auditable and versioned in Git.
type InferenceRules struct {
	Version            string              `json:"version"`
	PlatformExclusions map[string][]string `json:"platformExclusions"`
	PlatformTokens     map[string][]string `json:"platformTokens"`
	ArchTokens         map[string][]string `json:"archTokens"`
	FormatPreference   []string            `json:"formatPreference"`
	ArchiveExtensions  []string            `json:"archiveExtensions"`
}

// ProvenanceRecord captures verification actions for audit/compliance.
// Schema: schemas/provenance.schema.json
type ProvenanceRecord struct {
	Schema        string           `json:"$schema"`
	Version       string           `json:"version"`
	Timestamp     string           `json:"timestamp"`
	SfetchVersion string           `json:"sfetchVersion"`
	Source        ProvenanceSource `json:"source"`
	Asset         ProvenanceAsset  `json:"asset"`
	Verification  ProvenanceVerify `json:"verification"`
	TrustLevel    string           `json:"trustLevel"`
	Warnings      []string         `json:"warnings,omitempty"`
	Flags         ProvenanceFlags  `json:"flags,omitempty"`
}

type ProvenanceSource struct {
	Type       string             `json:"type"`
	Repository string             `json:"repository,omitempty"`
	Release    *ProvenanceRelease `json:"release,omitempty"`
}

type ProvenanceRelease struct {
	Tag string `json:"tag"`
	URL string `json:"url"`
}

type ProvenanceAsset struct {
	Name             string          `json:"name"`
	Size             int64           `json:"size"`
	URL              string          `json:"url"`
	ComputedChecksum *ProvenanceHash `json:"computedChecksum,omitempty"`
}

type ProvenanceHash struct {
	Algorithm string `json:"algorithm"`
	Value     string `json:"value"`
}

type ProvenanceVerify struct {
	Workflow  string              `json:"workflow"`
	Signature ProvenanceSigStatus `json:"signature"`
	Checksum  ProvenanceCSStatus  `json:"checksum"`
}

type ProvenanceSigStatus struct {
	Available bool   `json:"available"`
	Format    string `json:"format,omitempty"`
	File      string `json:"file,omitempty"`
	KeySource string `json:"keySource,omitempty"`
	Verified  bool   `json:"verified"`
	Skipped   bool   `json:"skipped"`
	Reason    string `json:"reason,omitempty"`
}

type ProvenanceCSStatus struct {
	Available bool   `json:"available"`
	Algorithm string `json:"algorithm,omitempty"`
	File      string `json:"file,omitempty"`
	Type      string `json:"type,omitempty"`
	Verified  bool   `json:"verified"`
	Skipped   bool   `json:"skipped"`
	Reason    string `json:"reason,omitempty"`
}

type ProvenanceFlags struct {
	SkipSig         bool `json:"skipSig,omitempty"`
	SkipChecksum    bool `json:"skipChecksum,omitempty"`
	Insecure        bool `json:"insecure,omitempty"`
	RequireMinisign bool `json:"requireMinisign,omitempty"`
	PreferPerAsset  bool `json:"preferPerAsset,omitempty"`
	DryRun          bool `json:"dryRun,omitempty"`
}

// VerificationAssessment captures what verification is available for a release.
// This is computed before any downloads to enable --dry-run and informed decisions.
type VerificationAssessment struct {
	// Asset selection
	SelectedAsset *Asset

	// Signature availability
	SignatureAvailable  bool
	SignatureFormat     string // minisign, pgp, ed25519, or ""
	SignatureFile       string // filename of signature
	SignatureIsChecksum bool   // true if sig is over checksum file (Workflow A)
	ChecksumFileForSig  string // checksum file name when SignatureIsChecksum is true

	// Checksum availability
	ChecksumAvailable bool
	ChecksumFile      string // filename of checksum file
	ChecksumType      string // "consolidated" (SHA256SUMS) or "per-asset" (.sha256)
	ChecksumAlgorithm string // sha256, sha512

	// Computed workflow and trust
	Workflow   string // A, B, C, or insecure
	TrustLevel string // high, medium, low, none

	// Warnings generated during assessment
	Warnings []string
}

// assessRelease analyzes a release to determine what verification is available.
// This does NOT download anything - it only inspects the asset list.
func assessRelease(rel *Release, cfg *RepoConfig, selectedAsset *Asset, flags assessmentFlags) *VerificationAssessment {
	assessment := &VerificationAssessment{
		SelectedAsset: selectedAsset,
		Warnings:      []string{},
	}

	// Handle --insecure flag first
	if flags.insecure {
		assessment.Workflow = workflowInsecure
		assessment.TrustLevel = trustNone
		assessment.Warnings = append(assessment.Warnings, "No verification performed (--insecure flag)")
		return assessment
	}

	baseName := trimKnownExtension(selectedAsset.Name, cfg.ArchiveExtensions)
	ctx := templateContext{
		AssetName:       selectedAsset.Name,
		BaseName:        baseName,
		BinaryName:      cfg.BinaryName,
		GOOS:            runtime.GOOS,
		GOARCH:          runtime.GOARCH,
		Version:         rel.TagName,
		VersionNoPrefix: strings.TrimPrefix(rel.TagName, "v"),
	}

	// Check for checksum-level signature (Workflow A)
	checksumSigAsset, checksumFileName := findChecksumSignature(rel.Assets, cfg)
	if checksumSigAsset != nil && !flags.skipSig && !flags.preferPerAsset {
		assessment.SignatureAvailable = true
		assessment.SignatureFile = checksumSigAsset.Name
		assessment.SignatureFormat = signatureFormatFromExtension(checksumSigAsset.Name, cfg.SignatureFormats)
		assessment.SignatureIsChecksum = true
		assessment.ChecksumFileForSig = checksumFileName

		// The checksum file is implicitly available if we have a sig over it
		assessment.ChecksumAvailable = true
		assessment.ChecksumFile = checksumFileName
		assessment.ChecksumType = "consolidated"
		assessment.ChecksumAlgorithm = detectChecksumAlgorithm(checksumFileName, cfg.HashAlgo)

		assessment.Workflow = workflowA
		if flags.skipChecksum {
			assessment.TrustLevel = trustMedium
			assessment.Warnings = append(assessment.Warnings, "Checksum verification skipped (--skip-checksum flag)")
		} else {
			assessment.TrustLevel = trustHigh
		}
		return assessment
	}

	// Check for per-asset signature (Workflow B)
	perAssetSig := findPerAssetSignature(rel.Assets, ctx, cfg)
	if perAssetSig != nil && !flags.skipSig {
		assessment.SignatureAvailable = true
		assessment.SignatureFile = perAssetSig.Name
		assessment.SignatureFormat = signatureFormatFromExtension(perAssetSig.Name, cfg.SignatureFormats)
		assessment.SignatureIsChecksum = false

		// Check for checksum file (optional in Workflow B)
		checksumAsset := findChecksumFile(rel.Assets, ctx, cfg)
		if checksumAsset != nil && !flags.skipChecksum {
			assessment.ChecksumAvailable = true
			assessment.ChecksumFile = checksumAsset.Name
			assessment.ChecksumType = detectChecksumType(checksumAsset.Name)
			assessment.ChecksumAlgorithm = detectChecksumAlgorithm(checksumAsset.Name, cfg.HashAlgo)
			assessment.TrustLevel = trustHigh
		} else {
			assessment.TrustLevel = trustMedium
			if flags.skipChecksum {
				assessment.Warnings = append(assessment.Warnings, "Checksum verification skipped (--skip-checksum flag)")
			} else {
				assessment.Warnings = append(assessment.Warnings, "No checksum file found; using signature for integrity")
			}
		}

		assessment.Workflow = workflowB
		return assessment
	}

	// No signature available - check for checksum-only (Workflow C)
	checksumAsset := findChecksumFile(rel.Assets, ctx, cfg)
	if checksumAsset != nil && !flags.skipChecksum {
		assessment.ChecksumAvailable = true
		assessment.ChecksumFile = checksumAsset.Name
		assessment.ChecksumType = detectChecksumType(checksumAsset.Name)
		assessment.ChecksumAlgorithm = detectChecksumAlgorithm(checksumAsset.Name, cfg.HashAlgo)

		assessment.Workflow = workflowC
		assessment.TrustLevel = trustLow
		assessment.Warnings = append(assessment.Warnings, "No signature available; authenticity cannot be proven")

		if flags.skipSig {
			// User explicitly skipped sig, but there wasn't one anyway
			assessment.Warnings = append(assessment.Warnings, "Note: --skip-sig had no effect (no signature found)")
		}
		return assessment
	}

	// Nothing available
	assessment.Workflow = ""
	assessment.TrustLevel = trustNone
	assessment.Warnings = append(assessment.Warnings, "No verification available (no signature or checksum found)")

	return assessment
}

// assessmentFlags holds CLI flags that affect assessment behavior
type assessmentFlags struct {
	skipSig         bool
	skipChecksum    bool
	insecure        bool
	preferPerAsset  bool
	requireMinisign bool
	dryRun          bool
}

// findPerAssetSignature looks for a signature file for the specific asset (Workflow B).
func findPerAssetSignature(assets []Asset, ctx templateContext, cfg *RepoConfig) *Asset {
	// Try template-based matching first
	for _, tpl := range cfg.SignatureCandidates {
		name := renderTemplate(tpl, ctx)
		if name == "" {
			continue
		}
		for i := range assets {
			if assets[i].Name == name {
				return &assets[i]
			}
		}
	}
	return nil
}

// findChecksumFile looks for a checksum file in the release assets.
func findChecksumFile(assets []Asset, ctx templateContext, cfg *RepoConfig) *Asset {
	// Try template-based matching first
	for _, tpl := range cfg.ChecksumCandidates {
		name := renderTemplate(tpl, ctx)
		if name == "" {
			continue
		}
		for i := range assets {
			if assets[i].Name == name {
				return &assets[i]
			}
		}
	}
	return nil
}

// SelfUpdateDryRunInfo holds version comparison info for dry-run output.
type SelfUpdateDryRunInfo struct {
	CurrentVersion string
	TargetVersion  string
	Decision       update.Decision
}

// formatDryRunOutput generates human-readable dry-run output.
func formatDryRunOutput(repo string, rel *Release, assessment *VerificationAssessment, selfUpdateInfo *SelfUpdateDryRunInfo) string {
	var sb strings.Builder

	sb.WriteString("\nsfetch dry-run assessment\n")
	sb.WriteString("─────────────────────────\n")
	sb.WriteString(fmt.Sprintf("Repository:  %s\n", repo))
	sb.WriteString(fmt.Sprintf("Release:     %s\n", rel.TagName))

	// Self-update version comparison section
	if selfUpdateInfo != nil {
		sb.WriteString("\nVersion check:\n")
		sb.WriteString(fmt.Sprintf("  Current:    %s\n", update.FormatVersionDisplay(selfUpdateInfo.CurrentVersion)))
		sb.WriteString(fmt.Sprintf("  Target:     %s\n", update.FormatVersionDisplay(selfUpdateInfo.TargetVersion)))
		sb.WriteString(fmt.Sprintf("  Status:     %s\n", update.DescribeDecision(selfUpdateInfo.Decision)))
	}

	if assessment.SelectedAsset != nil {
		size := formatSize(assessment.SelectedAsset.Size)
		sb.WriteString(fmt.Sprintf("Asset:       %s (%s)\n", assessment.SelectedAsset.Name, size))
	}

	sb.WriteString("\nVerification available:\n")

	// Signature info
	if assessment.SignatureAvailable {
		sigType := assessment.SignatureFormat
		if assessment.SignatureIsChecksum {
			sb.WriteString(fmt.Sprintf("  Signature:  %s (%s, checksum-level)\n", assessment.SignatureFile, sigType))
		} else {
			sb.WriteString(fmt.Sprintf("  Signature:  %s (%s, per-asset)\n", assessment.SignatureFile, sigType))
		}
	} else {
		sb.WriteString("  Signature:  none\n")
	}

	// Checksum info
	if assessment.ChecksumAvailable {
		sb.WriteString(fmt.Sprintf("  Checksum:   %s (%s, %s)\n",
			assessment.ChecksumFile, assessment.ChecksumAlgorithm, assessment.ChecksumType))
	} else {
		sb.WriteString("  Checksum:   none\n")
	}

	sb.WriteString("\nVerification plan:\n")
	sb.WriteString(fmt.Sprintf("  Workflow:   %s\n", describeWorkflow(assessment.Workflow)))
	sb.WriteString(fmt.Sprintf("  Trust:      %s\n", assessment.TrustLevel))

	if len(assessment.Warnings) > 0 {
		sb.WriteString("\nWarnings:\n")
		for _, w := range assessment.Warnings {
			sb.WriteString(fmt.Sprintf("  - %s\n", w))
		}
	}

	return sb.String()
}

// describeWorkflow returns a human-readable description of a workflow.
func describeWorkflow(workflow string) string {
	switch workflow {
	case workflowA:
		return "A (checksum-level signature)"
	case workflowB:
		return "B (per-asset signature)"
	case workflowC:
		return "C (checksum-only)"
	case workflowInsecure:
		return "insecure (no verification)"
	default:
		return "none (no verification available)"
	}
}

// buildProvenanceRecord creates a provenance record from assessment and results.
func buildProvenanceRecord(repo string, rel *Release, assessment *VerificationAssessment, flags assessmentFlags, computedHash string) *ProvenanceRecord {
	now := time.Now().UTC().Format(time.RFC3339)

	record := &ProvenanceRecord{
		Schema:        "https://github.com/3leaps/sfetch/schemas/provenance.schema.json",
		Version:       "1.0.0",
		Timestamp:     now,
		SfetchVersion: version,
		Source: ProvenanceSource{
			Type:       "github",
			Repository: repo,
			Release: &ProvenanceRelease{
				Tag: rel.TagName,
				URL: fmt.Sprintf("https://github.com/%s/releases/tag/%s", repo, rel.TagName),
			},
		},
		TrustLevel: assessment.TrustLevel,
		Warnings:   assessment.Warnings,
		Flags: ProvenanceFlags{
			SkipSig:         flags.skipSig,
			SkipChecksum:    flags.skipChecksum,
			Insecure:        flags.insecure,
			RequireMinisign: flags.requireMinisign,
			PreferPerAsset:  flags.preferPerAsset,
			DryRun:          flags.dryRun,
		},
	}

	if assessment.SelectedAsset != nil {
		record.Asset = ProvenanceAsset{
			Name: assessment.SelectedAsset.Name,
			Size: assessment.SelectedAsset.Size,
			URL:  assessment.SelectedAsset.BrowserDownloadUrl,
		}
		if computedHash != "" {
			record.Asset.ComputedChecksum = &ProvenanceHash{
				Algorithm: "sha256",
				Value:     computedHash,
			}
		}
	}

	// Signature status
	sigStatus := ProvenanceSigStatus{
		Available: assessment.SignatureAvailable,
		Verified:  false,
		Skipped:   flags.skipSig || flags.insecure,
	}
	if assessment.SignatureAvailable {
		sigStatus.Format = assessment.SignatureFormat
		sigStatus.File = assessment.SignatureFile
		if !flags.skipSig && !flags.insecure && assessment.Workflow != workflowC {
			sigStatus.Verified = true
		}
	} else {
		sigStatus.Reason = "no signature file found in release"
	}
	if flags.skipSig {
		sigStatus.Reason = "--skip-sig flag"
	}
	if flags.insecure {
		sigStatus.Reason = "--insecure flag"
	}

	// Checksum status
	csStatus := ProvenanceCSStatus{
		Available: assessment.ChecksumAvailable,
		Verified:  false,
		Skipped:   flags.skipChecksum || flags.insecure,
	}
	if assessment.ChecksumAvailable {
		csStatus.Algorithm = assessment.ChecksumAlgorithm
		csStatus.File = assessment.ChecksumFile
		csStatus.Type = assessment.ChecksumType
		if !flags.skipChecksum && !flags.insecure {
			csStatus.Verified = true
		}
	} else {
		csStatus.Reason = "no checksum file found in release"
	}
	if flags.skipChecksum {
		csStatus.Reason = "--skip-checksum flag"
	}
	if flags.insecure {
		csStatus.Reason = "--insecure flag"
	}

	record.Verification = ProvenanceVerify{
		Workflow:  assessment.Workflow,
		Signature: sigStatus,
		Checksum:  csStatus,
	}

	return record
}

// outputProvenance writes the provenance record to the specified destination.
func outputProvenance(record *ProvenanceRecord, toFile string) error {
	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal provenance: %w", err)
	}

	if toFile != "" {
		// #nosec G306 -- provenance file is user-specified output
		if err := os.WriteFile(toFile, data, 0o644); err != nil {
			return fmt.Errorf("write provenance file: %w", err)
		}
		fmt.Fprintf(os.Stderr, "Provenance record written to %s\n", toFile)
	} else {
		fmt.Fprintln(os.Stderr, string(data))
	}
	return nil
}

// ValidateMinisignPubkey checks if a file contains a valid minisign public key.
// Returns nil if valid, error describing the problem otherwise.
// Detects: wrong format, secret key, signature file, or other content.
func ValidateMinisignPubkey(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("read file: %w", err)
	}

	content := strings.TrimSpace(string(data))
	lines := strings.Split(content, "\n")

	if len(lines) == 0 {
		return fmt.Errorf("file is empty")
	}

	// Find the key line (skip optional comment)
	var keyLine string

	if len(lines) == 1 {
		// Single line: must be the key itself
		keyLine = strings.TrimSpace(lines[0])
	} else if len(lines) == 2 {
		// Two lines: first should be comment, second is key
		keyLine = strings.TrimSpace(lines[1])
	} else if len(lines) >= 4 {
		// 4+ lines suggests a signature file, not a key
		return fmt.Errorf("file has %d lines (signature files have 4 lines; public keys have 1-2)", len(lines))
	} else {
		// 3 lines is unusual
		return fmt.Errorf("unexpected format: %d lines (public keys have 1-2 lines)", len(lines))
	}

	// Check if it starts with RW (minisign prefix)
	if !strings.HasPrefix(keyLine, "RW") {
		return fmt.Errorf("not a minisign key: line does not start with 'RW' prefix")
	}

	// Check for known secret key prefixes FIRST (before length check)
	for _, prefix := range minisignSecretkeyPrefixes {
		if strings.HasPrefix(keyLine, prefix) {
			return fmt.Errorf("DANGER: this is a SECRET KEY (prefix %s), not a public key", prefix)
		}
	}

	// Check length to distinguish public vs secret key
	keyLen := len(keyLine)
	switch {
	case keyLen == minisignPubkeyLen:
		// Correct length for public key - validate base64 charset
		if !minisignPubkeyRegex.MatchString(keyLine) {
			return fmt.Errorf("invalid characters in key (expected base64)")
		}
		// Valid public key
		return nil

	case keyLen == minisignSecretkeyLen:
		return fmt.Errorf("DANGER: this appears to be a SECRET KEY (%d chars), not a public key (56 chars)", keyLen)

	case keyLen > minisignPubkeyLen && keyLen < minisignSecretkeyLen:
		return fmt.Errorf("invalid key length %d (public=56, secret=212): possibly corrupted or signature", keyLen)

	case keyLen < minisignPubkeyLen:
		return fmt.Errorf("key too short: %d chars (expected 56 for public key)", keyLen)

	default:
		return fmt.Errorf("key too long: %d chars (expected 56 for public key, 212 for secret)", keyLen)
	}
}

//go:embed docs/quickstart.txt
var quickstartDoc string

const (
	sigFormatBinary   = "binary"
	sigFormatPGP      = "pgp"
	sigFormatMinisign = "minisign"
)

type signatureData struct {
	format string
	bytes  []byte // raw ed25519 signature bytes (only for sigFormatBinary)
}

func apiBaseURL() string {
	return apiBaseURLWithDefault(defaultAPIBase)
}

func apiBaseURLWithDefault(defaultBase string) string {
	base := strings.TrimSpace(os.Getenv("SFETCH_API_BASE"))
	if base == "" {
		base = defaultBase
	}
	return strings.TrimRight(base, "/")
}

func main() {
	repo := flag.String("repo", "", "GitHub repo owner/repo")
	tag := flag.String("tag", "", "release tag (mutually exclusive with --latest)")
	latest := flag.Bool("latest", false, "fetch latest release (mutually exclusive with --tag)")
	assetMatch := flag.String("asset-match", "", "asset name glob/substring (simpler than regex)")
	assetRegex := flag.String("asset-regex", "", "asset name regex (advanced override)")
	assetTypeFlag := flag.String("asset-type", "", "force asset handling type (archive, raw, package)")
	binaryNameFlag := flag.String("binary-name", "", "binary name to extract (default: inferred from repo name)")
	destDir := flag.String("dest-dir", "", "destination directory")
	output := flag.String("output", "", "output path")
	cacheDir := flag.String("cache-dir", "", "cache directory")
	preferPerAsset := flag.Bool("prefer-per-asset", false, "prefer per-asset signatures over checksum-level signatures (Workflow B over A)")
	requireMinisign := flag.Bool("require-minisign", false, "require minisign signature verification (fail if unavailable)")
	skipSig := flag.Bool("skip-sig", false, "skip signature verification (testing only)")
	skipChecksum := flag.Bool("skip-checksum", false, "skip checksum verification even if available")
	insecure := flag.Bool("insecure", false, "skip all verification (dangerous - use only for testing)")
	selfUpdate := flag.Bool("self-update", false, "update sfetch to the latest release for this platform")
	selfUpdateYes := flag.Bool("yes", false, "confirm self-update without prompting")
	selfUpdateForce := flag.Bool("self-update-force", false, "allow major-version jumps and proceed even if target is locked")
	selfUpdateDir := flag.String("self-update-dir", "", "install path for self-update (default: current binary directory)")
	minisignPubKey := flag.String("minisign-key", "", "path to minisign public key file (.pub)")
	minisignKeyURL := flag.String("minisign-key-url", "", "URL to download minisign public key")
	minisignKeyAsset := flag.String("minisign-key-asset", "", "release asset name for minisign public key")
	pgpKeyFile := flag.String("pgp-key-file", "", "path to ASCII-armored PGP public key")
	pgpKeyURL := flag.String("pgp-key-url", "", "URL to download ASCII-armored PGP public key")
	pgpKeyAsset := flag.String("pgp-key-asset", "", "release asset name for ASCII-armored PGP public key")
	gpgBin := flag.String("gpg-bin", "gpg", "path to gpg executable")
	key := flag.String("key", "", "ed25519 pubkey hex (32 bytes)")
	selfVerify := flag.Bool("self-verify", false, "print instructions to verify this binary externally")
	showTrustAnchors := flag.Bool("show-trust-anchors", false, "print embedded public keys (use --json for JSON output)")
	showUpdateConfig := flag.Bool("show-update-config", false, "print embedded self-update configuration and exit")
	validateUpdateConfig := flag.Bool("validate-update-config", false, "validate embedded self-update configuration and exit")
	dryRun := flag.Bool("dry-run", false, "assess release verification without downloading")
	provenance := flag.Bool("provenance", false, "output provenance record JSON to stderr")
	provenanceFile := flag.String("provenance-file", "", "write provenance record to file (implies --provenance)")
	skipToolsCheck := flag.Bool("skip-tools-check", false, "skip preflight tool checks")
	verifyMinisignPubkey := flag.String("verify-minisign-pubkey", "", "verify file is a valid minisign PUBLIC key (not secret)")
	jsonOut := flag.Bool("json", false, "JSON output for CI")
	extendedHelp := flag.Bool("helpextended", false, "print quickstart & examples")
	versionFlag := flag.Bool("version", false, "print version")
	versionExtended := flag.Bool("version-extended", false, "print extended version/build info")

	out := flag.CommandLine.Output()
	printFlag := func(name string) {
		if f := flag.Lookup(name); f != nil {
			def := f.DefValue
			if def != "" && def != "false" {
				fmt.Fprintf(out, "  -%s\t%s (default %q)\n", f.Name, f.Usage, def)
			} else {
				fmt.Fprintf(out, "  -%s\t%s\n", f.Name, f.Usage)
			}
		}
	}

	flag.Usage = func() {
		fmt.Fprintf(out, "Usage: sfetch [flags]\n\n")

		fmt.Fprintln(out, "Selection:")
		for _, name := range []string{"repo", "tag", "latest", "asset-match", "asset-regex", "asset-type", "binary-name", "output", "dest-dir", "cache-dir"} {
			printFlag(name)
		}

		fmt.Fprintln(out, "\nVerification:")
		for _, name := range []string{"minisign-key", "minisign-key-url", "minisign-key-asset", "pgp-key-file", "pgp-key-url", "pgp-key-asset", "gpg-bin", "key", "prefer-per-asset", "require-minisign", "skip-sig", "skip-checksum", "insecure"} {
			printFlag(name)
		}

		fmt.Fprintln(out, "\nProvenance & assessment:")
		for _, name := range []string{"dry-run", "provenance", "provenance-file"} {
			printFlag(name)
		}

		fmt.Fprintln(out, "\nTools & validation:")
		for _, name := range []string{"skip-tools-check", "verify-minisign-pubkey", "self-verify", "show-trust-anchors", "json"} {
			printFlag(name)
		}

		fmt.Fprintln(out, "\nMeta:")
		for _, name := range []string{"helpextended", "version", "version-extended"} {
			printFlag(name)
		}
	}

	flag.Parse()

	// Handle --self-verify: print verification instructions and exit
	if *selfVerify {
		printSelfVerify(*jsonOut)
		return
	}

	// Validate flag combinations
	if *insecure && *requireMinisign {
		fmt.Fprintln(os.Stderr, "error: --insecure and --require-minisign are mutually exclusive")
		os.Exit(1)
	}

	if *versionFlag {
		fmt.Println("sfetch", version)
		return
	}

	if *versionExtended {
		fmt.Printf("sfetch %s\n", version)
		fmt.Printf("  build time: %s\n", buildTime)
		fmt.Printf("  git commit: %s\n", gitCommit)
		fmt.Printf("  go version: %s\n", runtime.Version())
		fmt.Printf("  platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return
	}

	if *extendedHelp {
		fmt.Println(strings.TrimSpace(quickstartDoc))
		return
	}

	// Handle --verify-minisign-pubkey: validate and exit
	if *verifyMinisignPubkey != "" {
		if err := ValidateMinisignPubkey(*verifyMinisignPubkey); err != nil {
			fmt.Fprintf(os.Stderr, "INVALID: %s: %v\n", *verifyMinisignPubkey, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "OK: %s is a valid minisign public key\n", *verifyMinisignPubkey)
		return
	}

	// Handle --show-trust-anchors: output embedded keys and exit
	if *showTrustAnchors {
		if *jsonOut {
			trustJSON := map[string]interface{}{
				"minisign": map[string]string{
					"pubkey": EmbeddedMinisignPubkey,
					"keyId":  EmbeddedMinisignKeyID,
				},
			}
			data, _ := json.MarshalIndent(trustJSON, "", "  ")
			fmt.Println(string(data))
		} else {
			fmt.Printf("minisign:%s\n", EmbeddedMinisignPubkey)
		}
		return
	}

	if *showUpdateConfig || *validateUpdateConfig {
		cfg, err := loadEmbeddedUpdateTarget()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if *validateUpdateConfig {
			fmt.Fprintln(os.Stderr, "OK: embedded update configuration is valid")
			return
		}

		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: marshal update config: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
		return
	}

	if *selfUpdate {
		ucfg, err := loadEmbeddedUpdateTarget()
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		if *repo != "" && *repo != ucfg.Repo.ID {
			fmt.Fprintf(os.Stderr, "warning: ignoring --repo (%s); self-update targets %s\n", *repo, ucfg.Repo.ID)
		}
		*repo = ucfg.Repo.ID

		targetPath, err := computeSelfUpdatePath(*selfUpdateDir)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if *destDir != "" || *output != "" {
			fmt.Fprintln(os.Stderr, "warning: ignoring --dest-dir/--output when --self-update is set")
		}
		*output = targetPath
		if !*dryRun && !*selfUpdateYes {
			fmt.Fprintln(os.Stderr, "--self-update requires --yes to proceed (rerun with --self-update --yes)")
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Self-update target: %s\n", targetPath)
	}

	if !*skipToolsCheck {
		goos := runtime.GOOS
		goarch := runtime.GOARCH
		goosAliases := aliasList(goos, goosAliasTable)
		archAliases := aliasList(goarch, archAliasTable)
		fmt.Fprintf(os.Stderr, "Preflight: GOOS=%s GOARCH=%s goosAliases=%v archAliases=%v\n", goos, goarch, goosAliases, archAliases)

		tools := []string{"tar", "unzip"}
		for _, tool := range tools {
			if _, err := exec.LookPath(tool); err != nil {
				fmt.Fprintf(os.Stderr, "missing required tool: %s\n", tool)
				os.Exit(1)
			}
		}
	}

	if *repo == "" {
		fmt.Fprintln(os.Stderr, "error: --repo is required")
		flag.Usage()
		os.Exit(1)
	}

	if *tag != "" && *latest {
		fmt.Fprintln(os.Stderr, "error: --tag and --latest are mutually exclusive")
		os.Exit(1)
	}

	releaseID := "latest"
	if *tag != "" {
		releaseID = "tags/" + *tag
	}

	baseURL := apiBaseURL()
	if *selfUpdate {
		if ucfg, err := loadEmbeddedUpdateTarget(); err == nil && strings.TrimSpace(ucfg.Source.APIBase) != "" {
			baseURL = apiBaseURLWithDefault(ucfg.Source.APIBase)
		}
	}
	url := fmt.Sprintf("%s/repos/%s/releases/%s", baseURL, *repo, releaseID)

	resp, err := httpGetWithAuth(url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: fetching release: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(os.Stderr, "error: API request failed %d: %s\n", resp.StatusCode, string(body))
		os.Exit(1)
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading response: %v\n", err)
		os.Exit(1)
	}

	var rel Release
	if err := json.Unmarshal(respBody, &rel); err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing JSON: %v\n", err)
		os.Exit(1)
	}

	if *selfUpdate {
		// Determine whether to proceed with self-update
		explicitTag := *tag != ""
		decision, message, exitCode := update.DecideSelfUpdate(version, rel.TagName, explicitTag, *selfUpdateForce)

		switch decision {
		case update.DecisionSkip:
			fmt.Fprintln(os.Stderr, message)
			os.Exit(exitCode)
		case update.DecisionRefuse:
			fmt.Fprintln(os.Stderr, message)
			os.Exit(exitCode)
		case update.DecisionProceed, update.DecisionReinstall, update.DecisionDowngrade, update.DecisionDevInstall:
			fmt.Fprintln(os.Stderr, message)
			// Continue with update
		}
	}

	cfg := getConfig(*repo)
	if *selfUpdate {
		if ucfg, err := loadEmbeddedUpdateTarget(); err == nil {
			cfg = &ucfg.RepoConfig
		}
	}

	// Apply CLI override for binary name
	if *binaryNameFlag != "" {
		cfg.BinaryName = *binaryNameFlag
	}

	goos := runtime.GOOS
	goarch := runtime.GOARCH

	selected, err := selectAsset(&rel, cfg, goos, goarch, *assetMatch, *assetRegex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	classification, classifyWarnings, err := classifyAsset(selected.Name, cfg, *assetTypeFlag)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Build assessment flags from CLI
	aflags := assessmentFlags{
		skipSig:         *skipSig,
		skipChecksum:    *skipChecksum,
		insecure:        *insecure,
		preferPerAsset:  *preferPerAsset,
		requireMinisign: *requireMinisign,
	}

	// Assess what verification is available
	assessment := assessRelease(&rel, cfg, selected, aflags)
	assessment.Warnings = append(classifyWarnings, assessment.Warnings...)

	// Handle --dry-run: print assessment and exit
	if *dryRun {
		// Build self-update info for dry-run if in self-update mode
		var selfUpdateInfo *SelfUpdateDryRunInfo
		if *selfUpdate {
			explicitTag := *tag != ""
			decision, _, _ := update.DecideSelfUpdate(version, rel.TagName, explicitTag, *selfUpdateForce)
			selfUpdateInfo = &SelfUpdateDryRunInfo{
				CurrentVersion: version,
				TargetVersion:  rel.TagName,
				Decision:       decision,
			}
		}

		if *provenance || *provenanceFile != "" {
			// --dry-run + --provenance: JSON output only (no computed checksum since no download)
			aflags.dryRun = true // Mark as dry-run in flags
			record := buildProvenanceRecord(*repo, &rel, assessment, aflags, "")
			if err := outputProvenance(record, *provenanceFile); err != nil {
				fmt.Fprintf(os.Stderr, "error: %v\n", err)
				os.Exit(1)
			}
		} else {
			// --dry-run only: human-readable output
			fmt.Print(formatDryRunOutput(*repo, &rel, assessment, selfUpdateInfo))
		}
		os.Exit(0)
	}

	// Handle cases where no verification is available
	if assessment.Workflow == "" {
		fmt.Fprintln(os.Stderr, "error: no verification available (no signature or checksum found)")
		fmt.Fprintln(os.Stderr, "hint: use --insecure to proceed without verification (not recommended)")
		os.Exit(1)
	}

	// Print warnings
	for _, w := range assessment.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", w)
	}

	tmpDir, err := os.MkdirTemp("", "sfetch-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: mkdir temp: %v\n", err)
		os.Exit(1)
	}
	defer os.RemoveAll(tmpDir)

	assetPath := filepath.Join(tmpDir, selected.Name)
	if err := download(selected.BrowserDownloadUrl, assetPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Handle --require-minisign validation
	if *requireMinisign && !assessment.SignatureAvailable {
		fmt.Fprintln(os.Stderr, "error: --require-minisign specified but no .minisig signature found in release")
		os.Exit(1)
	}
	if *requireMinisign && assessment.SignatureFormat != sigFormatMinisign {
		fmt.Fprintf(os.Stderr, "error: --require-minisign specified but signature %s is %s format, not minisign\n",
			assessment.SignatureFile, assessment.SignatureFormat)
		os.Exit(1)
	}

	var sigAsset *Asset
	var sigPath string
	var checksumPath string
	var checksumBytes []byte

	// Execute verification based on assessed workflow
	switch assessment.Workflow {
	case workflowInsecure:
		// No verification - just download and proceed
		fmt.Fprintln(os.Stderr, "WARNING: --insecure mode - NO VERIFICATION PERFORMED")

	case workflowA:
		// Workflow A: Verify signature over checksum file, then verify hash
		fmt.Fprintf(os.Stderr, "Detected checksum-level signature: %s\n", assessment.SignatureFile)

		// Find and download the checksum file
		checksumAsset := findAssetByName(rel.Assets, assessment.ChecksumFileForSig)
		if checksumAsset == nil {
			fmt.Fprintf(os.Stderr, "error: checksum file %s not found\n", assessment.ChecksumFileForSig)
			os.Exit(1)
		}

		checksumPath = filepath.Join(tmpDir, checksumAsset.Name)
		if err := download(checksumAsset.BrowserDownloadUrl, checksumPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Download checksum signature
		sigAsset = findAssetByName(rel.Assets, assessment.SignatureFile)
		sigPath = filepath.Join(tmpDir, sigAsset.Name)
		if err := download(sigAsset.BrowserDownloadUrl, sigPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Read checksum file for verification
		// #nosec G304 -- checksumPath tmp controlled
		checksumBytes, err = os.ReadFile(checksumPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read checksum: %v\n", err)
			os.Exit(1)
		}

		// Verify checksum file signature (not asset signature)
		if !*skipSig {
			switch assessment.SignatureFormat {
			case sigFormatMinisign:
				minisignKeyPath, err := resolveMinisignKey(*minisignPubKey, *minisignKeyURL, *minisignKeyAsset, rel.Assets, tmpDir)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				if err := verifyMinisignSignature(checksumBytes, sigPath, minisignKeyPath); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				fmt.Println("Minisign checksum signature verified OK")

			case sigFormatPGP:
				pgpKeyPath, err := resolvePGPKey(*pgpKeyFile, *pgpKeyURL, *pgpKeyAsset, rel.Assets, tmpDir)
				if err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				if err := verifyPGPSignature(checksumPath, sigPath, pgpKeyPath, *gpgBin); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				fmt.Println("PGP checksum signature verified OK")

			default:
				fmt.Fprintf(os.Stderr, "error: unknown signature format for %s\n", assessment.SignatureFile)
				os.Exit(1)
			}
		}

	case workflowB:
		// Workflow B: Per-asset signature
		sigAsset = findAssetByName(rel.Assets, assessment.SignatureFile)
		if sigAsset == nil {
			fmt.Fprintf(os.Stderr, "error: signature file %s not found\n", assessment.SignatureFile)
			os.Exit(1)
		}

		sigPath = filepath.Join(tmpDir, sigAsset.Name)
		if err := download(sigAsset.BrowserDownloadUrl, sigPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Load checksum file if available
		if assessment.ChecksumAvailable && !*skipChecksum {
			checksumAsset := findAssetByName(rel.Assets, assessment.ChecksumFile)
			if checksumAsset != nil {
				checksumPath = filepath.Join(tmpDir, checksumAsset.Name)
				if err := download(checksumAsset.BrowserDownloadUrl, checksumPath); err != nil {
					fmt.Fprintln(os.Stderr, err)
					os.Exit(1)
				}
				// #nosec G304 -- checksumPath tmp controlled
				checksumBytes, err = os.ReadFile(checksumPath)
				if err != nil {
					fmt.Fprintf(os.Stderr, "read checksum: %v\n", err)
					os.Exit(1)
				}
			}
		}

	case workflowC:
		// Workflow C: Checksum-only (no signature)
		fmt.Fprintf(os.Stderr, "Using checksum-only verification (no signature available)\n")

		checksumAsset := findAssetByName(rel.Assets, assessment.ChecksumFile)
		if checksumAsset == nil {
			fmt.Fprintf(os.Stderr, "error: checksum file %s not found\n", assessment.ChecksumFile)
			os.Exit(1)
		}

		checksumPath = filepath.Join(tmpDir, checksumAsset.Name)
		if err := download(checksumAsset.BrowserDownloadUrl, checksumPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// #nosec G304 -- checksumPath tmp controlled
		checksumBytes, err = os.ReadFile(checksumPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "read checksum: %v\n", err)
			os.Exit(1)
		}
	}

	// #nosec G304 -- assetPath tmp controlled
	assetBytes, err := os.ReadFile(assetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read asset: %v\n", err)
		os.Exit(1)
	}

	// Compute hash for caching (and verification if checksum file exists)
	hashAlgo := cfg.HashAlgo
	if checksumBytes != nil && assessment.ChecksumAlgorithm != "" {
		hashAlgo = assessment.ChecksumAlgorithm
	}
	var h hash.Hash
	switch hashAlgo {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		fmt.Fprintf(os.Stderr, "unknown hash algo %q\n", hashAlgo)
		os.Exit(1)
	}
	h.Write(assetBytes)
	actualHash := hex.EncodeToString(h.Sum(nil))

	// Verify checksum if checksum file was found
	if checksumBytes != nil {
		expectedHash, err := extractChecksum(checksumBytes, hashAlgo, selected.Name)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		if actualHash != strings.ToLower(expectedHash) {
			fmt.Fprintf(os.Stderr, "checksum mismatch: expected %s, got %s\n", expectedHash, actualHash)
			os.Exit(1)
		}
		fmt.Println("Checksum verified OK")
	}

	cd := *cacheDir
	if cd == "" {
		cd = filepath.Join(os.Getenv("XDG_CACHE_HOME"), "sfetch")
		if cd == "sfetch" {
			home, _ := os.UserHomeDir()
			cd = filepath.Join(home, ".cache", "sfetch")
		}
	}
	cacheAssetDir := filepath.Join(cd, actualHash)
	if err := // #nosec G301 -- cacheAssetDir XDG_CACHE_HOME/hash controlled
		os.MkdirAll(cacheAssetDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir cache %s: %v\n", cacheAssetDir, err)
		os.Exit(1)
	}
	cacheAssetPath := filepath.Join(cacheAssetDir, selected.Name)
	if err := os.Rename(assetPath, cacheAssetPath); err != nil {
		fmt.Fprintf(os.Stderr, "cache asset: %v\n", err)
		os.Exit(1)
	}
	assetPath = cacheAssetPath
	fmt.Printf("Cached to %s\n", cacheAssetPath)

	// Workflow B: Verify per-asset signature
	if assessment.Workflow == workflowB && !*skipSig {
		sigData, err := loadSignature(sigPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		switch sigData.format {
		case sigFormatPGP:
			pgpKeyPath, err := resolvePGPKey(*pgpKeyFile, *pgpKeyURL, *pgpKeyAsset, rel.Assets, tmpDir)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := verifyPGPSignature(assetPath, sigPath, pgpKeyPath, *gpgBin); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("PGP signature verified OK")

		case sigFormatMinisign:
			minisignKeyPath, err := resolveMinisignKey(*minisignPubKey, *minisignKeyURL, *minisignKeyAsset, rel.Assets, tmpDir)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := verifyMinisignSignature(assetBytes, sigPath, minisignKeyPath); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			fmt.Println("Minisign signature verified OK")

		case sigFormatBinary:
			normalizedKey, err := normalizeHexKey(*key)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			pubKeyBytes, err := hex.DecodeString(normalizedKey)
			if err != nil {
				fmt.Fprintln(os.Stderr, "invalid ed25519 key provided")
				os.Exit(1)
			}
			if len(pubKeyBytes) != ed25519.PublicKeySize {
				fmt.Fprintf(os.Stderr, "invalid pubkey size: %d\n", len(pubKeyBytes))
				os.Exit(1)
			}
			pub := ed25519.PublicKey(pubKeyBytes)
			if !ed25519.Verify(pub, assetBytes, sigData.bytes) {
				fmt.Fprintln(os.Stderr, "signature verification failed")
				os.Exit(1)
			}
			fmt.Println("Signature verified OK")

		default:
			fmt.Fprintln(os.Stderr, "error: unsupported signature format")
			os.Exit(1)
		}
	}

	binaryName := cfg.BinaryName
	installName := binaryName
	var binaryPath string

	switch classification.Type {
	case AssetTypeArchive:
		extractDir := filepath.Join(tmpDir, "extract")
		if err := // #nosec G301 -- extractDir tmpdir controlled
			os.Mkdir(extractDir, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "mkdir extract: %v\n", err)
			os.Exit(1)
		}

		var cmd *exec.Cmd
		switch classification.ArchiveFormat {
		case ArchiveFormatZip:
			// #nosec G204 -- assetPath tmp controlled
			cmd = exec.Command("unzip", "-q", assetPath, "-d", extractDir)
		case ArchiveFormatTarXz:
			// #nosec G204 -- assetPath tmp controlled
			cmd = exec.Command("tar", "xJf", assetPath, "-C", extractDir)
		case ArchiveFormatTarBz2:
			// #nosec G204 -- assetPath tmp controlled
			cmd = exec.Command("tar", "xjf", assetPath, "-C", extractDir)
		case ArchiveFormatTar:
			// #nosec G204 -- assetPath tmp controlled
			cmd = exec.Command("tar", "xf", assetPath, "-C", extractDir)
		case ArchiveFormatTarGz:
			fallthrough
		default:
			// #nosec G204 -- assetPath tmp controlled
			cmd = exec.Command("tar", "xzf", assetPath, "-C", extractDir)
		}

		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "extract archive: %v\n", err)
			os.Exit(1)
		}

		binaryPath = filepath.Join(extractDir, binaryName)
		if _, err := os.Stat(binaryPath); err != nil {
			fmt.Fprintf(os.Stderr, "binary %s not found in archive\n", binaryName)
			os.Exit(1)
		}

		if err := // #nosec G302 -- binaryPath extracted tmp chmod +x safe
			os.Chmod(binaryPath, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "chmod: %v\n", err)
			os.Exit(1)
		}

	case AssetTypePackage:
		installName = selected.Name
		binaryPath = assetPath
	case AssetTypeRaw:
		installName = selected.Name
		binaryPath = assetPath
	default:
		installName = selected.Name
		binaryPath = assetPath
	}

	if binaryPath == "" {
		fmt.Fprintln(os.Stderr, "error: could not resolve binary path")
		os.Exit(1)
	}

	var finalPath string
	if *output != "" {
		finalPath = *output
	} else if *destDir != "" {
		finalPath = filepath.Join(*destDir, installName)
	} else {
		finalPath = installName
	}

	if err := // #nosec G301 -- Dir(finalPath) user-controlled safe mkdir tmp
		os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", filepath.Dir(finalPath), err)
		os.Exit(1)
	}

	if err := os.Rename(binaryPath, finalPath); err != nil {
		if *selfUpdate && runtime.GOOS == "windows" {
			alt := finalPath + ".new"
			if errAlt := os.Rename(binaryPath, alt); errAlt == nil {
				fmt.Fprintf(os.Stderr, "target appears locked; new binary written to %s. Close running sfetch and replace manually.\n", alt)
				fmt.Printf("Release: %s\n", rel.TagName)
				fmt.Printf("Installed %s to %s\n", installName, alt)
				return
			}
		}
		if *selfUpdate {
			if errCopy := copyFile(binaryPath, finalPath); errCopy == nil {
				fmt.Printf("Release: %s\n", rel.TagName)
				fmt.Printf("Installed %s to %s\n", installName, finalPath)
				return
			}
		}
		fmt.Fprintf(os.Stderr, "install to %s: %v\n", finalPath, err)
		os.Exit(1)
	}

	if classification.Type == AssetTypeRaw && runtime.GOOS != "windows" && classification.NeedsChmod {
		if err := // #nosec G302 -- finalPath user-controlled chmod +x optional
			os.Chmod(finalPath, 0o755); err != nil {
			fmt.Fprintf(os.Stderr, "chmod %s: %v\n", finalPath, err)
			os.Exit(1)
		}
	}

	fmt.Printf("Release: %s\n", rel.TagName)
	fmt.Printf("Installed %s to %s\n", installName, finalPath)

	// Output provenance record if requested
	if *provenance || *provenanceFile != "" {
		record := buildProvenanceRecord(*repo, &rel, assessment, aflags, actualHash)
		if err := outputProvenance(record, *provenanceFile); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		}
	}
}

func getConfig(repo string) *RepoConfig {
	// Start with defaults, then infer BinaryName from repo
	cfg := defaults
	cfg.BinaryName = inferBinaryName(repo)

	// Apply repo-specific overrides if any
	if override, ok := repoConfigs[repo]; ok {
		cfg = mergeConfig(cfg, override)
	}
	return &cfg
}

// inferBinaryName extracts the binary name from "owner/repo" format.
// Examples: "jedisct1/minisign" → "minisign", "3leaps/sfetch" → "sfetch"
func inferBinaryName(repo string) string {
	parts := strings.Split(repo, "/")
	if len(parts) >= 2 {
		return parts[1]
	}
	return repo // fallback to full string if no slash
}

type AssetClassification struct {
	Type          AssetType
	ArchiveFormat ArchiveFormat
	IsScript      bool
	IsPackage     bool
	NeedsChmod    bool
}

func classifyAsset(assetName string, cfg *RepoConfig, override string) (AssetClassification, []string, error) {
	cls := inferAssetClassification(assetName)
	warnings := []string{}

	// Backward compatibility: legacy archiveType
	if cfg.ArchiveType != "" && cfg.AssetType == "" && cfg.ArchiveFormat == "" {
		if fmt := archiveFormatFromString(cfg.ArchiveType); fmt != "" {
			cls.Type = AssetTypeArchive
			cls.ArchiveFormat = fmt
		}
	}

	// Repo config overrides
	if cfg.AssetType != "" {
		cls.Type = cfg.AssetType
	}
	if cfg.ArchiveFormat != "" {
		cls.ArchiveFormat = cfg.ArchiveFormat
	}

	// CLI override
	if override != "" {
		switch strings.ToLower(override) {
		case string(AssetTypeArchive):
			cls.Type = AssetTypeArchive
		case string(AssetTypeRaw):
			cls.Type = AssetTypeRaw
		case string(AssetTypePackage):
			cls.Type = AssetTypePackage
		default:
			return cls, warnings, fmt.Errorf("invalid --asset-type %q (allowed: archive, raw, package)", override)
		}
	}

	// Fill archive format when needed
	if cls.Type == AssetTypeArchive && cls.ArchiveFormat == "" {
		cls.ArchiveFormat = inferArchiveFormat(assetName)
	}

	if cls.Type == AssetTypeArchive && cls.ArchiveFormat == "" {
		return cls, warnings, fmt.Errorf("could not determine archive format for %s", assetName)
	}

	if cls.Type == AssetTypeUnknown {
		warnings = append(warnings, fmt.Sprintf("asset %s has unknown type; treating as raw", assetName))
		cls.Type = AssetTypeRaw
	}

	if cls.Type == AssetTypePackage {
		warnings = append(warnings, fmt.Sprintf("asset %s looks like a package; sfetch does not install packages", assetName))
	}

	return cls, warnings, nil
}

func inferAssetClassification(assetName string) AssetClassification {
	lower := strings.ToLower(assetName)
	cls := AssetClassification{}

	// Archive detection first
	if fmt := inferArchiveFormat(lower); fmt != "" {
		cls.Type = AssetTypeArchive
		cls.ArchiveFormat = fmt
		return cls
	}

	// Packages
	if isPackageExtension(lower) {
		cls.Type = AssetTypePackage
		cls.IsPackage = true
		return cls
	}

	cls.Type = AssetTypeRaw
	cls.IsScript = isScriptExtension(lower)

	ext := filepath.Ext(lower)
	if cls.IsScript || ext == "" {
		cls.NeedsChmod = true
	}

	return cls
}

func inferArchiveFormat(assetName string) ArchiveFormat {
	switch {
	case strings.HasSuffix(assetName, ".tar.gz"), strings.HasSuffix(assetName, ".tgz"):
		return ArchiveFormatTarGz
	case strings.HasSuffix(assetName, ".tar.xz"), strings.HasSuffix(assetName, ".txz"):
		return ArchiveFormatTarXz
	case strings.HasSuffix(assetName, ".tar.bz2"), strings.HasSuffix(assetName, ".tbz2"):
		return ArchiveFormatTarBz2
	case strings.HasSuffix(assetName, ".tar"):
		return ArchiveFormatTar
	case strings.HasSuffix(assetName, ".zip"):
		return ArchiveFormatZip
	default:
		return ""
	}
}

func archiveFormatFromString(s string) ArchiveFormat {
	switch strings.ToLower(s) {
	case "tar.gz", "tgz":
		return ArchiveFormatTarGz
	case "tar.xz", "txz":
		return ArchiveFormatTarXz
	case "tar.bz2", "tbz2":
		return ArchiveFormatTarBz2
	case "tar":
		return ArchiveFormatTar
	case "zip":
		return ArchiveFormatZip
	default:
		return ""
	}
}

func isScriptExtension(name string) bool {
	scriptExts := []string{".sh", ".bash", ".zsh", ".py", ".rb", ".pl", ".ps1", ".bat", ".cmd"}
	for _, ext := range scriptExts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func isPackageExtension(name string) bool {
	pkgExts := []string{".deb", ".rpm", ".pkg", ".msi"}
	for _, ext := range pkgExts {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

func mergeConfig(base RepoConfig, override RepoConfig) RepoConfig {
	cfg := base
	if override.BinaryName != "" {
		cfg.BinaryName = override.BinaryName
	}
	if override.HashAlgo != "" {
		cfg.HashAlgo = override.HashAlgo
	}
	if override.ArchiveType != "" {
		cfg.ArchiveType = override.ArchiveType
	}
	if override.AssetType != "" {
		cfg.AssetType = override.AssetType
	}
	if override.ArchiveFormat != "" {
		cfg.ArchiveFormat = override.ArchiveFormat
	}
	if len(override.ArchiveExtensions) > 0 {
		cfg.ArchiveExtensions = append([]string(nil), override.ArchiveExtensions...)
	}
	if len(override.AssetPatterns) > 0 {
		cfg.AssetPatterns = append([]string(nil), override.AssetPatterns...)
	}
	if len(override.ChecksumCandidates) > 0 {
		cfg.ChecksumCandidates = append([]string(nil), override.ChecksumCandidates...)
	}
	if len(override.ChecksumSigCandidates) > 0 {
		cfg.ChecksumSigCandidates = append([]string(nil), override.ChecksumSigCandidates...)
	}
	if len(override.SignatureCandidates) > 0 {
		cfg.SignatureCandidates = append([]string(nil), override.SignatureCandidates...)
	}
	// Merge SignatureFormats if any overrides provided
	if len(override.SignatureFormats.Minisign) > 0 {
		cfg.SignatureFormats.Minisign = append([]string(nil), override.SignatureFormats.Minisign...)
	}
	if len(override.SignatureFormats.PGP) > 0 {
		cfg.SignatureFormats.PGP = append([]string(nil), override.SignatureFormats.PGP...)
	}
	if len(override.SignatureFormats.Ed25519) > 0 {
		cfg.SignatureFormats.Ed25519 = append([]string(nil), override.SignatureFormats.Ed25519...)
	}
	// PreferChecksumSig: only override if explicitly set (non-nil pointer)
	if override.PreferChecksumSig != nil {
		cfg.PreferChecksumSig = override.PreferChecksumSig
	}
	return cfg
}

func download(url, path string) error {
	resp, err := httpGetWithAuth(url)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d from %s: %s", resp.StatusCode, url, string(body))
	}

	// #nosec G304 -- path tmp controlled
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("create %s: %w", path, err)
	}
	defer f.Close()

	if _, err := io.Copy(f, resp.Body); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}

	return nil
}

type templateContext struct {
	AssetName       string
	BaseName        string
	BinaryName      string
	GOOS            string
	GOARCH          string
	Version         string
	VersionNoPrefix string
}

func selectAsset(rel *Release, cfg *RepoConfig, goos, goarch, assetMatch, assetRegex string) (*Asset, error) {
	if assetMatch != "" {
		return matchWithMatch(rel.Assets, assetMatch, cfg, goos, goarch)
	}

	if assetRegex != "" {
		re, err := regexp.Compile(assetRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid --asset-regex: %w", err)
		}
		return matchWithRegex(rel.Assets, re, cfg, goos, goarch)
	}

	if len(cfg.AssetPatterns) > 0 {
		if asset := matchWithPatterns(rel.Assets, cfg, goos, goarch); asset != nil {
			return asset, nil
		}
	}

	return pickByHeuristics(rel.Assets, cfg, goos, goarch)
}

func matchWithRegex(assets []Asset, re *regexp.Regexp, cfg *RepoConfig, goos, goarch string) (*Asset, error) {
	var matches []Asset
	for i := range assets {
		if re.MatchString(assets[i].Name) {
			matches = append(matches, assets[i])
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no asset matches provided regex")
	}
	if len(matches) == 1 {
		return &matches[0], nil
	}
	return pickWithInference(matches, cfg, goos, goarch, "regex")
}

func matchWithMatch(assets []Asset, pattern string, cfg *RepoConfig, goos, goarch string) (*Asset, error) {
	var matches []Asset
	p := strings.ToLower(pattern)
	isGlob := strings.ContainsAny(pattern, "*?[")
	for i := range assets {
		name := strings.ToLower(assets[i].Name)
		match := false
		if isGlob {
			if ok, err := filepath.Match(p, name); err == nil && ok {
				match = true
			}
		} else if strings.Contains(name, p) {
			match = true
		}
		if match {
			matches = append(matches, assets[i])
		}
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("no asset matches provided pattern")
	}
	if len(matches) == 1 {
		return &matches[0], nil
	}
	return pickWithInference(matches, cfg, goos, goarch, "pattern")
}

func matchWithPatterns(assets []Asset, cfg *RepoConfig, goos, goarch string) *Asset {
	for _, pattern := range cfg.AssetPatterns {
		regexStr := renderPattern(pattern, cfg, goos, goarch)
		re, err := regexp.Compile(regexStr)
		if err != nil {
			continue
		}
		match, err := matchWithRegex(assets, re, cfg, goos, goarch)
		if err == nil {
			return match
		}
	}
	return nil
}

func pickWithInference(candidates []Asset, cfg *RepoConfig, goos, goarch, source string) (*Asset, error) {
	rules, _ := loadInferenceRules()
	filtered := filterNonSupplemental(candidates)
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no asset matches provided %s", source)
	}
	if rules != nil {
		filtered = applyInferenceRules(filtered, rules, goos, goarch, cfg.ArchiveExtensions)
		if len(filtered) == 1 {
			return &filtered[0], nil
		}
	}
	if len(filtered) == 1 {
		return &filtered[0], nil
	}
	if len(filtered) == 0 {
		return nil, fmt.Errorf("no asset matches provided %s", source)
	}
	return nil, fmt.Errorf("multiple assets tie for selection: %s and %s", filtered[0].Name, filtered[1].Name)
}

func pickByHeuristics(assets []Asset, cfg *RepoConfig, goos, goarch string) (*Asset, error) {
	rules, _ := loadInferenceRules()
	candidates := filterNonSupplemental(assets)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no asset matches GOOS/GOARCH heuristics")
	}
	if rules != nil {
		candidates = applyInferenceRules(candidates, rules, goos, goarch, cfg.ArchiveExtensions)
		if len(candidates) == 1 {
			return &candidates[0], nil
		}
	}

	goosAliases := aliasList(goos, goosAliasTable)
	archAliases := aliasList(goarch, archAliasTable)
	binaryToken := strings.ToLower(cfg.BinaryName)

	// Prefer exact matches
	exactGoos := strings.ToLower(goos)
	exactArch := strings.ToLower(goarch)

	bestScore := 0
	var best *Asset

	for i := range assets {
		nameLower := strings.ToLower(assets[i].Name)
		if looksLikeSupplemental(nameLower) {
			continue
		}
		score := 0

		// GoOS score: exact > alias
		goosScore := 0
		if strings.Contains(nameLower, exactGoos) {
			goosScore = 5
		} else {
			extraGoos := make([]string, 0, len(goosAliases))
			for _, a := range goosAliases {
				if a != exactGoos {
					extraGoos = append(extraGoos, a)
				}
			}
			if len(extraGoos) > 0 && containsAny(nameLower, extraGoos) {
				goosScore = 3
			}
		}
		score += goosScore

		// GoARCH score: exact > alias
		archScore := 0
		if strings.Contains(nameLower, exactArch) {
			archScore = 5
		} else {
			extraArch := make([]string, 0, len(archAliases))
			for _, a := range archAliases {
				if a != exactArch {
					extraArch = append(extraArch, a)
				}
			}
			if len(extraArch) > 0 && containsAny(nameLower, extraArch) {
				archScore = 3
			}
		}
		score += archScore
		if binaryToken != "" && strings.Contains(nameLower, binaryToken) {
			score += 3
		}
		if hasAllowedExtension(nameLower, cfg.ArchiveExtensions) {
			score += 2
		}
		if score == 0 {
			continue
		}
		if best != nil {
			if score > bestScore {
				best = &assets[i]
				bestScore = score
			} else if score == bestScore {
				return nil, fmt.Errorf("multiple assets tie for selection: %s and %s", best.Name, assets[i].Name)
			}
		} else {
			best = &assets[i]
			bestScore = score
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no asset matches GOOS/GOARCH heuristics")
	}
	return best, nil
}

func looksLikeSupplemental(name string) bool {
	lower := strings.ToLower(name)
	if strings.HasSuffix(lower, ".asc") || strings.HasSuffix(lower, ".sig") || strings.HasSuffix(lower, ".sig.ed25519") {
		return true
	}
	return strings.Contains(lower, "sha256") || strings.Contains(lower, "checksum") || strings.Contains(lower, "sig") || strings.Contains(lower, "signature")
}

func filterNonSupplemental(assets []Asset) []Asset {
	var filtered []Asset
	for _, asset := range assets {
		if looksLikeSupplemental(asset.Name) {
			continue
		}
		filtered = append(filtered, asset)
	}
	return filtered
}

var (
	inferenceRulesOnce sync.Once
	inferenceRules     *InferenceRules
	inferenceRulesErr  error
)

func loadInferenceRules() (*InferenceRules, error) {
	inferenceRulesOnce.Do(func() {
		if len(defaultInferenceRulesJSON) == 0 {
			return
		}
		var rules InferenceRules
		if err := json.Unmarshal(defaultInferenceRulesJSON, &rules); err != nil {
			inferenceRulesErr = fmt.Errorf("parse inference rules: %w", err)
			return
		}
		inferenceRules = &rules
	})
	return inferenceRules, inferenceRulesErr
}

func applyInferenceRules(candidates []Asset, rules *InferenceRules, goos, goarch string, cfgArchiveExts []string) []Asset {
	goosLower := strings.ToLower(goos)
	goarchLower := strings.ToLower(goarch)
	archiveExts := mergeExtensions(rules.ArchiveExtensions, cfgArchiveExts)

	candidates = excludeByPlatform(candidates, rules.PlatformExclusions[goosLower])
	if len(candidates) == 0 {
		return candidates
	}

	if platformSpecific := filterByTokens(candidates, rules.PlatformTokens[goosLower]); len(platformSpecific) > 0 {
		candidates = platformSpecific
	}

	if len(candidates) > 1 {
		if archSpecific := filterByTokens(candidates, rules.ArchTokens[goarchLower]); len(archSpecific) > 0 {
			candidates = archSpecific
		}
	}

	if len(candidates) > 1 {
		candidates = preferRawOverArchive(candidates, archiveExts)
	}

	if len(candidates) > 1 {
		candidates = preferFormatPreference(candidates, rules.FormatPreference)
	}

	return candidates
}

func excludeByPlatform(assets []Asset, excludedExts []string) []Asset {
	if len(excludedExts) == 0 {
		return assets
	}
	var out []Asset
	for _, asset := range assets {
		lower := strings.ToLower(asset.Name)
		skip := false
		for _, ext := range excludedExts {
			if ext == "" {
				continue
			}
			if strings.HasSuffix(lower, strings.ToLower(ext)) {
				skip = true
				break
			}
		}
		if !skip {
			out = append(out, asset)
		}
	}
	return out
}

func filterByTokens(assets []Asset, tokens []string) []Asset {
	if len(tokens) == 0 {
		return nil
	}
	var out []Asset
	for _, asset := range assets {
		if containsTokenCI(asset.Name, tokens) {
			out = append(out, asset)
		}
	}
	return out
}

func preferRawOverArchive(assets []Asset, archiveExts []string) []Asset {
	baseToAssets := make(map[string][]Asset)
	for _, asset := range assets {
		base := trimExtensionCI(asset.Name, archiveExts)
		baseToAssets[base] = append(baseToAssets[base], asset)
	}

	var out []Asset
	for _, group := range baseToAssets {
		if len(group) == 1 {
			out = append(out, group[0])
			continue
		}
		var raw []Asset
		for _, asset := range group {
			nameLower := strings.ToLower(asset.Name)
			if !hasArchiveExtension(nameLower, archiveExts) {
				raw = append(raw, asset)
			}
		}
		if len(raw) > 0 {
			out = append(out, raw...)
		} else {
			out = append(out, group...)
		}
	}
	return out
}

func preferFormatPreference(assets []Asset, prefs []string) []Asset {
	if len(prefs) == 0 {
		return assets
	}
	classified := make(map[string][]Asset)
	for _, asset := range assets {
		cls := inferAssetClassification(asset.Name)
		classified[string(cls.Type)] = append(classified[string(cls.Type)], asset)
	}
	for _, pref := range prefs {
		if group := classified[pref]; len(group) > 0 {
			return group
		}
	}
	return assets
}

func containsTokenCI(name string, tokens []string) bool {
	lower := strings.ToLower(name)
	for _, tok := range tokens {
		if tok == "" {
			continue
		}
		if strings.Contains(lower, strings.ToLower(tok)) {
			return true
		}
	}
	return false
}

func trimExtensionCI(name string, exts []string) string {
	lower := strings.ToLower(name)
	for _, ext := range exts {
		extLower := strings.ToLower(ext)
		if extLower == "" {
			continue
		}
		if strings.HasSuffix(lower, extLower) {
			return name[:len(name)-len(extLower)]
		}
	}
	return name
}

func hasArchiveExtension(name string, exts []string) bool {
	for _, ext := range exts {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(name, strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

func mergeExtensions(ruleExts, cfgExts []string) []string {
	seen := make(map[string]struct{})
	var merged []string
	for _, arr := range [][]string{ruleExts, cfgExts} {
		for _, ext := range arr {
			extLower := strings.ToLower(ext)
			if extLower == "" {
				continue
			}
			if _, ok := seen[extLower]; ok {
				continue
			}
			seen[extLower] = struct{}{}
			merged = append(merged, extLower)
		}
	}
	return merged
}

func computeSelfUpdatePath(dir string) (string, error) {
	exePath, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("determine current executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exePath); err == nil {
		exePath = resolved
	}
	targetDir := filepath.Dir(exePath)
	if dir != "" {
		targetDir = dir
	}
	base := filepath.Base(exePath)
	return filepath.Join(targetDir, base), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", filepath.Dir(dst), err)
	}

	tmp := dst + ".tmp"
	out, err := os.Create(tmp)
	if err != nil {
		return fmt.Errorf("create %s: %w", tmp, err)
	}

	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("copy %s: %w", dst, err)
	}
	if err := out.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename %s: %w", dst, err)
	}
	return nil
}

func containsAny(haystack string, needles []string) bool {
	for _, needle := range needles {
		if needle != "" && strings.Contains(haystack, needle) {
			return true
		}
	}
	return false
}

func hasAllowedExtension(name string, exts []string) bool {
	for _, ext := range exts {
		if ext == "" {
			return true
		}
		if strings.HasSuffix(name, strings.ToLower(ext)) {
			return true
		}
	}
	return false
}

func trimKnownExtension(name string, exts []string) string {
	for _, ext := range exts {
		if ext == "" {
			continue
		}
		if strings.HasSuffix(strings.ToLower(name), strings.ToLower(ext)) {
			return name[:len(name)-len(ext)]
		}
	}
	return name
}

func renderPattern(pattern string, cfg *RepoConfig, goos, goarch string) string {
	replacements := []string{
		"{{binary}}", regexp.QuoteMeta(cfg.BinaryName),
		"{{osToken}}", aliasRegex(goos, goosAliasTable),
		"{{archToken}}", aliasRegex(goarch, archAliasTable),
		"{{goos}}", regexp.QuoteMeta(goos),
		"{{GOOS}}", regexp.QuoteMeta(strings.ToUpper(goos)),
		"{{Goos}}", regexp.QuoteMeta(titleCase(goos)),
		"{{goarch}}", regexp.QuoteMeta(goarch),
		"{{GOARCH}}", regexp.QuoteMeta(strings.ToUpper(goarch)),
		"{{Goarch}}", regexp.QuoteMeta(titleCase(goarch)),
	}
	return strings.NewReplacer(replacements...).Replace(pattern)
}

func aliasRegex(value string, table map[string][]string) string {
	aliases := aliasList(value, table)
	if len(aliases) == 0 {
		return regexp.QuoteMeta(strings.ToLower(value))
	}
	parts := make([]string, len(aliases))
	for i, alias := range aliases {
		parts[i] = regexp.QuoteMeta(alias)
	}
	return "(?:" + strings.Join(parts, "|") + ")"
}

var goosAliasTable = map[string][]string{
	"darwin":  {"macos", "macosx", "osx"},
	"windows": {"win", "win32", "win64", "mingw"},
	"linux":   {"linux"},
}

var archAliasTable = map[string][]string{
	"amd64": {"x86_64", "x64"},
	"arm64": {"aarch64"},
	"386":   {"x86", "i386", "i686"},
}

func aliasList(value string, table map[string][]string) []string {
	base := strings.ToLower(value)
	seen := map[string]struct{}{base: {}}
	if extras, ok := table[base]; ok {
		for _, alias := range extras {
			seen[strings.ToLower(alias)] = struct{}{}
		}
	}
	arr := make([]string, 0, len(seen))
	for k := range seen {
		arr = append(arr, k)
	}
	sort.Strings(arr)
	return arr
}

func titleCase(s string) string {
	if s == "" {
		return s
	}
	runes := []rune(strings.ToLower(s))
	runes[0] = []rune(strings.ToUpper(string(runes[0])))[0]
	return string(runes)
}

// findChecksumSignature looks for a signature over the checksum file (Workflow A).
// It searches for assets matching the ChecksumSigCandidates patterns.
// Returns the signature asset and the corresponding checksum asset name, or nil if not found.
func findChecksumSignature(assets []Asset, cfg *RepoConfig) (*Asset, string) {
	for _, candidate := range cfg.ChecksumSigCandidates {
		for i := range assets {
			if assets[i].Name == candidate {
				// Extract the checksum file name by removing the signature extension
				checksumName := strings.TrimSuffix(candidate, ".minisig")
				checksumName = strings.TrimSuffix(checksumName, ".asc")
				checksumName = strings.TrimSuffix(checksumName, ".sig")
				return &assets[i], checksumName
			}
		}
	}
	return nil, ""
}

// signatureFormatFromExtension determines the signature verification method from file extension.
// Returns sigFormatMinisign, sigFormatPGP, sigFormatBinary, or empty string if unknown.
func signatureFormatFromExtension(filename string, formats SignatureFormats) string {
	lower := strings.ToLower(filename)

	// Special-case .sig: checksum-level sigs use PGP, per-asset default to ed25519
	if strings.HasSuffix(lower, ".sig") {
		if looksLikeChecksumSig(lower) {
			return sigFormatPGP
		}
		return sigFormatBinary
	}

	for _, ext := range formats.Minisign {
		if strings.HasSuffix(lower, ext) {
			return sigFormatMinisign
		}
	}
	for _, ext := range formats.PGP {
		if strings.HasSuffix(lower, ext) {
			return sigFormatPGP
		}
	}
	for _, ext := range formats.Ed25519 {
		if strings.HasSuffix(lower, ext) {
			return sigFormatBinary
		}
	}
	return ""
}

func looksLikeChecksumSig(name string) bool {
	// Heuristic: checksum manifests typically end with "sums" or "checksums"
	return strings.Contains(name, "sums.sig") || strings.Contains(name, "checksums.sig")
}

func resolvePGPKey(localPath, keyURL, keyAsset string, assets []Asset, tmpDir string) (string, error) {
	if localPath != "" {
		if isHTTPURL(localPath) {
			return downloadKeyFromURL(localPath, tmpDir)
		}
		if _, err := os.Stat(localPath); err != nil {
			return "", fmt.Errorf("pgp key file: %w", err)
		}
		return localPath, nil
	}
	if keyURL != "" {
		return downloadKeyFromURL(keyURL, tmpDir)
	}
	if keyAsset != "" {
		asset := findAssetByName(assets, keyAsset)
		if asset == nil {
			return "", fmt.Errorf("pgp key asset %q not found in release", keyAsset)
		}
		return downloadAssetToTemp(asset, tmpDir)
	}
	if asset := autoDetectKeyAsset(assets); asset != nil {
		path, err := downloadAssetToTemp(asset, tmpDir)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Auto-detected PGP key asset %s\n", asset.Name)
		}
		return path, err
	}
	return "", fmt.Errorf("error: provide --pgp-key-file, --pgp-key-url, or --pgp-key-asset to verify .asc signatures")
}

func downloadKeyFromURL(src string, tmpDir string) (string, error) {
	resp, err := httpGetWithAuth(src)
	if err != nil {
		return "", fmt.Errorf("fetch key %s: %w", src, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status %d from %s: %s", resp.StatusCode, src, strings.TrimSpace(string(body)))
	}
	f, err := os.CreateTemp(tmpDir, "pgp-key-*.asc")
	if err != nil {
		return "", fmt.Errorf("create temp key: %w", err)
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", fmt.Errorf("write key: %w", err)
	}
	return f.Name(), nil
}

func downloadAssetToTemp(asset *Asset, tmpDir string) (string, error) {
	path := filepath.Join(tmpDir, asset.Name)
	if err := download(asset.BrowserDownloadUrl, path); err != nil {
		return "", err
	}
	return path, nil
}

func findAssetByName(assets []Asset, name string) *Asset {
	for i := range assets {
		if assets[i].Name == name {
			return &assets[i]
		}
	}
	return nil
}

func autoDetectKeyAsset(assets []Asset) *Asset {
	keywords := []string{"key", "pub", "release"}
	for i := range assets {
		nameLower := strings.ToLower(assets[i].Name)
		if !strings.HasSuffix(nameLower, ".asc") {
			continue
		}
		if strings.Contains(nameLower, ".tar") || strings.Contains(nameLower, ".zip") || strings.Contains(nameLower, ".gz") {
			continue
		}
		for _, kw := range keywords {
			if strings.Contains(nameLower, kw) {
				return &assets[i]
			}
		}
	}
	return nil
}

// autoDetectMinisignKeyAsset scans release assets for a minisign public key.
// Looks for patterns like *minisign*.pub or *-signing-key.pub
func autoDetectMinisignKeyAsset(assets []Asset) *Asset {
	// Priority order: explicit minisign key names first
	patterns := []string{
		"minisign.pub",     // exact match first
		"minisign",         // contains minisign
		"-signing-key.pub", // common naming pattern
		"release-key.pub",  // alternate naming
	}

	for _, pattern := range patterns {
		for i := range assets {
			nameLower := strings.ToLower(assets[i].Name)
			if !strings.HasSuffix(nameLower, ".pub") {
				continue
			}
			// Skip archive-like names
			if strings.Contains(nameLower, ".tar") || strings.Contains(nameLower, ".zip") || strings.Contains(nameLower, ".gz") {
				continue
			}
			if strings.Contains(nameLower, pattern) {
				return &assets[i]
			}
		}
	}
	return nil
}

// resolveMinisignKey resolves a minisign public key from various sources.
// Priority: localPath (file or URL) > keyURL > keyAsset > auto-detect.
// Mirrors resolvePGPKey for consistency.
func resolveMinisignKey(localPath, keyURL, keyAsset string, assets []Asset, tmpDir string) (string, error) {
	// 1. Local path (or URL passed as path)
	if localPath != "" {
		if isHTTPURL(localPath) {
			return downloadMinisignKeyFromURL(localPath, tmpDir)
		}
		if _, err := os.Stat(localPath); err != nil {
			return "", fmt.Errorf("minisign key file: %w", err)
		}
		return localPath, nil
	}

	// 2. Explicit URL
	if keyURL != "" {
		return downloadMinisignKeyFromURL(keyURL, tmpDir)
	}

	// 3. Explicit release asset name
	if keyAsset != "" {
		asset := findAssetByName(assets, keyAsset)
		if asset == nil {
			return "", fmt.Errorf("minisign key asset %q not found in release", keyAsset)
		}
		return downloadAssetToTemp(asset, tmpDir)
	}

	// 4. Auto-detect from release assets
	if asset := autoDetectMinisignKeyAsset(assets); asset != nil {
		path, err := downloadAssetToTemp(asset, tmpDir)
		if err == nil {
			fmt.Fprintf(os.Stderr, "Auto-detected minisign key asset %s\n", asset.Name)
		}
		return path, err
	}

	return "", fmt.Errorf("error: provide --minisign-key, --minisign-key-url, or --minisign-key-asset to verify minisign signatures")
}

// downloadMinisignKeyFromURL fetches a minisign public key from a URL.
func downloadMinisignKeyFromURL(src string, tmpDir string) (string, error) {
	resp, err := httpGetWithAuth(src)
	if err != nil {
		return "", fmt.Errorf("fetch minisign key %s: %w", src, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status %d from %s: %s", resp.StatusCode, src, strings.TrimSpace(string(body)))
	}
	f, err := os.CreateTemp(tmpDir, "minisign-key-*.pub")
	if err != nil {
		return "", fmt.Errorf("create temp key: %w", err)
	}
	defer f.Close()
	if _, err := io.Copy(f, resp.Body); err != nil {
		return "", fmt.Errorf("write key: %w", err)
	}
	return f.Name(), nil
}

func isHTTPURL(value string) bool {
	lower := strings.ToLower(value)
	return strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://")
}

func renderTemplate(tpl string, ctx templateContext) string {
	replacements := []string{
		"{{asset}}", ctx.AssetName,
		"{{base}}", ctx.BaseName,
		"{{binary}}", ctx.BinaryName,
		"{{goos}}", ctx.GOOS,
		"{{GOOS}}", strings.ToUpper(ctx.GOOS),
		"{{Goos}}", titleCase(ctx.GOOS),
		"{{goarch}}", ctx.GOARCH,
		"{{GOARCH}}", strings.ToUpper(ctx.GOARCH),
		"{{Goarch}}", titleCase(ctx.GOARCH),
		"{{version}}", ctx.Version,
		"{{versionNoPrefix}}", ctx.VersionNoPrefix,
	}
	return strings.NewReplacer(replacements...).Replace(tpl)
}

func extractChecksum(data []byte, algo, assetName string) (string, error) {
	text := strings.TrimSpace(string(data))
	if text == "" {
		return "", fmt.Errorf("checksum file is empty")
	}
	digestLen := expectedDigestLength(algo)
	if isHexDigest(text, digestLen) {
		return strings.ToLower(text), nil
	}

	lines := strings.Split(text, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		digest := fields[0]
		if !isHexDigest(digest, digestLen) {
			continue
		}
		candidate := filepath.Base(fields[len(fields)-1])
		if candidate == assetName {
			return strings.ToLower(digest), nil
		}
	}

	return "", fmt.Errorf("checksum for %s not found", assetName)
}

func isHexDigest(value string, expectedLen int) bool {
	if expectedLen > 0 && len(value) != expectedLen {
		return false
	}
	if len(value)%2 != 0 {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') && (ch < 'A' || ch > 'F') {
			return false
		}
	}
	return true
}

func expectedDigestLength(algo string) int {
	switch strings.ToLower(algo) {
	case "sha256":
		return 64
	case "sha512":
		return 128
	default:
		return 0
	}
}

func normalizeHexKey(input string) (string, error) {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "", fmt.Errorf("error: --key is required to verify ed25519 signatures")
	}
	upper := strings.ToUpper(trimmed)
	if strings.Contains(upper, "BEGIN") || strings.Contains(upper, "PRIVATE") {
		return "", fmt.Errorf("ed25519 keys must be provided as 64-character hex strings, not PEM/PGP blobs")
	}
	expectedLen := ed25519.PublicKeySize * 2
	if len(trimmed) != expectedLen {
		return "", fmt.Errorf("ed25519 key must be %d hex characters", expectedLen)
	}
	if !isHexDigest(trimmed, expectedLen) {
		return "", fmt.Errorf("ed25519 key must contain only hexadecimal characters")
	}
	return strings.ToLower(trimmed), nil
}

func loadSignature(path string) (signatureData, error) {
	// #nosec G304 -- path sig tmp controlled
	data, err := os.ReadFile(path)
	if err != nil {
		return signatureData{}, fmt.Errorf("read sig: %w", err)
	}
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "-----BEGIN PGP SIGNATURE-----") {
		return signatureData{format: sigFormatPGP}, nil
	}
	// Check for minisign format (starts with "untrusted comment:")
	// Actual parsing is done by minisign library during verification
	if strings.HasPrefix(trimmed, "untrusted comment:") {
		return signatureData{format: sigFormatMinisign}, nil
	}
	if len(data) == ed25519.SignatureSize {
		return signatureData{format: sigFormatBinary, bytes: data}, nil
	}
	decoded, err := hex.DecodeString(trimmed)
	if err == nil && len(decoded) == ed25519.SignatureSize {
		return signatureData{format: sigFormatBinary, bytes: decoded}, nil
	}
	return signatureData{}, fmt.Errorf("unsupported signature format in %s", path)
}

// verifyMinisignSignature verifies a minisign signature using the github.com/jedisct1/go-minisign library.
// sigPath is the path to the .minisig file, pubKeyPath is the path to the .pub file.
// contentToVerify is the bytes that were signed (either asset bytes or checksum file bytes).
func verifyMinisignSignature(contentToVerify []byte, sigPath, pubKeyPath string) error {
	pubKey, err := minisign.NewPublicKeyFromFile(pubKeyPath)
	if err != nil {
		return fmt.Errorf("read minisign pubkey: %w", err)
	}

	sig, err := minisign.NewSignatureFromFile(sigPath)
	if err != nil {
		return fmt.Errorf("read minisign signature: %w", err)
	}

	valid, err := pubKey.Verify(contentToVerify, sig)
	if err != nil {
		return fmt.Errorf("minisign: verification error: %w", err)
	}
	if !valid {
		return fmt.Errorf("minisign: signature verification failed")
	}

	return nil
}

func verifyPGPSignature(assetPath, sigPath, pubKeyPath, gpgBin string) error {
	home, err := os.MkdirTemp("", "sfetch-gpg-")
	if err != nil {
		return fmt.Errorf("create gpg home: %w", err)
	}
	defer os.RemoveAll(home)

	importArgs := []string{"--batch", "--no-tty", "--homedir", home, "--import", pubKeyPath}
	if err := runCommand(gpgBin, importArgs...); err != nil {
		return fmt.Errorf("import pgp key: %w", err)
	}

	verifyArgs := []string{"--batch", "--no-tty", "--homedir", home, "--trust-model", "always", "--verify", sigPath, assetPath}
	if err := runCommand(gpgBin, verifyArgs...); err != nil {
		return fmt.Errorf("verify pgp signature: %w", err)
	}

	return nil
}

func runCommand(bin string, args ...string) error {
	cmd := exec.Command(bin, args...)
	var combined bytes.Buffer
	cmd.Stdout = &combined
	cmd.Stderr = &combined
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %s", bin, strings.Join(args, " "), trimCommandOutput(combined.String()))
	}
	return nil
}

func trimCommandOutput(out string) string {
	clean := strings.TrimSpace(out)
	if clean == "" {
		return "command failed"
	}
	if len(clean) > maxCommandError {
		return clean[:maxCommandError] + "..."
	}
	return clean
}

// selfVerifyAssetName returns the expected asset filename for the current platform.
func selfVerifyAssetName() string {
	if runtime.GOOS == "windows" {
		return fmt.Sprintf("sfetch_%s_%s.zip", runtime.GOOS, runtime.GOARCH)
	}
	return fmt.Sprintf("sfetch_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
}

// fetchExpectedHash fetches SHA256SUMS from GitHub and extracts the hash for the given asset.
// Returns (hash, error). On network failure, returns ("", err) but caller can continue with instructions.
func fetchExpectedHash(ver, assetName string) (string, error) {
	if ver == "dev" {
		return "", fmt.Errorf("dev build, no published checksums")
	}

	url := fmt.Sprintf("https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS", ver)

	client := &http.Client{Timeout: 2 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", fmt.Sprintf("sfetch/%s", version))
	if tok := githubToken(); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("network unavailable: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d fetching SHA256SUMS", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("read SHA256SUMS: %w", err)
	}

	// Parse SHA256SUMS format: "<hash>  <filename>" or "<hash> <filename>"
	lines := strings.Split(string(body), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			hash := fields[0]
			filename := fields[len(fields)-1]
			if filename == assetName && len(hash) == 64 {
				return strings.ToLower(hash), nil
			}
		}
	}

	return "", fmt.Errorf("asset %s not found in SHA256SUMS", assetName)
}

// checksumCommand returns the platform-appropriate checksum command.
func checksumCommand() string {
	// macOS uses shasum, Linux uses sha256sum
	if runtime.GOOS == "darwin" {
		return "shasum -a 256"
	}
	return "sha256sum"
}

// printSelfVerify outputs verification instructions for the running binary.
func printSelfVerify(jsonOutput bool) {
	assetName := selfVerifyAssetName()
	ver := version

	// Attempt to fetch expected hash (optional, may fail on network issues or dev builds)
	expectedHash, hashErr := fetchExpectedHash(ver, assetName)

	if jsonOutput {
		printSelfVerifyJSON(ver, assetName, expectedHash, hashErr)
		return
	}

	// Header
	fmt.Printf("\nsfetch %s (%s/%s)\n", ver, runtime.GOOS, runtime.GOARCH)
	fmt.Printf("Built: %s\n", buildTime)
	fmt.Printf("Commit: %s\n", gitCommit)

	// Dev build early exit
	if ver == "dev" {
		fmt.Println("\nThis is a development build. No published checksums available.")
		fmt.Println("To verify a release build, install from: https://github.com/3leaps/sfetch/releases")
		fmt.Println()
		fmt.Println("Embedded trust anchors:")
		fmt.Printf("  Minisign pubkey: %s\n", EmbeddedMinisignPubkey)
		fmt.Printf("  Key ID: %s\n", EmbeddedMinisignKeyID)
		return
	}

	// Release URLs
	fmt.Println()
	fmt.Println("Release URLs:")
	fmt.Printf("  SHA256SUMS:         https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS\n", ver)
	fmt.Printf("  SHA256SUMS.minisig: https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS.minisig\n", ver)
	fmt.Printf("  SHA256SUMS.asc:     https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS.asc\n", ver)

	// Expected asset
	fmt.Println()
	fmt.Printf("Expected asset: %s\n", assetName)

	// Expected hash
	fmt.Println()
	if hashErr != nil {
		fmt.Printf("Expected SHA256: (network unavailable - fetch manually from URLs above)\n")
	} else {
		fmt.Printf("Expected SHA256 (fetched from release):\n")
		fmt.Printf("  %s\n", expectedHash)
	}

	// Checksum verification commands
	fmt.Println()
	fmt.Println("Verify checksum externally:")
	if runtime.GOOS == "darwin" {
		fmt.Println("  # macOS")
		fmt.Println("  shasum -a 256 $(which sfetch)")
	} else if runtime.GOOS == "windows" {
		fmt.Println("  # Windows (PowerShell)")
		fmt.Println("  Get-FileHash (Get-Command sfetch).Source -Algorithm SHA256")
	} else {
		fmt.Println("  # Linux")
		fmt.Println("  sha256sum $(which sfetch)")
	}

	// Minisign verification
	fmt.Println()
	fmt.Println("Verify signature with minisign:")
	fmt.Printf("  curl -sL https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS -o /tmp/SHA256SUMS\n", ver)
	fmt.Printf("  curl -sL https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS.minisig -o /tmp/SHA256SUMS.minisig\n", ver)
	fmt.Printf("  minisign -Vm /tmp/SHA256SUMS -P %s\n", EmbeddedMinisignPubkey)

	// GPG verification
	fmt.Println()
	fmt.Println("Verify signature with GPG:")
	fmt.Printf("  curl -sL https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS -o /tmp/SHA256SUMS\n", ver)
	fmt.Printf("  curl -sL https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS.asc -o /tmp/SHA256SUMS.asc\n", ver)
	fmt.Printf("  curl -sL https://github.com/3leaps/sfetch/releases/download/v%s/sfetch-release-signing-key.asc | gpg --import\n", ver)
	fmt.Println("  gpg --verify /tmp/SHA256SUMS.asc /tmp/SHA256SUMS")

	// Trust anchors
	fmt.Println()
	fmt.Println("Embedded trust anchors:")
	fmt.Printf("  Minisign pubkey: %s\n", EmbeddedMinisignPubkey)
	fmt.Printf("  Key ID: %s\n", EmbeddedMinisignKeyID)

	// Security warning
	fmt.Println()
	fmt.Println("WARNING: A compromised binary could lie. Run these commands yourself.")
}

// SelfVerifyOutput is the JSON structure for --self-verify --json output.
type SelfVerifyOutput struct {
	Version     string           `json:"version"`
	Platform    string           `json:"platform"`
	BuildTime   string           `json:"buildTime"`
	GitCommit   string           `json:"gitCommit"`
	IsDev       bool             `json:"isDev"`
	Asset       string           `json:"asset,omitempty"`
	ExpectedSHA string           `json:"expectedSHA256,omitempty"`
	HashError   string           `json:"hashError,omitempty"`
	URLs        *SelfVerifyURLs  `json:"urls,omitempty"`
	TrustAnchor *TrustAnchorInfo `json:"trustAnchor"`
	Commands    *VerifyCommands  `json:"commands,omitempty"`
	Warning     string           `json:"warning,omitempty"`
}

type SelfVerifyURLs struct {
	SHA256SUMS        string `json:"sha256sums"`
	SHA256SUMSMinisig string `json:"sha256sumsMinisig"`
	SHA256SUMSAsc     string `json:"sha256sumsAsc"`
}

type TrustAnchorInfo struct {
	MinisignPubkey string `json:"minisignPubkey"`
	KeyID          string `json:"keyId"`
}

type VerifyCommands struct {
	Checksum string `json:"checksum"`
	Minisign string `json:"minisign"`
}

func printSelfVerifyJSON(ver, assetName, expectedHash string, hashErr error) {
	output := SelfVerifyOutput{
		Version:   ver,
		Platform:  fmt.Sprintf("%s/%s", runtime.GOOS, runtime.GOARCH),
		BuildTime: buildTime,
		GitCommit: gitCommit,
		IsDev:     ver == "dev",
		TrustAnchor: &TrustAnchorInfo{
			MinisignPubkey: EmbeddedMinisignPubkey,
			KeyID:          EmbeddedMinisignKeyID,
		},
		Warning: "A compromised binary could lie. Run verification commands yourself.",
	}

	if ver != "dev" {
		output.Asset = assetName
		if hashErr != nil {
			output.HashError = hashErr.Error()
		} else {
			output.ExpectedSHA = expectedHash
		}
		output.URLs = &SelfVerifyURLs{
			SHA256SUMS:        fmt.Sprintf("https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS", ver),
			SHA256SUMSMinisig: fmt.Sprintf("https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS.minisig", ver),
			SHA256SUMSAsc:     fmt.Sprintf("https://github.com/3leaps/sfetch/releases/download/v%s/SHA256SUMS.asc", ver),
		}
		output.Commands = &VerifyCommands{
			Checksum: checksumCommand() + " $(which sfetch)",
			Minisign: fmt.Sprintf("minisign -Vm /tmp/SHA256SUMS -P %s", EmbeddedMinisignPubkey),
		}
	}

	data, _ := json.MarshalIndent(output, "", "  ")
	fmt.Println(string(data))
}
