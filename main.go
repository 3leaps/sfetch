package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
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
	"syscall"
	"time"

	"github.com/3leaps/sfetch/internal/hostenv"
	"github.com/3leaps/sfetch/pkg/update"
)

const (
	defaultAPIBase  = "https://api.github.com"
	defaultCDNBase  = "https://github.com"
	defaultCacheDir = "~/.cache/sfetch"
	maxCommandError = 512
)

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
	workflowNone     = "none"     // No verification artifacts provided by source
	workflowInsecure = "insecure" // Verification bypass (--insecure flag)
)

// Legacy trust levels for provenance records.
//
// Deprecated in v0.3.0: retained for one minor cycle for backwards compatibility.
// New callers should use TrustScore/TrustLevel.
const (
	trustHigh   = "high"   // Signature + checksum verified
	trustMedium = "medium" // Signature only (no checksum)
	trustLow    = "low"    // Checksum only (no signature)
	trustNone   = "none"   // No verification (--insecure) or no-verification available
)

type TrustLevel int

const (
	TrustBypassed TrustLevel = 0 // User bypassed verifiable checks
	TrustMinimal  TrustLevel = 1 // HTTPS-only, no verification available
	TrustLow      TrustLevel = 2 // Checksum-only
	TrustMedium   TrustLevel = 3 // Signature-only, or partial verification
	TrustHigh     TrustLevel = 4 // Signature + checksum verified
)

func TrustLevelFromScore(score int) TrustLevel {
	switch {
	case score <= 0:
		return TrustBypassed
	case score < 30:
		return TrustMinimal
	case score < 60:
		return TrustLow
	case score < 85:
		return TrustMedium
	default:
		return TrustHigh
	}
}

func (tl TrustLevel) Name() string {
	switch tl {
	case TrustBypassed:
		return "bypassed"
	case TrustMinimal:
		return "minimal"
	case TrustLow:
		return "low"
	case TrustMedium:
		return "medium"
	case TrustHigh:
		return "high"
	default:
		return "unknown"
	}
}

type TrustSigFactor struct {
	Verifiable bool `json:"verifiable"`
	Validated  bool `json:"validated"`
	Skipped    bool `json:"skipped"`
	Points     int  `json:"points"`
}

type TrustChecksumFactor struct {
	Verifiable bool   `json:"verifiable"`
	Validated  bool   `json:"validated"`
	Skipped    bool   `json:"skipped"`
	Algorithm  string `json:"algorithm,omitempty"`
	Points     int    `json:"points"`
}

type TrustTransportFactor struct {
	HTTPS  bool `json:"https"`
	Points int  `json:"points"`
}

type TrustAlgorithmFactor struct {
	Name   string `json:"name,omitempty"`
	Points int    `json:"points"`
}

type TrustFactors struct {
	Signature TrustSigFactor       `json:"signature"`
	Checksum  TrustChecksumFactor  `json:"checksum"`
	Transport TrustTransportFactor `json:"transport"`
	Algorithm TrustAlgorithmFactor `json:"algorithm"`
}

type TrustScore struct {
	Score     int          `json:"score"`
	Level     TrustLevel   `json:"level"`
	LevelName string       `json:"levelName"`
	Factors   TrustFactors `json:"factors"`
}

type trustScoreInput struct {
	SignatureVerifiable bool
	SignatureValidated  bool
	SignatureSkipped    bool

	ChecksumVerifiable bool
	ChecksumValidated  bool
	ChecksumSkipped    bool
	ChecksumAlgorithm  string

	HTTPSUsed bool

	InsecureFlag bool
}

func computeTrustScore(in trustScoreInput) TrustScore {
	var out TrustScore

	out.Factors.Signature.Verifiable = in.SignatureVerifiable
	out.Factors.Signature.Validated = in.SignatureValidated
	out.Factors.Signature.Skipped = in.SignatureSkipped

	out.Factors.Checksum.Verifiable = in.ChecksumVerifiable
	out.Factors.Checksum.Validated = in.ChecksumValidated
	out.Factors.Checksum.Skipped = in.ChecksumSkipped
	out.Factors.Checksum.Algorithm = in.ChecksumAlgorithm

	out.Factors.Transport.HTTPS = in.HTTPSUsed

	verifiedAny := in.SignatureValidated || in.ChecksumValidated

	score := 0

	// Signature (dominant factor)
	if in.SignatureValidated {
		score += 70
		out.Factors.Signature.Points = 70
	} else if in.SignatureVerifiable && in.SignatureSkipped {
		score -= 20
		out.Factors.Signature.Points = -20
	}

	// Checksum
	if in.ChecksumValidated {
		score += 40
		out.Factors.Checksum.Points = 40
	} else if in.ChecksumVerifiable && in.ChecksumSkipped {
		score -= 15
		out.Factors.Checksum.Points = -15
	}

	// Transport baseline (only if nothing verified)
	if !verifiedAny && in.HTTPSUsed {
		score += 25
		out.Factors.Transport.Points = 25
	}

	// Algorithm (only meaningful if checksum validated)
	if in.ChecksumValidated {
		switch strings.ToLower(in.ChecksumAlgorithm) {
		case "sha256", "sha512":
			score += 5
			out.Factors.Algorithm.Name = strings.ToLower(in.ChecksumAlgorithm)
			out.Factors.Algorithm.Points = 5
		case "sha1", "md5":
			score -= 10
			out.Factors.Algorithm.Name = strings.ToLower(in.ChecksumAlgorithm)
			out.Factors.Algorithm.Points = -10
		}
	}

	// Bypass semantics
	if in.InsecureFlag && (in.SignatureVerifiable || in.ChecksumVerifiable) {
		score = 0
		out.Factors.Signature.Points = 0
		out.Factors.Checksum.Points = 0
		out.Factors.Transport.Points = 0
		out.Factors.Algorithm.Points = 0
		out.Factors.Algorithm.Name = ""
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}

	out.Score = score
	out.Level = TrustLevelFromScore(score)
	out.LevelName = out.Level.Name()

	return out
}

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
	Trust         TrustScore       `json:"trust"`
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
	TrustLevel string // legacy: high, medium, low, none
	Trust      TrustScore

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

	// Handle --insecure flag first.
	// We still compute what verification artifacts are present so we can distinguish
	// "bypassed available verification" from "no verification possible" in trust scoring.
	if flags.insecure {
		assessment.Workflow = workflowInsecure
		assessment.Warnings = append(assessment.Warnings, "No verification performed (--insecure flag)")

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

		// Prefer checking for signature artifacts so bypass semantics are accurate.
		if checksumSigAsset, checksumFileName := findChecksumSignature(rel.Assets, cfg); checksumSigAsset != nil {
			assessment.SignatureAvailable = true
			assessment.SignatureFile = checksumSigAsset.Name
			assessment.SignatureFormat = signatureFormatFromExtension(checksumSigAsset.Name, cfg.SignatureFormats)
			assessment.SignatureIsChecksum = true
			assessment.ChecksumFileForSig = checksumFileName

			assessment.ChecksumAvailable = true
			assessment.ChecksumFile = checksumFileName
			assessment.ChecksumType = "consolidated"
			assessment.ChecksumAlgorithm = detectChecksumAlgorithm(checksumFileName, cfg.HashAlgo)
		} else if perAssetSig := findPerAssetSignature(rel.Assets, ctx, cfg); perAssetSig != nil {
			assessment.SignatureAvailable = true
			assessment.SignatureFile = perAssetSig.Name
			assessment.SignatureFormat = signatureFormatFromExtension(perAssetSig.Name, cfg.SignatureFormats)
			assessment.SignatureIsChecksum = false

			if checksumAsset := findChecksumFile(rel.Assets, ctx, cfg); checksumAsset != nil {
				assessment.ChecksumAvailable = true
				assessment.ChecksumFile = checksumAsset.Name
				assessment.ChecksumType = detectChecksumType(checksumAsset.Name)
				assessment.ChecksumAlgorithm = detectChecksumAlgorithm(checksumAsset.Name, cfg.HashAlgo)
			}
		} else if checksumAsset := findChecksumFile(rel.Assets, ctx, cfg); checksumAsset != nil {
			assessment.ChecksumAvailable = true
			assessment.ChecksumFile = checksumAsset.Name
			assessment.ChecksumType = detectChecksumType(checksumAsset.Name)
			assessment.ChecksumAlgorithm = detectChecksumAlgorithm(checksumAsset.Name, cfg.HashAlgo)
		}

		finalizeAssessmentTrust(assessment, rel, flags)
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
			assessment.Warnings = append(assessment.Warnings, "Checksum verification skipped (--skip-checksum flag)")
		}
		finalizeAssessmentTrust(assessment, rel, flags)
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
		} else {
			if flags.skipChecksum {
				assessment.Warnings = append(assessment.Warnings, "Checksum verification skipped (--skip-checksum flag)")
			} else {
				assessment.Warnings = append(assessment.Warnings, "No checksum file found")
			}
		}

		assessment.Workflow = workflowB
		finalizeAssessmentTrust(assessment, rel, flags)
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
		assessment.Warnings = append(assessment.Warnings, "No signature available; authenticity cannot be proven")

		if flags.skipSig {
			// User explicitly skipped sig, but there wasn't one anyway
			assessment.Warnings = append(assessment.Warnings, "Note: --skip-sig had no effect (no signature found)")
		}
		finalizeAssessmentTrust(assessment, rel, flags)
		return assessment
	}

	// Nothing available
	assessment.Workflow = workflowNone
	assessment.Warnings = append(assessment.Warnings, "No verification artifacts provided by source")

	finalizeAssessmentTrust(assessment, rel, flags)
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

	minisignKeyConfigured bool
	pgpKeyConfigured      bool
	ed25519KeyConfigured  bool
	gpgBin                string
}

func legacyTrustLevelFromTrust(score TrustScore) string {
	switch score.Level {
	case TrustHigh:
		return trustHigh
	case TrustMedium:
		return trustMedium
	case TrustLow:
		return trustLow
	default:
		return trustNone
	}
}

func finalizeAssessmentTrust(assessment *VerificationAssessment, rel *Release, flags assessmentFlags) {
	// GitHub release downloads are HTTPS in production. Tests may use http://
	// for local servers, but the transport property should model the real
	// acquisition surface.
	httpsUsed := true

	signatureVerifiable := false
	switch assessment.SignatureFormat {
	case sigFormatMinisign:
		signatureVerifiable = flags.minisignKeyConfigured || autoDetectMinisignKeyAsset(rel.Assets) != nil
	case sigFormatPGP:
		signatureVerifiable = flags.pgpKeyConfigured || autoDetectKeyAsset(rel.Assets) != nil
	case sigFormatBinary:
		signatureVerifiable = flags.ed25519KeyConfigured
	default:
		signatureVerifiable = false
	}
	if !assessment.SignatureAvailable {
		signatureVerifiable = false
	}

	if assessment.SignatureAvailable && !signatureVerifiable {
		assessment.Warnings = append(assessment.Warnings, "Signature file found but no verification key available")
	}

	signatureSkipped := flags.skipSig || flags.insecure
	checksumSkipped := flags.skipChecksum || flags.insecure

	checksumVerifiable := assessment.ChecksumAvailable

	in := trustScoreInput{
		SignatureVerifiable: signatureVerifiable,
		SignatureValidated:  signatureVerifiable && assessment.SignatureAvailable && !signatureSkipped,
		SignatureSkipped:    signatureSkipped,

		ChecksumVerifiable: checksumVerifiable,
		ChecksumValidated:  checksumVerifiable && !checksumSkipped,
		ChecksumSkipped:    checksumSkipped,
		ChecksumAlgorithm:  assessment.ChecksumAlgorithm,

		HTTPSUsed:    httpsUsed,
		InsecureFlag: flags.insecure,
	}

	assessment.Trust = computeTrustScore(in)
	assessment.TrustLevel = legacyTrustLevelFromTrust(assessment.Trust)
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
		verifiable := assessment.Trust.Factors.Signature.Verifiable
		if assessment.SignatureIsChecksum {
			sb.WriteString(fmt.Sprintf("  Signature:  %s (%s, checksum-level, verifiable=%t)\n", assessment.SignatureFile, sigType, verifiable))
		} else {
			sb.WriteString(fmt.Sprintf("  Signature:  %s (%s, per-asset, verifiable=%t)\n", assessment.SignatureFile, sigType, verifiable))
		}
	} else {
		sb.WriteString("  Signature:  none\n")
	}

	// Checksum info
	if assessment.ChecksumAvailable {
		verifiable := assessment.Trust.Factors.Checksum.Verifiable
		sb.WriteString(fmt.Sprintf("  Checksum:   %s (%s, %s, verifiable=%t)\n",
			assessment.ChecksumFile, assessment.ChecksumAlgorithm, assessment.ChecksumType, verifiable))
	} else {
		sb.WriteString("  Checksum:   none\n")
	}

	sb.WriteString("\nVerification plan:\n")
	sb.WriteString(fmt.Sprintf("  Workflow:   %s\n", describeWorkflow(assessment.Workflow)))
	sb.WriteString(fmt.Sprintf("  Trust:      %d/100 (%s)\n", assessment.Trust.Score, assessment.Trust.LevelName))
	// Trust factor breakdown
	sb.WriteString("\nTrust factors:\n")
	sb.WriteString(fmt.Sprintf("  Signature:  verifiable=%t validated=%t skipped=%t points=%d\n",
		assessment.Trust.Factors.Signature.Verifiable,
		assessment.Trust.Factors.Signature.Validated,
		assessment.Trust.Factors.Signature.Skipped,
		assessment.Trust.Factors.Signature.Points))
	sb.WriteString(fmt.Sprintf("  Checksum:   verifiable=%t validated=%t skipped=%t algo=%s points=%d\n",
		assessment.Trust.Factors.Checksum.Verifiable,
		assessment.Trust.Factors.Checksum.Validated,
		assessment.Trust.Factors.Checksum.Skipped,
		assessment.Trust.Factors.Checksum.Algorithm,
		assessment.Trust.Factors.Checksum.Points))
	sb.WriteString(fmt.Sprintf("  Transport:  https=%t points=%d\n",
		assessment.Trust.Factors.Transport.HTTPS,
		assessment.Trust.Factors.Transport.Points))
	sb.WriteString(fmt.Sprintf("  Algorithm:  name=%s points=%d\n",
		assessment.Trust.Factors.Algorithm.Name,
		assessment.Trust.Factors.Algorithm.Points))

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
	case workflowNone:
		return "none (no verification artifacts)"
	case workflowInsecure:
		return "insecure (verification bypass)"
	default:
		return "unknown"
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
		Trust:      assessment.Trust,
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

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("sfetch", flag.ContinueOnError)
	fs.SetOutput(io.Discard)

	repo := fs.String("repo", "", "GitHub repo owner/repo")
	tag := fs.String("tag", "", "release tag (mutually exclusive with --latest)")
	latest := fs.Bool("latest", false, "fetch latest release (mutually exclusive with --tag)")
	assetMatch := fs.String("asset-match", "", "asset name glob/substring (simpler than regex)")
	assetRegex := fs.String("asset-regex", "", "asset name regex (advanced override)")
	assetTypeFlag := fs.String("asset-type", "", "force asset handling type (archive, raw, package)")
	binaryNameFlag := fs.String("binary-name", "", "binary name to extract (default: inferred from repo name)")
	destDir := fs.String("dest-dir", "", "destination directory")
	output := fs.String("output", "", "output path")
	cacheDir := fs.String("cache-dir", "", "cache directory")
	preferPerAsset := fs.Bool("prefer-per-asset", false, "prefer per-asset signatures over checksum-level signatures (Workflow B over A)")
	requireMinisign := fs.Bool("require-minisign", false, "require minisign signature verification (fail if unavailable)")
	skipSig := fs.Bool("skip-sig", false, "skip signature verification (testing only)")
	skipChecksum := fs.Bool("skip-checksum", false, "skip checksum verification even if available")
	insecure := fs.Bool("insecure", false, "skip all verification (dangerous - use only for testing)")
	trustMinimum := fs.Int("trust-minimum", 0, "minimum trust score required to proceed (0-100)")
	selfUpdate := fs.Bool("self-update", false, "update sfetch to the latest release for this platform")
	selfUpdateYes := fs.Bool("yes", false, "confirm self-update without prompting")
	selfUpdateForce := fs.Bool("self-update-force", false, "allow major-version jumps and proceed even if target is locked")
	selfUpdateDir := fs.String("self-update-dir", "", "install path for self-update (default: current binary directory)")
	minisignPubKey := fs.String("minisign-key", "", "path to minisign public key file (.pub)")
	minisignKeyURL := fs.String("minisign-key-url", "", "URL to download minisign public key")
	minisignKeyAsset := fs.String("minisign-key-asset", "", "release asset name for minisign public key")
	pgpKeyFile := fs.String("pgp-key-file", "", "path to ASCII-armored PGP public key")
	pgpKeyURL := fs.String("pgp-key-url", "", "URL to download ASCII-armored PGP public key")
	pgpKeyAsset := fs.String("pgp-key-asset", "", "release asset name for ASCII-armored PGP public key")
	gpgBin := fs.String("gpg-bin", "gpg", "path to gpg executable")
	key := fs.String("key", "", "ed25519 pubkey hex (32 bytes)")
	selfVerify := fs.Bool("self-verify", false, "print instructions to verify this binary externally")
	showTrustAnchors := fs.Bool("show-trust-anchors", false, "print embedded public keys (use --json for JSON output)")
	showUpdateConfig := fs.Bool("show-update-config", false, "print embedded self-update configuration and exit")
	validateUpdateConfig := fs.Bool("validate-update-config", false, "validate embedded self-update configuration and exit")
	dryRun := fs.Bool("dry-run", false, "assess release verification without downloading")
	provenance := fs.Bool("provenance", false, "output provenance record JSON to stderr")
	provenanceFile := fs.String("provenance-file", "", "write provenance record to file (implies --provenance)")
	skipToolsCheck := fs.Bool("skip-tools-check", false, "skip preflight tool checks")
	verifyMinisignPubkey := fs.String("verify-minisign-pubkey", "", "verify file is a valid minisign PUBLIC key (not secret)")
	jsonOut := fs.Bool("json", false, "JSON output for CI")
	extendedHelp := fs.Bool("helpextended", false, "print quickstart & examples")
	fs.BoolVar(extendedHelp, "help-extended", false, "print quickstart & examples")
	versionFlag := fs.Bool("version", false, "print version")
	versionExtended := fs.Bool("version-extended", false, "print extended version/build info")
	install := fs.Bool("install", false, "install to user bin directory (~/.local/bin or %USERPROFILE%\\bin)")

	out := stdout
	printFlag := func(name string) {
		if f := fs.Lookup(name); f != nil {
			def := f.DefValue
			if def != "" && def != "false" {
				fmt.Fprintf(out, "  -%s\t%s (default %q)\n", f.Name, f.Usage, def)
			} else {
				fmt.Fprintf(out, "  -%s\t%s\n", f.Name, f.Usage)
			}
		}
	}

	fs.Usage = func() {
		fmt.Fprintf(out, "Usage: sfetch [flags]\n\n")

		fmt.Fprintln(out, "Selection:")
		for _, name := range []string{"repo", "tag", "latest", "asset-match", "asset-regex", "asset-type", "binary-name", "output", "dest-dir", "install", "cache-dir"} {
			printFlag(name)
		}

		fmt.Fprintln(out, "\nVerification:")
		for _, name := range []string{"minisign-key", "minisign-key-url", "minisign-key-asset", "pgp-key-file", "pgp-key-url", "pgp-key-asset", "gpg-bin", "key", "prefer-per-asset", "require-minisign", "skip-sig", "skip-checksum", "insecure"} {
			printFlag(name)
		}

		fmt.Fprintln(out, "\nProvenance & assessment:")
		for _, name := range []string{"dry-run", "trust-minimum", "provenance", "provenance-file"} {
			printFlag(name)
		}

		fmt.Fprintln(out, "\nTools & validation:")
		for _, name := range []string{"skip-tools-check", "verify-minisign-pubkey", "self-verify", "show-trust-anchors", "show-update-config", "validate-update-config", "json"} {
			printFlag(name)
		}

		fmt.Fprintln(out, "\nMeta:")
		for _, name := range []string{"helpextended", "version", "version-extended"} {
			printFlag(name)
		}
	}

	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.Usage()
			return 0
		}
		fmt.Fprintln(stderr, err)
		fs.Usage()
		return 2
	}

	// Handle --self-verify: print verification instructions and exit
	if *selfVerify {
		printSelfVerify(*jsonOut)
		return 0
	}

	// Validate flag combinations
	if *insecure && *requireMinisign {
		fmt.Fprintln(stderr, "error: --insecure and --require-minisign are mutually exclusive")
		return 1
	}

	if *versionFlag {
		fmt.Fprintln(stdout, "sfetch", version)
		return 0
	}

	if *versionExtended {
		fmt.Fprintf(stdout, "sfetch %s\n", version)
		fmt.Fprintf(stdout, "  build time: %s\n", buildTime)
		fmt.Fprintf(stdout, "  git commit: %s\n", gitCommit)
		fmt.Fprintf(stdout, "  go version: %s\n", runtime.Version())
		fmt.Fprintf(stdout, "  platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
		return 0
	}

	if *extendedHelp {
		fmt.Fprintln(stdout, strings.TrimSpace(quickstartDoc))
		return 0
	}

	// Handle --verify-minisign-pubkey: validate and exit
	if *verifyMinisignPubkey != "" {
		if err := ValidateMinisignPubkey(*verifyMinisignPubkey); err != nil {
			fmt.Fprintf(stderr, "INVALID: %s: %v\n", *verifyMinisignPubkey, err)
			return 1
		}
		fmt.Fprintf(stderr, "OK: %s is a valid minisign public key\n", *verifyMinisignPubkey)
		return 0
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
			fmt.Fprintln(stdout, string(data))
		} else {
			fmt.Fprintf(stdout, "minisign:%s\n", EmbeddedMinisignPubkey)
		}
		return 0
	}

	if *showUpdateConfig || *validateUpdateConfig {
		cfg, err := loadEmbeddedUpdateTarget()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}

		if *validateUpdateConfig {
			fmt.Fprintln(stderr, "OK: embedded update configuration is valid")
			return 0
		}

		data, err := json.MarshalIndent(cfg, "", "  ")
		if err != nil {
			fmt.Fprintf(stderr, "error: marshal update config: %v\n", err)
			return 1
		}
		fmt.Fprintln(stdout, string(data))
		return 0
	}

	if *selfUpdate && *install {
		fmt.Fprintln(stderr, "error: --install cannot be used with --self-update (use --self-update-dir)")
		return 1
	}

	if *selfUpdate {
		ucfg, err := loadEmbeddedUpdateTarget()
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}

		if *repo != "" && *repo != ucfg.Repo.ID {
			fmt.Fprintf(stderr, "warning: ignoring --repo (%s); self-update targets %s\n", *repo, ucfg.Repo.ID)
		}
		*repo = ucfg.Repo.ID

		targetPath, err := computeSelfUpdatePath(*selfUpdateDir)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if *destDir != "" || *output != "" {
			fmt.Fprintln(stderr, "warning: ignoring --dest-dir/--output when --self-update is set")
		}
		*output = targetPath
		if !*dryRun && !*selfUpdateYes {
			fmt.Fprintln(stderr, "--self-update requires --yes to proceed (rerun with --self-update --yes)")
			return 1
		}
		fmt.Fprintf(stderr, "Self-update target: %s\n", targetPath)
	}

	if !*skipToolsCheck {
		goos := runtime.GOOS
		goarch := runtime.GOARCH
		goosAliases := aliasList(goos, goosAliasTable)
		archAliases := aliasList(goarch, archAliasTable)
		fmt.Fprintf(stderr, "Preflight: GOOS=%s GOARCH=%s goosAliases=%v archAliases=%v\n", goos, goarch, goosAliases, archAliases)

		tools := []string{"tar"}
		for _, tool := range tools {
			if _, err := exec.LookPath(tool); err != nil {
				fmt.Fprintf(stderr, "missing required tool: %s\n", tool)
				return 1
			}
		}
	}

	// Handle --install: set destDir to user bin directory
	if *install {
		if *destDir != "" || *output != "" {
			fmt.Fprintln(stderr, "error: --install is mutually exclusive with --dest-dir and --output")
			return 1
		}
		path, err := userBinDirPath()
		if err != nil {
			fmt.Fprintf(stderr, "error: cannot determine user bin directory: %v\n", err)
			return 1
		}
		*destDir = path
	}

	if *repo == "" {
		fmt.Fprintln(stderr, "error: --repo is required")
		fs.Usage()
		return 1
	}

	if *tag != "" && *latest {
		fmt.Fprintln(stderr, "error: --tag and --latest are mutually exclusive")
		return 1
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
		fmt.Fprintf(stderr, "error: fetching release: %v\n", err)
		return 1
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		fmt.Fprintf(stderr, "error: API request failed %d: %s\n", resp.StatusCode, string(body))
		return 1
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(stderr, "error: reading response: %v\n", err)
		return 1
	}

	var rel Release
	if err := json.Unmarshal(respBody, &rel); err != nil {
		fmt.Fprintf(stderr, "error: parsing JSON: %v\n", err)
		return 1
	}

	if *selfUpdate {
		// Determine whether to proceed with self-update
		explicitTag := *tag != ""
		decision, message, exitCode := update.DecideSelfUpdate(version, rel.TagName, explicitTag, *selfUpdateForce)

		switch decision {
		case update.DecisionSkip:
			fmt.Fprintln(stderr, message)
			return exitCode
		case update.DecisionRefuse:
			fmt.Fprintln(stderr, message)
			return exitCode
		case update.DecisionProceed, update.DecisionReinstall, update.DecisionDowngrade, update.DecisionDevInstall:
			fmt.Fprintln(stderr, message)
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
		fmt.Fprintln(stderr, err)
		return 1
	}

	classification, classifyWarnings, err := classifyAsset(selected.Name, cfg, *assetTypeFlag)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	// Build assessment flags from CLI
	aflags := assessmentFlags{
		skipSig:         *skipSig,
		skipChecksum:    *skipChecksum,
		insecure:        *insecure,
		preferPerAsset:  *preferPerAsset,
		requireMinisign: *requireMinisign,

		minisignKeyConfigured: *minisignPubKey != "" || *minisignKeyURL != "" || *minisignKeyAsset != "",
		pgpKeyConfigured:      *pgpKeyFile != "" || *pgpKeyURL != "" || *pgpKeyAsset != "",
		ed25519KeyConfigured:  *key != "",
		gpgBin:                *gpgBin,
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
				fmt.Fprintf(stderr, "error: %v\n", err)
				return 1
			}
		} else {
			// --dry-run only: human-readable output
			fmt.Fprint(stdout, formatDryRunOutput(*repo, &rel, assessment, selfUpdateInfo))
		}
		return 0
	}

	// Enforce minimum trust if requested.
	if *trustMinimum < 0 || *trustMinimum > 100 {
		fmt.Fprintln(stderr, "error: --trust-minimum must be between 0 and 100")
		return 1
	}
	if assessment.Trust.Score < *trustMinimum {
		fmt.Fprintf(stderr, "error: trust score %d/100 (%s) is below --trust-minimum %d\n", assessment.Trust.Score, assessment.Trust.LevelName, *trustMinimum)
		fmt.Fprintln(stderr, "trust factors:")
		fmt.Fprintf(stderr, "  signature:  verifiable=%t validated=%t skipped=%t points=%d\n",
			assessment.Trust.Factors.Signature.Verifiable,
			assessment.Trust.Factors.Signature.Validated,
			assessment.Trust.Factors.Signature.Skipped,
			assessment.Trust.Factors.Signature.Points)
		fmt.Fprintf(stderr, "  checksum:   verifiable=%t validated=%t skipped=%t algo=%s points=%d\n",
			assessment.Trust.Factors.Checksum.Verifiable,
			assessment.Trust.Factors.Checksum.Validated,
			assessment.Trust.Factors.Checksum.Skipped,
			assessment.Trust.Factors.Checksum.Algorithm,
			assessment.Trust.Factors.Checksum.Points)
		fmt.Fprintf(stderr, "  transport:  https=%t points=%d\n",
			assessment.Trust.Factors.Transport.HTTPS,
			assessment.Trust.Factors.Transport.Points)
		fmt.Fprintf(stderr, "  algorithm:  name=%s points=%d\n",
			assessment.Trust.Factors.Algorithm.Name,
			assessment.Trust.Factors.Algorithm.Points)
		return 1
	}

	// Print trust and warnings
	fmt.Fprintf(stderr, "Trust: %d/100 (%s)\n", assessment.Trust.Score, assessment.Trust.LevelName)
	for _, w := range assessment.Warnings {
		fmt.Fprintf(stderr, "warning: %s\n", w)
	}

	// If no verification artifacts exist, proceed but make the situation explicit.
	if assessment.Workflow == workflowNone {
		fmt.Fprintln(stderr, "note: proceeding without verification artifacts provided by the source")
	}

	tmpDir, err := os.MkdirTemp("", "sfetch-*")
	if err != nil {
		fmt.Fprintf(stderr, "error: mkdir temp: %v\n", err)
		return 1
	}
	defer os.RemoveAll(tmpDir)

	assetPath := filepath.Join(tmpDir, selected.Name)
	if err := download(selected.BrowserDownloadUrl, assetPath); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}

	// Handle --require-minisign validation
	if *requireMinisign && !assessment.SignatureAvailable {
		fmt.Fprintln(stderr, "error: --require-minisign specified but no .minisig signature found in release")
		return 1
	}
	if *requireMinisign && assessment.SignatureFormat != sigFormatMinisign {
		fmt.Fprintf(stderr, "error: --require-minisign specified but signature %s is %s format, not minisign\n",
			assessment.SignatureFile, assessment.SignatureFormat)
		return 1
	}

	var sigAsset *Asset
	var sigPath string
	var checksumPath string
	var checksumBytes []byte

	// Execute verification based on assessed workflow
	switch assessment.Workflow {
	case workflowNone:
		// No verification artifacts - just download and proceed.
		fmt.Fprintln(stderr, "Note: no verification artifacts provided by the source")

	case workflowInsecure:
		// Verification bypass - just download and proceed.
		fmt.Fprintln(stderr, "WARNING: verification bypass enabled (--insecure)")

	case workflowA:
		// Workflow A: Verify signature over checksum file, then verify hash
		fmt.Fprintf(stderr, "Detected checksum-level signature: %s\n", assessment.SignatureFile)

		// Find and download the checksum file
		checksumAsset := findAssetByName(rel.Assets, assessment.ChecksumFileForSig)
		if checksumAsset == nil {
			fmt.Fprintf(stderr, "error: checksum file %s not found\n", assessment.ChecksumFileForSig)
			return 1
		}

		checksumPath = filepath.Join(tmpDir, checksumAsset.Name)
		if err := download(checksumAsset.BrowserDownloadUrl, checksumPath); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}

		// Download checksum signature
		sigAsset = findAssetByName(rel.Assets, assessment.SignatureFile)
		sigPath = filepath.Join(tmpDir, sigAsset.Name)
		if err := download(sigAsset.BrowserDownloadUrl, sigPath); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}

		// Read checksum file for verification
		// #nosec G304 -- checksumPath tmp controlled
		checksumBytes, err = os.ReadFile(checksumPath)
		if err != nil {
			fmt.Fprintf(stderr, "read checksum: %v\n", err)
			return 1
		}

		// Verify checksum file signature (not asset signature)
		if !*skipSig {
			switch assessment.SignatureFormat {
			case sigFormatMinisign:
				minisignKeyPath, err := resolveMinisignKey(*minisignPubKey, *minisignKeyURL, *minisignKeyAsset, rel.Assets, tmpDir)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
				if err := verifyMinisignSignature(checksumBytes, sigPath, minisignKeyPath); err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
				fmt.Fprintln(stdout, "Minisign checksum signature verified OK")

			case sigFormatPGP:
				pgpKeyPath, err := resolvePGPKey(*pgpKeyFile, *pgpKeyURL, *pgpKeyAsset, rel.Assets, tmpDir)
				if err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
				if err := verifyPGPSignature(checksumPath, sigPath, pgpKeyPath, *gpgBin); err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
				fmt.Fprintln(stdout, "PGP checksum signature verified OK")

			default:
				fmt.Fprintf(stderr, "error: unknown signature format for %s\n", assessment.SignatureFile)
				return 1
			}
		}

	case workflowB:
		// Workflow B: Per-asset signature
		sigAsset = findAssetByName(rel.Assets, assessment.SignatureFile)
		if sigAsset == nil {
			fmt.Fprintf(stderr, "error: signature file %s not found\n", assessment.SignatureFile)
			return 1
		}

		sigPath = filepath.Join(tmpDir, sigAsset.Name)
		if err := download(sigAsset.BrowserDownloadUrl, sigPath); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}

		// Load checksum file if available
		if assessment.ChecksumAvailable && !*skipChecksum {
			checksumAsset := findAssetByName(rel.Assets, assessment.ChecksumFile)
			if checksumAsset != nil {
				checksumPath = filepath.Join(tmpDir, checksumAsset.Name)
				if err := download(checksumAsset.BrowserDownloadUrl, checksumPath); err != nil {
					fmt.Fprintln(stderr, err)
					return 1
				}
				// #nosec G304 -- checksumPath tmp controlled
				checksumBytes, err = os.ReadFile(checksumPath)
				if err != nil {
					fmt.Fprintf(stderr, "read checksum: %v\n", err)
					return 1
				}
			}
		}

	case workflowC:
		// Workflow C: Checksum-only (no signature)
		fmt.Fprintf(stderr, "Using checksum-only verification (no signature available)\n")

		checksumAsset := findAssetByName(rel.Assets, assessment.ChecksumFile)
		if checksumAsset == nil {
			fmt.Fprintf(stderr, "error: checksum file %s not found\n", assessment.ChecksumFile)
			return 1
		}

		checksumPath = filepath.Join(tmpDir, checksumAsset.Name)
		if err := download(checksumAsset.BrowserDownloadUrl, checksumPath); err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}

		// #nosec G304 -- checksumPath tmp controlled
		checksumBytes, err = os.ReadFile(checksumPath)
		if err != nil {
			fmt.Fprintf(stderr, "read checksum: %v\n", err)
			return 1
		}
	}

	// #nosec G304 -- assetPath tmp controlled
	assetBytes, err := os.ReadFile(assetPath)
	if err != nil {
		fmt.Fprintf(stderr, "read asset: %v\n", err)
		return 1
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
		fmt.Fprintf(stderr, "unknown hash algo %q\n", hashAlgo)
		return 1
	}
	h.Write(assetBytes)
	actualHash := hex.EncodeToString(h.Sum(nil))

	// Verify checksum if checksum file was found
	if checksumBytes != nil {
		expectedHash, err := extractChecksum(checksumBytes, hashAlgo, selected.Name)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}
		if actualHash != strings.ToLower(expectedHash) {
			fmt.Fprintf(stderr, "checksum mismatch: expected %s, got %s\n", expectedHash, actualHash)
			return 1
		}
		fmt.Fprintln(stdout, "Checksum verified OK")
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
		fmt.Fprintf(stderr, "mkdir cache %s: %v\n", cacheAssetDir, err)
		return 1
	}
	cacheAssetPath := filepath.Join(cacheAssetDir, selected.Name)
	if err := os.Rename(assetPath, cacheAssetPath); err != nil {
		if errors.Is(err, syscall.EXDEV) {
			if errCopy := copyFile(assetPath, cacheAssetPath); errCopy != nil {
				fmt.Fprintf(stderr, "cache asset: %v\n", errCopy)
				return 1
			}
			_ = os.Remove(assetPath)
		} else {
			fmt.Fprintf(stderr, "cache asset: %v\n", err)
			return 1
		}
	}
	assetPath = cacheAssetPath
	fmt.Fprintf(stdout, "Cached to %s\n", cacheAssetPath)

	// Workflow B: Verify per-asset signature
	if assessment.Workflow == workflowB && !*skipSig {
		sigData, err := loadSignature(sigPath)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 1
		}

		switch sigData.format {
		case sigFormatPGP:
			pgpKeyPath, err := resolvePGPKey(*pgpKeyFile, *pgpKeyURL, *pgpKeyAsset, rel.Assets, tmpDir)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if err := verifyPGPSignature(assetPath, sigPath, pgpKeyPath, *gpgBin); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			fmt.Fprintln(stdout, "PGP signature verified OK")

		case sigFormatMinisign:
			minisignKeyPath, err := resolveMinisignKey(*minisignPubKey, *minisignKeyURL, *minisignKeyAsset, rel.Assets, tmpDir)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			if err := verifyMinisignSignature(assetBytes, sigPath, minisignKeyPath); err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			fmt.Fprintln(stdout, "Minisign signature verified OK")

		case sigFormatBinary:
			normalizedKey, err := normalizeHexKey(*key)
			if err != nil {
				fmt.Fprintln(stderr, err)
				return 1
			}
			pubKeyBytes, err := hex.DecodeString(normalizedKey)
			if err != nil {
				fmt.Fprintln(stderr, "invalid ed25519 key provided")
				return 1
			}
			if len(pubKeyBytes) != ed25519.PublicKeySize {
				fmt.Fprintf(stderr, "invalid pubkey size: %d\n", len(pubKeyBytes))
				return 1
			}
			pub := ed25519.PublicKey(pubKeyBytes)
			if !ed25519.Verify(pub, assetBytes, sigData.bytes) {
				fmt.Fprintln(stderr, "signature verification failed")
				return 1
			}
			fmt.Fprintln(stdout, "Signature verified OK")

		default:
			fmt.Fprintln(stderr, "error: unsupported signature format")
			return 1
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
			fmt.Fprintf(stderr, "mkdir extract: %v\n", err)
			return 1
		}

		switch classification.ArchiveFormat {
		case ArchiveFormatZip:
			if err := extractZip(assetPath, extractDir); err != nil {
				fmt.Fprintf(stderr, "extract zip: %v\n", err)
				return 1
			}
		case ArchiveFormatTarXz:
			// #nosec G204 -- assetPath tmp controlled
			cmd := exec.Command("tar", "xJf", assetPath, "-C", extractDir)
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(stderr, "extract archive: %v\n", err)
				return 1
			}
		case ArchiveFormatTarBz2:
			// #nosec G204 -- assetPath tmp controlled
			cmd := exec.Command("tar", "xjf", assetPath, "-C", extractDir)
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(stderr, "extract archive: %v\n", err)
				return 1
			}
		case ArchiveFormatTar:
			// #nosec G204 -- assetPath tmp controlled
			cmd := exec.Command("tar", "xf", assetPath, "-C", extractDir)
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(stderr, "extract archive: %v\n", err)
				return 1
			}
		case ArchiveFormatTarGz:
			fallthrough
		default:
			// #nosec G204 -- assetPath tmp controlled
			cmd := exec.Command("tar", "xzf", assetPath, "-C", extractDir)
			if err := cmd.Run(); err != nil {
				fmt.Fprintf(stderr, "extract archive: %v\n", err)
				return 1
			}
		}

		binaryPath = filepath.Join(extractDir, binaryName)
		if _, err := os.Stat(binaryPath); err != nil {
			fmt.Fprintf(stderr, "binary %s not found in archive\n", binaryName)
			return 1
		}

		if err := // #nosec G302 -- binaryPath extracted tmp chmod +x safe
			os.Chmod(binaryPath, 0o755); err != nil {
			fmt.Fprintf(stderr, "chmod: %v\n", err)
			return 1
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
		fmt.Fprintln(stderr, "error: could not resolve binary path")
		return 1
	}

	var finalPath string
	if *output != "" {
		finalPath = *output
	} else if *destDir != "" {
		finalPath = filepath.Join(*destDir, installName)
	} else {
		// No destination specified - install to current directory with warning
		fmt.Fprintf(stderr, "warning: no --dest-dir or --output specified, installing to current directory\n")
		fmt.Fprintf(stderr, "  hint: use --install to install to %s\n", userBinDirDisplay())
		finalPath = installName
	}

	if runtime.GOOS == "linux" {
		dest := filepath.Dir(finalPath)
		if dest != "." && dest != "" && hostenv.IsNoExecMount(dest) {
			fmt.Fprintf(stderr, "warning: destination %s appears to be mounted noexec; installed binaries may fail to run\n", dest)
			fmt.Fprintln(stderr, "  hint: choose a different --dest-dir/--output location; noexec cannot be fixed with chmod")
		}
	}

	if err := // #nosec G301 -- Dir(finalPath) user-controlled safe mkdir tmp
		os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		fmt.Fprintf(stderr, "mkdir %s: %v\n", filepath.Dir(finalPath), err)
		return 1
	}

	installedPath, err := installFile(binaryPath, finalPath, classification, *selfUpdate)
	if err != nil {
		fmt.Fprintf(stderr, "install to %s: %v\n", finalPath, err)
		return 1
	}

	// Windows self-update: target may be locked, write to .new file.
	if *selfUpdate && runtime.GOOS == "windows" && installedPath != finalPath {
		fmt.Fprintf(stderr, "target appears locked; new binary written to %s. Close running sfetch and replace manually.\n", installedPath)
		fmt.Fprintf(stdout, "Release: %s\n", rel.TagName)
		fmt.Fprintf(stdout, "Installed %s to %s\n", installName, installedPath)
		return 0
	}

	finalPath = installedPath

	fmt.Fprintf(stdout, "Release: %s\n", rel.TagName)
	fmt.Fprintf(stdout, "Installed %s to %s\n", installName, finalPath)

	// Output provenance record if requested
	if *provenance || *provenanceFile != "" {
		record := buildProvenanceRecord(*repo, &rel, assessment, aflags, actualHash)
		if err := outputProvenance(record, *provenanceFile); err != nil {
			fmt.Fprintf(stderr, "warning: %v\n", err)
		}
	}

	return 0
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
	// Only apply when inferred type is Archive or Unknown (don't override raw scripts/packages)
	if cfg.ArchiveType != "" && cfg.AssetType == "" && cfg.ArchiveFormat == "" {
		if cls.Type == AssetTypeArchive || cls.Type == AssetTypeUnknown {
			if fmt := archiveFormatFromString(cfg.ArchiveType); fmt != "" {
				cls.Type = AssetTypeArchive
				cls.ArchiveFormat = fmt
			}
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

func extractZip(zipPath, extractDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return fmt.Errorf("open zip %s: %w", zipPath, err)
	}
	defer r.Close()

	extractDirClean := filepath.Clean(extractDir)
	prefix := extractDirClean + string(os.PathSeparator)

	for _, f := range r.File {
		name := filepath.FromSlash(f.Name)
		cleaned := filepath.Clean(name)
		if cleaned == "." {
			continue
		}
		if cleaned == ".." || strings.HasPrefix(cleaned, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("zip slip: invalid path %q", f.Name)
		}
		if filepath.IsAbs(cleaned) || filepath.VolumeName(cleaned) != "" {
			return fmt.Errorf("zip slip: invalid path %q", f.Name)
		}

		destPath := filepath.Join(extractDirClean, cleaned)
		destPathClean := filepath.Clean(destPath)
		if destPathClean != extractDirClean && !strings.HasPrefix(destPathClean, prefix) {
			return fmt.Errorf("zip slip: invalid path %q", f.Name)
		}

		mode := f.Mode()
		if mode&os.ModeSymlink != 0 {
			return fmt.Errorf("zip contains symlink %q", f.Name)
		}
		if mode&os.ModeType != 0 && !mode.IsDir() {
			return fmt.Errorf("zip contains unsupported file type %q", f.Name)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(destPathClean, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", destPathClean, err)
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(destPathClean), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(destPathClean), err)
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("open %s in zip: %w", f.Name, err)
		}

		out, err := os.OpenFile(destPathClean, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
		if err != nil {
			_ = rc.Close()
			return fmt.Errorf("create %s: %w", destPathClean, err)
		}

		if _, err := io.Copy(out, rc); err != nil {
			_ = out.Close()
			_ = rc.Close()
			return fmt.Errorf("write %s: %w", destPathClean, err)
		}
		if err := out.Close(); err != nil {
			_ = rc.Close()
			return fmt.Errorf("close %s: %w", destPathClean, err)
		}
		if err := rc.Close(); err != nil {
			return fmt.Errorf("close %s in zip: %w", f.Name, err)
		}

		if runtime.GOOS != "windows" {
			perm := mode.Perm()
			if perm != 0 {
				if err := os.Chmod(destPathClean, perm); err != nil {
					return fmt.Errorf("chmod %s: %w", destPathClean, err)
				}
			}
		}
	}

	return nil
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
	// Signature file extensions
	if strings.HasSuffix(lower, ".asc") || strings.HasSuffix(lower, ".sig") ||
		strings.HasSuffix(lower, ".sig.ed25519") || strings.HasSuffix(lower, ".minisig") {
		return true
	}
	// Checksum files (substring match is safe - no common tools named these patterns)
	if strings.Contains(lower, "sha256") || strings.Contains(lower, "sha512") ||
		strings.Contains(lower, "sha2-256") || strings.Contains(lower, "sha2-512") ||
		strings.Contains(lower, "checksum") {
		return true
	}
	// Public key files
	if strings.HasSuffix(lower, ".pub") {
		return true
	}
	return false
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

type renameFunc func(oldPath, newPath string) error

func installFile(src, dst string, classification AssetClassification, selfUpdate bool) (string, error) {
	return installFileWithRename(src, dst, classification, selfUpdate, os.Rename)
}

func installFileWithRename(src, dst string, classification AssetClassification, selfUpdate bool, rename renameFunc) (string, error) {
	if err := rename(src, dst); err != nil {
		// Windows self-update: target may be locked, write to .new file.
		if selfUpdate && runtime.GOOS == "windows" {
			alt := dst + ".new"
			if errAlt := rename(src, alt); errAlt == nil {
				return alt, nil
			}
		}
		// Fallback to copy for cross-device errors (EXDEV) or self-update.
		// EXDEV occurs when tmpDir and destDir are on different filesystems,
		// common in CI containers with mounted volumes.
		if errors.Is(err, syscall.EXDEV) || selfUpdate {
			if errCopy := copyFile(src, dst); errCopy != nil {
				return "", errCopy
			}
			if classification.Type == AssetTypeRaw && runtime.GOOS != "windows" && classification.NeedsChmod {
				if errChmod := os.Chmod(dst, 0o755); errChmod != nil {
					return "", errChmod
				}
			}
			return dst, nil
		}
		return "", err
	}

	if classification.Type == AssetTypeRaw && runtime.GOOS != "windows" && classification.NeedsChmod {
		if err := os.Chmod(dst, 0o755); err != nil {
			return "", err
		}
	}

	return dst, nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open %s: %w", src, err)
	}
	defer in.Close()

	srcInfo, err := in.Stat()
	if err != nil {
		return fmt.Errorf("stat %s: %w", src, err)
	}

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
	if err := os.Chmod(tmp, srcInfo.Mode().Perm()); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod %s: %w", tmp, err)
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

func userBinDirPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(home, "bin"), nil
	}
	return filepath.Join(home, ".local", "bin"), nil
}

func userBinDirDisplay() string {
	if runtime.GOOS == "windows" {
		return "%USERPROFILE%\\bin"
	}
	return "~/.local/bin"
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
