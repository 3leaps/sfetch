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

	"github.com/jedisct1/go-minisign"
)

const (
	defaultAPIBase  = "https://api.github.com"
	maxCommandError = 2048
)

var version = "dev"

//go:embed docs/quickstart.txt
var quickstartDoc string

type Release struct {
	TagName string  `json:"tag_name"`
	Assets  []Asset `json:"assets"`
}

type Asset struct {
	Name               string `json:"name"`
	BrowserDownloadUrl string `json:"browser_download_url"`
	Size               int64  `json:"size"`
}

// SignatureFormats maps file extensions to verification methods.
// This allows detection of signature type from filename without inspecting content.
type SignatureFormats struct {
	Minisign []string `json:"minisign"` // verified via minisign (pure-Go)
	PGP      []string `json:"pgp"`      // verified via gpg sidecar
	Ed25519  []string `json:"ed25519"`  // verified as raw ed25519 (pure-Go)
}

// RepoConfig defines how sfetch discovers and verifies release artifacts.
// Schema: schemas/repo-config.schema.json
type RepoConfig struct {
	BinaryName            string           `json:"binaryName"`
	HashAlgo              string           `json:"hashAlgo"`
	ArchiveType           string           `json:"archiveType"`
	ArchiveExtensions     []string         `json:"archiveExtensions"`
	AssetPatterns         []string         `json:"assetPatterns"`
	ChecksumCandidates    []string         `json:"checksumCandidates"`
	ChecksumSigCandidates []string         `json:"checksumSigCandidates"` // Workflow A: sigs over checksum files
	SignatureCandidates   []string         `json:"signatureCandidates"`   // Workflow B: per-asset sigs
	SignatureFormats      SignatureFormats `json:"signatureFormats"`
	PreferChecksumSig     *bool            `json:"preferChecksumSig,omitempty"` // prefer Workflow A over B; nil = use default (true)
}

var defaults = RepoConfig{
	BinaryName:        "sfetch",
	HashAlgo:          "sha256",
	ArchiveType:       "tar.gz",
	ArchiveExtensions: []string{".tar.gz", ".tgz", ".zip"},
	AssetPatterns: []string{
		"(?i)^{{binary}}[_-]{{osToken}}[_-]{{archToken}}.*",
		"(?i)^{{binary}}.*{{osToken}}.*{{archToken}}.*",
	},
	ChecksumCandidates: []string{
		"{{asset}}.sha256",
		"{{asset}}.sha256.txt",
		"{{base}}.sha256",
		"{{base}}.sha256.txt",
		"SHA256SUMS",
		"SHA256SUMS.txt",
		"checksums.txt",
		"CHECKSUMS",
		"CHECKSUMS.txt",
	},
	// Workflow A: signatures over checksum files (preferred)
	ChecksumSigCandidates: []string{
		"SHA256SUMS.minisig",
		"SHA256SUMS.txt.minisig",
		"checksums.txt.minisig",
		"CHECKSUMS.minisig",
		"SHA256SUMS.asc",
		"SHA256SUMS.txt.asc",
		"checksums.txt.asc",
		"CHECKSUMS.asc",
	},
	// Workflow B: per-asset signatures
	SignatureCandidates: []string{
		"{{asset}}.minisig",
		"{{asset}}.sig",
		"{{asset}}.sig.ed25519",
		"{{base}}.sig",
		"{{base}}.sig.ed25519",
		"{{asset}}.asc",
		"{{base}}.asc",
	},
	// Extension to verification method mapping
	SignatureFormats: SignatureFormats{
		Minisign: []string{".minisig"},
		PGP:      []string{".asc", ".gpg", ".sig.asc"},
		Ed25519:  []string{".sig", ".sig.ed25519"},
	},
	PreferChecksumSig: boolPtr(true),
}

// boolPtr returns a pointer to a bool value
func boolPtr(v bool) *bool { return &v }

// preferChecksumSig returns whether to prefer checksum-level signatures.
// Defaults to true if not explicitly set.
func (c *RepoConfig) preferChecksumSig() bool {
	if c.PreferChecksumSig == nil {
		return true // default
	}
	return *c.PreferChecksumSig
}

// repoConfigs holds overrides for repos that don't follow standard patterns.
// Most repos work without entries here - BinaryName is inferred from repo name,
// ArchiveType is inferred from asset extension. Only add entries for edge cases.
var repoConfigs = map[string]RepoConfig{
	// Example: repos where binary name differs from repo name
	// "owner/repo": {BinaryName: "actual-binary-name"},
}

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
	base := strings.TrimSpace(os.Getenv("SFETCH_API_BASE"))
	if base == "" {
		return defaultAPIBase
	}
	return strings.TrimRight(base, "/")
}

func main() {
	repo := flag.String("repo", "", "GitHub repo owner/repo")
	tag := flag.String("tag", "", "release tag (mutually exclusive with --latest)")
	latest := flag.Bool("latest", false, "fetch latest release (mutually exclusive with --tag)")
	output := flag.String("output", "", "output path")
	assetRegex := flag.String("asset-regex", "", "asset name regex (overrides auto-detect)")
	key := flag.String("key", "", "ed25519 pubkey hex (32 bytes)")
	minisignPubKey := flag.String("minisign-key", "", "path to minisign public key file (.pub)")
	minisignKeyURL := flag.String("minisign-key-url", "", "URL to download minisign public key")
	minisignKeyAsset := flag.String("minisign-key-asset", "", "release asset name for minisign public key")
	requireMinisign := flag.Bool("require-minisign", false, "require minisign signature verification (fail if unavailable)")
	preferPerAsset := flag.Bool("prefer-per-asset", false, "prefer per-asset signatures over checksum-level signatures (Workflow B over A)")
	pgpKeyFile := flag.String("pgp-key-file", "", "path to ASCII-armored PGP public key")
	pgpKeyURL := flag.String("pgp-key-url", "", "URL to download ASCII-armored PGP public key")
	pgpKeyAsset := flag.String("pgp-key-asset", "", "release asset name for ASCII-armored PGP public key")
	gpgBin := flag.String("gpg-bin", "gpg", "path to gpg executable")
	binaryNameFlag := flag.String("binary-name", "", "binary name to extract (default: inferred from repo name)")
	destDir := flag.String("dest-dir", "", "destination directory")
	cacheDir := flag.String("cache-dir", "", "cache directory")
	selfVerify := flag.Bool("self-verify", false, "self-verify mode")
	skipSig := flag.Bool("skip-sig", false, "skip signature verification (testing only)")
	skipToolsCheck := flag.Bool("skip-tools-check", false, "skip preflight tool checks")
	jsonOut := flag.Bool("json", false, "JSON output for CI")
	extendedHelp := flag.Bool("helpextended", false, "print quickstart & examples")
	versionFlag := flag.Bool("version", false, "print version")
	flag.Parse()

	if *selfVerify {
		*repo = "3leaps/sfetch"
		*latest = true
		*output = ""
		*destDir = ""
	}

	_ = *output     // TODO
	_ = *assetRegex // TODO
	_ = *key        // TODO
	_ = *destDir    // TODO
	_ = *cacheDir   // TODO
	_ = *selfVerify // TODO
	_ = *jsonOut    // TODO

	if *versionFlag {
		fmt.Println("sfetch", version)
		return
	}

	if *extendedHelp {
		fmt.Println(strings.TrimSpace(quickstartDoc))
		return
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
	url := fmt.Sprintf("%s/repos/%s/releases/%s", baseURL, *repo, releaseID)

	// #nosec G107 -- url GitHub API fmt.Sprintf controlled
	resp, err := http.Get(url)
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

	cfg := getConfig(*repo)

	// Apply CLI override for binary name
	if *binaryNameFlag != "" {
		cfg.BinaryName = *binaryNameFlag
	}

	goos := runtime.GOOS
	goarch := runtime.GOARCH

	selected, err := selectAsset(&rel, cfg, goos, goarch, *assetRegex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// Infer archive type from selected asset extension
	if inferred := inferArchiveType(selected.Name); inferred != "" {
		cfg.ArchiveType = inferred
	}

	fmt.Fprintf(os.Stderr, "DEBUG repo=%q BinaryName=%q ArchiveType=%q Asset=%q\n",
		*repo, cfg.BinaryName, cfg.ArchiveType, selected.Name)

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

	baseName := trimKnownExtension(selected.Name, cfg.ArchiveExtensions)
	ctx := templateContext{
		AssetName:  selected.Name,
		BaseName:   baseName,
		BinaryName: cfg.BinaryName,
		GOOS:       goos,
		GOARCH:     goarch,
	}

	// Check for checksum-level signature first (Workflow A: signature over checksum file)
	checksumSigAsset, checksumFileName := findChecksumSignature(rel.Assets, cfg)
	// Use checksum-level sig if: (1) it exists AND (2) config prefers it OR --require-minisign forces minisign path
	// UNLESS --prefer-per-asset is set, which forces Workflow B
	useChecksumLevelSig := checksumSigAsset != nil && (cfg.preferChecksumSig() || *requireMinisign) && !*preferPerAsset

	// --prefer-per-asset: verify per-asset signatures exist before bypassing Workflow A
	if *preferPerAsset && checksumSigAsset != nil {
		fmt.Fprintf(os.Stderr, "Note: --prefer-per-asset specified, bypassing checksum-level signature (%s)\n", checksumSigAsset.Name)
	}

	// --require-minisign: validate that minisign signature is available and will be used
	if *requireMinisign {
		checksumSigIsMinisign := checksumSigAsset != nil &&
			signatureFormatFromExtension(checksumSigAsset.Name, cfg.SignatureFormats) == sigFormatMinisign

		if checksumSigIsMinisign {
			// Checksum-level minisign available - force using it
			useChecksumLevelSig = true
		} else {
			// Check for per-asset minisign sig as fallback
			perAssetMinisig := false
			for _, candidate := range cfg.SignatureCandidates {
				if strings.Contains(candidate, ".minisig") {
					rendered := renderTemplate(candidate, ctx)
					if findAssetByName(rel.Assets, rendered) != nil {
						perAssetMinisig = true
						break
					}
				}
			}
			if perAssetMinisig {
				// Force per-asset path (Workflow B) for minisign verification
				useChecksumLevelSig = false
			} else {
				fmt.Fprintln(os.Stderr, "error: --require-minisign specified but no .minisig signature found in release")
				os.Exit(1)
			}
		}
	}

	var checksumAsset *Asset
	var sigAsset *Asset
	var sigPath string
	var checksumPath string
	var checksumBytes []byte

	if useChecksumLevelSig {
		// Workflow A: Verify signature over checksum file, then verify hash
		fmt.Fprintf(os.Stderr, "Detected checksum-level signature: %s\n", checksumSigAsset.Name)

		// Find the checksum file
		checksumAsset = findAssetByName(rel.Assets, checksumFileName)
		if checksumAsset == nil {
			fmt.Fprintf(os.Stderr, "error: checksum file %s not found\n", checksumFileName)
			os.Exit(1)
		}

		// Download checksum file
		checksumPath = filepath.Join(tmpDir, checksumAsset.Name)
		if err := download(checksumAsset.BrowserDownloadUrl, checksumPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Download checksum signature
		sigPath = filepath.Join(tmpDir, checksumSigAsset.Name)
		if err := download(checksumSigAsset.BrowserDownloadUrl, sigPath); err != nil {
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
			sigFormat := signatureFormatFromExtension(checksumSigAsset.Name, cfg.SignatureFormats)
			switch sigFormat {
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
				fmt.Fprintf(os.Stderr, "error: unknown signature format for %s\n", checksumSigAsset.Name)
				os.Exit(1)
			}
		} else {
			fmt.Fprintln(os.Stderr, "warning: --skip-sig enabled; signature verification skipped")
		}
	} else {
		// Workflow B: Per-asset signature (original behavior)
		// Find signature first - it's required
		sigAsset, err = findSupplementalAsset(rel.Assets, ctx, cfg.SignatureCandidates, [][]string{
			{strings.ToLower(baseName), "sig"},
			{strings.ToLower(baseName), "signature"},
			{"minisig"},
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}

		sigPath = filepath.Join(tmpDir, sigAsset.Name)
		if err := download(sigAsset.BrowserDownloadUrl, sigPath); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// In Workflow B (per-asset), the signature directly verifies the asset bytes.
		// Checksum is optional since the signature provides integrity verification.
		// This applies to minisign, GPG, and ed25519 per-asset signatures.
		sigFormat := signatureFormatFromExtension(sigAsset.Name, cfg.SignatureFormats)

		// When --prefer-per-asset is set, skip checksum file entirely (trust the signature)
		if *preferPerAsset {
			fmt.Fprintf(os.Stderr, "Skipping checksum verification; using %s per-asset signature for integrity\n", sigFormat)
		} else {
			checksumAsset, _ = findSupplementalAsset(rel.Assets, ctx, cfg.ChecksumCandidates, [][]string{
				{strings.ToLower(baseName), "sha"},
				{"sha256sum"},
				{"checksum"},
			})

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
			} else if sigFormat == sigFormatBinary {
				// Raw ed25519 requires checksum for integrity (signature alone isn't sufficient
				// without knowing what was signed - could be hash of asset or asset itself)
				fmt.Fprintf(os.Stderr, "error: no checksum file found for %s (required for raw ed25519 signatures)\n", selected.Name)
				os.Exit(1)
			} else {
				fmt.Fprintf(os.Stderr, "No checksum file found; using %s signature for integrity verification\n", sigFormat)
			}
		}
	}

	// #nosec G304 -- assetPath tmp controlled
	assetBytes, err := os.ReadFile(assetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read asset: %v\n", err)
		os.Exit(1)
	}

	// Compute hash for caching (and verification if checksum file exists)
	var h hash.Hash
	switch cfg.HashAlgo {
	case "sha256":
		h = sha256.New()
	case "sha512":
		h = sha512.New()
	default:
		fmt.Fprintf(os.Stderr, "unknown hash algo %q\n", cfg.HashAlgo)
		os.Exit(1)
	}
	h.Write(assetBytes)
	actualHash := hex.EncodeToString(h.Sum(nil))

	// Verify checksum if checksum file was found
	if checksumBytes != nil {
		expectedHash, err := extractChecksum(checksumBytes, cfg.HashAlgo, selected.Name)
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

	// Workflow B: Verify per-asset signature (only if not using checksum-level sig)
	if !useChecksumLevelSig {
		sigData, err := loadSignature(sigPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}

		// Enforce minisign format when --require-minisign is set
		if *requireMinisign && sigData.format != sigFormatMinisign {
			fmt.Fprintf(os.Stderr, "error: --require-minisign specified but signature %s is %s format, not minisign\n", sigAsset.Name, sigData.format)
			os.Exit(1)
		}

		if *skipSig {
			fmt.Fprintln(os.Stderr, "warning: --skip-sig enabled; signature verification skipped")
		} else {
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
	}

	binaryName := cfg.BinaryName
	extractDir := filepath.Join(tmpDir, "extract")
	if err := // #nosec G301 -- extractDir tmpdir controlled
		os.Mkdir(extractDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir extract: %v\n", err)
		os.Exit(1)
	}

	var cmd *exec.Cmd
	if cfg.ArchiveType == "zip" {
		// #nosec G204 -- assetPath tmp controlled
		cmd = exec.Command("unzip", "-q", assetPath, "-d", extractDir)
	} else {
		// #nosec G204 -- assetPath tmp controlled
		cmd = exec.Command("tar", "xzf", assetPath, "-C", extractDir)
	}
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "extract archive: %v\n", err)
		os.Exit(1)
	}

	binaryPath := filepath.Join(extractDir, binaryName)
	if _, err := os.Stat(binaryPath); err != nil {
		fmt.Fprintf(os.Stderr, "binary %s not found in archive\n", binaryName)
		os.Exit(1)
	}

	if err := // #nosec G302 -- binaryPath extracted tmp chmod +x safe
		os.Chmod(binaryPath, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "chmod: %v\n", err)
		os.Exit(1)
	}

	var finalPath string
	if *output != "" {
		finalPath = *output
	} else if *destDir != "" {
		finalPath = filepath.Join(*destDir, binaryName)
	} else {
		finalPath = binaryName
	}

	if err := // #nosec G301 -- Dir(finalPath) user-controlled safe mkdir tmp
		os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir %s: %v\n", filepath.Dir(finalPath), err)
		os.Exit(1)
	}

	if err := os.Rename(binaryPath, finalPath); err != nil {
		fmt.Fprintf(os.Stderr, "install to %s: %v\n", finalPath, err)
		os.Exit(1)
	}

	fmt.Printf("Release: %s\n", rel.TagName)
	fmt.Printf("Installed %s to %s\n", binaryName, finalPath)
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

// inferArchiveType determines archive type from asset filename extension.
// Returns "zip" for .zip files, "tar.gz" for .tar.gz/.tgz, empty string if unknown.
func inferArchiveType(assetName string) string {
	lower := strings.ToLower(assetName)
	switch {
	case strings.HasSuffix(lower, ".zip"):
		return "zip"
	case strings.HasSuffix(lower, ".tar.gz"), strings.HasSuffix(lower, ".tgz"):
		return "tar.gz"
	case strings.HasSuffix(lower, ".tar.xz"):
		return "tar.xz"
	case strings.HasSuffix(lower, ".tar.bz2"):
		return "tar.bz2"
	default:
		return ""
	}
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
	// #nosec G107 -- url GitHub API fmt.Sprintf controlled
	resp, err := http.Get(url)
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
	AssetName  string
	BaseName   string
	BinaryName string
	GOOS       string
	GOARCH     string
}

func selectAsset(rel *Release, cfg *RepoConfig, goos, goarch, assetRegex string) (*Asset, error) {
	if assetRegex != "" {
		re, err := regexp.Compile(assetRegex)
		if err != nil {
			return nil, fmt.Errorf("invalid --asset-regex: %w", err)
		}
		return matchWithRegex(rel.Assets, re)
	}

	if len(cfg.AssetPatterns) > 0 {
		if asset := matchWithPatterns(rel.Assets, cfg, goos, goarch); asset != nil {
			return asset, nil
		}
	}

	return pickByHeuristics(rel.Assets, cfg, goos, goarch)
}

func matchWithRegex(assets []Asset, re *regexp.Regexp) (*Asset, error) {
	var selected *Asset
	for i := range assets {
		if re.MatchString(assets[i].Name) {
			if selected != nil {
				return nil, fmt.Errorf("multiple assets match regex: %s and %s", selected.Name, assets[i].Name)
			}
			selected = &assets[i]
		}
	}
	if selected == nil {
		return nil, fmt.Errorf("no asset matches provided regex")
	}
	return selected, nil
}

func matchWithPatterns(assets []Asset, cfg *RepoConfig, goos, goarch string) *Asset {
	for _, pattern := range cfg.AssetPatterns {
		regexStr := renderPattern(pattern, cfg, goos, goarch)
		re, err := regexp.Compile(regexStr)
		if err != nil {
			continue
		}
		match, err := matchWithRegex(assets, re)
		if err == nil {
			return match
		}
	}
	return nil
}

func pickByHeuristics(assets []Asset, cfg *RepoConfig, goos, goarch string) (*Asset, error) {
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

func findSupplementalAsset(assets []Asset, ctx templateContext, templates []string, fallback [][]string) (*Asset, error) {
	if asset := findAssetByTemplates(assets, ctx, templates); asset != nil {
		return asset, nil
	}
	if asset := findAssetByKeywords(assets, ctx.AssetName, fallback); asset != nil {
		return asset, nil
	}
	return nil, fmt.Errorf("missing supplemental asset for %s", ctx.AssetName)
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
	resp, err := http.Get(src)
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
	resp, err := http.Get(src)
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

func findAssetByTemplates(assets []Asset, ctx templateContext, templates []string) *Asset {
	for _, tpl := range templates {
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
	}
	return strings.NewReplacer(replacements...).Replace(tpl)
}

func findAssetByKeywords(assets []Asset, skip string, groups [][]string) *Asset {
	for _, group := range groups {
		keywords := make([]string, 0, len(group))
		for _, kw := range group {
			if kw != "" {
				keywords = append(keywords, strings.ToLower(kw))
			}
		}
		if len(keywords) == 0 {
			continue
		}
		for i := range assets {
			if assets[i].Name == skip {
				continue
			}
			nameLower := strings.ToLower(assets[i].Name)
			if containsAll(nameLower, keywords) {
				return &assets[i]
			}
		}
	}
	return nil
}

func containsAll(haystack string, keywords []string) bool {
	for _, kw := range keywords {
		if !strings.Contains(haystack, kw) {
			return false
		}
	}
	return true
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
