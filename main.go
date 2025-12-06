package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/base64"
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

type RepoConfig struct {
	BinaryName          string
	HashAlgo            string
	ArchiveType         string
	ArchiveExtensions   []string
	AssetPatterns       []string
	ChecksumCandidates  []string
	SignatureCandidates []string
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
	},
	SignatureCandidates: []string{
		"{{asset}}.sig",
		"{{asset}}.sig.ed25519",
		"{{base}}.sig",
		"{{base}}.sig.ed25519",
		"{{asset}}.minisig",
		"{{asset}}.asc",
		"{{base}}.asc",
	},
}

var repoConfigs = map[string]RepoConfig{
	"fulmenhq/goneat": {BinaryName: "goneat"},
}

const (
	sigFormatBinary   = "binary"
	sigFormatPGP      = "pgp"
	sigFormatMinisign = "minisign"
)

type signatureData struct {
	format         string
	bytes          []byte
	keyID          []byte // minisign: 8-byte key ID
	trustedComment string // minisign: trusted comment (signed)
	globalSig      []byte // minisign: signature over (sig + trusted comment)
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
	pgpKeyFile := flag.String("pgp-key-file", "", "path to ASCII-armored PGP public key")
	pgpKeyURL := flag.String("pgp-key-url", "", "URL to download ASCII-armored PGP public key")
	pgpKeyAsset := flag.String("pgp-key-asset", "", "release asset name for ASCII-armored PGP public key")
	gpgBin := flag.String("gpg-bin", "gpg", "path to gpg executable")
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
	fmt.Fprintf(os.Stderr, "DEBUG repo=%q BinaryName=%q\n", *repo, cfg.BinaryName)
	goos := runtime.GOOS
	goarch := runtime.GOARCH

	selected, err := selectAsset(&rel, cfg, goos, goarch, *assetRegex)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
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

	baseName := trimKnownExtension(selected.Name, cfg.ArchiveExtensions)
	ctx := templateContext{
		AssetName:  selected.Name,
		BaseName:   baseName,
		BinaryName: cfg.BinaryName,
		GOOS:       goos,
		GOARCH:     goarch,
	}

	checksumAsset, err := findSupplementalAsset(rel.Assets, ctx, cfg.ChecksumCandidates, [][]string{
		{strings.ToLower(baseName), "sha"},
		{"sha256sum"},
		{"checksum"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	sigAsset, err := findSupplementalAsset(rel.Assets, ctx, cfg.SignatureCandidates, [][]string{
		{strings.ToLower(baseName), "sig"},
		{strings.ToLower(baseName), "signature"},
		{"minisig"},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	checksumPath := filepath.Join(tmpDir, checksumAsset.Name)
	if err := download(checksumAsset.BrowserDownloadUrl, checksumPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	sigPath := filepath.Join(tmpDir, sigAsset.Name)
	if err := download(sigAsset.BrowserDownloadUrl, sigPath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// #nosec G304 -- checksumPath tmp controlled
	checksumBytes, err := os.ReadFile(checksumPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read checksum: %v\n", err)
		os.Exit(1)
	}

	expectedHash, err := extractChecksum(checksumBytes, cfg.HashAlgo, selected.Name)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	// #nosec G304 -- assetPath tmp controlled
	assetBytes, err := os.ReadFile(assetPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read asset: %v\n", err)
		os.Exit(1)
	}

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

	if actualHash != strings.ToLower(expectedHash) {
		fmt.Fprintf(os.Stderr, "checksum mismatch: expected %s, got %s\n", expectedHash, actualHash)
		os.Exit(1)
	}
	fmt.Println("Checksum verified OK")

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

	sigData, err := loadSignature(sigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
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
			if *minisignPubKey == "" {
				fmt.Fprintln(os.Stderr, "error: --minisign-key required for .minisig signatures")
				os.Exit(1)
			}
			pubKey, err := parseMinisignPublicKey(*minisignPubKey)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			if err := verifyMinisignSignature(assetBytes, sigData, pubKey); err != nil {
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
	if override, ok := repoConfigs[repo]; ok {
		cfg := mergeConfig(defaults, override)
		return &cfg
	}
	return &defaults
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
	if len(override.SignatureCandidates) > 0 {
		cfg.SignatureCandidates = append([]string(nil), override.SignatureCandidates...)
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
	if strings.HasPrefix(trimmed, "untrusted comment:") {
		return parseMinisignSignature(trimmed)
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

// parseMinisignSignature parses a minisign .minisig file.
// Format:
//
//	untrusted comment: <text>
//	<base64: 2-byte algo "Ed" + 8-byte keyID + 64-byte sig>
//	trusted comment: <text>
//	<base64: 64-byte global sig>
func parseMinisignSignature(content string) (signatureData, error) {
	lines := strings.Split(content, "\n")
	if len(lines) < 4 {
		return signatureData{}, fmt.Errorf("minisign signature: expected 4 lines, got %d", len(lines))
	}

	// Line 0: untrusted comment (ignored)
	// Line 1: base64 signature blob
	sigBlob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return signatureData{}, fmt.Errorf("minisign signature: decode sig: %w", err)
	}
	// Expected: 2 (algo) + 8 (keyID) + 64 (sig) = 74 bytes
	if len(sigBlob) != 74 {
		return signatureData{}, fmt.Errorf("minisign signature: expected 74 bytes, got %d", len(sigBlob))
	}
	algo := sigBlob[0:2]
	if algo[0] != 0x45 || algo[1] != 0x64 { // "Ed"
		return signatureData{}, fmt.Errorf("minisign signature: unsupported algorithm %x", algo)
	}
	keyID := sigBlob[2:10]
	sig := sigBlob[10:74]

	// Line 2: trusted comment
	if !strings.HasPrefix(lines[2], "trusted comment:") {
		return signatureData{}, fmt.Errorf("minisign signature: expected 'trusted comment:' on line 3")
	}
	trustedComment := strings.TrimPrefix(lines[2], "trusted comment:")
	trustedComment = strings.TrimSpace(trustedComment)

	// Line 3: global signature
	globalSig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[3]))
	if err != nil {
		return signatureData{}, fmt.Errorf("minisign signature: decode global sig: %w", err)
	}
	if len(globalSig) != 64 {
		return signatureData{}, fmt.Errorf("minisign signature: expected 64-byte global sig, got %d", len(globalSig))
	}

	return signatureData{
		format:         sigFormatMinisign,
		bytes:          sig,
		keyID:          keyID,
		trustedComment: trustedComment,
		globalSig:      globalSig,
	}, nil
}

// minisignPublicKey holds a parsed minisign public key.
type minisignPublicKey struct {
	keyID  []byte
	pubKey ed25519.PublicKey
}

// parseMinisignPublicKey parses a minisign .pub file.
// Format:
//
//	untrusted comment: <text>
//	<base64: 2-byte algo "Ed" + 8-byte keyID + 32-byte pubkey>
func parseMinisignPublicKey(path string) (minisignPublicKey, error) {
	// #nosec G304 -- path controlled by user flag
	data, err := os.ReadFile(path)
	if err != nil {
		return minisignPublicKey{}, fmt.Errorf("read minisign pubkey: %w", err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) < 2 {
		return minisignPublicKey{}, fmt.Errorf("minisign pubkey: expected at least 2 lines")
	}

	// Line 0: untrusted comment (ignored)
	// Line 1: base64 key blob
	keyBlob, err := base64.StdEncoding.DecodeString(strings.TrimSpace(lines[1]))
	if err != nil {
		return minisignPublicKey{}, fmt.Errorf("minisign pubkey: decode: %w", err)
	}
	// Expected: 2 (algo) + 8 (keyID) + 32 (pubkey) = 42 bytes
	if len(keyBlob) != 42 {
		return minisignPublicKey{}, fmt.Errorf("minisign pubkey: expected 42 bytes, got %d", len(keyBlob))
	}
	algo := keyBlob[0:2]
	if algo[0] != 0x45 || algo[1] != 0x64 { // "Ed"
		return minisignPublicKey{}, fmt.Errorf("minisign pubkey: unsupported algorithm %x", algo)
	}

	return minisignPublicKey{
		keyID:  keyBlob[2:10],
		pubKey: ed25519.PublicKey(keyBlob[10:42]),
	}, nil
}

// verifyMinisignSignature verifies a minisign signature.
// It checks both the main signature over the file content and the global signature
// over (signature + trusted comment).
func verifyMinisignSignature(fileContent []byte, sig signatureData, pubKey minisignPublicKey) error {
	// Check key ID matches
	if !bytes.Equal(sig.keyID, pubKey.keyID) {
		return fmt.Errorf("minisign: key ID mismatch (sig: %x, key: %x)", sig.keyID, pubKey.keyID)
	}

	// Verify main signature over file content
	if !ed25519.Verify(pubKey.pubKey, fileContent, sig.bytes) {
		return fmt.Errorf("minisign: signature verification failed")
	}

	// Verify global signature over (signature + trusted comment)
	// The trusted comment is prefixed with "trusted comment: " in the global sig calculation
	globalMsg := append(sig.bytes, []byte(sig.trustedComment)...)
	if !ed25519.Verify(pubKey.pubKey, globalMsg, sig.globalSig) {
		return fmt.Errorf("minisign: global signature verification failed")
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
