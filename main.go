package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
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

var version = "dev"

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
	},
}

var repoConfigs = map[string]RepoConfig{
	"3leaps/sfetch": defaults,
}

func main() {
	repo := flag.String("repo", "", "GitHub repo owner/repo")
	tag := flag.String("tag", "", "release tag (mutually exclusive with --latest)")
	latest := flag.Bool("latest", false, "fetch latest release (mutually exclusive with --tag)")
	output := flag.String("output", "", "output path")
	assetRegex := flag.String("asset-regex", "", "asset name regex (overrides auto-detect)")
	key := flag.String("key", "", "ed25519 pubkey hex (32 bytes)")
	destDir := flag.String("dest-dir", "", "destination directory")
	cacheDir := flag.String("cache-dir", "", "cache directory")
	selfVerify := flag.Bool("self-verify", false, "self-verify mode")
	jsonOut := flag.Bool("json", false, "JSON output for CI")
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

	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/%s", *repo, releaseID)

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
	if err := os.MkdirAll(cacheAssetDir, 0o755); err != nil {
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

	sigBytes, err := loadSignature(sigPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	pubKeyBytes, err := hex.DecodeString(*key)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid pubkey hex: %v\n", err)
		os.Exit(1)
	}
	if len(pubKeyBytes) != ed25519.PublicKeySize {
		fmt.Fprintf(os.Stderr, "invalid pubkey size: %d\n", len(pubKeyBytes))
		os.Exit(1)
	}

	pub := ed25519.PublicKey(pubKeyBytes)
	if !ed25519.Verify(pub, assetBytes, sigBytes) {
		fmt.Fprintln(os.Stderr, "signature verification failed")
		os.Exit(1)
	}
	fmt.Println("Signature verified OK")

	binaryName := cfg.BinaryName
	extractDir := filepath.Join(tmpDir, "extract")
	if err := os.Mkdir(extractDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir extract: %v\n", err)
		os.Exit(1)
	}

	var cmd *exec.Cmd
	if cfg.ArchiveType == "zip" {
		cmd = exec.Command("unzip", "-q", assetPath, "-d", extractDir)
	} else {
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

	if err := os.Chmod(binaryPath, 0o755); err != nil {
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

	if err := os.MkdirAll(filepath.Dir(finalPath), 0o755); err != nil {
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
	if c, ok := repoConfigs[repo]; ok {
		return &c
	}
	return &defaults
}

func download(url, path string) error {
	resp, err := http.Get(url)
	if err != nil {
		return fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("status %d from %s: %s", resp.StatusCode, url, string(body))
	}

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
	bestScore := 0
	var best *Asset

	for i := range assets {
		nameLower := strings.ToLower(assets[i].Name)
		if looksLikeSupplemental(nameLower) {
			continue
		}
		score := 0
		if containsAny(nameLower, goosAliases) {
			score += 4
		}
		if containsAny(nameLower, archAliases) {
			score += 4
		}
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
	return strings.Contains(name, "sha256") || strings.Contains(name, "checksum") || strings.Contains(name, "sig") || strings.Contains(name, "signature")
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

func loadSignature(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read sig: %w", err)
	}
	if len(data) == ed25519.SignatureSize {
		return data, nil
	}
	trimmed := strings.TrimSpace(string(data))
	decoded, err := hex.DecodeString(trimmed)
	if err == nil && len(decoded) == ed25519.SignatureSize {
		return decoded, nil
	}
	return nil, fmt.Errorf("unsupported signature format in %s", path)
}
