package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
)

type corpusEntry struct {
	Repo             string `json:"repo"`
	Tag              string `json:"tag"`
	AssetMatch       string `json:"assetMatch"`
	AssetRegex       string `json:"assetRegex"`
	ExpectedWorkflow string `json:"expectedWorkflow"`
	ExpectSuccess    bool   `json:"expectSuccess"`
	Tier             string `json:"tier"`
	Category         string `json:"category"`
	Note             string `json:"note"`
	Pattern          string `json:"pattern"`
	AllowHTTP        bool   `json:"allowHTTP"`
}

type result struct {
	Repo        string `json:"repo"`
	Tag         string `json:"tag"`
	Asset       string `json:"asset"`
	Tier        string `json:"tier"`
	Expected    bool   `json:"expectedSuccess"`
	ExitSuccess bool   `json:"exitSuccess"`
	Status      string `json:"status"`
	Note        string `json:"note,omitempty"`
	Pattern     string `json:"pattern,omitempty"`
	Output      string `json:"output,omitempty"`
}

func main() {
	manifestPath := flag.String("manifest", "testdata/corpus.json", "path to corpus manifest")
	sfetchBinFlag := flag.String("sfetch-bin", "", "path to sfetch binary to run")
	includeSlow := flag.Bool("include-slow", false, "include slow/large entries")
	dryRunOnly := flag.Bool("dry-run", true, "perform dry-run only (no downloads)")
	destDirFlag := flag.String("dest", "", "destination dir for downloads (when dry-run is false)")
	flag.Parse()

	manifest := firstSet(*manifestPath, os.Getenv("CORPUS_MANIFEST"))
	destDir := firstSet(*destDirFlag, os.Getenv("CORPUS_DEST"), "test-corpus")
	sfetchBin := firstSet(*sfetchBinFlag, os.Getenv("CORPUS_SFETCH_BIN"), "sfetch")

	entries, err := loadManifest(manifest)
	if err != nil {
		fatalf("load manifest: %v", err)
	}
	if err := validateEntries(entries); err != nil {
		fatalf("manifest validation failed: %v", err)
	}

	if _, err := os.Stat(destDir); err != nil {
		fatalf("destination %s not found (create it or set CORPUS_DEST)", destDir)
	}

	var results []result
	var failures int

	for _, e := range entries {
		if strings.EqualFold(e.Tier, "slow") && !*includeSlow {
			continue
		}

		res := runEntry(e, *dryRunOnly, destDir, sfetchBin)
		results = append(results, res)
		if res.Status != "pass" {
			failures++
		}
	}

	for _, r := range results {
		fmt.Printf("[%s] %s@%s asset=%s tier=%s expected=%v gotExit=%v", strings.ToUpper(r.Status), r.Repo, r.Tag, r.Asset, r.Tier, r.Expected, r.ExitSuccess)
		if r.Note != "" {
			fmt.Printf(" note=%s", r.Note)
		}
		if r.Pattern != "" {
			fmt.Printf(" pattern=%s", r.Pattern)
		}
		fmt.Println()
		if r.Status != "pass" && strings.TrimSpace(r.Output) != "" {
			fmt.Printf("  output:\n%s\n", r.Output)
		}
	}

	if failures > 0 {
		os.Exit(1)
	}
}

func runEntry(e corpusEntry, dryRunOnly bool, dest, sfetchBin string) result {
	args := []string{}
	mode := "release" // default: --repo
	rawSpec := ""

	// Determine fetch mode based on URL type
	if spec, err := rawGitHubSpecFromURL(e.Repo); err == nil {
		// raw.githubusercontent.com → --github-raw
		mode = "github-raw"
		rawSpec = spec
		args = append(args, "--github-raw", rawSpec)
	} else if isGenericURL(e.Repo) {
		// Other http/https URLs → --url
		mode = "url"
		args = append(args, "--url", e.Repo, "--follow-redirects")
		if e.AllowHTTP {
			args = append(args, "--allow-http")
		}
	} else {
		// owner/repo format → --repo + --tag
		args = append(args, "--repo", e.Repo, "--tag", e.Tag)
		if e.AssetMatch != "" {
			args = append(args, "--asset-match", e.AssetMatch)
		}
		if e.AssetRegex != "" {
			args = append(args, "--asset-regex", e.AssetRegex)
		}
	}

	args = append(args, "--dry-run")
	dryRunExit, dryRunOut := runCmd(sfetchBin, args...)

	exitSuccess := dryRunExit == 0
	workflowOK := true
	if exitSuccess {
		// Only validate workflow when sfetch produced an assessment.
		workflowOK = strings.Contains(dryRunOut, "Workflow:   "+e.ExpectedWorkflow)
	}

	status := "fail"
	if exitSuccess == e.ExpectSuccess && workflowOK {
		status = "pass"
	}

	asset := e.AssetMatch
	if e.AssetRegex != "" {
		asset = e.AssetRegex
	}

	// Optional full download when requested and expecting success
	if !dryRunOnly && e.ExpectSuccess {
		var dlArgs []string
		switch mode {
		case "github-raw":
			dlArgs = []string{"--github-raw", rawSpec, "--dest-dir", dest}
		case "url":
			dlArgs = []string{"--url", e.Repo, "--follow-redirects", "--dest-dir", dest}
			if e.AllowHTTP {
				dlArgs = append(dlArgs, "--allow-http")
			}
		default:
			dlArgs = []string{"--repo", e.Repo, "--tag", e.Tag, "--dest-dir", dest}
			if e.AssetMatch != "" {
				dlArgs = append(dlArgs, "--asset-match", e.AssetMatch)
			}
			if e.AssetRegex != "" {
				dlArgs = append(dlArgs, "--asset-regex", e.AssetRegex)
			}
		}
		runCmd(sfetchBin, dlArgs...)
	}

	return result{
		Repo:        e.Repo,
		Tag:         e.Tag,
		Asset:       asset,
		Tier:        e.Tier,
		Expected:    e.ExpectSuccess,
		ExitSuccess: exitSuccess,
		Status:      status,
		Note:        e.Note,
		Pattern:     e.Pattern,
		Output:      dryRunOut,
	}
}

func runCmd(bin string, args ...string) (int, string) {
	cmd := exec.Command(bin, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			return exitErr.ExitCode(), string(out)
		}
		return 1, string(out)
	}
	return 0, string(out)
}

func loadManifest(path string) ([]corpusEntry, error) {
	f, err := os.Open(path) // #nosec G304 -- SDR-001: test harness manifest path
	if err != nil {
		return nil, err
	}
	defer f.Close() //nolint:errcheck // read-only file, close error non-critical

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	var entries []corpusEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func validateEntries(entries []corpusEntry) error {
	for i, e := range entries {
		if strings.TrimSpace(e.Repo) == "" {
			return fmt.Errorf("entry %d: repo is required", i)
		}
		if strings.TrimSpace(e.Tag) == "" {
			return fmt.Errorf("entry %d: tag is required", i)
		}
		if strings.TrimSpace(e.AssetMatch) == "" && strings.TrimSpace(e.AssetRegex) == "" {
			return fmt.Errorf("entry %d: assetMatch or assetRegex required", i)
		}
		if e.ExpectedWorkflow != "A" && e.ExpectedWorkflow != "B" && e.ExpectedWorkflow != "C" && e.ExpectedWorkflow != "none" && e.ExpectedWorkflow != "insecure" {
			return fmt.Errorf("entry %d: expectedWorkflow must be A, B, C, none, or insecure", i)
		}
		if e.Tier != "fast" && e.Tier != "slow" {
			return fmt.Errorf("entry %d: tier must be fast or slow", i)
		}
	}
	return nil
}

func rawGitHubSpecFromURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if !strings.EqualFold(parsed.Host, "raw.githubusercontent.com") {
		return "", fmt.Errorf("not raw GitHub content")
	}
	cleanedPath := path.Clean(parsed.Path)
	segments := strings.Split(strings.TrimPrefix(cleanedPath, "/"), "/")
	if len(segments) < 4 {
		return "", fmt.Errorf("invalid raw GitHub URL")
	}
	owner := segments[0]
	repo := segments[1]
	ref := segments[2]
	filePath := strings.Join(segments[3:], "/")
	if owner == "" || repo == "" || ref == "" || filePath == "" {
		return "", fmt.Errorf("invalid raw GitHub URL")
	}
	return fmt.Sprintf("%s/%s@%s:%s", owner, repo, ref, filePath), nil
}

// isGenericURL returns true if the string is an http/https URL (not raw.githubusercontent.com)
func isGenericURL(s string) bool {
	if !strings.HasPrefix(s, "http://") && !strings.HasPrefix(s, "https://") {
		return false
	}
	parsed, err := url.Parse(s)
	if err != nil {
		return false
	}
	// Exclude raw.githubusercontent.com (handled by --github-raw)
	return !strings.EqualFold(parsed.Host, "raw.githubusercontent.com")
}

func firstSet(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", args...)
	os.Exit(1)
}
