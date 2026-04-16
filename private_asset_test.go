package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gh "github.com/3leaps/sfetch/internal/host/github"
)

// TestDownloadAsset_PrivateRepoUsesAPIEndpoint asserts that when a token
// is available, downloadAsset hits the API asset endpoint with
// Accept: application/octet-stream + Authorization: Bearer, follows the
// 302 to a signed URL on a different host (different httptest port), and
// writes the asset to disk — without leaking the Authorization header to
// the signed-URL host (Go's stdlib strips Authorization on cross-host
// redirects since 1.17).
func TestDownloadAsset_PrivateRepoUsesAPIEndpoint(t *testing.T) {
	const wantBody = "private-asset-bytes"
	const tokenValue = "ghp_test_token_xyz"

	var (
		mu                      sync.Mutex
		signedAuthorizationSeen string
		apiAuthorizationSeen    string
		apiAcceptSeen           string
		signedHandlerHitCount   int
		apiHandlerHitCount      int
	)

	// The signed-URL server runs on its own port to make the redirect
	// truly cross-host from net/http's perspective.
	signedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		signedAuthorizationSeen = r.Header.Get("Authorization")
		signedHandlerHitCount++
		mu.Unlock()
		_, _ = w.Write([]byte(wantBody))
	}))
	t.Cleanup(signedSrv.Close)

	apiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		apiAuthorizationSeen = r.Header.Get("Authorization")
		apiAcceptSeen = r.Header.Get("Accept")
		apiHandlerHitCount++
		mu.Unlock()
		http.Redirect(w, r, signedSrv.URL+"/asset-bytes?sig=opaque", http.StatusFound)
	}))
	t.Cleanup(apiSrv.Close)

	// Trust the API host; never trust the signed host. Mirrors prod
	// where api.github.com is trusted and S3-style hosts are not.
	signedHost, err := url.Parse(signedSrv.URL)
	if err != nil {
		t.Fatalf("parse signed URL: %v", err)
	}
	gh.SetTrustedHostMatcher(func(u string) bool {
		parsed, err := url.Parse(u)
		if err != nil {
			return false
		}
		return parsed.Host != signedHost.Host
	})
	t.Cleanup(func() { gh.SetTrustedHostMatcher(nil) })

	gh.SetResolver(staticResolver{token: tokenValue, source: "TEST_TOKEN"})
	t.Cleanup(func() { gh.SetResolver(nil) })

	asset := &Asset{
		Name:               "private-asset.tar.gz",
		ID:                 123,
		URL:                apiSrv.URL + "/repos/owner/repo/releases/assets/123",
		BrowserDownloadUrl: apiSrv.URL + "/browser/private-asset.tar.gz",
	}

	dest := filepath.Join(t.TempDir(), asset.Name)
	if err := downloadAsset(asset, dest); err != nil {
		t.Fatalf("downloadAsset returned error: %v", err)
	}

	got, err := os.ReadFile(dest) // #nosec G304 -- test temp path
	if err != nil {
		t.Fatalf("read written asset: %v", err)
	}
	if string(got) != wantBody {
		t.Errorf("body = %q, want %q", got, wantBody)
	}

	mu.Lock()
	defer mu.Unlock()

	if apiHandlerHitCount != 1 {
		t.Errorf("api handler hits = %d, want 1", apiHandlerHitCount)
	}
	if signedHandlerHitCount != 1 {
		t.Errorf("signed handler hits = %d, want 1", signedHandlerHitCount)
	}
	if apiAuthorizationSeen != "Bearer "+tokenValue {
		t.Errorf("API Authorization header = %q, want %q", apiAuthorizationSeen, "Bearer "+tokenValue)
	}
	if apiAcceptSeen != "application/octet-stream" {
		t.Errorf("API Accept header = %q, want %q", apiAcceptSeen, "application/octet-stream")
	}
	if signedAuthorizationSeen != "" {
		t.Errorf("signed-URL Authorization header = %q, want empty (token leaked across host boundary)", signedAuthorizationSeen)
	}
}

// TestDownloadAsset_NoTokenFallsBackToBrowserURL asserts that without a
// token (or with a token but no Asset.URL) the helper uses the browser
// download URL — preserving today's public-repo behavior.
func TestDownloadAsset_NoTokenFallsBackToBrowserURL(t *testing.T) {
	const wantBody = "public-asset-bytes"

	var browserHits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		browserHits++
		_, _ = w.Write([]byte(wantBody))
	}))
	t.Cleanup(srv.Close)

	gh.SetResolver(staticResolver{}) // empty token
	t.Cleanup(func() { gh.SetResolver(nil) })

	asset := &Asset{
		Name:               "public-asset.tar.gz",
		BrowserDownloadUrl: srv.URL + "/asset",
	}

	dest := filepath.Join(t.TempDir(), asset.Name)
	if err := downloadAsset(asset, dest); err != nil {
		t.Fatalf("downloadAsset returned error: %v", err)
	}
	if browserHits != 1 {
		t.Errorf("browser hits = %d, want 1", browserHits)
	}
}

// TestDownloadAsset_PrivateRepo404IncludesAuthHint asserts that a 404
// from the browser URL produces an error message naming the token source
// and prescribing --token-env.
func TestDownloadAsset_PrivateRepo404IncludesAuthHint(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Not Found", http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)

	gh.SetResolver(staticResolver{token: "tok", source: "GITHUB_TOKEN"})
	t.Cleanup(func() { gh.SetResolver(nil) })
	// No Asset.URL → we fall through to the browser path even though a
	// token is present. That path should still annotate the failure.
	asset := &Asset{
		Name:               "asset.tar.gz",
		BrowserDownloadUrl: srv.URL + "/asset",
	}

	dest := filepath.Join(t.TempDir(), asset.Name)
	err := downloadAsset(asset, dest)
	if err == nil {
		t.Fatal("expected error from 404, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "GITHUB_TOKEN") {
		t.Errorf("error should name the token source GITHUB_TOKEN, got: %s", msg)
	}
	if !strings.Contains(msg, "--token-env") {
		t.Errorf("error should prescribe --token-env, got: %s", msg)
	}
}

// staticResolver is a test resolver that returns a fixed token + source.
type staticResolver struct {
	token  string
	source gh.TokenSource
}

func (r staticResolver) Resolve() (string, gh.TokenSource, error) {
	return r.token, r.source, nil
}
