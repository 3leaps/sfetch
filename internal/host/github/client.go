package github

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// TokenSource reports where a resolved token came from. Empty when no token
// was resolved. Used for error attribution — never exposes the token value.
type TokenSource string

const (
	SourceNone       TokenSource = ""
	SourceSfetch     TokenSource = "SFETCH_GITHUB_TOKEN"
	SourceGhToken    TokenSource = "GH_TOKEN"
	SourceGithubTok  TokenSource = "GITHUB_TOKEN"
	SourceExplicit   TokenSource = "--token-env" // prefix; actual env var name appended
)

// defaultChain is the precedence used when no explicit resolver is set.
var defaultChain = []struct {
	env    string
	source TokenSource
}{
	{"SFETCH_GITHUB_TOKEN", SourceSfetch},
	{"GH_TOKEN", SourceGhToken},
	{"GITHUB_TOKEN", SourceGithubTok},
}

// TokenResolver returns a GitHub token and the name of the source it came
// from. An error means the resolver had an explicit target that could not
// be satisfied (e.g., --token-env was set to a name that is empty in env).
// Returning ("", SourceNone, nil) means "no token available, proceed
// unauthenticated."
type TokenResolver interface {
	Resolve() (token string, source TokenSource, err error)
}

var (
	resolverMu      sync.RWMutex
	resolver        TokenResolver       = defaultResolver{}
	trustedHostFn   func(url string) bool = defaultTrustedHost
)

func defaultTrustedHost(url string) bool {
	return strings.Contains(url, "github.com")
}

// SetTrustedHostMatcher replaces the predicate that decides whether to
// attach the resolved GitHub token to an outbound request. The default
// matches any URL containing "github.com" (api.github.com, github.com,
// codeload.github.com). Pass nil to restore the default. Intended for
// tests that need to point at httptest servers; keep the production
// default unless you have validated the alternative.
func SetTrustedHostMatcher(fn func(url string) bool) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	if fn == nil {
		trustedHostFn = defaultTrustedHost
		return
	}
	trustedHostFn = fn
}

// SetResolver installs a custom resolver. Pass nil to restore the default
// env-chain resolver. Safe to call once from CLI startup before any HTTP
// request.
func SetResolver(r TokenResolver) {
	resolverMu.Lock()
	defer resolverMu.Unlock()
	if r == nil {
		resolver = defaultResolver{}
		return
	}
	resolver = r
}

// currentResolver returns the active resolver under read lock.
func currentResolver() TokenResolver {
	resolverMu.RLock()
	defer resolverMu.RUnlock()
	return resolver
}

// defaultResolver walks the env-chain and returns the first non-empty token.
type defaultResolver struct{}

func (defaultResolver) Resolve() (string, TokenSource, error) {
	for _, entry := range defaultChain {
		if tok := strings.TrimSpace(os.Getenv(entry.env)); tok != "" {
			return tok, entry.source, nil
		}
	}
	return "", SourceNone, nil
}

// EnvVarResolver reads the token from a single named env var. If the var is
// empty, Resolve returns an error — there is no fallback to the default
// chain, because the user explicitly chose this source via --token-env.
type EnvVarResolver struct {
	Name string
}

func (r EnvVarResolver) Resolve() (string, TokenSource, error) {
	name := strings.TrimSpace(r.Name)
	if name == "" {
		return "", SourceNone, fmt.Errorf("--token-env requires a non-empty env var name")
	}
	tok := strings.TrimSpace(os.Getenv(name))
	if tok == "" {
		return "", TokenSource(name), fmt.Errorf("--token-env %s: environment variable is empty or unset", name)
	}
	return tok, TokenSource(name), nil
}

// TokenFromEnv returns the resolved token value, or "" if none is available.
// Resolver errors are swallowed here for backwards compatibility with call
// sites that only care about the value; use ResolveToken for full context.
func TokenFromEnv() string {
	tok, _, _ := currentResolver().Resolve()
	return tok
}

// ResolveToken returns the token, its source (for error attribution), and
// any resolver error. An error from a resolver is terminal for that request:
// callers should surface it rather than retry unauthenticated.
func ResolveToken() (string, TokenSource, error) {
	return currentResolver().Resolve()
}

// Get fetches url with the resolved GitHub token attached as a Bearer
// credential when the URL targets a github.com host. Cross-host redirects
// (e.g., to pre-signed S3) rely on Go's stdlib Authorization-stripping
// behavior (since 1.17) to avoid leaking credentials.
func Get(url, userAgent string) (*http.Response, error) {
	return doGet(url, userAgent, "")
}

// GetAsset fetches a release asset via the GitHub API asset endpoint
// (https://api.github.com/repos/<o>/<r>/releases/assets/<id>). It sets
// Accept: application/octet-stream so the API returns a 302 to a signed
// download URL rather than the JSON metadata.
func GetAsset(url, userAgent string) (*http.Response, error) {
	return doGet(url, userAgent, "application/octet-stream")
}

func doGet(url, userAgent, accept string) (*http.Response, error) {
	client := &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: stripAuthOnUntrustedRedirect,
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	if shouldAttachAuth(url) {
		tok, _, err := currentResolver().Resolve()
		if err != nil {
			return nil, err
		}
		if tok != "" {
			req.Header.Set("Authorization", "Bearer "+tok)
		}
	}
	return client.Do(req)
}

// stripAuthOnUntrustedRedirect runs on every redirect hop and removes the
// Authorization header when the next hop is not on a trusted host. This
// is stronger than Go's default same-domain rule: two distinct hosts on
// the same domain (or two ports on the same IP) would otherwise inherit
// the credential. Defense-in-depth for the github→S3 hop.
func stripAuthOnUntrustedRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 10 {
		return http.ErrUseLastResponse
	}
	if !shouldAttachAuth(req.URL.String()) {
		req.Header.Del("Authorization")
	}
	return nil
}

// shouldAttachAuth is true when the URL targets a host trusted to receive
// the GitHub token. Pre-signed S3 URLs deliberately do not receive the
// Authorization header. Go's stdlib also strips Authorization on
// cross-host redirects (≥ 1.17), but this predicate avoids attaching it
// in the first place when the original URL is not github-controlled.
func shouldAttachAuth(url string) bool {
	resolverMu.RLock()
	fn := trustedHostFn
	resolverMu.RUnlock()
	return fn(url)
}

// UserAgent returns the canonical User-Agent string for outbound requests.
func UserAgent(version string) string {
	return fmt.Sprintf("sfetch/%s", version)
}
