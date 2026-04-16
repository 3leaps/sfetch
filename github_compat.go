package main

import (
	"net/http"

	gh "github.com/3leaps/sfetch/internal/host/github"
)

// Re-export TokenSource so call sites in main.go don't need to import gh
// directly. Mirrors the model_aliases.go pattern.
type ghTokenSource = gh.TokenSource

const ghSourceNone = gh.SourceNone

func githubToken() string {
	return gh.TokenFromEnv()
}

// resolveGithubToken returns the token value, the env-var name it came from
// (or "" if none), and any resolver error. Used for authenticated requests
// that need to attribute the token source in error messages.
func resolveGithubToken() (string, gh.TokenSource, error) {
	return gh.ResolveToken()
}

// setTokenEnvOverride installs an EnvVarResolver for --token-env <name>.
// Call before any HTTP request; pass "" to restore the default chain.
func setTokenEnvOverride(name string) {
	if name == "" {
		gh.SetResolver(nil)
		return
	}
	gh.SetResolver(gh.EnvVarResolver{Name: name})
}

func httpGetWithAuth(url string) (*http.Response, error) {
	return gh.Get(url, gh.UserAgent(version))
}

// httpGetAssetAPI fetches a release asset via the API endpoint. Sets
// `Accept: application/octet-stream` so the API returns a 302 to the signed
// download URL rather than JSON metadata.
func httpGetAssetAPI(url string) (*http.Response, error) {
	return gh.GetAsset(url, gh.UserAgent(version))
}
