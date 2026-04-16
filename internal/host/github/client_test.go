package github

import (
	"testing"
)

// clearChain unsets every env var on the default chain so tests start clean.
func clearChain(t *testing.T) {
	t.Helper()
	for _, entry := range defaultChain {
		t.Setenv(entry.env, "")
	}
}

func TestDefaultResolver_Precedence(t *testing.T) {
	tests := []struct {
		name       string
		env        map[string]string
		wantToken  string
		wantSource TokenSource
	}{
		{
			name:       "no env set",
			env:        map[string]string{},
			wantToken:  "",
			wantSource: SourceNone,
		},
		{
			name:       "only GITHUB_TOKEN",
			env:        map[string]string{"GITHUB_TOKEN": "gh-tok"},
			wantToken:  "gh-tok",
			wantSource: SourceGithubTok,
		},
		{
			name:       "only GH_TOKEN",
			env:        map[string]string{"GH_TOKEN": "cli-tok"},
			wantToken:  "cli-tok",
			wantSource: SourceGhToken,
		},
		{
			name:       "only SFETCH_GITHUB_TOKEN",
			env:        map[string]string{"SFETCH_GITHUB_TOKEN": "sfetch-tok"},
			wantToken:  "sfetch-tok",
			wantSource: SourceSfetch,
		},
		{
			name: "SFETCH wins over GH_TOKEN and GITHUB_TOKEN",
			env: map[string]string{
				"SFETCH_GITHUB_TOKEN": "sfetch-tok",
				"GH_TOKEN":            "cli-tok",
				"GITHUB_TOKEN":        "gh-tok",
			},
			wantToken:  "sfetch-tok",
			wantSource: SourceSfetch,
		},
		{
			name: "GH_TOKEN wins over GITHUB_TOKEN",
			env: map[string]string{
				"GH_TOKEN":     "cli-tok",
				"GITHUB_TOKEN": "gh-tok",
			},
			wantToken:  "cli-tok",
			wantSource: SourceGhToken,
		},
		{
			name:       "whitespace-only value treated as empty",
			env:        map[string]string{"GITHUB_TOKEN": "   "},
			wantToken:  "",
			wantSource: SourceNone,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			clearChain(t)
			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			tok, src, err := defaultResolver{}.Resolve()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tok != tc.wantToken {
				t.Errorf("token = %q, want %q", tok, tc.wantToken)
			}
			if src != tc.wantSource {
				t.Errorf("source = %q, want %q", src, tc.wantSource)
			}
		})
	}
}

func TestEnvVarResolver_ExplicitOverride(t *testing.T) {
	clearChain(t)
	t.Setenv("PRIVATE_REPO_PAT", "scoped-pat")

	tok, src, err := EnvVarResolver{Name: "PRIVATE_REPO_PAT"}.Resolve()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "scoped-pat" {
		t.Errorf("token = %q, want %q", tok, "scoped-pat")
	}
	if string(src) != "PRIVATE_REPO_PAT" {
		t.Errorf("source = %q, want %q", src, "PRIVATE_REPO_PAT")
	}
}

func TestEnvVarResolver_EmptyValueIsHardError(t *testing.T) {
	// Even if the default chain has a token, --token-env PRIVATE_REPO_PAT with
	// PRIVATE_REPO_PAT unset must fail — no silent fallback.
	t.Setenv("GITHUB_TOKEN", "would-have-worked")
	t.Setenv("PRIVATE_REPO_PAT", "")

	_, _, err := EnvVarResolver{Name: "PRIVATE_REPO_PAT"}.Resolve()
	if err == nil {
		t.Fatal("expected error for unset explicit env var, got nil")
	}
}

func TestEnvVarResolver_BlankNameIsHardError(t *testing.T) {
	_, _, err := EnvVarResolver{Name: "   "}.Resolve()
	if err == nil {
		t.Fatal("expected error for blank --token-env name, got nil")
	}
}

func TestSetResolver_OverridesDefault(t *testing.T) {
	clearChain(t)
	t.Setenv("GITHUB_TOKEN", "default-chain-value")
	t.Setenv("CUSTOM_PAT", "explicit-value")

	t.Cleanup(func() { SetResolver(nil) })
	SetResolver(EnvVarResolver{Name: "CUSTOM_PAT"})

	tok, src, err := ResolveToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "explicit-value" {
		t.Errorf("token = %q, want %q", tok, "explicit-value")
	}
	if string(src) != "CUSTOM_PAT" {
		t.Errorf("source = %q, want %q", src, "CUSTOM_PAT")
	}
}

func TestSetResolver_NilRestoresDefault(t *testing.T) {
	clearChain(t)
	t.Setenv("GITHUB_TOKEN", "default-value")

	SetResolver(EnvVarResolver{Name: "SHOULD_BE_REPLACED"})
	SetResolver(nil)

	tok, src, err := ResolveToken()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok != "default-value" {
		t.Errorf("token = %q, want %q", tok, "default-value")
	}
	if src != SourceGithubTok {
		t.Errorf("source = %q, want %q", src, SourceGithubTok)
	}
}

func TestTokenFromEnv_BackwardCompat(t *testing.T) {
	clearChain(t)
	t.Setenv("GITHUB_TOKEN", "legacy")

	if got := TokenFromEnv(); got != "legacy" {
		t.Errorf("TokenFromEnv() = %q, want %q", got, "legacy")
	}
}

func TestShouldAttachAuth(t *testing.T) {
	tests := []struct {
		url  string
		want bool
	}{
		{"https://github.com/owner/repo/releases/download/v1/asset.tar.gz", true},
		{"https://api.github.com/repos/owner/repo/releases/assets/123", true},
		{"https://objects.githubusercontent.com/signed-url", false},
		{"https://codeload.github.com/owner/repo/tar.gz/main", true}, // github.com substring present
		{"https://example.com/not-github", false},
	}
	for _, tc := range tests {
		if got := shouldAttachAuth(tc.url); got != tc.want {
			t.Errorf("shouldAttachAuth(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}
