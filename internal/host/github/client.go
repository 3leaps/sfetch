package github

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func TokenFromEnv() string {
	if tok := strings.TrimSpace(os.Getenv("SFETCH_GITHUB_TOKEN")); tok != "" {
		return tok
	}
	return strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
}

func Get(url, userAgent string) (*http.Response, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if tok := TokenFromEnv(); tok != "" && strings.Contains(url, "github.com") {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	return client.Do(req)
}

func UserAgent(version string) string {
	return fmt.Sprintf("sfetch/%s", version)
}
