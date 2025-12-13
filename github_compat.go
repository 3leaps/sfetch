package main

import (
	"net/http"

	gh "github.com/3leaps/sfetch/internal/host/github"
)

func githubToken() string {
	return gh.TokenFromEnv()
}

func httpGetWithAuth(url string) (*http.Response, error) {
	return gh.Get(url, gh.UserAgent(version))
}
