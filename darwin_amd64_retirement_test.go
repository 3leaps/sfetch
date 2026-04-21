package main

import (
	"testing"
)

// TestHasDarwinAMD64Asset covers the helper that drives the
// --self-update retirement hint (ADR-0002). When a target release
// lacks a darwin/amd64 asset, sfetch surfaces the retirement
// guidance instead of the generic asset-selection error.
func TestHasDarwinAMD64Asset(t *testing.T) {
	tests := []struct {
		name   string
		assets []Asset
		want   bool
	}{
		{
			name:   "empty asset list",
			assets: nil,
			want:   false,
		},
		{
			name: "release with darwin_amd64 asset (v0.4.6 naming)",
			assets: []Asset{
				{Name: "sfetch_linux_amd64.tar.gz"},
				{Name: "sfetch_darwin_amd64.tar.gz"},
				{Name: "sfetch_darwin_arm64.tar.gz"},
			},
			want: true,
		},
		{
			name: "release with darwin-amd64 asset (dash naming)",
			assets: []Asset{
				{Name: "tool-darwin-amd64"},
				{Name: "tool-linux-amd64"},
			},
			want: true,
		},
		{
			name: "release without darwin_amd64 (v0.4.7+ matrix)",
			assets: []Asset{
				{Name: "sfetch_darwin_arm64.tar.gz"},
				{Name: "sfetch_linux_amd64.tar.gz"},
				{Name: "sfetch_linux_arm64.tar.gz"},
				{Name: "sfetch_windows_amd64.zip"},
				{Name: "sfetch_windows_arm64.zip"},
			},
			want: false,
		},
		{
			name: "uppercase naming still matches",
			assets: []Asset{
				{Name: "sfetch_DARWIN_AMD64.tar.gz"},
			},
			want: true,
		},
		{
			name: "darwin-only or amd64-only does not match",
			assets: []Asset{
				{Name: "sfetch_darwin_arm64.tar.gz"},
				{Name: "sfetch_linux_amd64.tar.gz"},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := hasDarwinAMD64Asset(tc.assets); got != tc.want {
				t.Errorf("hasDarwinAMD64Asset() = %v, want %v", got, tc.want)
			}
		})
	}
}
