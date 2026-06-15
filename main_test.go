package main

import (
	"testing"
	"time"
)

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		want    config
		wantErr bool
	}{
		{
			name: "url only gets defaults",
			args: []string{"https://example.com"},
			want: config{url: "https://example.com", profile: "chrome", method: "GET", timeout: 30 * time.Second},
		},
		{
			name: "scheme is added when missing",
			args: []string{"example.com"},
			want: config{url: "https://example.com", profile: "chrome", method: "GET", timeout: 30 * time.Second},
		},
		{
			name: "flags before url",
			args: []string{"-p", "firefox", "-X", "head", "-t", "5s", "-v", "https://x.io"},
			want: config{url: "https://x.io", profile: "firefox", method: "HEAD", timeout: 5 * time.Second, verbose: true},
		},
		{
			name: "profile equals form",
			args: []string{"--profile=firefox", "https://x.io"},
			want: config{url: "https://x.io", profile: "firefox", method: "GET", timeout: 30 * time.Second},
		},
		{name: "missing url", args: []string{"-v"}, wantErr: true},
		{name: "unknown flag", args: []string{"--nope", "https://x.io"}, wantErr: true},
		{name: "two urls", args: []string{"https://a.io", "https://b.io"}, wantErr: true},
		{name: "bad timeout", args: []string{"-t", "nope", "https://x.io"}, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseArgs(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.url != tt.want.url || got.profile != tt.want.profile ||
				got.method != tt.want.method || got.timeout != tt.want.timeout ||
				got.verbose != tt.want.verbose {
				t.Errorf("parseArgs(%v) = %+v, want %+v", tt.args, got, tt.want)
			}
		})
	}
}
