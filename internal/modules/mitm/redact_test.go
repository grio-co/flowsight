package mitm

import (
	"net/url"
	"strings"
	"testing"
)

func TestRedactURL(t *testing.T) {
	u, _ := url.Parse("https://user:pw@api.example.com/v1/items?token=secret123&page=2&password=abc#frag")
	got := redactURL(u)
	for _, bad := range []string{"secret123", "abc", "pw", "user", "frag", "=2"} {
		if strings.Contains(got, bad) {
			t.Fatalf("leaked %q: %s", bad, got)
		}
	}
	if !strings.HasPrefix(got, "https://api.example.com/v1/items?") || !strings.Contains(got, "token=") || !strings.Contains(got, "page=") {
		t.Fatalf("lost what the request was for: %s", got)
	}
	u2, _ := url.Parse("http://example.com/plain/path")
	if redactURL(u2) != "http://example.com/plain/path" {
		t.Fatal(redactURL(u2))
	}
}
