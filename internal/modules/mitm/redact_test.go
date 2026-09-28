package mitm

import (
	"net/http"
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

// A header that carries access is recorded as a length, whatever an
// application chose to call it; a signature or an app key is recorded, since
// that is what says how a request was built.
func TestCredentialHeadersAreNotRecorded(t *testing.T) {
	for _, n := range []string{"Cookie", "Authorization", "Authentication", "X-User-Token", "X-Auth-Token",
		"x-api-key", "X-Client-Secret", "Set-Cookie", "X-Session-Id", "My-Password"} {
		if !credentialHeader(n) {
			t.Errorf("%s should not be recorded", n)
		}
	}
	for _, n := range []string{"X-APP", "X-APP-VERSION", "X-Client-Id", "X-MCS-AppKey", "X-Equipment-Code",
		"x-insta360-platform", "X-MainLand", "X-Timestamp", "X-Nonce", "X-Sign", "X-Signature", "User-Agent", "Content-Type"} {
		if credentialHeader(n) {
			t.Errorf("%s says how the request was built and should be recorded", n)
		}
	}
	h := http.Header{}
	h.Set("X-User-Token", "a-real-session-token")
	h.Set("X-Sign", "deadbeef")
	got := safeHeaders(h)
	if got["X-User-Token"] != "(20 bytes, not recorded)" || got["X-Sign"] != "deadbeef" {
		t.Fatalf("safeHeaders: %v", got)
	}
}
