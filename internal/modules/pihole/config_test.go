package pihole

import (
	"reflect"
	"testing"
)

func TestCoerceFollowsPiholeTypes(t *testing.T) {
	cases := []struct {
		typ  string
		in   any
		want any
	}{
		{"boolean", false, false},
		{"boolean", "true", true},
		{"unsigned integer", "2", int64(2)},
		{"unsigned integer", float64(10000), int64(10000)},
		{"string array", "127.0.0.1#5053\n\n 9.9.9.9 ", []string{"127.0.0.1#5053", "9.9.9.9"}},
		{"string array", []any{"a", " ", "b"}, []string{"a", "b"}},
		{"enum (string)", " NULL ", "NULL"},
	}
	for _, c := range cases {
		got, err := coerce(c.typ, c.in)
		if err != nil || !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s %v: got %#v %v want %#v", c.typ, c.in, got, err, c.want)
		}
	}
	if _, err := coerce("unsigned integer", "-1"); err == nil {
		t.Error("negative unsigned must fail")
	}
	if _, err := coerce("boolean", "maybe"); err == nil {
		t.Error("not a boolean")
	}
}

func TestNestAndFlatten(t *testing.T) {
	n := nest("dns.specialDomains.iCloudPrivateRelay", false)
	want := map[string]any{"dns": map[string]any{"specialDomains": map[string]any{"iCloudPrivateRelay": false}}}
	if !reflect.DeepEqual(n, want) {
		t.Fatalf("nest: %#v", n)
	}
	out := map[string]map[string]any{}
	flatten("", map[string]any{"dns": map[string]any{"port": map[string]any{"value": 53.0, "description": "p"},
		"specialDomains": map[string]any{"mozillaCanary": map[string]any{"value": true, "description": "c"}}}}, out)
	if out["dns.port"]["value"] != 53.0 || out["dns.specialDomains.mozillaCanary"]["value"] != true || len(out) != 2 {
		t.Fatalf("flatten: %#v", out)
	}
}

// Every catalogue entry belongs to a section the page shows, and the
// settings that can stop the Pi-hole answering are never writable.
func TestCatalogueIsSafe(t *testing.T) {
	secs := map[string]bool{}
	for _, s := range phSections {
		secs[s.ID] = true
	}
	for _, c := range phCatalogue {
		if !secs[c.Section] {
			t.Errorf("%s: unknown section %q", c.Key, c.Section)
		}
		if c.Guide == "" && c.ReadOnly == "" {
			t.Errorf("%s: no guidance", c.Key)
		}
	}
	for _, k := range []string{"dns.port", "dns.interface", "dns.listeningMode"} {
		if c := settingFor(k); c == nil || c.ReadOnly == "" {
			t.Errorf("%s must be view only", k)
		}
	}
	for _, k := range []string{"webserver.api.app_sudo", "webserver.api.app_pwhash", "dhcp.active"} {
		if settingFor(k) != nil {
			t.Errorf("%s must not be offered", k)
		}
	}
}
