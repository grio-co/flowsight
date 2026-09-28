package mitm

import (
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/grioghar/flowsight/internal/core"
)

func bodyTestModule(t *testing.T) *Module {
	t.Helper()
	// These tests save settings. Without this they would write to the
	// developer's own ~/.flowsight/etc/flowsight.json, and leak state into
	// the next run.
	t.Setenv("FLOWSIGHT_CONFIG", filepath.Join(t.TempDir(), "flowsight.json"))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	c, err := core.New("0.9.8r000000000000", "", t.TempDir(), nil, logger)
	if err != nil {
		t.Fatal(err)
	}
	c.LoadModules()
	m, ok := c.Modules["mitm"].(*Module)
	if !ok {
		t.Fatal("mitm module not loaded")
	}
	if err := m.initBodySchema(); err != nil {
		t.Fatal(err)
	}
	return m
}

func setBodySettings(t *testing.T, m *Module, v map[string]any) {
	t.Helper()
	if err := m.ctx.Core.Config.SetModule("mitm", v); err != nil {
		t.Fatal(err)
	}
}

func storedBodies(t *testing.T, m *Module) []map[string]any {
	t.Helper()
	rows, err := m.ctx.Store.Rows(`SELECT host,direction,size,complete,body FROM mitm_bodies ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

// Recording is off until it is switched on AND a host is named: the switch
// alone must never start recording the whole network.
func TestBodiesAreNotKeptUntilAHostIsNamed(t *testing.T) {
	m := bodyTestModule(t)
	rec := Request{Host: "api.example.com", Method: "POST"}
	m.keepBody(rec, []byte(`{"a":1}`), false, "", true)
	if n := len(storedBodies(t, m)); n != 0 {
		t.Fatalf("off by default, got %d", n)
	}
	setBodySettings(t, m, map[string]any{"store_bodies": true})
	m.keepBody(rec, []byte(`{"a":1}`), false, "", true)
	if n := len(storedBodies(t, m)); n != 0 {
		t.Fatalf("on with no host named must keep nothing, got %d", n)
	}
	setBodySettings(t, m, map[string]any{"body_hosts": []any{"other.example.com"}})
	m.keepBody(rec, []byte(`{"a":1}`), false, "", true)
	if n := len(storedBodies(t, m)); n != 0 {
		t.Fatalf("a host not named must keep nothing, got %d", n)
	}
	setBodySettings(t, m, map[string]any{"body_hosts": []any{"*.example.com"}})
	m.keepBody(rec, []byte(`{"a":1}`), false, "", true)
	rows := storedBodies(t, m)
	if len(rows) != 1 || string(asBytes(rows[0]["body"])) != `{"a":1}` || rows[0]["direction"] != "request" {
		t.Fatalf("named host should be kept: %v", rows)
	}
}

// A body longer than the cap is kept up to the cap and marked incomplete.
func TestBodyIsCappedAndMarked(t *testing.T) {
	m := bodyTestModule(t)
	setBodySettings(t, m, map[string]any{"store_bodies": true, "body_hosts": []any{"api.example.com"}, "body_max_bytes": 10})
	m.keepBody(Request{Host: "api.example.com:443"}, bytes.Repeat([]byte("x"), 50), true, "", true)
	rows := storedBodies(t, m)
	if len(rows) != 1 || rows[0]["size"] != int64(10) || rows[0]["complete"] != int64(0) || rows[0]["direction"] != "response" {
		t.Fatalf("cap and mark: %v", rows)
	}
}

// Bodies expire on their own, and switching recording off empties the store.
func TestBodiesExpireAndClearWhenRecordingStops(t *testing.T) {
	m := bodyTestModule(t)
	setBodySettings(t, m, map[string]any{"store_bodies": true, "body_hosts": []any{"api.example.com"}, "body_keep_minutes": 60})
	m.keepBody(Request{Host: "api.example.com", TS: 1}, []byte("old"), false, "", true)
	if err := m.expireBodies(); err != nil {
		t.Fatal(err)
	}
	if n := len(storedBodies(t, m)); n != 0 {
		t.Fatalf("a body older than the keep time should go, got %d", n)
	}
	m.keepBody(Request{Host: "api.example.com", TS: 1 << 40}, []byte("new"), false, "", true)
	if err := m.expireBodies(); err != nil {
		t.Fatal(err)
	}
	if n := len(storedBodies(t, m)); n != 1 {
		t.Fatalf("a fresh body should stay, got %d", n)
	}
	setBodySettings(t, m, map[string]any{"store_bodies": false})
	if err := m.expireBodies(); err != nil {
		t.Fatal(err)
	}
	if n := len(storedBodies(t, m)); n != 0 {
		t.Fatalf("switching recording off should empty the store, got %d", n)
	}
}

// A read-only token may see that a recording exists but not read it.
func TestReadOnlyTokenCannotReadABody(t *testing.T) {
	m := bodyTestModule(t)
	setBodySettings(t, m, map[string]any{"store_bodies": true, "body_hosts": []any{"api.example.com"}})
	m.keepBody(Request{Host: "api.example.com", TS: 1 << 40, Type: "application/json"}, []byte(`{"secret":1}`), false, "", true)
	id := m.ctx.Store.Int(`SELECT id FROM mitm_bodies`)
	admin, err := m.apiBodies(&core.Req{Request: httpGet(t, "/api/mitm/bodies?id="+strconv.FormatInt(id, 10))})
	if err != nil {
		t.Fatalf("an admin token reads the body: %v", err)
	}
	if got := admin.(map[string]any)["body"].(map[string]any)["text"]; got != `{"secret":1}` {
		t.Fatalf("body text: %v", got)
	}
	ro := &core.Req{Request: httpGet(t, "/api/mitm/bodies?id="+strconv.FormatInt(id, 10)).WithContext(core.WithReadOnly(context.Background()))}
	out, err := m.apiBodies(ro)
	if err == nil {
		t.Fatalf("a read-only token must not read a body: %v", out)
	}
	// The listing is still allowed, and carries no bodies.
	list, err := m.apiBodies(&core.Req{Request: httpGet(t, "/api/mitm/bodies").WithContext(core.WithReadOnly(context.Background()))})
	if err != nil {
		t.Fatal(err)
	}
	rows := list.(map[string]any)["bodies"].([]map[string]any)
	if len(rows) != 1 {
		t.Fatalf("listing: %v", rows)
	}
	if _, leaked := rows[0]["body"]; leaked {
		t.Fatal("the listing must not carry bodies")
	}
}

// A gzipped body reads as it was written.
func TestGzippedBodyIsDecoded(t *testing.T) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write([]byte(`{"hello":"world"}`))
	w.Close()
	out, ok := decodeBody(buf.Bytes(), "gzip")
	if !ok || string(out) != `{"hello":"world"}` {
		t.Fatalf("gzip: %q %v", out, ok)
	}
	if out, ok := decodeBody([]byte("plain"), ""); !ok || string(out) != "plain" {
		t.Fatalf("identity: %q %v", out, ok)
	}
	if _, ok := decodeBody([]byte("\x1f\x8bbroken"), "br"); ok {
		t.Fatal("brotli has no decoder here and must say so")
	}
}

// The preview squid is asked for grows to cover what is being recorded, and
// the tag changes with it so squid re-reads the options.
func TestPreviewGrowsForRecording(t *testing.T) {
	m := bodyTestModule(t)
	before, tagBefore := m.previewBytes(), m.istag()
	setBodySettings(t, m, map[string]any{"store_bodies": true, "body_hosts": []any{"api.example.com"}, "body_max_bytes": 65536})
	if after := m.previewBytes(); after != 65536 || after <= before {
		t.Fatalf("preview should cover the recorded size: %d -> %d", before, after)
	}
	if m.istag() == tagBefore {
		t.Fatal("the tag must change so squid asks for options again")
	}
}

func httpGet(t *testing.T, target string) *http.Request {
	t.Helper()
	return httptest.NewRequest("GET", target, nil)
}

// A GET has no body, and is the shape most of an API is made of, so it is
// recorded for its headers and URL alone — with credential headers already
// reduced to a length by safeHeaders before they reach the store.
func TestRequestWithNoBodyIsRecordedForItsHeaders(t *testing.T) {
	m := bodyTestModule(t)
	setBodySettings(t, m, map[string]any{"store_bodies": true, "body_hosts": []any{"*.example.com"}})
	h := http.Header{}
	h.Set("X-User-Token", "a-real-session-token")
	h.Set("X-Equipment-Code", "66:51:A7:6D:78:D8")
	h.Set("X-Sign", "deadbeef")
	rec := Request{Host: "api.example.com", Method: "GET", URL: "https://api.example.com/v1/list?page=…",
		TS: 1 << 40, Headers: safeHeaders(h)}
	m.keepBody(rec, nil, false, "", true)
	got, err := m.apiBodies(&core.Req{Request: httpGet(t, "/api/mitm/bodies")})
	if err != nil {
		t.Fatal(err)
	}
	rows := got.(map[string]any)["bodies"].([]map[string]any)
	if len(rows) != 1 || rows[0]["method"] != "GET" || rows[0]["size"] != int64(0) {
		t.Fatalf("a bodyless GET should be recorded: %v", rows)
	}
	hdrs := rows[0]["headers"].(map[string]string)
	if hdrs["X-Equipment-Code"] != "66:51:A7:6D:78:D8" || hdrs["X-Sign"] != "deadbeef" {
		t.Fatalf("identity and signing headers should be kept: %v", hdrs)
	}
	if hdrs["X-User-Token"] != "(20 bytes, not recorded)" {
		t.Fatalf("a credential header must be a length: %v", hdrs)
	}
}
