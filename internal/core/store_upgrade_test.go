package core

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// A database written before flows had an anycast column must open. The
// base schema once indexed that column before the migration that adds it
// had run, and a gateway upgrading from such a build never started.
func TestOpenStoreUpgradesFlowsWithoutAnycast(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, "flowsight.db"))
	if err != nil {
		t.Fatal(err)
	}
	// flows as it was before the migrated columns (anycast, domain_source,
	// country_source, visibility) existed.
	if _, err := db.Exec(`CREATE TABLE flows (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL, end_ts INTEGER,
    key TEXT,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, proto TEXT,
    app TEXT, category TEXT, domain TEXT,
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0, packets INTEGER DEFAULT 0,
    duration REAL DEFAULT 0,
    verdict TEXT DEFAULT 'observed', policy TEXT,
    source TEXT, iface TEXT,
    tls_version TEXT, tls_sni TEXT, tls_ja3 TEXT, tls_cert TEXT,
    country TEXT, asn TEXT, attrs TEXT)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	s, err := OpenStore(dir)
	if err != nil {
		t.Fatalf("an older database must open: %v", err)
	}
	defer s.db.Close()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='flows_country_anycast'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("anycast index not created after the column: n=%d err=%v", n, err)
	}
}
