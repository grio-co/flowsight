package core

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

// Store is the embedded database: SQLite in WAL mode, one file, no service.
//
// Raw tables (flows, dns, alerts, tls_sessions) are kept for days; five-minute
// rollups answer every long-window report and are kept for a year. Writers are
// serialised by a mutex so a report query never makes a collection cycle
// fail with a busy error, and every write is a short transaction.
type Store struct {
	Path string
	db   *sql.DB
	wmu  sync.Mutex
}

const schemaVersion = 1

const schema = `
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);

CREATE TABLE IF NOT EXISTS hosts (
    ip TEXT PRIMARY KEY,
    mac TEXT, name TEXT, vendor TEXT, zone TEXT, os TEXT, device_type TEXT,
    first_seen INTEGER, last_seen INTEGER,
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0,
    flows INTEGER DEFAULT 0, blocked INTEGER DEFAULT 0, alerts INTEGER DEFAULT 0,
    is_local INTEGER DEFAULT 1, source TEXT, attrs TEXT
);
CREATE INDEX IF NOT EXISTS hosts_last_seen ON hosts(last_seen);

CREATE TABLE IF NOT EXISTS flows (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL, end_ts INTEGER,
    key TEXT,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, proto TEXT,
    app TEXT, category TEXT, domain TEXT, domain_source TEXT,
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0, packets INTEGER DEFAULT 0,
    duration REAL DEFAULT 0,
    verdict TEXT DEFAULT 'observed', policy TEXT,
    anycast INTEGER DEFAULT 0,
    source TEXT, iface TEXT,
    tls_version TEXT, tls_sni TEXT, tls_ja3 TEXT, tls_cert TEXT,
    country TEXT, country_source TEXT, asn TEXT, attrs TEXT,
    visibility TEXT
);
CREATE INDEX IF NOT EXISTS flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS flows_src ON flows(src_ip, ts);
CREATE INDEX IF NOT EXISTS flows_src_dst ON flows(src_ip, dst_ip, ts);
CREATE INDEX IF NOT EXISTS flows_key ON flows(key);
CREATE INDEX IF NOT EXISTS flows_app ON flows(app, ts);
CREATE INDEX IF NOT EXISTS flows_domain ON flows(domain, ts);
CREATE INDEX IF NOT EXISTS flows_dst ON flows(dst_ip, ts);
CREATE INDEX IF NOT EXISTS flows_country ON flows(country, src_ip, ts);

CREATE TABLE IF NOT EXISTS rollup_app (
    bucket INTEGER NOT NULL, src_ip TEXT NOT NULL, app TEXT NOT NULL,
    category TEXT, verdict TEXT NOT NULL DEFAULT 'observed',
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0, flows INTEGER DEFAULT 0,
    PRIMARY KEY (bucket, src_ip, app, verdict)
);
CREATE TABLE IF NOT EXISTS rollup_domain (
    bucket INTEGER NOT NULL, src_ip TEXT NOT NULL, domain TEXT NOT NULL,
    category TEXT, verdict TEXT NOT NULL DEFAULT 'observed',
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0, flows INTEGER DEFAULT 0,
    PRIMARY KEY (bucket, src_ip, domain, verdict)
);
CREATE TABLE IF NOT EXISTS rollup_dst (
    bucket INTEGER NOT NULL, src_ip TEXT NOT NULL, dst_ip TEXT NOT NULL,
    dst_port INTEGER, proto TEXT,
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0, flows INTEGER DEFAULT 0,
    PRIMARY KEY (bucket, src_ip, dst_ip, dst_port, proto)
);

CREATE INDEX IF NOT EXISTS rollup_dst_dst ON rollup_dst(dst_ip, bucket);

CREATE TABLE IF NOT EXISTS dns (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL, client TEXT, domain TEXT, qtype TEXT,
    action TEXT, list TEXT, rcode TEXT, answer_source TEXT, dnssec TEXT, ms REAL,
    answers TEXT, source TEXT
);
CREATE INDEX IF NOT EXISTS dns_ts ON dns(ts);
CREATE INDEX IF NOT EXISTS dns_client ON dns(client, ts);

CREATE TABLE IF NOT EXISTS rollup_dns (
    bucket INTEGER NOT NULL, client TEXT NOT NULL, domain TEXT NOT NULL,
    action TEXT NOT NULL, list TEXT, queries INTEGER DEFAULT 0,
    PRIMARY KEY (bucket, client, domain, action)
);

CREATE TABLE IF NOT EXISTS dns_names (
    ip TEXT PRIMARY KEY, name TEXT, ts INTEGER
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL, source TEXT, severity TEXT, verdict TEXT,
    sig_id TEXT, signature TEXT, category TEXT,
    src_ip TEXT, src_port INTEGER, dst_ip TEXT, dst_port INTEGER, proto TEXT,
    iface TEXT, message TEXT, attrs TEXT, acked INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
CREATE INDEX IF NOT EXISTS alerts_src ON alerts(src_ip, ts);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL, kind TEXT, source TEXT, severity TEXT, verdict TEXT,
    actor_ip TEXT, actor_name TEXT, target_ip TEXT, target_domain TEXT,
    rule_id TEXT, rule_name TEXT, category TEXT, message TEXT, attrs TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS events_kind ON events(kind, ts);

CREATE TABLE IF NOT EXISTS tls_certs (
    fingerprint TEXT PRIMARY KEY,
    subject TEXT, issuer TEXT, sans TEXT, serial TEXT,
    not_before INTEGER, not_after INTEGER,
    key_type TEXT, key_bits INTEGER, sig_alg TEXT,
    self_signed INTEGER DEFAULT 0, trusted INTEGER,
    first_seen INTEGER, last_seen INTEGER, seen INTEGER DEFAULT 0,
    hosts TEXT, snis TEXT, source TEXT, attrs TEXT
);
CREATE INDEX IF NOT EXISTS tls_certs_last ON tls_certs(last_seen);

CREATE TABLE IF NOT EXISTS tls_sessions (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL, src_ip TEXT, dst_ip TEXT, dst_port INTEGER,
    sni TEXT, version TEXT, cipher TEXT, ja3 TEXT, ja3s TEXT, ja4 TEXT,
    fingerprint TEXT, mode TEXT, source TEXT
);
CREATE INDEX IF NOT EXISTS tls_sessions_ts ON tls_sessions(ts);
-- Naming a destination means asking which server name was seen at an
-- address, which is a scan of the whole table without this.
CREATE INDEX IF NOT EXISTS tls_sessions_dst ON tls_sessions(dst_ip, ts);

CREATE TABLE IF NOT EXISTS metrics (
    ts INTEGER NOT NULL, name TEXT NOT NULL, labels TEXT NOT NULL DEFAULT '',
    value REAL, PRIMARY KEY (ts, name, labels)
);

CREATE TABLE IF NOT EXISTS devices (
    mac TEXT PRIMARY KEY,
    ip TEXT, ip6 TEXT, hostname TEXT, vendor TEXT, vendor_class TEXT, fingerprint TEXT,
    zone TEXT, class TEXT, confidence TEXT, rule TEXT, why TEXT,
    pinned INTEGER DEFAULT 0, randomized INTEGER DEFAULT 0,
    guest_name TEXT, guest_kind TEXT, user TEXT, iface TEXT,
    first_seen INTEGER, last_seen INTEGER, attrs TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL, module TEXT, kind TEXT, severity TEXT,
    subject TEXT, title TEXT, detail TEXT, fingerprint TEXT,
    resolved_ts INTEGER, acked INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS findings_fp ON findings(fingerprint);

CREATE TABLE IF NOT EXISTS changes (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL, module TEXT, subject TEXT, actor TEXT,
    before_hash TEXT, after_hash TEXT, diff TEXT, summary TEXT
);
CREATE INDEX IF NOT EXISTS changes_ts ON changes(ts);

CREATE TABLE IF NOT EXISTS policy_state (
    provider TEXT PRIMARY KEY, hash TEXT, applied_ts INTEGER, artifact TEXT, note TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY,
    ts INTEGER NOT NULL, channel TEXT, rule TEXT, subject TEXT, ok INTEGER, error TEXT
);

CREATE TABLE IF NOT EXISTS user_sessions (
    id INTEGER PRIMARY KEY,
    user TEXT NOT NULL, source TEXT NOT NULL DEFAULT 'radius',
    ipv4 TEXT, ipv6 TEXT, mac TEXT,
    nas_ip TEXT, nas_id TEXT, acct_session_id TEXT,
    start_ts INTEGER NOT NULL, last_seen INTEGER NOT NULL, stop_ts INTEGER,
    bytes_in INTEGER DEFAULT 0, bytes_out INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS user_sessions_user ON user_sessions(user, stop_ts DESC);
CREATE INDEX IF NOT EXISTS user_sessions_ipv4 ON user_sessions(ipv4, stop_ts DESC);
CREATE INDEX IF NOT EXISTS user_sessions_ipv6 ON user_sessions(ipv6, stop_ts DESC);
CREATE INDEX IF NOT EXISTS user_sessions_last_seen ON user_sessions(last_seen DESC);

CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT, ts INTEGER);
`

// OpenStore opens (creating if needed) the database at dir/flowsight.db.
func OpenStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "flowsight.db")
	dsn := "file:" + path + "?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)&_pragma=temp_store(MEMORY)&_pragma=foreign_keys(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	db.SetConnMaxLifetime(0)
	s := &Store{Path: path, db: db}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("schema: %w", err)
	}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	var have int
	_ = s.db.QueryRow(`SELECT CAST(value AS INTEGER) FROM meta WHERE key='schema_version'`).Scan(&have)
	// Additive migrations only. A downgrade must never lose data.
	if err := s.ensureColumn("flows", "anycast", "INTEGER DEFAULT 0"); err != nil {
		return err
	}
	// An index on a column a migration adds is created here, after the
	// column, never in the base schema: the base schema runs first, and on a
	// database from before the column it would fail and the daemon would
	// not start.
	if _, err := s.db.Exec(`CREATE INDEX IF NOT EXISTS flows_country_anycast ON flows(country, anycast, ts)`); err != nil {
		return err
	}
	if err := s.ensureColumn("flows", "domain_source", "TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("flows", "country_source", "TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("findings", "attrs", "TEXT"); err != nil {
		return err
	}
	if err := s.ensureColumn("flows", "visibility", "TEXT"); err != nil {
		return err
	}
	_, err := s.db.Exec(`INSERT OR REPLACE INTO meta VALUES('schema_version', ?)`, fmt.Sprint(schemaVersion))
	return err
}

// ensureColumn adds a column to a table that predates it.
func (s *Store) ensureColumn(table, col, decl string) error {
	rows, err := s.db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		if name == col {
			return nil
		}
	}
	_, err = s.db.Exec(`ALTER TABLE ` + table + ` ADD COLUMN ` + col + ` ` + decl)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

// DB exposes the handle for module queries.
func (s *Store) DB() *sql.DB { return s.db }

// Tx runs fn in a write transaction under the writer mutex.
func (s *Store) Tx(fn func(tx *sql.Tx) error) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// Exec runs one write statement under the writer mutex.
func (s *Store) Exec(q string, args ...any) error {
	s.wmu.Lock()
	defer s.wmu.Unlock()
	_, err := s.db.Exec(q, args...)
	return err
}

// Rows runs a query and returns generic maps, which is what the API serves.
func (s *Store) Rows(q string, args ...any) ([]map[string]any, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			switch v := vals[i].(type) {
			case []byte:
				m[c] = string(v)
			default:
				m[c] = v
			}
		}
		out = append(out, m)
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out, rows.Err()
}

// Row returns the first row or nil.
func (s *Store) Row(q string, args ...any) (map[string]any, error) {
	rows, err := s.Rows(q, args...)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return rows[0], nil
}

// Int returns a single integer scalar (0 on no row).
func (s *Store) Int(q string, args ...any) int64 {
	var v sql.NullInt64
	_ = s.db.QueryRow(q, args...).Scan(&v)
	return v.Int64
}

// Float returns a single float scalar.
func (s *Store) Float(q string, args ...any) float64 {
	var v sql.NullFloat64
	_ = s.db.QueryRow(q, args...).Scan(&v)
	return v.Float64
}

// KV ----------------------------------------------------------------------

func (s *Store) KVGet(key string, into any) bool {
	var raw string
	if err := s.db.QueryRow(`SELECT value FROM kv WHERE key=?`, key).Scan(&raw); err != nil {
		return false
	}
	return json.Unmarshal([]byte(raw), into) == nil
}

// KVCount is how many keys sit under a prefix. It answers "how much do we
// know" where a counter in memory would answer "how much since the restart",
// which is a different and less useful question.
func (s *Store) KVCount(prefix string) int64 {
	// The escape character is one that never needs escaping itself. A
	// backslash here went through two layers of quoting on its way into the
	// source and reached SQLite as two characters, which is an error -- and an
	// error this method swallows, so the count read zero while eighty hops
	// sat placed by the very answers it was failing to count.
	pat := strings.NewReplacer("!", "!!", "%", "!%", "_", "!_").Replace(prefix) + "%"
	var n int64
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM kv WHERE key LIKE ? ESCAPE '!'`, pat).Scan(&n); err != nil {
		return -1 // a count that could not be taken is not nought
	}
	return n
}

// KVDelete removes one key; a missing key is not an error.
func (s *Store) KVDelete(key string) error { return s.Exec(`DELETE FROM kv WHERE key=?`, key) }

func (s *Store) KVSet(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Exec(`INSERT OR REPLACE INTO kv VALUES(?,?,?)`, key, string(b), time.Now().Unix())
}

// Records ----------------------------------------------------------------

type Flow struct {
	TS, EndTS                  int64
	Key                        string
	SrcIP                      string
	SrcPort                    int
	DstIP                      string
	DstPort                    int
	Proto, App, Category       string
	Domain                     string
	DomainSource               string // sni | http_host | dns_query | probe_name | none
	BytesIn, BytesOut, Packets int64
	Duration                   float64
	Verdict, Policy            string
	Source, Iface              string
	TLSVersion, TLSSNI, TLSJA3 string
	TLSCert, Country, ASN      string
	CountrySource              string // database | none
	// Anycast: the far end is in a range announced from many sites at once,
	// so Country is where the range is registered, not where it answered.
	Anycast bool
	// Visibility: why this flow is or is not readable. One of: inspected
	// (squid bumped it), sni (name from ClientHello only), http (plain HTTP),
	// quic (QUIC: name from Initial if available, else opaque), ech (TLS with
	// encrypted_client_hello extension seen, name unknown by design),
	// opaque (encrypted, no name), dns (a DNS transaction), plain (unencrypted),
	// local (communication inside the LAN).
	Visibility string
	Attrs      map[string]any
}

func jsonOrNil(m map[string]any) any {
	if len(m) == 0 {
		return nil
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nz(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// AddFlows inserts flows, updating an open flow when the same key was seen.
// rollupDelta is what one flow observation adds to the five-minute rollups.
type rollupDelta struct {
	bucket                             int64
	srcIP, dstIP, proto, app, cat, dom string
	dstPort                            int
	verdict                            string
	bytesIn, bytesOut                  int64
	newFlow                            bool
}

// AddFlows upserts flows by key and, at the same time, credits the bytes
// that appeared since the previous observation to the rollup bucket of the
// moment they were observed. Rollups therefore show when traffic moved, not
// when a flow started, and a long download is spread over its duration.
func (s *Store) AddFlows(flows []Flow) error {
	if len(flows) == 0 {
		return nil
	}
	now := time.Now().Unix()
	return s.Tx(func(tx *sql.Tx) error {
		prevQ, err := tx.Prepare(`SELECT bytes_in, bytes_out FROM flows WHERE key=? ORDER BY id DESC LIMIT 1`)
		if err != nil {
			return err
		}
		defer prevQ.Close()
		var deltas []rollupDelta
		upd, err := tx.Prepare(`UPDATE flows SET end_ts=?, bytes_in=?, bytes_out=?, packets=?,
			duration=?, app=COALESCE(?,app), category=COALESCE(?,category), domain=COALESCE(?,domain),
			domain_source=COALESCE(?,domain_source), country_source=COALESCE(?,country_source),
			visibility=COALESCE(?,visibility),
			verdict=?, policy=COALESCE(?,policy), tls_version=COALESCE(?,tls_version),
			tls_sni=COALESCE(?,tls_sni), tls_ja3=COALESCE(?,tls_ja3), attrs=COALESCE(?,attrs)
			WHERE id=(SELECT id FROM flows WHERE key=? ORDER BY id DESC LIMIT 1)`)
		if err != nil {
			return err
		}
		defer upd.Close()
		ins, err := tx.Prepare(`INSERT INTO flows(ts,end_ts,key,src_ip,src_port,dst_ip,dst_port,proto,
			app,category,domain,domain_source,bytes_in,bytes_out,packets,duration,verdict,policy,source,iface,
			tls_version,tls_sni,tls_ja3,tls_cert,country,country_source,asn,attrs,anycast,visibility)
			VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, f := range flows {
			if f.Verdict == "" {
				f.Verdict = "observed"
			}
			end := f.EndTS
			if end == 0 {
				end = time.Now().Unix()
			}
			// Where in time do these bytes belong: now for a live flow, at its
			// end for a record that arrives complete (a proxy log line).
			bucket := (now / 300) * 300
			if end > 0 && now-end > 600 {
				bucket = (end / 300) * 300
			}
			d := rollupDelta{bucket: bucket, srcIP: f.SrcIP, dstIP: f.DstIP, proto: f.Proto, app: f.App, cat: f.Category,
				dom: f.Domain, dstPort: f.DstPort, verdict: f.Verdict, bytesIn: f.BytesIn, bytesOut: f.BytesOut, newFlow: true}
			if f.Key != "" {
				var pin, pout int64
				if err := prevQ.QueryRow(f.Key).Scan(&pin, &pout); err == nil {
					d.newFlow = false
					d.bytesIn, d.bytesOut = flowDelta(pin, pout, f.BytesIn, f.BytesOut)
				}
			}
			// A proxy log line describes a transfer the flow probe already
			// counted live, byte for byte, as it happened. It still counts
			// as a request (and carries the verdict and the domain), but its
			// bytes must not be added a second time.
			if f.Source == "squid" {
				d.bytesIn, d.bytesOut = 0, 0
			}
			if f.Key != "" {
				res, err := upd.Exec(end, f.BytesIn, f.BytesOut, f.Packets, f.Duration,
					nz(f.App), nz(f.Category), nz(f.Domain), nz(f.DomainSource), nz(f.CountrySource), nz(f.Visibility), f.Verdict, nz(f.Policy),
					nz(f.TLSVersion), nz(f.TLSSNI), nz(f.TLSJA3), jsonOrNil(f.Attrs), f.Key)
				if err != nil {
					return err
				}
				if n, _ := res.RowsAffected(); n > 0 {
					deltas = append(deltas, d)
					continue
				}
			}
			deltas = append(deltas, d)
			if _, err := ins.Exec(f.TS, nzInt(f.EndTS), nz(f.Key), nz(f.SrcIP), f.SrcPort, nz(f.DstIP),
				f.DstPort, nz(f.Proto), nz(f.App), nz(f.Category), nz(f.Domain), nz(f.DomainSource), f.BytesIn, f.BytesOut,
				f.Packets, f.Duration, f.Verdict, nz(f.Policy), nz(f.Source), nz(f.Iface),
				nz(f.TLSVersion), nz(f.TLSSNI), nz(f.TLSJA3), nz(f.TLSCert), nz(f.Country), nz(f.CountrySource), nz(f.ASN),
				jsonOrNil(f.Attrs), b2i(f.Anycast), nz(f.Visibility)); err != nil {
				return err
			}
		}
		return accumulateRollups(tx, deltas)
	})
}

// flowDelta is how many bytes a flow moved since it was last seen, split by
// direction. The probe's counters are cumulative per flow, but its split by
// direction is derived from a percentage that shifts as the mix changes, so
// one direction can read lower than last time while the flow grew. Judging
// a reset by one direction credited the whole cumulative total again each
// time that happened, which put hundreds of gigabytes an hour on a tunnel
// that moved a few. Only the total says whether the counter reset; the
// growth is then split the way the flow currently splits.
func flowDelta(pin, pout, in, out int64) (int64, int64) {
	total, prev := in+out, pin+pout
	if total < prev {
		return in, out // re-created upstream: the counters started over
	}
	grow := total - prev
	if grow <= 0 || total <= 0 {
		return 0, 0
	}
	dIn := grow * in / total
	return dIn, grow - dIn
}

// FlowDelta is flowDelta for the modules that keep their own counters.
func FlowDelta(pin, pout, in, out int64) (int64, int64) { return flowDelta(pin, pout, in, out) }

// accumulateRollups adds observation deltas to the three flow rollups.
func accumulateRollups(tx *sql.Tx, deltas []rollupDelta) error {
	if len(deltas) == 0 {
		return nil
	}
	app, err := tx.Prepare(`INSERT INTO rollup_app(bucket,src_ip,app,category,verdict,bytes_in,bytes_out,flows)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(bucket,src_ip,app,verdict) DO UPDATE SET
		bytes_in=bytes_in+excluded.bytes_in, bytes_out=bytes_out+excluded.bytes_out, flows=flows+excluded.flows,
		category=CASE WHEN excluded.category<>'' THEN excluded.category ELSE category END`)
	if err != nil {
		return err
	}
	defer app.Close()
	dom, err := tx.Prepare(`INSERT INTO rollup_domain(bucket,src_ip,domain,category,verdict,bytes_in,bytes_out,flows)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(bucket,src_ip,domain,verdict) DO UPDATE SET
		bytes_in=bytes_in+excluded.bytes_in, bytes_out=bytes_out+excluded.bytes_out, flows=flows+excluded.flows,
		category=CASE WHEN excluded.category<>'' THEN excluded.category ELSE category END`)
	if err != nil {
		return err
	}
	defer dom.Close()
	dst, err := tx.Prepare(`INSERT INTO rollup_dst(bucket,src_ip,dst_ip,dst_port,proto,bytes_in,bytes_out,flows)
		VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(bucket,src_ip,dst_ip,dst_port,proto) DO UPDATE SET
		bytes_in=bytes_in+excluded.bytes_in, bytes_out=bytes_out+excluded.bytes_out, flows=flows+excluded.flows`)
	if err != nil {
		return err
	}
	defer dst.Close()
	for _, d := range deltas {
		if d.bytesIn == 0 && d.bytesOut == 0 && !d.newFlow {
			continue
		}
		n := int64(0)
		if d.newFlow {
			n = 1
		}
		a := d.app
		if a == "" {
			a = "Unknown"
		}
		v := d.verdict
		if v == "" {
			v = "observed"
		}
		if _, err := app.Exec(d.bucket, d.srcIP, a, d.cat, v, d.bytesIn, d.bytesOut, n); err != nil {
			return err
		}
		if d.dom != "" {
			if _, err := dom.Exec(d.bucket, d.srcIP, d.dom, d.cat, v, d.bytesIn, d.bytesOut, n); err != nil {
				return err
			}
		}
		if _, err := dst.Exec(d.bucket, d.srcIP, d.dstIP, d.dstPort, d.proto, d.bytesIn, d.bytesOut, n); err != nil {
			return err
		}
	}
	return nil
}

func nzInt(v int64) any {
	if v == 0 {
		return nil
	}
	return v
}

type DNSRecord struct {
	TS                    int64
	Client, Domain, QType string
	Action, List, RCode   string
	AnswerSource, DNSSEC  string
	MS                    float64
	Answers               []string
	Source                string
}

func (s *Store) AddDNS(recs []DNSRecord) error {
	if len(recs) == 0 {
		return nil
	}
	// Rows older than the rollup's rolling window (a Pi-hole import, a log
	// read after downtime) would never be aggregated; mark the window dirty
	// back to the oldest one so the next rollup re-aggregates from there.
	var oldest int64
	for _, r := range recs {
		if r.TS > 0 && (oldest == 0 || r.TS < oldest) {
			oldest = r.TS
		}
	}
	if oldest > 0 && oldest < time.Now().Unix()-600 {
		var dirty int64
		s.KVGet("rollup.dirty", &dirty)
		if dirty == 0 || oldest < dirty {
			_ = s.KVSet("rollup.dirty", oldest)
		}
	}
	return s.Tx(func(tx *sql.Tx) error {
		st, err := tx.Prepare(`INSERT INTO dns(ts,client,domain,qtype,action,list,rcode,answer_source,
			dnssec,ms,answers,source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		names, err := tx.Prepare(`INSERT OR REPLACE INTO dns_names(ip,name,ts) VALUES(?,?,?)`)
		if err != nil {
			return err
		}
		defer names.Close()
		for _, r := range recs {
			if r.Action == "" {
				r.Action = "pass"
			}
			var ans any
			if len(r.Answers) > 0 {
				b, _ := json.Marshal(r.Answers)
				ans = string(b)
				for _, a := range r.Answers {
					if strings.ContainsAny(a, ".:") && !strings.Contains(a, " ") {
						_, _ = names.Exec(a, r.Domain, r.TS)
					}
				}
			}
			if _, err := st.Exec(r.TS, nz(r.Client), nz(r.Domain), nz(r.QType), r.Action, nz(r.List),
				nz(r.RCode), nz(r.AnswerSource), nz(r.DNSSEC), r.MS, ans, nz(r.Source)); err != nil {
				return err
			}
		}
		return nil
	})
}

type Alert struct {
	TS                         int64
	Source, Severity, Verdict  string
	SigID, Signature, Category string
	SrcIP                      string
	SrcPort                    int
	DstIP                      string
	DstPort                    int
	Proto, Iface, Message      string
	Attrs                      map[string]any
}

func (s *Store) AddAlerts(al []Alert) error {
	if len(al) == 0 {
		return nil
	}
	return s.Tx(func(tx *sql.Tx) error {
		st, err := tx.Prepare(`INSERT INTO alerts(ts,source,severity,verdict,sig_id,signature,category,
			src_ip,src_port,dst_ip,dst_port,proto,iface,message,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, a := range al {
			if a.Severity == "" {
				a.Severity = "medium"
			}
			if a.Verdict == "" {
				a.Verdict = "observed"
			}
			if _, err := st.Exec(a.TS, nz(a.Source), a.Severity, a.Verdict, nz(a.SigID), nz(a.Signature),
				nz(a.Category), nz(a.SrcIP), a.SrcPort, nz(a.DstIP), a.DstPort, nz(a.Proto), nz(a.Iface),
				nz(a.Message), jsonOrNil(a.Attrs)); err != nil {
				return err
			}
		}
		return nil
	})
}

type Event struct {
	TS                         int64
	Kind, Source               string
	Severity, Verdict          string
	ActorIP, ActorName         string
	TargetIP, TargetDomain     string
	RuleID, RuleName, Category string
	Message                    string
	Attrs                      map[string]any
}

func (e *Event) apply(fields map[string]any) {
	for k, v := range fields {
		sv, _ := v.(string)
		switch k {
		case "severity":
			e.Severity = sv
		case "verdict":
			e.Verdict = sv
		case "actor_ip":
			e.ActorIP = sv
		case "actor_name":
			e.ActorName = sv
		case "target_ip":
			e.TargetIP = sv
		case "target_domain":
			e.TargetDomain = sv
		case "rule_id":
			e.RuleID = sv
		case "rule_name":
			e.RuleName = sv
		case "category":
			e.Category = sv
		default:
			if e.Attrs == nil {
				e.Attrs = map[string]any{}
			}
			e.Attrs[k] = v
		}
	}
}

func (s *Store) AddEvents(ev []Event) error {
	if len(ev) == 0 {
		return nil
	}
	return s.Tx(func(tx *sql.Tx) error {
		st, err := tx.Prepare(`INSERT INTO events(ts,kind,source,severity,verdict,actor_ip,actor_name,
			target_ip,target_domain,rule_id,rule_name,category,message,attrs) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, e := range ev {
			if e.Severity == "" {
				e.Severity = "info"
			}
			if e.Verdict == "" {
				e.Verdict = "observed"
			}
			if e.TS == 0 {
				e.TS = time.Now().Unix()
			}
			if _, err := st.Exec(e.TS, e.Kind, nz(e.Source), e.Severity, e.Verdict, nz(e.ActorIP),
				nz(e.ActorName), nz(e.TargetIP), nz(e.TargetDomain), nz(e.RuleID), nz(e.RuleName),
				nz(e.Category), nz(e.Message), jsonOrNil(e.Attrs)); err != nil {
				return err
			}
		}
		return nil
	})
}

// Metric is one gauge/counter sample at minute resolution.
type Metric struct {
	Name   string
	Labels map[string]string
	Value  float64
}

func (s *Store) AddMetrics(ts int64, ms []Metric) error {
	if len(ms) == 0 {
		return nil
	}
	ts -= ts % 60
	return s.Tx(func(tx *sql.Tx) error {
		st, err := tx.Prepare(`INSERT OR REPLACE INTO metrics(ts,name,labels,value) VALUES(?,?,?,?)`)
		if err != nil {
			return err
		}
		defer st.Close()
		for _, m := range ms {
			lab := ""
			if len(m.Labels) > 0 {
				b, _ := json.Marshal(m.Labels)
				lab = string(b)
			}
			if _, err := st.Exec(ts, m.Name, lab, m.Value); err != nil {
				return err
			}
		}
		return nil
	})
}

// HostUpdate carries what a source learned about a host this cycle. Counters
// are added; identity fields replace only when non-empty.
type HostUpdate struct {
	IP, MAC, Name, Vendor, Zone, OS, DeviceType, Source string
	BytesIn, BytesOut, Flows, Blocked, Alerts           int64
	IsLocal                                             *bool
	LastSeen                                            int64
}

func (s *Store) UpsertHosts(ups []HostUpdate) error {
	if len(ups) == 0 {
		return nil
	}
	now := time.Now().Unix()
	return s.Tx(func(tx *sql.Tx) error {
		ins, err := tx.Prepare(`INSERT INTO hosts(ip,mac,name,vendor,zone,os,device_type,first_seen,last_seen,
			bytes_in,bytes_out,flows,blocked,alerts,is_local,source) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
			ON CONFLICT(ip) DO UPDATE SET
			  mac=COALESCE(excluded.mac,mac), name=COALESCE(excluded.name,name),
			  vendor=COALESCE(excluded.vendor,vendor), zone=COALESCE(excluded.zone,zone),
			  os=COALESCE(excluded.os,os), device_type=COALESCE(excluded.device_type,device_type),
			  last_seen=MAX(last_seen, excluded.last_seen),
			  bytes_in=bytes_in+excluded.bytes_in, bytes_out=bytes_out+excluded.bytes_out,
			  flows=flows+excluded.flows, blocked=blocked+excluded.blocked, alerts=alerts+excluded.alerts,
			  is_local=COALESCE(excluded.is_local,is_local), source=COALESCE(excluded.source,source)`)
		if err != nil {
			return err
		}
		defer ins.Close()
		for _, u := range ups {
			if u.IP == "" {
				continue
			}
			ls := u.LastSeen
			if ls == 0 {
				ls = now
			}
			var local any
			if u.IsLocal != nil {
				if *u.IsLocal {
					local = 1
				} else {
					local = 0
				}
			}
			if _, err := ins.Exec(u.IP, nz(u.MAC), nz(u.Name), nz(u.Vendor), nz(u.Zone), nz(u.OS),
				nz(u.DeviceType), ls, ls, u.BytesIn, u.BytesOut, u.Flows, u.Blocked, u.Alerts, local,
				nz(u.Source)); err != nil {
				return err
			}
		}
		return nil
	})
}

// Findings --------------------------------------------------------------

// AddFinding is idempotent on fingerprint: an open finding is refreshed, not
// duplicated. It returns true when the finding is new.
func (s *Store) AddFinding(module, kind, severity, subject, title, detail, fingerprint string) (bool, error) {
	return s.AddFindingWith(module, kind, severity, subject, title, detail, fingerprint, nil)
}

// AddFindingWith records a finding with structured detail beside the prose:
// who (the device), what (application, name, payload, volume), where (the
// far end, its place and network) and why (the rule and the numbers that
// tripped it). The prose stays for readers and for exports; the structure
// is what lets a page answer "which host sent what, where, and why" in
// columns rather than in a sentence. attrs may be nil.
func (s *Store) AddFindingWith(module, kind, severity, subject, title, detail, fingerprint string, attrs map[string]any) (bool, error) {
	if fingerprint == "" {
		fingerprint = module + ":" + kind + ":" + subject
	}
	var attrsJSON any
	if len(attrs) > 0 {
		if b, err := json.Marshal(attrs); err == nil {
			attrsJSON = string(b)
		}
	}
	isNew := false
	err := s.Tx(func(tx *sql.Tx) error {
		var id int64
		err := tx.QueryRow(`SELECT id FROM findings WHERE fingerprint=? AND resolved_ts IS NULL`,
			fingerprint).Scan(&id)
		if err == nil {
			if attrsJSON != nil {
				_, err = tx.Exec(`UPDATE findings SET severity=?, title=?, detail=?, attrs=? WHERE id=?`,
					severity, title, detail, attrsJSON, id)
			} else {
				_, err = tx.Exec(`UPDATE findings SET severity=?, title=?, detail=? WHERE id=?`,
					severity, title, detail, id)
			}
			return err
		}
		isNew = true
		_, err = tx.Exec(`INSERT INTO findings(ts,module,kind,severity,subject,title,detail,fingerprint,attrs)
			VALUES(?,?,?,?,?,?,?,?,?)`, time.Now().Unix(), module, kind, severity, subject, title, detail,
			fingerprint, attrsJSON)
		return err
	})
	return isNew, err
}

// ResolveFindings closes every open finding of a module not in keep.
func (s *Store) ResolveFindings(module string, keep map[string]bool) (int, error) {
	n := 0
	err := s.Tx(func(tx *sql.Tx) error {
		rows, err := tx.Query(`SELECT id, fingerprint FROM findings WHERE module=? AND resolved_ts IS NULL`, module)
		if err != nil {
			return err
		}
		var gone []int64
		for rows.Next() {
			var id int64
			var fp string
			if err := rows.Scan(&id, &fp); err != nil {
				rows.Close()
				return err
			}
			if !keep[fp] {
				gone = append(gone, id)
			}
		}
		rows.Close()
		now := time.Now().Unix()
		for _, id := range gone {
			if _, err := tx.Exec(`UPDATE findings SET resolved_ts=? WHERE id=?`, now, id); err != nil {
				return err
			}
			n++
		}
		return nil
	})
	return n, err
}

// RecordChange stores a configuration change with its diff.
func (s *Store) RecordChange(module, subject, actor, before, after, diff, summary string) error {
	if len(diff) > 200000 {
		diff = diff[:200000]
	}
	return s.Exec(`INSERT INTO changes(ts,module,subject,actor,before_hash,after_hash,diff,summary)
		VALUES(?,?,?,?,?,?,?,?)`, time.Now().Unix(), module, subject, actor, before, after, diff, summary)
}

// Rollup / retention ----------------------------------------------------

func bucketOf(ts int64) int64 { return ts - ts%300 }

// Rollup folds completed five-minute buckets into the rollup tables. It
// recomputes the two most recent buckets each time so a long flow whose
// byte counts kept growing is captured correctly.
func (s *Store) Rollup() error {
	now := time.Now().Unix()
	var last int64
	s.KVGet("rollup.last", &last)
	start := bucketOf(now) - 86400
	if last > 0 {
		start = last - 600
	}
	var dirty int64
	s.KVGet("rollup.dirty", &dirty)
	if dirty > 0 && bucketOf(dirty) < start {
		start = bucketOf(dirty)
	}
	end := bucketOf(now)
	if start >= end {
		return nil
	}
	err := s.Tx(func(tx *sql.Tx) error {
		// Only the DNS rollup is rebuilt from raw rows; the flow rollups are
		// accumulated as bytes are observed (see AddFlows) and left alone.
		for _, t := range []string{"rollup_dns"} {
			if _, err := tx.Exec(`DELETE FROM `+t+` WHERE bucket>=? AND bucket<?`, start, end); err != nil {
				return err
			}
		}
		stmts := []string{
			`INSERT INTO rollup_dns(bucket,client,domain,action,list,queries)
			 SELECT (ts/300)*300, COALESCE(client,''), COALESCE(domain,''), COALESCE(action,'pass'),
			 MAX(COALESCE(list,'')), COUNT(*) FROM dns WHERE ts>=? AND ts<? GROUP BY 1,2,3,4`,
		}
		for _, q := range stmts {
			if _, err := tx.Exec(q, start, end); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if dirty > 0 {
		_ = s.KVSet("rollup.dirty", int64(0))
	}
	return s.KVSet("rollup.last", end)
}

// Prune applies retention and compacts.
func (s *Store) Prune(r Retention) error {
	now := time.Now().Unix()
	days := func(d, def int) int64 {
		if d <= 0 {
			d = def
		}
		return now - int64(d)*86400
	}
	err := s.Tx(func(tx *sql.Tx) error {
		q := []struct {
			sql string
			arg int64
		}{
			{`DELETE FROM flows WHERE ts<?`, days(r.FlowsDays, 7)},
			{`DELETE FROM tls_sessions WHERE ts<?`, days(r.FlowsDays, 7)},
			{`DELETE FROM metrics WHERE ts<?`, days(r.FlowsDays, 7)},
			{`DELETE FROM dns WHERE ts<?`, days(r.DNSDays, 7)},
			{`DELETE FROM dns_names WHERE ts<?`, days(r.DNSDays, 7)},
			{`DELETE FROM alerts WHERE ts<?`, days(r.AlertsDays, 30)},
			{`DELETE FROM events WHERE ts<?`, days(r.EventsDays, 30)},
			{`DELETE FROM notifications WHERE ts<?`, days(r.EventsDays, 30)},
			{`DELETE FROM rollup_app WHERE bucket<?`, days(r.RollupDays, 400)},
			{`DELETE FROM rollup_domain WHERE bucket<?`, days(r.RollupDays, 400)},
			{`DELETE FROM rollup_dst WHERE bucket<?`, days(r.RollupDays, 400)},
			{`DELETE FROM rollup_dns WHERE bucket<?`, days(r.RollupDays, 400)},
			{`DELETE FROM tls_certs WHERE last_seen<?`, days(r.TLSDays, 90)},
			{`DELETE FROM findings WHERE resolved_ts IS NOT NULL AND resolved_ts<?`, days(r.EventsDays, 30)},
			{`DELETE FROM changes WHERE ts<?`, days(r.RollupDays, 400)},
			{`DELETE FROM hosts WHERE last_seen<?`, days(r.RollupDays, 400)},
		}
		for _, x := range q {
			if _, err := tx.Exec(x.sql, x.arg); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	_, _ = s.db.Exec(`PRAGMA wal_checkpoint(TRUNCATE)`)
	return nil
}

// Stats reports table sizes for the health page.
func (s *Store) Stats() map[string]any {
	out := map[string]any{"path": s.Path}
	if st, err := os.Stat(s.Path); err == nil {
		out["bytes"] = st.Size()
	}
	if st, err := os.Stat(s.Path + "-wal"); err == nil {
		out["wal_bytes"] = st.Size()
	}
	for _, t := range []string{"hosts", "flows", "dns", "alerts", "events", "tls_certs", "tls_sessions",
		"devices", "findings", "rollup_app", "rollup_domain", "rollup_dns", "metrics"} {
		out[t] = s.Int(`SELECT COUNT(*) FROM ` + t)
	}
	return out
}

// CountryLookup is what the enrich module publishes as "enrich": the
// country of a public address from the local database.
type CountryLookup interface{ CountryOf(ip string) string }

// AnycastLookup is what the paths module publishes as "anycast": whether an
// address sits in a range announced from many sites at once, and by whom.
type AnycastLookup interface {
	Anycast(ip string) (bool, string)
}

// FillCountries stamps the far end's country, and whether it is anycast, on
// flows that arrived without one (the flow probe does not know countries;
// the proxy log never does). The local end is the source for outbound flows
// and the destination for inbound ones, so whichever side is not local is
// looked up. Either lookup may be nil.
func FillCountries(flows []Flow, look CountryLookup, anyc AnycastLookup, isLocal func(string) bool) {
	if look == nil && anyc == nil {
		return
	}
	type ans struct {
		cc      string
		anycast bool
	}
	memo := map[string]ans{}
	far := func(ip string) (ans, bool) {
		if ip == "" || (isLocal != nil && isLocal(ip)) {
			return ans{}, false
		}
		if v, ok := memo[ip]; ok {
			return v, true
		}
		var v ans
		if look != nil {
			v.cc = look.CountryOf(ip)
		}
		if anyc != nil {
			v.anycast, _ = anyc.Anycast(ip)
		}
		memo[ip] = v
		return v, true
	}
	for i := range flows {
		if flows[i].Country != "" && flows[i].Anycast {
			continue
		}
		v, ok := far(flows[i].DstIP)
		if !ok || (v.cc == "" && !v.anycast) {
			if v2, ok2 := far(flows[i].SrcIP); ok2 && (v2.cc != "" || v2.anycast) {
				v = v2
			}
		}
		if flows[i].Country == "" {
			flows[i].Country = v.cc
		}
		if v.anycast {
			flows[i].Anycast = true
		}
	}
}

// IsSpecialIP is true for addresses no name or country should ever attach
// to: loopback, unspecified, link-local, multicast.
func IsSpecialIP(ip string) bool {
	a := net.ParseIP(strings.TrimSpace(ip))
	if a == nil {
		return false
	}
	return a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsLinkLocalMulticast() || a.IsMulticast()
}
