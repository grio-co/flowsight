package mitm

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"io"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// Recording bodies.
//
// Everywhere else this module previews a body to answer a question and drops
// it. Recording is the deliberate exception: to work out what an application
// sends, the operator needs the request and the response as they were.
//
// It is therefore narrow by construction. It is off by default; it keeps
// nothing unless the host is named in body_hosts; each body is capped; and
// every body is deleted once body_keep_minutes have passed, by a job that
// runs whether or not recording is still on. Turning recording off deletes
// what was recorded. A recorded body is the decrypted traffic of a device on
// this network, credentials and all, so it is meant to be switched on for a
// few minutes against one host and switched off again.

const bodySchema = `
CREATE TABLE IF NOT EXISTS mitm_bodies (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,
	client TEXT,
	host TEXT,
	method TEXT,
	url TEXT,
	direction TEXT,
	status INTEGER,
	content_type TEXT,
	encoding TEXT,
	complete INTEGER DEFAULT 0,
	size INTEGER DEFAULT 0,
	body BLOB
)`

func (m *Module) initBodySchema() error {
	if err := m.ctx.Store.Exec(bodySchema); err != nil {
		return err
	}
	return m.ctx.Store.Exec(`CREATE INDEX IF NOT EXISTS mitm_bodies_ts ON mitm_bodies(ts)`)
}

// recordingBodies reports whether recording is on and which hosts it covers.
func (m *Module) recordingBodies() (bool, []string) {
	s := m.ctx.Settings()
	if !core.Bool(s, "store_bodies", false) {
		return false, nil
	}
	var hosts []string
	for _, h := range core.Strs(s, "body_hosts") {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			hosts = append(hosts, h)
		}
	}
	// No host named is not "every host": it is nothing, so that turning the
	// switch on cannot by itself start recording the whole network.
	return len(hosts) > 0, hosts
}

// bodyHostMatch is an exact host match or a *.suffix match, port ignored.
func bodyHostMatch(host string, pats []string) bool {
	h := strings.ToLower(hostOnly(host))
	for _, p := range pats {
		switch {
		case p == h:
			return true
		case strings.HasPrefix(p, "*."):
			if suf := p[1:]; strings.HasSuffix(h, suf) {
				return true
			}
		case strings.HasPrefix(p, "."):
			if strings.HasSuffix(h, p) {
				return true
			}
		}
	}
	return false
}

// keepBody stores one body, capped, when the host is one of the named ones.
func (m *Module) keepBody(rec Request, body []byte, isResponse bool, encoding string, complete bool) {
	if len(body) == 0 {
		return
	}
	on, hosts := m.recordingBodies()
	if !on || !bodyHostMatch(rec.Host, hosts) {
		return
	}
	max := core.Int(m.ctx.Settings(), "body_max_bytes", 65536)
	if max < 1 {
		max = 1
	}
	if len(body) > max {
		body, complete = body[:max], false
	}
	dir := "request"
	if isResponse {
		dir = "response"
	}
	_ = m.ctx.Store.Exec(`INSERT INTO mitm_bodies(ts,client,host,method,url,direction,status,content_type,encoding,complete,size,body)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		rec.TS, rec.Client, rec.Host, rec.Method, rec.URL, dir, rec.Status, rec.Type, encoding,
		boolInt(complete), len(body), body)
}

// expireBodies deletes bodies past their keep time, and everything once
// recording is off. It runs on a job, so a forgotten switch still empties.
func (m *Module) expireBodies() error {
	on, _ := m.recordingBodies()
	if !on {
		return m.ctx.Store.Exec(`DELETE FROM mitm_bodies`)
	}
	keep := core.Int(m.ctx.Settings(), "body_keep_minutes", 60)
	if keep < 1 {
		keep = 1
	}
	return m.ctx.Store.Exec(`DELETE FROM mitm_bodies WHERE ts < ?`, time.Now().Unix()-int64(keep)*60)
}

// decodeBody undoes the transfer encoding so a recorded body reads as it was
// written. Brotli and zstd have no decoder here; those come back as they are.
func decodeBody(b []byte, encoding string) ([]byte, bool) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "gzip", "x-gzip":
		r, err := gzip.NewReader(bytes.NewReader(b))
		if err != nil {
			return b, false
		}
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, 8<<20))
		if err != nil && len(out) == 0 {
			return b, false
		}
		return out, true
	case "deflate":
		r := flate.NewReader(bytes.NewReader(b))
		defer r.Close()
		out, err := io.ReadAll(io.LimitReader(r, 8<<20))
		if err != nil && len(out) == 0 {
			return b, false
		}
		return out, true
	case "", "identity":
		return b, true
	}
	return b, false
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// apiBodies lists what was recorded. The list carries no bodies; one body
// comes back at a time, by id, and never to a read-only token: a recorded
// body is the most sensitive thing this product holds.
func (m *Module) apiBodies(r *core.Req) (any, error) {
	on, hosts := m.recordingBodies()
	out := map[string]any{"recording": on, "hosts": hosts,
		"expires_in_minutes": core.Int(m.ctx.Settings(), "body_keep_minutes", 60)}
	if id := r.QInt("id", 0, 0, 1<<31-1); id > 0 {
		if core.ReadOnly(r.Context()) {
			return nil, core.Forbidden("a read-only token cannot read a recorded body")
		}
		rows, err := m.ctx.Store.Rows(`SELECT id,ts,client,host,method,url,direction,status,content_type,encoding,complete,size,body
			FROM mitm_bodies WHERE id=?`, id)
		if err != nil {
			return nil, err
		}
		if len(rows) == 0 {
			return nil, core.NotFound("no recorded body %d", id)
		}
		row := rows[0]
		raw := asBytes(row["body"])
		enc, _ := row["encoding"].(string)
		b, decoded := decodeBody(raw, enc)
		delete(row, "body")
		row["complete"] = row["complete"] == int64(1)
		row["decoded"] = decoded
		if isText(row["content_type"]) && decoded {
			row["text"] = string(b)
		} else {
			row["base64"] = b
		}
		out["body"] = row
		return out, nil
	}
	q := `SELECT id,ts,client,host,method,url,direction,status,content_type,encoding,complete,size FROM mitm_bodies`
	args := []any{}
	h, err := r.QSafe("host", "", 120)
	if err != nil {
		return nil, err
	}
	if h != "" {
		q += ` WHERE host LIKE ?`
		args = append(args, "%"+h+"%")
	}
	limit := r.QInt("limit", 100, 1, 1000)
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err2 := m.ctx.Store.Rows(q, args...)
	if err2 != nil {
		return nil, err2
	}
	for _, row := range rows {
		row["complete"] = row["complete"] == int64(1)
	}
	out["bodies"] = rows
	out["count"] = len(rows)
	return out, nil
}

func (m *Module) apiBodiesClear(r *core.Req) (any, error) {
	if err := m.ctx.Store.Exec(`DELETE FROM mitm_bodies`); err != nil {
		return nil, err
	}
	m.ctx.Event("mitm", "recorded bodies deleted", map[string]any{"by": r.User})
	return map[string]any{"ok": true}, nil
}

// isText reports whether a content type is worth returning as a string.
func isText(v any) bool {
	t, _ := v.(string)
	t = strings.ToLower(t)
	return strings.HasPrefix(t, "text/") || strings.Contains(t, "json") ||
		strings.Contains(t, "xml") || strings.Contains(t, "urlencoded") || strings.Contains(t, "javascript")
}

// asBytes accepts what the driver gives for a BLOB, which is []byte for some
// values and string for others.
func asBytes(v any) []byte {
	switch b := v.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	}
	return nil
}
