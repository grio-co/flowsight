package mitm

import (
	"encoding/json"
	"net/url"
	"time"
)

// scrubStoredURLs rewrites the URLs earlier versions stored in the flow
// history with their query values, credentials and fragments intact, so
// what was recorded before redaction existed is redacted too. It runs once,
// in the background, in batches, and remembers that it has.
func (m *Module) scrubStoredURLs() error {
	var done bool
	if m.ctx.Store.KVGet("mitm.urls_redacted", &done) && done {
		return nil
	}
	last := int64(0)
	for {
		rows, err := m.ctx.Store.Rows(`SELECT id, attrs FROM flows WHERE source='mitm' AND id>? AND attrs LIKE '%"url":"%' ORDER BY id LIMIT 500`, last)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			id, _ := r["id"].(int64)
			last = id
			raw, _ := r["attrs"].(string)
			var attrs map[string]any
			if json.Unmarshal([]byte(raw), &attrs) != nil {
				continue
			}
			s, _ := attrs["url"].(string)
			u, err := url.Parse(s)
			if err != nil {
				attrs["url"] = ""
			} else if red := redactURL(u); red != s {
				attrs["url"] = red
			} else {
				continue
			}
			b, _ := json.Marshal(attrs)
			_ = m.ctx.Store.Exec(`UPDATE flows SET attrs=? WHERE id=?`, string(b), id)
		}
		time.Sleep(50 * time.Millisecond) // let the collectors in between batches
	}
	return m.ctx.Store.KVSet("mitm.urls_redacted", true)
}
