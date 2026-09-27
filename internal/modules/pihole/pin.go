package pihole

// Certificate pinning for Pi-holes.
//
// Pi-hole v6 serves a self-signed certificate, so ordinary verification
// cannot be used and was simply turned off: anyone able to intercept the
// connection could read the app password FlowSight sends and every
// configuration change. Now the first connection to each Pi-hole records
// the SHA-256 of its certificate, and every later connection must present
// the same one. A Pi-hole whose certificate is replaced on purpose is
// re-pinned from its status row (POST /api/pihole/pins/clear).

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

const pinsKV = "pihole.pins"

var pinMu sync.Mutex

func (m *Module) pins() map[string]string {
	out := map[string]string{}
	m.ctx.Store.KVGet(pinsKV, &out)
	return out
}

// pinnedClient trusts each Pi-hole's first certificate and nothing else.
func (m *Module) pinnedClient() *http.Client {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		ForceAttemptHTTP2: false,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			raw, err := dialer.DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			host, _, _ := net.SplitHostPort(addr)
			tc := tls.Client(raw, &tls.Config{InsecureSkipVerify: true, ServerName: host, MinVersion: tls.VersionTLS12}) // pinned below
			if err := tc.HandshakeContext(ctx); err != nil {
				raw.Close()
				return nil, err
			}
			certs := tc.ConnectionState().PeerCertificates
			if len(certs) == 0 {
				tc.Close()
				return nil, fmt.Errorf("%s presented no certificate", addr)
			}
			sum := sha256.Sum256(certs[0].Raw)
			got := hex.EncodeToString(sum[:])
			pinMu.Lock()
			defer pinMu.Unlock()
			p := m.pins()
			want, known := p[addr]
			switch {
			case !known:
				p[addr] = got
				_ = m.ctx.Store.KVSet(pinsKV, p)
				m.ctx.Log.Info("pi-hole certificate pinned", "server", addr, "sha256", got[:16])
			case want != got:
				tc.Close()
				return nil, fmt.Errorf("the certificate of %s changed (pinned %s…, now %s…); if it was replaced on purpose, re-pin it under DNS › Pi-hole", addr, want[:12], got[:12])
			}
			return tc, nil
		},
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     60 * time.Second,
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

func (m *Module) apiClearPin(r *core.Req) (any, error) {
	var in struct {
		Server string `json:"server"`
	}
	if err := r.Decode(&in); err != nil {
		return nil, err
	}
	pinMu.Lock()
	defer pinMu.Unlock()
	p := m.pins()
	removed := []string{}
	for addr := range p {
		host, _, _ := net.SplitHostPort(addr)
		if in.Server == "" || in.Server == "all" || strings.Contains(in.Server, host) {
			delete(p, addr)
			removed = append(removed, addr)
		}
	}
	if err := m.ctx.Store.KVSet(pinsKV, p); err != nil {
		return nil, err
	}
	_ = m.ctx.Store.RecordChange("pihole", "pins", r.User, "", "", "", "Pi-hole certificate pins cleared: "+strings.Join(removed, ", "))
	return map[string]any{"ok": true, "cleared": removed}, nil
}
