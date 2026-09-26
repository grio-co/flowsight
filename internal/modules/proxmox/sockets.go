package proxmox

// What a VM's own kernel says it is connected to.
//
// Traffic between two guests on the same bridge never crosses the gateway,
// so the flow probe cannot see it. A VM with a guest agent can be asked
// instead: one fixed command, `ss -Htn state established` (or `netstat -tn`
// where ss is missing), through the agent's exec channel, which needs the
// VM.Monitor privilege on the token. Off by default. Containers have no
// agent and are not asked.

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

// socketPeer is one established connection seen from inside a guest.
type socketPeer struct {
	LocalPort  int
	RemoteIP   string
	RemotePort int
}

// parseSockets reads `ss -Htn state established` (recvq sendq local peer
// [process]) or `netstat -tn` (proto recvq sendq local foreign state).
func parseSockets(out string) []socketPeer {
	var peers []socketPeer
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		var local, remote string
		switch {
		case f[0] == "tcp" || f[0] == "tcp6" || f[0] == "tcp4": // netstat
			if len(f) < 6 || !strings.EqualFold(f[5], "ESTABLISHED") {
				continue
			}
			local, remote = f[3], f[4]
		case f[0] == "Proto" || f[0] == "Active" || f[0] == "Recv-Q" || f[0] == "State":
			continue
		case strings.HasPrefix(f[0], "ESTAB"): // ss without -H
			if len(f) < 5 {
				continue
			}
			local, remote = f[3], f[4]
		default: // ss -H: recvq sendq local peer
			local, remote = f[2], f[3]
		}
		lp := hostPort(local)
		rip, rp := splitHostPort(remote)
		if rip == "" || rp == 0 || lp == 0 {
			continue
		}
		peers = append(peers, socketPeer{LocalPort: lp, RemoteIP: rip, RemotePort: rp})
	}
	return peers
}

func hostPort(s string) int {
	_, p := splitHostPort(s)
	return p
}

// splitHostPort takes "1.2.3.4:443", "[fd00::1]:22" and "fd00::1:22".
func splitHostPort(s string) (string, int) {
	s = strings.TrimSpace(s)
	if h, p, err := net.SplitHostPort(s); err == nil {
		n, _ := strconv.Atoi(p)
		return strings.TrimPrefix(strings.Trim(h, "[]"), "::ffff:"), n
	}
	i := strings.LastIndex(s, ":")
	if i < 0 {
		return "", 0
	}
	n, err := strconv.Atoi(s[i+1:])
	if err != nil {
		return "", 0
	}
	h := strings.TrimPrefix(strings.Trim(s[:i], "[]"), "::ffff:")
	if h == "" || h == "*" {
		return "", 0
	}
	return h, n
}

// peerEdges turns a guest's connections into edges towards other guests.
// The service side is the lower port: a connection whose remote port is
// ephemeral was opened by the far end towards our local port.
func peerEdges(vmid int, peers []socketPeer, ipToGuest map[string]int) []Edge {
	seen := map[string]*Edge{}
	for _, p := range peers {
		other, ok := ipToGuest[p.RemoteIP]
		if !ok || other == vmid {
			continue
		}
		e := Edge{From: vmid, To: other, Port: p.RemotePort, Proto: "tcp", Flows: 1, Source: "sockets"}
		if p.RemotePort >= 32768 && p.LocalPort < 32768 {
			e = Edge{From: other, To: vmid, Port: p.LocalPort, Proto: "tcp", Flows: 1, Source: "sockets"}
		}
		k := fmt.Sprintf("%d>%d:%d", e.From, e.To, e.Port)
		if x := seen[k]; x != nil {
			x.Flows++
			continue
		}
		cp := e
		seen[k] = &cp
	}
	out := make([]Edge, 0, len(seen))
	for _, e := range seen {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].From != out[j].From {
			return out[i].From < out[j].From
		}
		if out[i].To != out[j].To {
			return out[i].To < out[j].To
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// postValues posts a form with repeated keys (the agent exec command is an
// array parameter).
func (m *Module) postValues(hostURL, path string, vals url.Values) ([]byte, error) {
	u, err := url.Parse(hostURL)
	if err != nil {
		return nil, err
	}
	u.Path = path
	req, _ := http.NewRequest("POST", u.String(), strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	cr := m.credsFor(hostURL)
	req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", cr.TokenID, cr.TokenSecret))
	client, err := m.httpClient(hostURL)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, _ := readAllLimited(resp)
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return b, nil
}

// probeGuestSockets runs the fixed command in one VM and waits for it.
func (m *Module) probeGuestSockets(g Guest) ([]socketPeer, error) {
	run := func(cmd []string) (string, error) {
		vals := url.Values{}
		for _, c := range cmd {
			vals.Add("command", c)
		}
		b, err := m.postValues(g.HostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/exec", g.Node, g.VMID), vals)
		if err != nil {
			return "", err
		}
		var started struct {
			Data struct {
				PID int `json:"pid"`
			} `json:"data"`
		}
		if err := json.Unmarshal(b, &started); err != nil || started.Data.PID == 0 {
			return "", fmt.Errorf("agent exec gave no pid")
		}
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
			sb, err := m.get(g.HostURL, fmt.Sprintf("/api2/json/nodes/%s/qemu/%d/agent/exec-status?pid=%d", g.Node, g.VMID, started.Data.PID))
			if err != nil {
				return "", err
			}
			var st struct {
				Data struct {
					Exited   int    `json:"exited"`
					ExitCode int    `json:"exitcode"`
					Out      string `json:"out-data"`
				} `json:"data"`
			}
			if json.Unmarshal(sb, &st) == nil && st.Data.Exited == 1 {
				if st.Data.ExitCode != 0 {
					return "", fmt.Errorf("exit %d", st.Data.ExitCode)
				}
				return st.Data.Out, nil
			}
		}
		return "", fmt.Errorf("timed out")
	}
	out, err := run([]string{"ss", "-Htn", "state", "established"})
	if err != nil {
		out, err = run([]string{"netstat", "-tn"})
		if err != nil {
			return nil, err
		}
	}
	return parseSockets(out), nil
}

// probeSockets asks every running VM with an agent, once per poll, when
// the setting is on, and keeps the edges for the map.
func (m *Module) probeSockets(inv *Inventory) {
	if !core.Bool(m.ctx.Settings(), "probe_sockets", false) {
		m.mu.Lock()
		m.sockEdges, m.sockNotes = nil, nil
		m.mu.Unlock()
		return
	}
	ipToGuest := map[string]int{}
	for _, g := range inv.Guests {
		for _, ip := range g.IPs {
			ipToGuest[ip] = g.VMID
		}
	}
	var edges []Edge
	var notes []string
	for _, g := range inv.Guests {
		if g.Type != "qemu" || g.Status != "running" || g.AgentState != "responding" || g.HostURL == "" {
			continue
		}
		peers, err := m.probeGuestSockets(g)
		if err != nil {
			notes = append(notes, fmt.Sprintf("%s (%d): %v", g.Name, g.VMID, err))
			continue
		}
		edges = append(edges, peerEdges(g.VMID, peers, ipToGuest)...)
	}
	m.mu.Lock()
	m.sockEdges, m.sockNotes, m.sockAt = edges, notes, time.Now().Unix()
	m.mu.Unlock()
}

// socketEdges is what the last probe found.
func (m *Module) socketEdges(_ map[string]int) []Edge {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Edge(nil), m.sockEdges...)
}
