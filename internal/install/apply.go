package install

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Result is what an apply did. It is kept in the data directory as
// install.json, one entry per run, so an uninstall can put back what was
// there before.
type Result struct {
	AppliedAt time.Time    `json:"applied_at"`
	Version   string       `json:"version"`
	Platform  string       `json:"platform"`
	Position  string       `json:"position"`
	Files     []FileChange `json:"files"`
	Commands  []string     `json:"commands"`
	Notes     []string     `json:"notes,omitempty"`
	Verify    *Verify      `json:"verify,omitempty"`

	// Token is a newly created API token, shown once in the summary. It is
	// never written to install.json; the configuration file holds it.
	Token string `json:"-"`
}

// FileChange is one file an apply touched.
type FileChange struct {
	Path   string `json:"path"`
	Action string `json:"action"`           // created, replaced, unchanged, kept
	Backup string `json:"backup,omitempty"` // where the previous contents went
}

// Verify is what the installed daemon said about itself after starting.
type Verify struct {
	Answering bool              `json:"answering"`
	Modules   int               `json:"modules"`
	Degraded  map[string]string `json:"degraded,omitempty"` // module -> why
}

const (
	binaryPath  = "/usr/local/sbin/flowsightd"
	rcPath      = "/usr/local/etc/rc.d/flowsight"
	unitPath    = "/lib/systemd/system/flowsight.service"
	manifestOut = "install.json"
)

const rcScript = `#!/bin/sh
# PROVIDE: flowsight
# REQUIRE: LOGIN
# KEYWORD: shutdown
# Written by flowsightd install.
. /etc/rc.subr
name=flowsight
rcvar=flowsight_enable
load_rc_config $name
: ${flowsight_enable:=NO}
pidfile=/var/run/flowsight/flowsightd.pid
procname=/usr/local/sbin/flowsightd
supervisor_pidfile=/var/run/flowsight/daemon.pid
start_cmd=flowsight_start
stop_cmd=flowsight_stop
status_cmd=flowsight_status
flowsight_supervisor() {
    local pid
    [ -f ${supervisor_pidfile} ] || return 1
    pid=$(cat ${supervisor_pidfile})
    [ -n "${pid}" ] && kill -0 "${pid}" 2>/dev/null || return 1
    echo "${pid}"
}
flowsight_start() {
    if flowsight_supervisor >/dev/null; then echo "${name} is already running."; return 0; fi
    install -d -m 755 /var/run/flowsight /var/log/flowsight /var/db/flowsight
    echo "Starting ${name}."
    /usr/sbin/daemon -f -S -T flowsightd -R 5 -P ${supervisor_pidfile} -p ${pidfile} \
        ${procname} -config /usr/local/etc/flowsight/flowsight.json </dev/null >/dev/null 2>&1
}
# Stop the daemon(8) supervisor, which passes SIGTERM on to flowsightd;
# stopping only flowsightd left the supervisor to start it again.
flowsight_stop() {
    local pid
    if ! pid=$(flowsight_supervisor); then echo "${name} is not running."; return 1; fi
    echo "Stopping ${name}."
    kill -TERM "${pid}"
    pwait -t 30 "${pid}" 2>/dev/null
    ! kill -0 "${pid}" 2>/dev/null
}
flowsight_status() {
    local pid
    if pid=$(flowsight_supervisor); then echo "${name} is running as pid $(cat ${pidfile} 2>/dev/null) (supervisor ${pid})."; else echo "${name} is not running."; return 1; fi
}
run_rc_command "$1"
`

const systemdUnit = `# Written by flowsightd install.
[Unit]
Description=FlowSight: L7 visibility, policy and enforcement
After=network-online.target unbound.service
Wants=network-online.target
[Service]
ExecStart=/usr/local/sbin/flowsightd -config /etc/flowsight/flowsight.json
Restart=on-failure
RestartSec=5
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
`

// Apply carries out a plan. It refuses a plan that is not supported or
// needs root it does not have, backs up every file it replaces, never
// switches enforcement on, and records what it did. say reports progress.
func Apply(e Env, p Plan, version string, now time.Time, say func(string)) (Result, error) {
	r := Result{AppliedAt: now.UTC(), Version: version, Platform: p.Platform, Position: p.Position}
	if !p.Supported {
		return r, errors.New("this plan cannot be applied: " + p.Reason)
	}
	if !p.Facts.Root {
		return r, errors.New("applying a plan needs root")
	}
	stamp := now.UTC().Format("20060102T150405Z")
	var err error
	for _, s := range p.Steps {
		say(s.Do)
		switch s.ID {
		case "package":
			if !p.Facts.Installed {
				return r, errors.New("install the os-flowsight package first (System > Firmware > Plugins, or pkg add); on OPNsense the package, not this command, installs the binary and the GUI page")
			}
			r.Notes = append(r.Notes, "the os-flowsight package owns the binary; it was left as it is")
		case "binary":
			err = r.copyBinary(e, stamp)
		case "service":
			err = r.installService(e, p, stamp)
		case "enable":
			err = r.enable(e, p)
		case "container":
			r.Notes = append(r.Notes, "in a container nothing is installed on a host; run flowsightd as the container's command")
		case "config":
			err = r.writeConfig(e, p)
		case "anchors":
			r.checkAnchors(e)
		case "start":
			err = r.start(e, p)
		case "verify":
			if p.Service != "container" {
				r.Verify = verify(e, p)
			}
		}
		if err != nil {
			_ = r.save(e, p)
			return r, fmt.Errorf("%s: %w", s.ID, err)
		}
	}
	return r, r.save(e, p)
}

// writeFile replaces path with text, keeping the previous contents beside
// it when they differ. mode applies to a new or replaced file.
func (r *Result) writeFile(e Env, path string, text []byte, mode os.FileMode, stamp string) error {
	full := e.path(path)
	old, err := os.ReadFile(full)
	switch {
	case err == nil && bytes.Equal(old, text):
		r.Files = append(r.Files, FileChange{Path: path, Action: "unchanged"})
		return nil
	case err == nil:
		backup := path + ".flowsight-backup-" + stamp
		if err := os.WriteFile(e.path(backup), old, 0o600); err != nil {
			return fmt.Errorf("backing up %s: %w", path, err)
		}
		r.Files = append(r.Files, FileChange{Path: path, Action: "replaced", Backup: backup})
	case errors.Is(err, os.ErrNotExist):
		r.Files = append(r.Files, FileChange{Path: path, Action: "created"})
	default:
		return err
	}
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, text, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

func (r *Result) copyBinary(e Env, stamp string) error {
	src := e.Exe
	if src == "" {
		return errors.New("cannot tell which binary is running")
	}
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	// The updater keeps the binary before the current one as
	// flowsightd.previous for its rollback; the installer does the same.
	full := e.path(binaryPath)
	if old, err := os.ReadFile(full); err == nil && !bytes.Equal(old, b) {
		if err := os.WriteFile(full+".previous", old, 0o755); err != nil {
			return err
		}
		r.Files = append(r.Files, FileChange{Path: binaryPath, Action: "replaced", Backup: binaryPath + ".previous"})
		return r.put(e, binaryPath, b, 0o755)
	} else if err == nil {
		r.Files = append(r.Files, FileChange{Path: binaryPath, Action: "unchanged"})
		return nil
	}
	r.Files = append(r.Files, FileChange{Path: binaryPath, Action: "created"})
	return r.put(e, binaryPath, b, 0o755)
}

// put writes a file whose change has already been recorded.
func (r *Result) put(e Env, path string, b []byte, mode os.FileMode) error {
	full := e.path(path)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		return err
	}
	tmp := full + ".tmp"
	if err := os.WriteFile(tmp, b, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, full)
}

func (r *Result) run(e Env, name string, args ...string) error {
	r.Commands = append(r.Commands, strings.TrimSpace(name+" "+strings.Join(args, " ")))
	if e.Run == nil {
		return errors.New("cannot run commands")
	}
	out, err := e.Run(name, args...)
	if err != nil {
		return fmt.Errorf("%s %s: %v %s", name, strings.Join(args, " "), err, strings.TrimSpace(out))
	}
	return nil
}

func (r *Result) installService(e Env, p Plan, stamp string) error {
	switch p.Service {
	case "rc.d":
		if err := r.writeFile(e, rcPath, []byte(rcScript), 0o755, stamp); err != nil {
			return err
		}
	case "systemd":
		if err := r.writeFile(e, unitPath, []byte(systemdUnit), 0o644, stamp); err != nil {
			return err
		}
	}
	return r.enable(e, p)
}

// enable turns the service on at boot, whoever installed its file.
func (r *Result) enable(e Env, p Plan) error {
	switch p.Service {
	case "rc.d":
		return r.run(e, "sysrc", "-q", "flowsight_enable=YES")
	case "systemd":
		if err := r.run(e, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		return r.run(e, "systemctl", "enable", "flowsight")
	}
	return nil
}

func (r *Result) writeConfig(e Env, p Plan) error {
	cfg := p.Paths["config"]
	for _, d := range dirsFor(p) {
		if err := os.MkdirAll(e.path(d), 0o750); err != nil {
			return err
		}
	}
	if _, err := os.Stat(e.path(cfg)); err == nil {
		r.Files = append(r.Files, FileChange{Path: cfg, Action: "kept"})
		return nil
	}
	if p.Platform == "opnsense" {
		return nil // the GUI signs people in; the daemon writes its own defaults
	}
	tok, err := token()
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(map[string]any{"api_token": tok}, "", "  ")
	r.Files = append(r.Files, FileChange{Path: cfg, Action: "created"})
	r.Token = tok
	return r.put(e, cfg, append(b, '\n'), 0o600)
}

func dirsFor(p Plan) []string {
	out := []string{filepath.Dir(p.Paths["config"]), p.Paths["data"], p.Paths["log"]}
	if p.Platform == "freebsd" || p.Platform == "opnsense" {
		out = append(out, "/var/run/flowsight")
	}
	return out
}

// token is 32 letters and digits from the system's random source.
func token() (string, error) {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, 32)
	for i := range b {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", err
		}
		b[i] = alphabet[n.Int64()]
	}
	return string(b), nil
}

// checkAnchors reads pf.conf for FlowSight's anchors and says what to add
// when they are missing. pf.conf is never edited.
func (r *Result) checkAnchors(e Env) {
	conf, _ := os.ReadFile(e.path("/etc/pf.conf"))
	var missing []string
	for _, line := range []string{`nat-anchor "flowsight/*"`, `rdr-anchor "flowsight/*"`, `anchor "flowsight/*"`} {
		if !bytes.Contains(conf, []byte(line)) {
			missing = append(missing, line)
		}
	}
	if len(missing) > 0 {
		r.Notes = append(r.Notes, "pf.conf does not reference FlowSight's anchors; nothing FlowSight loads is evaluated until you add, then reload pf: "+
			strings.Join(missing, "; "))
	}
}

func (r *Result) start(e Env, p Plan) error {
	switch p.Service {
	case "rc.d", "opnsense-plugin":
		if err := r.run(e, "service", "flowsight", "restart"); err != nil {
			return r.run(e, "service", "flowsight", "start")
		}
	case "systemd":
		return r.run(e, "systemctl", "restart", "flowsight")
	}
	return nil
}

// verify asks the running daemon for its health over loopback, presenting
// the token from its configuration, and lists every module that is not
// well. It waits up to half a minute for the daemon to answer.
func verify(e Env, p Plan) *Verify {
	v := &Verify{}
	var cfg struct {
		Port     int    `json:"port"`
		APIToken string `json:"api_token"`
	}
	b, _ := os.ReadFile(e.path(p.Paths["config"]))
	_ = json.Unmarshal(b, &cfg)
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	get := e.Get
	if get == nil {
		get = httpGet
	}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/system/health", cfg.Port)
	hdr := map[string]string{"X-Requested-With": "Flowsight"}
	if cfg.APIToken != "" {
		hdr["X-Flowsight-Token"] = cfg.APIToken
	}
	var body []byte
	for i := 0; i < 30; i++ {
		code, out, err := get(url, hdr)
		if err == nil && code == 200 {
			body, v.Answering = out, true
			break
		}
		if e.Sleep != nil {
			e.Sleep(time.Second)
		}
	}
	if !v.Answering {
		return v
	}
	var h struct {
		Modules map[string]struct {
			OK     bool   `json:"ok"`
			Detail string `json:"detail"`
		} `json:"modules"`
	}
	_ = json.Unmarshal(body, &h)
	v.Modules = len(h.Modules)
	for name, m := range h.Modules {
		if !m.OK {
			if v.Degraded == nil {
				v.Degraded = map[string]string{}
			}
			v.Degraded[name] = m.Detail
		}
	}
	return v
}

func httpGet(url string, hdr map[string]string) (int, []byte, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, nil, err
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return resp.StatusCode, b, err
}

// save appends this run to install.json in the data directory.
func (r *Result) save(e Env, p Plan) error {
	dir := p.Paths["data"]
	if dir == "" {
		return nil
	}
	path := e.path(filepath.Join(dir, manifestOut))
	var runs []Result
	if b, err := os.ReadFile(path); err == nil {
		_ = json.Unmarshal(b, &runs)
	}
	runs = append(runs, *r)
	b, _ := json.MarshalIndent(runs, "", "  ")
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// Summary writes what an apply did in plain words.
func (r Result) Summary() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	for _, f := range r.Files {
		line := fmt.Sprintf("  %-9s %s", f.Action, f.Path)
		if f.Backup != "" {
			line += " (previous kept as " + f.Backup + ")"
		}
		w("%s", line)
	}
	for _, n := range r.Notes {
		w("Note: %s.", n)
	}
	if r.Token != "" {
		w("API token (shown once; it is also in the configuration file, readable by root only): %s", r.Token)
	}
	if v := r.Verify; v != nil {
		if !v.Answering {
			w("The daemon did not answer on loopback within half a minute; check the service log.")
		} else {
			w("The daemon answers: %d modules loaded, %d not well.", v.Modules, len(v.Degraded))
			names := make([]string, 0, len(v.Degraded))
			for n := range v.Degraded {
				names = append(names, n)
			}
			sort.Strings(names)
			for _, n := range names {
				w("  %s: %s", n, v.Degraded[n])
			}
		}
	}
	return b.String()
}
