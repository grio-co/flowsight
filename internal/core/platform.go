// Package core is the thin centre of FlowSight: configuration, the embedded
// store, the module registry, the scheduler and the HTTP API. Nothing
// domain-specific lives here.
package core

import (
	"context"
	"encoding/xml"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Platform describes where FlowSight is running and where the backends it
// composes keep their files. Modules never branch on the OS themselves; they
// ask the platform. Every path can be overridden in the config document.
type Platform struct {
	Name     string `json:"name"`     // opnsense, pfsense, freebsd, linux
	Family   string `json:"family"`   // freebsd, linux
	Firewall string `json:"firewall"` // pf, nft, none

	EtcDir   string `json:"etc_dir"`
	DataDir  string `json:"data_dir"`
	RunDir   string `json:"run_dir"`
	LogDir   string `json:"log_dir"`
	ShareDir string `json:"share_dir"`

	UnboundControl   string `json:"unbound_control"`
	UnboundConfig    string `json:"unbound_config"` // "" means do not pass -c
	UnboundCheckconf string `json:"unbound_checkconf"`
	UnboundInclude   string `json:"unbound_include"`
	// UnboundPersistDir is where includes are kept that the platform copies
	// into the live include directory whenever it (re)starts the resolver
	// (OPNsense's unbound.opnsense.d). Empty: the include directory is live
	// and persistent itself.
	UnboundPersistDir string `json:"unbound_persist_dir"`
	// UnboundZoneDir is where RPZ zone files go: inside the resolver's
	// chroot, and never in a directory the platform empties on a restart.
	// Empty: next to the include.
	UnboundZoneDir string `json:"unbound_zone_dir"`
	UnboundDuckDB  string `json:"unbound_duckdb"`
	UnboundLog     string `json:"unbound_log"`

	SuricataEve      string `json:"suricata_eve"`
	SuricataRulesDir string `json:"suricata_rules_dir"`

	SquidAccessLog  string `json:"squid_access_log"`
	SquidIncludeDir string `json:"squid_include_dir"`
	SquidBin        string `json:"squid_bin"`
	SquidConf       string `json:"squid_conf"`

	NtopngURL  string `json:"ntopng_url"`
	NtopngConf string `json:"ntopng_conf"`

	DHCPLeases     []string `json:"dhcp_leases"`
	DnsmasqConfDir string   `json:"dnsmasq_conf_dir"`
	Pfctl          string   `json:"pfctl"`
	OpenSSL        string   `json:"openssl"`
	Configctl      string   `json:"configctl"`
	ConfigXML      string   `json:"config_xml"`
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// DetectPlatform picks the platform from what is on disk.
func DetectPlatform() *Platform {
	switch {
	case exists("/usr/local/sbin/opnsense-version"):
		return opnsense()
	case isPfSense("/etc/platform"):
		return pfsense()
	case runtime.GOOS == "freebsd":
		return freebsd()
	case runtime.GOOS == "darwin":
		return darwin() // macOS: generic mode, no firewall integration
	default:
		return linux()
	}
}

func opnsense() *Platform {
	return &Platform{
		Name: "opnsense", Family: "freebsd", Firewall: "pf",
		EtcDir: "/usr/local/etc/flowsight", DataDir: "/var/db/flowsight",
		RunDir: "/var/run/flowsight", LogDir: "/var/log/flowsight",
		ShareDir:       "/usr/local/share/flowsight",
		UnboundControl: "/usr/local/sbin/unbound-control", UnboundConfig: "/var/unbound/unbound.conf",
		UnboundCheckconf: "/usr/local/sbin/unbound-checkconf",
		UnboundInclude:   "/var/unbound/etc/flowsight-policy.conf",
		// OPNsense's start.sh empties /var/unbound/etc on every start and
		// copies back only *.conf from unbound.opnsense.d, so a zone file
		// there vanishes while the include naming it comes back.
		UnboundPersistDir: "/usr/local/etc/unbound.opnsense.d",
		UnboundZoneDir:    "/var/unbound/flowsight",
		UnboundDuckDB:     "/var/unbound/data/unbound.duckdb",
		UnboundLog:        "/var/log/resolver/latest.log",
		SuricataEve:       "/var/log/suricata/eve.json",
		SuricataRulesDir:  "/usr/local/etc/suricata/opnsense.rules",
		SquidAccessLog:    "/var/log/squid/access.log", SquidIncludeDir: "/usr/local/etc/squid/pre-auth",
		SquidBin: "/usr/local/sbin/squid", SquidConf: "/usr/local/etc/squid/squid.conf",
		NtopngURL: "http://127.0.0.1:3000", NtopngConf: "/usr/local/etc/ntopng.conf",
		DHCPLeases: []string{"/var/db/dnsmasq.leases", "/var/dhcpd/var/db/dhcpd.leases",
			"/var/db/kea/kea-leases4.csv"},
		DnsmasqConfDir: "/usr/local/etc/dnsmasq.conf.d",
		Pfctl:          "/sbin/pfctl", OpenSSL: "/usr/bin/openssl",
		Configctl: "/usr/local/sbin/configctl", ConfigXML: "/conf/config.xml",
	}
}

// isPfSense reads pfSense's platform file, which holds the word pfSense
// (CE and Plus alike).
func isPfSense(path string) bool {
	b, err := os.ReadFile(path)
	return err == nil && strings.TrimSpace(string(b)) == "pfSense"
}

// pfsense is a FreeBSD with pfSense's own layout. Its resolver
// configuration is regenerated from config.xml on every change, so
// FlowSight's includes live in /var/unbound/flowsight, which the package
// names in the resolver's custom options once; pfSense never empties it.
// The resolver logs through syslog to /var/log/resolver.log. The Suricata
// package writes one EVE log per interface.
func pfsense() *Platform {
	p := freebsd()
	p.Name = "pfsense"
	p.UnboundConfig = "/var/unbound/unbound.conf"
	p.UnboundInclude = "/var/unbound/flowsight/flowsight-policy.conf"
	p.UnboundLog = "/var/log/resolver.log"
	p.SuricataEve = "/var/log/suricata/*/eve.json"
	p.SuricataRulesDir = ""
	p.DHCPLeases = []string{"/var/dhcpd/var/db/dhcpd.leases", "/var/lib/kea/dhcp4.leases"}
	p.DnsmasqConfDir = ""
	p.ConfigXML = "/cf/conf/config.xml"
	return p
}

func freebsd() *Platform {
	p := opnsense()
	p.Name = "freebsd"
	p.UnboundConfig = "/usr/local/etc/unbound/unbound.conf"
	p.UnboundInclude = "/usr/local/etc/unbound/conf.d/flowsight-policy.conf"
	p.UnboundPersistDir = ""
	p.UnboundZoneDir = ""
	p.UnboundDuckDB = ""
	p.UnboundLog = ""
	p.SquidIncludeDir = "/usr/local/etc/squid/conf.d"
	p.NtopngConf = "/usr/local/etc/ntopng/ntopng.conf"
	p.Configctl = ""
	p.ConfigXML = ""
	return p
}

func linux() *Platform {
	fw := "none"
	if _, err := exec.LookPath("nft"); err == nil {
		fw = "nft"
	}
	return &Platform{
		Name: "linux", Family: "linux", Firewall: fw,
		EtcDir: "/etc/flowsight", DataDir: "/var/lib/flowsight", RunDir: "/run/flowsight",
		LogDir: "/var/log/flowsight", ShareDir: "/usr/share/flowsight",
		UnboundControl: "/usr/sbin/unbound-control", UnboundConfig: "",
		UnboundCheckconf: "/usr/sbin/unbound-checkconf",
		UnboundInclude:   "/etc/unbound/unbound.conf.d/flowsight-policy.conf",
		SuricataEve:      "/var/log/suricata/eve.json", SuricataRulesDir: "/etc/suricata/rules",
		SquidAccessLog: "/var/log/squid/access.log", SquidIncludeDir: "/etc/squid/conf.d",
		SquidBin: "/usr/sbin/squid", SquidConf: "/etc/squid/squid.conf",
		NtopngURL: "http://127.0.0.1:3000", NtopngConf: "/etc/ntopng/ntopng.conf",
		DHCPLeases: []string{"/var/lib/misc/dnsmasq.leases", "/var/lib/dhcp/dhcpd.leases",
			"/var/lib/kea/kea-leases4.csv"},
		DnsmasqConfDir: "/etc/dnsmasq.d", Pfctl: "", OpenSSL: "/usr/bin/openssl",
	}
}

func darwin() *Platform {
	// macOS: generic read-only mode, no firewall or service integration.
	// Use this for testing and development on macOS.
	homeDir, _ := os.UserHomeDir()
	return &Platform{
		Name: "darwin", Family: "linux", Firewall: "none",
		EtcDir:   filepath.Join(homeDir, ".flowsight", "etc"),
		DataDir:  filepath.Join(homeDir, ".flowsight", "data"),
		RunDir:   filepath.Join(homeDir, ".flowsight", "run"),
		LogDir:   filepath.Join(homeDir, ".flowsight", "log"),
		ShareDir: filepath.Join(homeDir, ".flowsight", "share"),
		// No firewall, unbound, squid, or ntopng integration
		OpenSSL: "/usr/bin/openssl",
	}
}

// IsOPNsense reports whether the OPNsense integration points exist.
func (p *Platform) IsOPNsense() bool { return p.Name == "opnsense" }

// IsPfSense reports whether this is pfSense (CE or Plus).
func (p *Platform) IsPfSense() bool { return p.Name == "pfsense" }

// pfSsh is pfSense's scripting shell; its svc session starts, stops and
// restarts services the way the GUI does, so the GUI's view stays right.
const pfSsh = "/usr/local/sbin/pfSsh.php"

// Run executes a command with a timeout and returns combined output.
func Run(timeout time.Duration, name string, args ...string) (string, error) {
	return RunIn("", timeout, name, args...)
}

// RunIn is Run with a working directory.
func RunIn(dir string, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

// UnboundCheck validates the resolver configuration. OPNsense's Unbound
// loads its python module by a path relative to /var/unbound, so the check
// must run from the config's own directory or it fails for the wrong reason.
func (p *Platform) UnboundCheck() (string, error) {
	if p.UnboundCheckconf == "" {
		return "", nil
	}
	args := []string{}
	dir := ""
	if p.UnboundConfig != "" {
		args = append(args, p.UnboundConfig)
		dir = filepath.Dir(p.UnboundConfig)
	}
	return RunIn(dir, 60*time.Second, p.UnboundCheckconf, args...)
}

// UnboundRunning reports whether the resolver answers its control channel.
// Without a control program it cannot tell and says yes, so callers keep
// reloading as they always have.
func (p *Platform) UnboundRunning() bool {
	if p.UnboundControl == "" {
		return true
	}
	args := []string{}
	if p.UnboundConfig != "" {
		args = append(args, "-c", p.UnboundConfig)
	}
	_, err := Run(15*time.Second, p.UnboundControl, append(args, "status")...)
	return err == nil
}

// UnboundEnabled reports whether the operator has the resolver switched on,
// so that FlowSight may start it when it is down. FlowSight never starts a
// resolver someone turned off, so anything it cannot read counts as off.
func (p *Platform) UnboundEnabled() bool {
	switch {
	case p.IsOPNsense() && p.ConfigXML != "":
		b, err := os.ReadFile(p.ConfigXML)
		if err != nil {
			return false
		}
		var cfg struct {
			OPNsense struct {
				Unbound struct {
					General struct {
						Enabled string `xml:"enabled"`
					} `xml:"general"`
				} `xml:"unboundplus"`
			} `xml:"OPNsense"`
		}
		if xml.Unmarshal(b, &cfg) != nil {
			return false
		}
		return strings.TrimSpace(cfg.OPNsense.Unbound.General.Enabled) == "1"
	case p.IsPfSense() && p.ConfigXML != "":
		b, err := os.ReadFile(p.ConfigXML)
		if err != nil {
			return false
		}
		var cfg struct {
			Unbound *struct {
				Enable *struct{} `xml:"enable"`
			} `xml:"unbound"`
		}
		if xml.Unmarshal(b, &cfg) != nil {
			return false
		}
		return cfg.Unbound != nil && cfg.Unbound.Enable != nil
	case p.Family == "freebsd":
		_, err := Run(15*time.Second, "/usr/sbin/service", "unbound", "enabled")
		return err == nil
	case p.Family == "linux":
		_, err := Run(15*time.Second, "systemctl", "is-enabled", "--quiet", "unbound")
		return err == nil
	}
	return false
}

// Service restarts or reloads a backend the platform manages. On OPNsense the
// GUI's configd is used so its own view of service state stays right.
func (p *Platform) Service(name, action string) (string, error) {
	switch {
	case name == "unbound" && action == "reload":
		args := []string{}
		if p.UnboundConfig != "" {
			args = append(args, "-c", p.UnboundConfig)
		}
		args = append(args, "reload")
		return Run(60*time.Second, p.UnboundControl, args...)
	case name == "squid" && action == "reload":
		return Run(60*time.Second, p.SquidBin, "-k", "reconfigure")
	}
	if p.IsOPNsense() && p.Configctl != "" {
		svc := map[string]string{"unbound": "unbound", "squid": "proxy", "suricata": "ids",
			"ntopng": "ntopng", "dnsmasq": "dnsmasq", "filter": "filter"}[name]
		if svc != "" {
			act := action
			if name == "filter" {
				act = "reload"
			}
			return Run(180*time.Second, p.Configctl, svc, act)
		}
	}
	if p.IsPfSense() {
		if name == "filter" {
			return Run(180*time.Second, "/etc/rc.filter_configure_sync")
		}
		return Run(180*time.Second, pfSsh, "playback", "svc", action, name)
	}
	if p.Family == "freebsd" {
		return Run(180*time.Second, "/usr/sbin/service", name, "one"+action)
	}
	return Run(180*time.Second, "systemctl", action, name)
}
