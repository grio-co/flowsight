package install

import (
	"fmt"
	"strings"
	"time"
)

// Plan is what the installer will do, written before it does anything. It
// is also the file an unattended install is given, so a site installed by
// hand once can be installed the same way again.
type Plan struct {
	Format    int       `json:"format"` // bumped when the file changes incompatibly
	CreatedAt time.Time `json:"created_at"`
	Facts     Facts     `json:"facts"`

	Supported bool   `json:"supported"`
	Reason    string `json:"reason,omitempty"` // why not, when not

	Platform string `json:"platform"` // opnsense, freebsd, linux, darwin
	// Position is where FlowSight sits relative to the traffic: in-path (it
	// runs on the device that routes), adjacent (beside it, working through
	// what it exports and what is steered to FlowSight), or off-path (flow
	// exports or a mirror only).
	Position string   `json:"position"`
	Why      []string `json:"why"` // the facts the position was decided from

	Providers map[string]string `json:"providers"` // role -> provider, "none" when no provider is here
	Service   string            `json:"service"`   // opnsense-plugin, rc.d, systemd, container, none
	Paths     map[string]string `json:"paths"`     // config, data, log

	Steps     []Step     `json:"steps"`
	Questions []Question `json:"questions,omitempty"`
	Warnings  []string   `json:"warnings,omitempty"`
}

// Step is one thing apply will do.
type Step struct {
	ID      string   `json:"id"`
	Do      string   `json:"do"`      // what, in plain words
	Changes []string `json:"changes"` // files, services, objects touched
}

// Question is something detection could not settle. Answered in the plan
// file, it no longer has to be asked.
type Question struct {
	ID      string `json:"id"`
	Ask     string `json:"ask"`
	Default string `json:"default,omitempty"`
	Answer  string `json:"answer,omitempty"`
}

// PlanFormat is the current plan file format.
const PlanFormat = 1

// Roles a provider can fill (docs/DESIGN-PLATFORM.md, "Roles and providers").
var roles = []string{"enforcer", "resolver", "interceptor", "classifier", "detector"}

// MakePlan decides what to do from the facts. It never changes anything.
func MakePlan(f Facts, now time.Time) Plan {
	p := Plan{Format: PlanFormat, CreatedAt: now.UTC(), Facts: f, Supported: true,
		Providers: map[string]string{}, Paths: map[string]string{}}

	switch f.System {
	case "opnsense":
		p.Platform, p.Service = "opnsense", "opnsense-plugin"
		p.Paths = map[string]string{"config": "/usr/local/etc/flowsight/flowsight.json", "data": "/var/db/flowsight", "log": "/var/log/flowsight"}
	case "freebsd":
		p.Platform, p.Service = "freebsd", "rc.d"
		p.Paths = map[string]string{"config": "/usr/local/etc/flowsight/flowsight.json", "data": "/var/db/flowsight", "log": "/var/log/flowsight"}
	case "pfsense":
		p.unsupported("pfSense is not supported yet; the port is planned (docs/DESIGN-PLATFORM.md, Phase 4)")
	case "openwrt":
		p.unsupported("OpenWrt is not supported yet; it needs a smaller build and an nftables provider")
	case "vyos":
		p.unsupported("VyOS is not supported yet; it needs the nftables provider")
	case "darwin":
		p.unsupported("macOS runs FlowSight for development only; there is nothing to install on")
		p.Platform = "darwin"
	default:
		if f.OS != "linux" {
			p.unsupported(fmt.Sprintf("%s is not a platform FlowSight installs on", f.System))
			break
		}
		p.Platform, p.Service = "linux", "systemd"
		p.Paths = map[string]string{"config": "/etc/flowsight/flowsight.json", "data": "/var/lib/flowsight", "log": "/var/log/flowsight"}
	}
	if f.Container != "" && f.Init != "systemd" && p.Service != "" {
		p.Service = "container"
	}

	p.position(f)
	p.providers(f)
	if !p.Supported {
		return p
	}
	if !f.Root {
		p.Warnings = append(p.Warnings, "not running as root: the plan is shown, but applying it needs root")
	}
	if f.Installed {
		ver := f.InstalledVersion
		if ver == "" {
			ver = "an unknown version"
		}
		p.Warnings = append(p.Warnings, "FlowSight is already installed ("+ver+"); applying keeps its configuration and data")
	}
	p.steps(f)
	p.questions(f)
	return p
}

func (p *Plan) unsupported(why string) {
	p.Supported, p.Reason = false, why
}

// position decides where FlowSight sits. It is a proposal; the operator
// confirms it.
func (p *Plan) position(f Facts) {
	switch {
	case f.Firewall == "pf" && (f.System == "opnsense" || f.System == "pfsense" || f.Forwards):
		p.Position = "in-path"
		p.Why = append(p.Why, "this machine is the firewall ("+f.System+")")
		if f.Forwards {
			p.Why = append(p.Why, "it forwards packets between interfaces")
		}
	case f.Forwards && f.NAT && f.HostsGuests == "" && f.NetAdmin && f.Container == "":
		p.Position = "in-path"
		p.Why = append(p.Why, "it forwards packets between interfaces and translates addresses, as a gateway does",
			"FlowSight may change its network stack")
	case f.Container != "" && !f.NetAdmin:
		p.Position = "adjacent"
		p.Why = append(p.Why, fmt.Sprintf("it runs in a %s container without NET_ADMIN, so it cannot change the network", f.Container))
	default:
		p.Position = "adjacent"
		switch {
		case f.Forwards && f.HostsGuests != "":
			p.Why = append(p.Why, "it forwards packets for its "+f.HostsGuests+" guests, which does not make it the network's gateway")
		case f.Forwards && !f.NAT:
			p.Why = append(p.Why, "it forwards packets but does not translate addresses, so it is not the network's gateway")
		case f.Forwards:
			p.Why = append(p.Why, "it forwards packets, but FlowSight may not change its network stack here")
		default:
			p.Why = append(p.Why, "it does not forward packets: the firewall is another device")
		}
		if f.Gateway != "" {
			p.Why = append(p.Why, "the default gateway is "+f.Gateway)
		}
	}
	if f.Kubernetes {
		p.Why = append(p.Why, "it runs in a Kubernetes pod")
	}
}

// providers picks, per role, the tool already on this machine. Whatever is
// already there is what FlowSight uses; nothing is installed on the
// operator's behalf.
func (p *Plan) providers(f Facts) {
	for _, r := range roles {
		p.Providers[r] = "none"
	}
	if p.Position == "in-path" && f.Firewall == "pf" {
		p.Providers["enforcer"] = "pf"
	}
	for _, r := range []string{"unbound", "pihole", "adguard", "dnsmasq"} {
		if f.HasBackend(r) {
			p.Providers["resolver"] = r
			break
		}
	}
	if f.HasBackend("squid") && p.Providers["enforcer"] != "none" {
		p.Providers["interceptor"] = "squid"
	}
	if f.HasBackend("ntopng") {
		p.Providers["classifier"] = "ntopng"
	}
	if f.HasBackend("suricata") {
		p.Providers["detector"] = "suricata"
	}
	if p.Providers["enforcer"] == "none" && p.Supported {
		p.Warnings = append(p.Warnings, "no enforcer here: policies will be observed and reported, and blocked only where the resolver or an integration can")
	}
	if p.Providers["resolver"] == "unbound" && p.Providers["enforcer"] == "none" && f.HasBackend("squid") {
		p.Warnings = append(p.Warnings, "squid is installed, but transparent interception needs an enforcer to redirect traffic to it")
	}
}

func (p *Plan) steps(f Facts) {
	cfg := p.Paths["config"]
	add := func(id, do string, changes ...string) {
		p.Steps = append(p.Steps, Step{ID: id, Do: do, Changes: changes})
	}
	switch p.Service {
	case "opnsense-plugin":
		add("package", "install the os-flowsight package (binary, GUI page, service, pf anchors)",
			"/usr/local/sbin/flowsightd", "/usr/local/www/flowsight.php", "/usr/local/etc/rc.d/flowsight")
	case "rc.d":
		add("binary", "install the flowsightd binary", "/usr/local/sbin/flowsightd")
		add("service", "install the rc.d service and enable it", "/usr/local/etc/rc.d/flowsight", "flowsight_enable in /etc/rc.conf")
	case "systemd":
		add("binary", "install the flowsightd binary", "/usr/local/sbin/flowsightd")
		add("service", "install the systemd unit and enable it", "/lib/systemd/system/flowsight.service")
	case "container":
		add("container", "run flowsightd as the container's process; nothing is installed on a host")
	}
	if f.Installed {
		add("config", "keep the existing configuration", cfg)
	} else {
		add("config", "write a configuration with a new API token (readable by root only)", cfg)
	}
	if p.Providers["enforcer"] == "pf" && p.Platform == "freebsd" {
		add("anchors", "check that pf.conf references FlowSight's anchors, and say what to add if not; pf.conf is not edited",
			"/etc/pf.conf (read only)")
	}
	if p.Service != "container" {
		add("start", "start the service and check that every module loads")
		add("verify", "run each provider's own health check and report what works, what is degraded and why")
	}
	p.Warnings = append(p.Warnings, "enforcement stays off: the installer never turns it on")
}

func (p *Plan) questions(f Facts) {
	if p.Position == "adjacent" && f.Container != "" {
		// A container's default gateway is its bridge on the host, not the
		// network's firewall, so there is no address to offer.
		p.Questions = append(p.Questions, Question{ID: "firewall",
			Ask:     "Which firewall does this network use? Its address and type (opnsense, pfsense, mikrotik, unifi, other), or skip",
			Default: "skip"})
	} else if p.Position == "adjacent" && f.Gateway != "" {
		p.Questions = append(p.Questions, Question{ID: "firewall",
			Ask:     fmt.Sprintf("What is the firewall at %s? (opnsense, pfsense, mikrotik, unifi, other, or skip)", f.Gateway),
			Default: "skip"})
	}
	if len(upIfaces(f)) > 1 && p.Position == "in-path" {
		p.Questions = append(p.Questions, Question{ID: "lan",
			Ask:     "Which interfaces face the local network? (" + strings.Join(upIfaces(f), ", ") + ")",
			Default: "detect from the local networks"})
	}
}

func upIfaces(f Facts) []string {
	var out []string
	for _, i := range f.Ifaces {
		if i.Up && len(i.Addrs) > 0 {
			out = append(out, i.Name)
		}
	}
	return out
}
