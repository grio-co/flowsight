package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakeMachine builds an Env over a temporary root: files, binaries on PATH,
// command output, environment and interfaces.
type fakeMachine struct {
	t      *testing.T
	goos   string
	uid    int
	files  map[string]string
	bins   map[string]bool
	cmds   map[string]string // "name arg arg" -> output
	env    map[string]string
	ifaces []Iface
}

func machine(t *testing.T, goos string) *fakeMachine {
	return &fakeMachine{t: t, goos: goos, files: map[string]string{}, bins: map[string]bool{},
		cmds: map[string]string{}, env: map[string]string{}}
}

func (m *fakeMachine) env_() Env {
	root := m.t.TempDir()
	for p, text := range m.files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			m.t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(text), 0o755); err != nil {
			m.t.Fatal(err)
		}
	}
	return Env{
		Root: root, GOOS: m.goos, GOARCH: "amd64", UID: m.uid,
		Getenv: func(k string) string { return m.env[k] },
		LookPath: func(b string) (string, error) {
			if m.bins[b] {
				return "/usr/bin/" + b, nil
			}
			return "", errors.New("not found")
		},
		Run: func(name string, args ...string) (string, error) {
			key := filepath.Base(name)
			if len(args) > 0 {
				key += " " + strings.Join(args, " ")
			}
			if out, ok := m.cmds[key]; ok {
				return out, nil
			}
			return "", errors.New("no such command")
		},
		Ifaces: func() ([]Iface, error) { return m.ifaces, nil },
	}
}

func plan(m *fakeMachine) Plan {
	return MakePlan(Detect(m.env_()), time.Date(2026, 9, 26, 21, 0, 0, 0, time.UTC))
}

func (m *fakeMachine) twoLANs() *fakeMachine {
	m.ifaces = []Iface{{Name: "vtnet0", Up: true, Addrs: []string{"192.168.1.1/24"}}, {Name: "vtnet1", Up: true, Addrs: []string{"203.0.113.2/24"}}}
	return m
}

func TestOPNsenseFirewallIsInPath(t *testing.T) {
	m := machine(t, "freebsd").twoLANs()
	m.files["/usr/local/sbin/opnsense-version"] = "#!/bin/sh"
	m.files["/dev/pf"] = ""
	m.files["/usr/local/sbin/unbound"] = ""
	m.files["/usr/local/sbin/squid"] = ""
	m.files["/usr/local/bin/suricata"] = ""
	m.cmds["opnsense-version -v"] = "26.7"
	m.cmds["sysctl -n net.inet.ip.forwarding"] = "1"
	m.cmds["kenv -q smbios.system.maker"] = "QEMU"
	p := plan(m)
	if !p.Supported || p.Platform != "opnsense" || p.Position != "in-path" || p.Service != "opnsense-plugin" {
		t.Fatalf("opnsense: %+v", p)
	}
	if p.Facts.Version != "26.7" || p.Facts.Virtual != "kvm" {
		t.Errorf("facts: %+v", p.Facts)
	}
	want := map[string]string{"enforcer": "pf", "resolver": "unbound", "interceptor": "squid", "classifier": "none", "detector": "suricata"}
	for k, v := range want {
		if p.Providers[k] != v {
			t.Errorf("provider %s = %s, want %s", k, p.Providers[k], v)
		}
	}
	if !strings.Contains(p.Explain(), "enforcement stays off") {
		t.Error("the plan must say enforcement stays off")
	}
}

func TestFreeBSDChecksAnchorsWithoutEditingPFConf(t *testing.T) {
	m := machine(t, "freebsd").twoLANs()
	m.files["/dev/pf"] = ""
	m.cmds["sysctl -n net.inet.ip.forwarding"] = "1"
	m.cmds["freebsd-version"] = "15.1-RELEASE"
	p := plan(m)
	if p.Platform != "freebsd" || p.Service != "rc.d" || p.Providers["enforcer"] != "pf" {
		t.Fatalf("freebsd: %+v", p)
	}
	var anchors *Step
	for i := range p.Steps {
		if p.Steps[i].ID == "anchors" {
			anchors = &p.Steps[i]
		}
	}
	if anchors == nil || !strings.Contains(anchors.Do, "not edited") {
		t.Fatalf("pf.conf must only be checked: %+v", p.Steps)
	}
}

func TestDebianGatewayIsInPathWithoutAnEnforcerYet(t *testing.T) {
	m := machine(t, "linux").twoLANs()
	m.files["/etc/os-release"] = "ID=debian\nVERSION_ID=\"13\"\n"
	m.files["/proc/sys/net/ipv4/ip_forward"] = "1"
	m.files["/usr/sbin/unbound"] = ""
	m.bins["nft"] = true
	m.cmds["nft list ruleset"] = "table ip nat {\n\tchain postrouting {\n\t\toifname \"eth1\" masquerade\n\t}\n}"
	p := plan(m)
	if p.Platform != "linux" || p.Service != "systemd" || p.Position != "in-path" || p.Facts.System != "debian" || p.Facts.Version != "13" {
		t.Fatalf("debian gateway: %+v", p)
	}
	if p.Facts.Firewall != "nftables" || p.Providers["enforcer"] != "none" {
		t.Fatalf("nftables is detected but has no provider yet: %+v", p.Providers)
	}
	if !strings.Contains(strings.Join(p.Warnings, "|"), "no enforcer here") {
		t.Error("the plan must say policies are only observed without an enforcer")
	}
}

func TestHostBesideAFirewallIsAdjacentAndAsksAboutIt(t *testing.T) {
	m := machine(t, "linux")
	m.files["/etc/os-release"] = "ID=debian\nVERSION_ID=\"13\"\n"
	m.files["/proc/sys/net/ipv4/ip_forward"] = "0"
	m.cmds["ip route show default"] = "default via 192.168.1.1 dev vmbr0 proto kernel onlink"
	m.ifaces = []Iface{{Name: "vmbr0", Up: true, Addrs: []string{"192.168.1.253/24"}}}
	p := plan(m)
	if p.Position != "adjacent" || p.Facts.Gateway != "192.168.1.1" || p.Facts.GatewayIf != "vmbr0" {
		t.Fatalf("adjacent host: %+v", p)
	}
	if len(p.Questions) != 1 || p.Questions[0].ID != "firewall" || !strings.Contains(p.Questions[0].Ask, "192.168.1.1") {
		t.Fatalf("it should ask what the firewall at the gateway is: %+v", p.Questions)
	}
}

func TestDockerWithoutNetAdminIsAdjacent(t *testing.T) {
	m := machine(t, "linux")
	m.files["/.dockerenv"] = ""
	m.files["/etc/os-release"] = "ID=alpine\nVERSION_ID=3.20\n"
	m.files["/proc/self/status"] = "Name:\tflowsightd\nCapEff:\t00000000a80425fb\n"
	p := plan(m)
	if p.Facts.Container != "docker" || p.Facts.NetAdmin || p.Position != "adjacent" || p.Service != "container" {
		t.Fatalf("docker without NET_ADMIN: %+v", p)
	}
	// Its default gateway is the host's bridge, not the firewall; the
	// question must not offer it as one.
	m.files["/proc/net/route"] = "Iface\tDestination\tGateway \tFlags\neth0\t00000000\t010011AC\t0003\n"
	p = plan(m)
	if len(p.Questions) != 1 || strings.Contains(p.Questions[0].Ask, "172.17.0.1") {
		t.Fatalf("a container must ask for the firewall, not name its bridge: %+v", p.Questions)
	}
}

func TestDockerWithNetAdminIsSeen(t *testing.T) {
	m := machine(t, "linux")
	m.files["/.dockerenv"] = ""
	m.files["/proc/self/status"] = "CapEff:\t00000000a80435fb\n" // bit 12 set
	if f := Detect(m.env_()); !f.NetAdmin {
		t.Fatalf("CAP_NET_ADMIN not read: %+v", f)
	}
}

func TestKubernetesPod(t *testing.T) {
	m := machine(t, "linux")
	m.env["KUBERNETES_SERVICE_HOST"] = "10.96.0.1"
	m.files["/proc/1/cgroup"] = "0::/kubepods.slice/kubepods-burstable.slice/cri-containerd-abc.scope\n"
	f := Detect(m.env_())
	if !f.Kubernetes || f.Container == "" {
		t.Fatalf("pod not recognised: %+v", f)
	}
	if !strings.Contains(MakePlan(f, time.Now()).Explain(), "Kubernetes pod") {
		t.Error("the plan should say it is in a pod")
	}
}

func TestCloudFromDMIOnly(t *testing.T) {
	m := machine(t, "linux")
	m.files["/sys/class/dmi/id/sys_vendor"] = "Amazon EC2"
	m.files["/sys/class/dmi/id/product_name"] = "t3.small"
	if f := Detect(m.env_()); f.Cloud != "aws" || f.Virtual != "kvm" {
		t.Fatalf("aws not read from DMI: %+v", f)
	}
	m = machine(t, "linux")
	m.files["/sys/class/dmi/id/sys_vendor"] = "Microsoft Corporation"
	m.files["/sys/class/dmi/id/product_name"] = "Virtual Machine"
	if f := Detect(m.env_()); f.Cloud != "" || f.Virtual != "hyper-v" {
		t.Fatalf("hyper-v without the Azure asset tag is not Azure: %+v", f)
	}
}

func TestPfSenseIsRecognisedButNotYetSupported(t *testing.T) {
	m := machine(t, "freebsd")
	m.files["/etc/platform"] = "pfSense\n"
	m.files["/etc/version"] = "2.8.0-RELEASE"
	m.files["/dev/pf"] = ""
	p := plan(m)
	if p.Supported || p.Facts.System != "pfsense" || !strings.Contains(p.Reason, "pfSense") {
		t.Fatalf("pfsense: %+v", p)
	}
	if len(p.Steps) != 0 {
		t.Fatal("an unsupported system must have no steps")
	}
}

func TestExistingInstallIsKept(t *testing.T) {
	m := machine(t, "freebsd")
	m.files["/usr/local/sbin/opnsense-version"] = ""
	m.files["/usr/local/etc/flowsight/flowsight.json"] = "{}"
	m.files["/usr/local/sbin/flowsightd"] = ""
	m.cmds["flowsightd -version"] = "flowsightd 0.9.8r202609262120"
	p := plan(m)
	if !p.Facts.Installed || p.Facts.InstalledVersion != "0.9.8r202609262120" {
		t.Fatalf("existing install: %+v", p.Facts)
	}
	for _, s := range p.Steps {
		if s.ID == "config" && !strings.Contains(s.Do, "keep") {
			t.Fatalf("an existing configuration must be kept: %+v", s)
		}
	}
}

func TestNotRootIsWarned(t *testing.T) {
	m := machine(t, "linux")
	m.uid = 1000
	m.files["/etc/os-release"] = "ID=ubuntu\n"
	if p := plan(m); !strings.Contains(strings.Join(p.Warnings, "|"), "needs root") {
		t.Fatalf("not root: %+v", p.Warnings)
	}
}

// A Proxmox host forwards packets for its guests; that does not make it the
// gateway. Found on PVE2, which the first version called in-path.
func TestHypervisorHostIsNotTheGateway(t *testing.T) {
	m := machine(t, "linux").twoLANs()
	m.files["/etc/os-release"] = "ID=debian\nVERSION_ID=\"13\"\n"
	m.files["/proc/sys/net/ipv4/ip_forward"] = "1"
	m.files["/etc/pve/.version"] = ""
	m.bins["nft"] = true
	m.files["/proc/net/route"] = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\nvmbr0\t00000000\t0100A8C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n"
	p := plan(m)
	if p.Facts.HostsGuests != "proxmox" || p.Position != "adjacent" || !strings.Contains(strings.Join(p.Why, " "), "proxmox guests") {
		t.Fatalf("proxmox host: %+v %v", p.Facts, p.Why)
	}
	if p.Facts.Gateway != "192.168.0.1" || p.Facts.GatewayIf != "vmbr0" {
		t.Fatalf("gateway from /proc/net/route: %q %q", p.Facts.Gateway, p.Facts.GatewayIf)
	}
	if len(p.Questions) == 0 || p.Questions[0].ID != "firewall" {
		t.Fatalf("it should ask what the firewall at 192.168.0.1 is: %+v", p.Questions)
	}
}

// Docker's own masquerade for its bridge is not a gateway's NAT.
func TestDockerHostMasqueradeIsNotNAT(t *testing.T) {
	m := machine(t, "linux")
	m.bins["iptables"] = true
	m.cmds["iptables -t nat -S"] = "-P POSTROUTING ACCEPT\n-A POSTROUTING -s 172.17.0.0/16 ! -o docker0 -j MASQUERADE"
	if f := Detect(m.env_()); f.NAT {
		t.Fatal("docker's bridge masquerade counted as a gateway's NAT")
	}
}

// A minimal container has no ip(8); the default route comes from /proc.
func TestContainerGatewayWithoutTools(t *testing.T) {
	m := machine(t, "linux")
	m.files["/.dockerenv"] = ""
	m.files["/proc/net/route"] = "Iface\tDestination\tGateway \tFlags\nlo\t0000007F\t00000000\t0001\neth0\t00000000\t010011AC\t0003\n"
	if f := Detect(m.env_()); f.Gateway != "172.17.0.1" || f.GatewayIf != "eth0" {
		t.Fatalf("container default route: %q %q", f.Gateway, f.GatewayIf)
	}
}

// An LXC system container runs systemd as process 1 and is installed like a
// host. Found on the test client, which the first version treated as an
// application container and gave no service.
func TestSystemContainerIsInstalledLikeAHost(t *testing.T) {
	m := machine(t, "linux")
	m.files["/etc/os-release"] = "ID=debian\nVERSION_ID=\"13\"\n"
	m.files["/proc/1/environ"] = "container=lxc\x00"
	m.files["/proc/1/comm"] = "systemd"
	p := plan(m)
	if p.Facts.Container != "lxc" || p.Service != "systemd" {
		t.Fatalf("lxc with systemd: container=%q service=%q", p.Facts.Container, p.Service)
	}
	ids := []string{}
	for _, s := range p.Steps {
		ids = append(ids, s.ID)
	}
	if strings.Join(ids, ",") != "binary,service,config,start,verify" {
		t.Fatalf("steps: %v", ids)
	}
}

// An application container starts nothing itself, so its plan must not
// promise to start or verify a service.
func TestApplicationContainerPlanHasNoServiceSteps(t *testing.T) {
	m := machine(t, "linux")
	m.files["/.dockerenv"] = ""
	m.files["/proc/1/comm"] = "flowsightd"
	for _, s := range plan(m).Steps {
		if s.ID == "start" || s.ID == "verify" || s.ID == "service" {
			t.Fatalf("an application container got a %s step", s.ID)
		}
	}
}
