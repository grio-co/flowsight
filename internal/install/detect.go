// Package install is FlowSight's installer: it works out where it is
// running and what is next to it, writes a plan, and (in later steps)
// applies and verifies it. See docs/DESIGN-PLATFORM.md ("The installer").
//
// Detection reads local facts only. Nothing here opens a network
// connection, and a cloud is recognised from the machine's own DMI data,
// never by probing a metadata endpoint.
package install

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Env is everything detection reads from the machine. The zero value is not
// usable; LocalEnv returns the real one, and tests build fakes.
type Env struct {
	Root     string // filesystem root; "/" on a real machine
	GOOS     string
	GOARCH   string
	UID      int
	Getenv   func(string) string
	LookPath func(string) (string, error)
	Run      func(name string, args ...string) (string, error)
	Ifaces   func() ([]Iface, error)
}

// Iface is a network interface with its addresses.
type Iface struct {
	Name  string   `json:"name"`
	Up    bool     `json:"up"`
	Addrs []string `json:"addrs"` // CIDR notation
}

// LocalEnv reads the machine this runs on.
func LocalEnv() Env {
	return Env{
		Root: "/", GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, UID: os.Getuid(),
		Getenv: os.Getenv, LookPath: exec.LookPath,
		Run: func(name string, args ...string) (string, error) {
			cmd := exec.Command(name, args...)
			done := make(chan struct{})
			var out []byte
			var err error
			go func() { out, err = cmd.CombinedOutput(); close(done) }()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				_ = cmd.Process.Kill()
				<-done
			}
			return strings.TrimSpace(string(out)), err
		},
		Ifaces: localIfaces,
	}
}

func localIfaces() ([]Iface, error) {
	list, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []Iface
	for _, i := range list {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		f := Iface{Name: i.Name, Up: i.Flags&net.FlagUp != 0}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			f.Addrs = append(f.Addrs, a.String())
		}
		out = append(out, f)
	}
	return out, nil
}

func (e Env) path(p string) string { return filepath.Join(e.Root, p) }

func (e Env) exists(p string) bool {
	_, err := os.Stat(e.path(p))
	return err == nil
}

func (e Env) read(p string) string {
	b, err := os.ReadFile(e.path(p))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func (e Env) has(bin string) bool {
	if e.LookPath == nil {
		return false
	}
	_, err := e.LookPath(bin)
	return err == nil
}

func (e Env) run(name string, args ...string) string {
	if e.Run == nil {
		return ""
	}
	out, err := e.Run(name, args...)
	if err != nil {
		return ""
	}
	return out
}

// Facts is what detection found. Every field is something the machine said
// about itself; nothing is guessed from the network.
type Facts struct {
	OS       string `json:"os"`      // freebsd, linux, darwin
	Arch     string `json:"arch"`    // amd64, arm64, ...
	System   string `json:"system"`  // opnsense, pfsense, freebsd, openwrt, vyos, debian, ubuntu, ..., darwin
	Version  string `json:"version"` // of System, when it says
	Root     bool   `json:"root"`    // running as root
	CPUs     int    `json:"cpus"`
	MemoryMB int    `json:"memory_mb"`

	Container  string `json:"container,omitempty"`  // docker, podman, containerd, lxc; empty on a host
	Kubernetes bool   `json:"kubernetes,omitempty"` // inside a pod
	Virtual    string `json:"virtual,omitempty"`    // kvm, vmware, hyper-v, xen, ...; empty on bare metal or unknown
	Cloud      string `json:"cloud,omitempty"`      // aws, gcp, azure, digitalocean, hetzner, oracle; from DMI only

	Firewall string `json:"firewall"` // pf, nftables, iptables, none
	// HostsGuests names what this machine runs guests with (proxmox,
	// docker, libvirt, lxd). Such a host forwards packets for its guests,
	// which does not make it the network's gateway.
	HostsGuests string   `json:"hosts_guests,omitempty"`
	NAT         bool     `json:"nat"`       // translates addresses (masquerade/SNAT), as a gateway does
	NetAdmin    bool     `json:"net_admin"` // may change the network stack (root, or CAP_NET_ADMIN)
	Forwards    bool     `json:"forwards"`  // routes packets between interfaces
	Ifaces      []Iface  `json:"interfaces"`
	Gateway     string   `json:"default_gateway,omitempty"`
	GatewayIf   string   `json:"default_interface,omitempty"`
	Backends    []string `json:"backends"` // unbound, dnsmasq, pihole, adguard, squid, suricata, ntopng, zeek

	Installed        bool   `json:"installed"`         // a FlowSight configuration is present
	InstalledVersion string `json:"installed_version"` // of the flowsightd binary already installed
}

// HasBackend reports whether a backend was found.
func (f Facts) HasBackend(name string) bool {
	for _, b := range f.Backends {
		if b == name {
			return true
		}
	}
	return false
}

// Detect reads the machine.
func Detect(e Env) Facts {
	f := Facts{OS: e.GOOS, Arch: e.GOARCH, Root: e.UID == 0}
	f.System, f.Version = detectSystem(e)
	f.CPUs, f.MemoryMB = detectSize(e)
	f.Container, f.Kubernetes = detectContainer(e)
	f.Virtual, f.Cloud = detectVirtual(e)
	f.Firewall = detectFirewall(e, f.System)
	f.NetAdmin = f.Root && f.Container == "" || detectNetAdmin(e)
	f.Forwards = detectForwarding(e)
	f.HostsGuests = detectGuests(e)
	f.NAT = detectNAT(e, f.Firewall)
	if e.Ifaces != nil {
		f.Ifaces, _ = e.Ifaces()
	}
	f.Gateway, f.GatewayIf = detectGateway(e)
	f.Backends = detectBackends(e)
	f.Installed, f.InstalledVersion = detectInstalled(e)
	return f
}

func detectSystem(e Env) (string, string) {
	switch {
	case e.exists("/usr/local/sbin/opnsense-version"):
		return "opnsense", firstField(e.run("/usr/local/sbin/opnsense-version", "-v"))
	case strings.Contains(e.read("/etc/platform"), "pfSense"):
		return "pfsense", e.read("/etc/version")
	case e.exists("/etc/openwrt_release"):
		return "openwrt", osReleaseField(e.read("/etc/openwrt_release"), "DISTRIB_RELEASE")
	case e.exists("/opt/vyatta/etc/version") || e.exists("/usr/libexec/vyos"):
		return "vyos", ""
	case e.GOOS == "freebsd":
		return "freebsd", firstField(e.run("freebsd-version"))
	case e.GOOS == "darwin":
		return "darwin", ""
	}
	rel := e.read("/etc/os-release")
	if rel == "" {
		return e.GOOS, ""
	}
	id := osReleaseField(rel, "ID")
	if id == "" {
		id = e.GOOS
	}
	return id, osReleaseField(rel, "VERSION_ID")
}

func osReleaseField(text, key string) string {
	for _, line := range strings.Split(text, "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if ok && k == key {
			return strings.Trim(v, `"'`)
		}
	}
	return ""
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}

func detectSize(e Env) (int, int) {
	cpus := runtime.NumCPU()
	mem := 0
	switch e.GOOS {
	case "linux":
		for _, line := range strings.Split(e.read("/proc/meminfo"), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				if f := strings.Fields(line); len(f) >= 2 {
					kb, _ := strconv.Atoi(f[1])
					mem = kb / 1024
				}
			}
		}
	case "freebsd", "darwin":
		key := "hw.physmem"
		if e.GOOS == "darwin" {
			key = "hw.memsize"
		}
		if b, err := strconv.ParseInt(e.run("sysctl", "-n", key), 10, 64); err == nil {
			mem = int(b >> 20)
		}
	}
	return cpus, mem
}

func detectContainer(e Env) (string, bool) {
	k8s := e.Getenv != nil && e.Getenv("KUBERNETES_SERVICE_HOST") != "" ||
		e.exists("/var/run/secrets/kubernetes.io/serviceaccount/token")
	switch {
	case e.exists("/.dockerenv"):
		return "docker", k8s
	case e.exists("/run/.containerenv"):
		return "podman", k8s
	}
	cg := e.read("/proc/1/cgroup")
	switch {
	case strings.Contains(cg, "kubepods"):
		return "containerd", true
	case strings.Contains(cg, "docker"):
		return "docker", k8s
	case strings.Contains(cg, "containerd"):
		return "containerd", k8s
	case strings.Contains(cg, "/lxc/"):
		return "lxc", k8s
	}
	if e.Getenv != nil && e.Getenv("container") == "lxc" || strings.Contains(e.read("/proc/1/environ"), "container=lxc") {
		return "lxc", k8s
	}
	if k8s {
		return "containerd", true
	}
	return "", false
}

// detectVirtual reads the machine's own firmware tables: DMI on Linux,
// kenv's SMBIOS on FreeBSD.
func detectVirtual(e Env) (string, string) {
	var vendor, product string
	switch e.GOOS {
	case "linux":
		vendor, product = e.read("/sys/class/dmi/id/sys_vendor"), e.read("/sys/class/dmi/id/product_name")
		if b := e.read("/sys/class/dmi/id/bios_vendor"); vendor == "" {
			vendor = b
		}
	case "freebsd":
		vendor, product = e.run("kenv", "-q", "smbios.system.maker"), e.run("kenv", "-q", "smbios.system.product")
	}
	v := strings.ToLower(vendor + " " + product)
	switch {
	case strings.Contains(v, "amazon ec2"):
		return "kvm", "aws"
	case strings.Contains(v, "google"):
		return "kvm", "gcp"
	case strings.Contains(v, "digitalocean"):
		return "kvm", "digitalocean"
	case strings.Contains(v, "hetzner"):
		return "kvm", "hetzner"
	case strings.Contains(v, "oraclecloud") || strings.Contains(v, "oracle cloud"):
		return "kvm", "oracle"
	case strings.Contains(v, "microsoft corporation") && strings.Contains(v, "virtual machine"):
		// Hyper-V on a desktop and Azure look alike in DMI; Azure's
		// asset tag is the difference.
		if e.read("/sys/class/dmi/id/chassis_asset_tag") == "7783-7084-3265-9085-8269-3286-77" {
			return "hyper-v", "azure"
		}
		return "hyper-v", ""
	case strings.Contains(v, "qemu") || strings.Contains(v, "kvm") || strings.Contains(v, "proxmox"):
		return "kvm", ""
	case strings.Contains(v, "vmware"):
		return "vmware", ""
	case strings.Contains(v, "xen"):
		return "xen", ""
	case strings.Contains(v, "virtualbox") || strings.Contains(v, "innotek"):
		return "virtualbox", ""
	case strings.Contains(v, "bhyve"):
		return "bhyve", ""
	}
	return "", ""
}

func detectFirewall(e Env, system string) string {
	switch {
	case e.exists("/dev/pf") || e.GOOS == "freebsd" && e.exists("/sbin/pfctl"):
		return "pf"
	case e.has("nft"):
		return "nftables"
	case e.has("iptables"):
		return "iptables"
	}
	return "none"
}

// detectNetAdmin reads the effective capabilities of this process on Linux:
// CAP_NET_ADMIN is bit 12.
func detectNetAdmin(e Env) bool {
	if e.GOOS != "linux" {
		return false
	}
	for _, line := range strings.Split(e.read("/proc/self/status"), "\n") {
		if strings.HasPrefix(line, "CapEff:") {
			v, err := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			return err == nil && v&(1<<12) != 0
		}
	}
	return false
}

func detectForwarding(e Env) bool {
	switch e.GOOS {
	case "linux":
		return e.read("/proc/sys/net/ipv4/ip_forward") == "1"
	case "freebsd":
		return e.run("sysctl", "-n", "net.inet.ip.forwarding") == "1"
	}
	return false
}

// detectGuests recognises a machine that runs virtual machines or
// containers.
func detectGuests(e Env) string {
	switch {
	case e.exists("/etc/pve") || e.exists("/usr/bin/pveversion"):
		return "proxmox"
	case e.exists("/var/run/docker.sock") || e.exists("/run/docker.sock"):
		return "docker"
	case e.exists("/var/run/libvirt") || e.exists("/run/libvirt"):
		return "libvirt"
	case e.exists("/var/snap/lxd") || e.exists("/var/lib/lxd"):
		return "lxd"
	}
	return ""
}

// detectNAT reports whether the firewall translates addresses, which is what
// a home or office gateway does and a hypervisor bridging its guests does
// not (Docker's own masquerade for its bridge is not counted).
func detectNAT(e Env, fw string) bool {
	var rules string
	switch fw {
	case "pf":
		rules = e.run("pfctl", "-sn")
	case "nftables":
		rules = e.run("nft", "list", "ruleset")
	case "iptables":
		rules = e.run("iptables", "-t", "nat", "-S")
	}
	for _, line := range strings.Split(rules, "\n") {
		l := strings.ToLower(line)
		if strings.Contains(l, "docker") || strings.Contains(l, "172.17.") {
			continue
		}
		if strings.Contains(l, "masquerade") || strings.Contains(l, "snat") || strings.HasPrefix(strings.TrimSpace(l), "nat ") {
			return true
		}
	}
	return false
}

// linuxDefaultRoute reads /proc/net/route, which needs no tools: a minimal
// container has no ip(8). The gateway is hexadecimal, little-endian.
func linuxDefaultRoute(e Env) (string, string) {
	for _, line := range strings.Split(e.read("/proc/net/route"), "\n")[1:] {
		f := strings.Fields(line)
		if len(f) < 3 || f[1] != "00000000" {
			continue
		}
		v, err := strconv.ParseUint(f[2], 16, 32)
		if err != nil || v == 0 {
			continue
		}
		return fmt.Sprintf("%d.%d.%d.%d", v&0xff, v>>8&0xff, v>>16&0xff, v>>24&0xff), f[0]
	}
	return "", ""
}

func detectGateway(e Env) (string, string) {
	if e.GOOS == "linux" {
		if gw, ifc := linuxDefaultRoute(e); gw != "" {
			return gw, ifc
		}
	}
	switch e.GOOS {
	case "freebsd", "darwin":
		var gw, ifc string
		for _, line := range strings.Split(e.run("route", "-n", "get", "default"), "\n") {
			k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
			if !ok {
				continue
			}
			switch k {
			case "gateway":
				gw = strings.TrimSpace(v)
			case "interface":
				ifc = strings.TrimSpace(v)
			}
		}
		return gw, ifc
	case "linux":
		for _, line := range strings.Split(e.run("ip", "route", "show", "default"), "\n") {
			f := strings.Fields(line)
			if len(f) >= 3 && f[0] == "default" && f[1] == "via" {
				ifc := ""
				for i := 3; i+1 < len(f); i++ {
					if f[i] == "dev" {
						ifc = f[i+1]
					}
				}
				return f[2], ifc
			}
		}
	}
	return "", ""
}

// detectBackends finds the tools FlowSight composes. Whatever is already
// there is what FlowSight will use.
func detectBackends(e Env) []string {
	var out []string
	check := func(name string, paths ...string) {
		for _, p := range paths {
			if strings.HasPrefix(p, "/") {
				if e.exists(p) {
					out = append(out, name)
					return
				}
			} else if e.has(p) {
				out = append(out, name)
				return
			}
		}
	}
	check("unbound", "/usr/local/sbin/unbound", "/usr/sbin/unbound", "unbound")
	check("dnsmasq", "/usr/local/sbin/dnsmasq", "/usr/sbin/dnsmasq", "dnsmasq")
	check("pihole", "/etc/pihole", "pihole-FTL")
	check("adguard", "/opt/AdGuardHome/AdGuardHome", "AdGuardHome")
	check("squid", "/usr/local/sbin/squid", "/usr/sbin/squid", "squid")
	check("suricata", "/usr/local/bin/suricata", "/usr/bin/suricata", "suricata")
	check("ntopng", "/usr/local/bin/ntopng", "/usr/bin/ntopng", "ntopng")
	check("zeek", "/opt/zeek/bin/zeek", "/usr/local/zeek/bin/zeek", "zeek")
	return out
}

func detectInstalled(e Env) (bool, string) {
	installed := false
	for _, p := range []string{"/usr/local/etc/flowsight/flowsight.json", "/etc/flowsight/flowsight.json"} {
		if e.exists(p) {
			installed = true
		}
	}
	version := ""
	for _, p := range []string{"/usr/local/sbin/flowsightd", "/usr/sbin/flowsightd"} {
		if e.exists(p) {
			if f := strings.Fields(e.run(e.path(p), "-version")); len(f) >= 2 {
				version = f[1]
			}
			break
		}
	}
	return installed, version
}
