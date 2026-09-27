package scan

// What a device is, from everything the scan and the inventory know.
//
// The probes answer narrow questions: which ports answer, what banners say,
// whether mDNS or SSDP reply, what the TTL was. None of that names a device.
// Naming one is a matter of putting the answers next to what the inventory
// already holds -- the maker from the hardware address, the DHCP fingerprint
// and vendor class, the name the device gave itself -- and matching the lot
// against the signatures consumer devices actually have: an Amazon speaker
// listens on 55442/55443, a Chromecast on 8008/8009/8443, a Roku on 8060, a
// Sonos on 1400, a Kasa plug on 9999. Each guess carries its evidence.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/grioghar/flowsight/internal/core"
)

// iotPorts are the consumer and appliance ports the top-100 list lacks;
// the identify profile scans them as well.
var iotPorts = []int{
	1400, 1443, 1883, 2323, 3689, 4070, 5000, 5001, 5009, 5060, 5228, 5900, 6466, 6467, 6668, 6881,
	7000, 7100, 8006, 8008, 8009, 8060, 8081, 8096, 8123, 8181, 8200, 8443, 8883, 8888, 9000, 9090,
	9100, 9295, 9998, 9999, 10001, 32400, 32469, 40317, 49152, 49153, 49154, 55442, 55443, 62078,
}

// signature is one recognisable shape: ports that must all be open, ports
// where any one open counts, a maker the hardware address should name, and
// what that adds up to.
type signature struct {
	Kind    string  // what it is
	All     []int   // every one of these open
	Any     []int   // at least one of these open
	Vendor  string  // substring of the OUI vendor, lower case; "" = any
	Weight  float64 // confidence when it matches fully
	Because string  // the sentence shown as evidence
}

var signatures = []signature{
	{Kind: "Amazon Echo (Alexa device)", All: []int{55443}, Vendor: "amazon", Weight: 0.95, Because: "Alexa's local control port 55443 is open on an Amazon device"},
	{Kind: "Amazon Echo (Alexa device)", Any: []int{55442, 55443}, Weight: 0.7, Because: "ports 55442/55443 are the Alexa local control ports"},
	{Kind: "Amazon Fire TV", All: []int{5555}, Vendor: "amazon", Weight: 0.8, Because: "ADB (5555) open on an Amazon device"},
	{Kind: "Google Cast device (Chromecast, Nest, Android TV)", All: []int{8008, 8009}, Weight: 0.9, Because: "Cast control ports 8008 and 8009 are open"},
	{Kind: "Google Cast device (Chromecast, Nest, Android TV)", Any: []int{8009}, Weight: 0.65, Because: "the Cast control port 8009 is open"},
	{Kind: "Android TV / Google TV", All: []int{6466, 6467}, Weight: 0.85, Because: "Android TV remote service ports 6466/6467 are open"},
	{Kind: "Roku player", All: []int{8060}, Weight: 0.9, Because: "Roku's External Control Protocol port 8060 is open"},
	{Kind: "Sonos speaker", All: []int{1400}, Weight: 0.9, Because: "Sonos control port 1400 is open"},
	{Kind: "Apple TV or HomePod (AirPlay)", All: []int{7000}, Vendor: "apple", Weight: 0.85, Because: "AirPlay port 7000 on an Apple device"},
	{Kind: "AirPlay receiver", Any: []int{7000, 7100}, Weight: 0.6, Because: "an AirPlay port is open"},
	{Kind: "iPhone or iPad", All: []int{62078}, Weight: 0.9, Because: "iOS lockdown/sync port 62078 is open"},
	{Kind: "TP-Link Kasa smart plug or bulb", All: []int{9999}, Weight: 0.85, Because: "Kasa's local protocol port 9999 is open"},
	{Kind: "Tuya-based smart device", All: []int{6668}, Weight: 0.85, Because: "Tuya's local protocol port 6668 is open"},
	{Kind: "Plex Media Server", All: []int{32400}, Weight: 0.95, Because: "Plex serves on 32400"},
	{Kind: "Home Assistant", All: []int{8123}, Weight: 0.9, Because: "Home Assistant serves on 8123"},
	{Kind: "Proxmox VE host", All: []int{8006}, Weight: 0.9, Because: "the Proxmox web console is on 8006"},
	{Kind: "Ubiquiti network device", All: []int{10001}, Weight: 0.8, Because: "Ubiquiti discovery port 10001 is open"},
	{Kind: "Spotify Connect speaker", All: []int{4070}, Weight: 0.6, Because: "Spotify Connect port 4070 is open"},
	{Kind: "Jellyfin server", All: []int{8096}, Weight: 0.85, Because: "Jellyfin serves on 8096"},
	{Kind: "Network printer", All: []int{9100}, Weight: 0.8, Because: "raw printing port 9100 is open"},
	{Kind: "Network printer", All: []int{631}, Any: []int{9100, 515}, Weight: 0.7, Because: "IPP and a print port are open"},
	{Kind: "PlayStation console", All: []int{9295}, Weight: 0.8, Because: "PS Remote Play port 9295 is open"},
	{Kind: "MQTT broker", Any: []int{1883, 8883}, Weight: 0.6, Because: "an MQTT port is open"},
	{Kind: "Windows host", All: []int{135, 445}, Weight: 0.75, Because: "RPC (135) and SMB (445) are open"},
	{Kind: "Windows host (Remote Desktop)", All: []int{3389}, Weight: 0.7, Because: "Remote Desktop (3389) is open"},
	{Kind: "Linux or BSD host (SSH)", All: []int{22}, Weight: 0.35, Because: "SSH is open"},
	{Kind: "Camera or NVR (RTSP)", All: []int{554}, Weight: 0.7, Because: "RTSP (554) is open"},
	{Kind: "Media server (DLNA)", Any: []int{8200, 32469}, Weight: 0.55, Because: "a DLNA media port is open"},
	{Kind: "VNC-served host", All: []int{5900}, Weight: 0.4, Because: "VNC (5900) is open"},
}

// vendorKinds is what the maker alone suggests, at low confidence, for the
// makers that only make one kind of thing.
var vendorKinds = []struct{ vendor, kind string }{
	{"amazon", "Amazon device (Echo, Fire TV or Kindle)"}, {"roku", "Roku player"}, {"sonos", "Sonos speaker"},
	{"tuya", "Tuya-based smart device"}, {"tp-link", "TP-Link device"}, {"espressif", "ESP32/ESP8266-based smart device"},
	{"nest", "Google Nest device"}, {"google", "Google device"}, {"ring", "Ring camera or doorbell"}, {"wyze", "Wyze camera or device"},
	{"reolink", "Reolink camera or hub"}, {"hikvision", "Hikvision camera"}, {"dahua", "Dahua camera"}, {"raspberry", "Raspberry Pi"},
	{"nintendo", "Nintendo console"}, {"sony interactive", "PlayStation console"}, {"microsoft", "Microsoft device (Xbox or Surface)"},
	{"philips lighting", "Philips Hue bridge"}, {"signify", "Philips Hue bridge"}, {"ecobee", "ecobee thermostat"}, {"lutron", "Lutron bridge"},
	{"aqara", "Aqara hub"}, {"lumi", "Aqara hub"}, {"roborock", "Roborock vacuum"}, {"irobot", "iRobot vacuum"}, {"proxmox", "Proxmox virtual machine or container"},
	{"brother", "Brother printer"}, {"hewlett", "HP printer or PC"}, {"canon", "Canon printer"}, {"epson", "Epson printer"},
	{"ubiquiti", "Ubiquiti network device"}, {"netgear", "Netgear network device"}, {"apple", "Apple device"}, {"samsung", "Samsung device"},
	{"azurewave", "Wi-Fi module (found in Steam Deck, laptops, TVs)"}, {"valve", "Steam Deck"}, {"intel corporate", "PC with an Intel Wi-Fi adapter"},
}

var ttlRe = regexp.MustCompile(`ttl=(\d+)`)

// mdnsModelRe pulls a model out of an mDNS device-info TXT, when a probe
// recorded one in the findings ("mdns model=MacBookPro18,3").
var mdnsModelRe = regexp.MustCompile(`(?i)model=([^\s;,]+)`)

// inventory is what the device table and identity already know about the
// hardware address, before any packet is sent.
type inventory struct {
	Vendor, VendorClass, Fingerprint, Hostname string
}

func (m *Module) inventoryFor(result *ScanResult) inventory {
	inv := inventory{}
	if result.MAC == "" || m.ctx == nil || m.ctx.Store == nil {
		return inv
	}
	if row, err := m.ctx.Store.Row(`SELECT vendor, vendor_class, fingerprint, hostname FROM devices WHERE lower(mac)=?`, strings.ToLower(result.MAC)); err == nil && row != nil {
		inv.Vendor, _ = row["vendor"].(string)
		inv.VendorClass, _ = row["vendor_class"].(string)
		inv.Fingerprint, _ = row["fingerprint"].(string)
		inv.Hostname, _ = row["hostname"].(string)
	}
	if inv.Vendor == "" && m.identity != nil {
		inv.Vendor = m.identity.Vendor(result.MAC)
	}
	return privateVendor(result.MAC, inv)
}

// privateVendor drops a registered maker from a private (locally
// administered) hardware address: such an address has none, so the name
// came from another device and would make a laptop a vacuum.
func privateVendor(mac string, inv inventory) inventory {
	if core.LocallyAdministered(mac) && !strings.Contains(inv.Vendor, "private address") {
		inv.Vendor = ""
	}
	return inv
}

// identifyDevice turns the evidence into ranked guesses about what the
// device is, keeping whatever the probes already guessed about the OS
// underneath.
func (m *Module) identifyDevice(result *ScanResult) {
	result.OSGuesses = append(result.OSGuesses, identify(result, m.inventoryFor(result))...)
	sort.SliceStable(result.OSGuesses, func(i, j int) bool { return result.OSGuesses[i].Confidence > result.OSGuesses[j].Confidence })
	// One line per kind: the strongest reason wins, the rest join it.
	seen := map[string]int{}
	out := result.OSGuesses[:0]
	for _, g := range result.OSGuesses {
		if i, ok := seen[g.OS]; ok {
			out[i].Evidence = append(out[i].Evidence, g.Evidence...)
			continue
		}
		seen[g.OS] = len(out)
		out = append(out, g)
	}
	result.OSGuesses = out
}

func identify(result *ScanResult, inv inventory) []OSGuess {
	open := map[int]bool{}
	for _, p := range result.OpenPorts {
		if p.State == "open" && (p.Protocol == "" || p.Protocol == "tcp") {
			open[p.Port] = true
		}
	}
	vendor := strings.ToLower(inv.Vendor)
	var out []OSGuess
	for _, sg := range signatures {
		ok := len(sg.All) > 0 || len(sg.Any) > 0
		for _, p := range sg.All {
			if !open[p] {
				ok = false
			}
		}
		if ok && len(sg.Any) > 0 {
			any := false
			for _, p := range sg.Any {
				any = any || open[p]
			}
			ok = any
		}
		if !ok {
			continue
		}
		if sg.Vendor != "" && !strings.Contains(vendor, sg.Vendor) {
			continue
		}
		ev := []string{sg.Because}
		if sg.Vendor != "" {
			ev = append(ev, "hardware address registered to "+inv.Vendor)
		}
		out = append(out, OSGuess{OS: sg.Kind, Confidence: sg.Weight, Evidence: ev})
	}
	// The maker alone, when it makes one kind of thing.
	for _, vk := range vendorKinds {
		if vendor != "" && strings.Contains(vendor, vk.vendor) {
			out = append(out, OSGuess{OS: vk.kind, Confidence: 0.45, Evidence: []string{"hardware address registered to " + inv.Vendor}})
			break
		}
	}
	// The DHCP conversation: fingerprint and vendor class.
	vc := strings.ToLower(inv.VendorClass)
	fp := inv.Fingerprint
	switch {
	case strings.Contains(vc, "android"):
		out = append(out, OSGuess{OS: "Android device", Confidence: 0.75, Evidence: []string{"DHCP vendor class " + inv.VendorClass}})
	case strings.Contains(vc, "msft"):
		out = append(out, OSGuess{OS: "Windows host", Confidence: 0.75, Evidence: []string{"DHCP vendor class " + inv.VendorClass}})
	case strings.HasPrefix(fp, "1,121,3,6,15,108,114,119,252") || strings.HasPrefix(fp, "1,121,3,6,15,119,252"):
		out = append(out, OSGuess{OS: "Apple device (iOS or macOS)", Confidence: 0.7, Evidence: []string{"Apple's DHCP option fingerprint"}})
	case strings.HasPrefix(fp, "1,3,6,15,26,28,51,58,59,43"):
		out = append(out, OSGuess{OS: "Android device", Confidence: 0.65, Evidence: []string{"Android's DHCP option fingerprint"}})
	case strings.HasPrefix(fp, "1,3,6,15,31,33,43,44,46,47,119,121,249,252"):
		out = append(out, OSGuess{OS: "Windows host", Confidence: 0.7, Evidence: []string{"Windows' DHCP option fingerprint"}})
	case strings.Contains(vc, "dhcpcd") || strings.Contains(vc, "udhcp"):
		out = append(out, OSGuess{OS: "Linux-based device", Confidence: 0.5, Evidence: []string{"DHCP vendor class " + inv.VendorClass}})
	}
	// The name it gave itself.
	name := strings.ToLower(inv.Hostname)
	for _, nk := range []struct{ sub, kind string }{
		{"iphone", "iPhone"}, {"ipad", "iPad"}, {"macbook", "Mac laptop"}, {"imac", "iMac"}, {"appletv", "Apple TV"}, {"homepod", "HomePod"},
		{"echo", "Amazon Echo (Alexa device)"}, {"firetv", "Amazon Fire TV"}, {"fire-tv", "Amazon Fire TV"}, {"roku", "Roku player"}, {"chromecast", "Google Cast device (Chromecast, Nest, Android TV)"},
		{"galaxy", "Samsung Galaxy phone or tablet"}, {"pixel", "Google Pixel phone"}, {"nest", "Google Nest device"}, {"sonos", "Sonos speaker"}, {"kasa", "TP-Link Kasa device"},
		{"steamdeck", "Steam Deck"}, {"switch", "Nintendo Switch"}, {"ps5", "PlayStation 5"}, {"ps4", "PlayStation 4"}, {"xbox", "Xbox console"}, {"raspberrypi", "Raspberry Pi"},
		{"printer", "Network printer"}, {"roborock", "Roborock vacuum"}, {"reolink", "Reolink camera or hub"}, {"thermostat", "Thermostat"},
	} {
		if strings.Contains(name, nk.sub) {
			out = append(out, OSGuess{OS: nk.kind, Confidence: 0.6, Evidence: []string{"calls itself " + inv.Hostname}})
			break
		}
	}
	// mDNS model strings, when a probe recorded one.
	for _, f := range result.Findings {
		if mm := mdnsModelRe.FindStringSubmatch(f); mm != nil {
			out = append(out, OSGuess{OS: "Model " + mm[1], Confidence: 0.8, Evidence: []string{"mDNS device-info says model=" + mm[1]}})
		}
	}
	// The TTL narrows the operating-system family.
	for _, f := range result.Findings {
		if mm := ttlRe.FindStringSubmatch(f); mm != nil {
			var ttl int
			fmt.Sscanf(mm[1], "%d", &ttl)
			switch {
			case ttl > 128:
				out = append(out, OSGuess{OS: "BSD, Solaris or network equipment (TTL 255)", Confidence: 0.3, Evidence: []string{"reply TTL " + mm[1]}})
			case ttl > 64:
				out = append(out, OSGuess{OS: "Windows (TTL 128)", Confidence: 0.35, Evidence: []string{"reply TTL " + mm[1]}})
			case ttl > 0:
				out = append(out, OSGuess{OS: "Linux, Android, macOS or iOS (TTL 64)", Confidence: 0.3, Evidence: []string{"reply TTL " + mm[1]}})
			}
			break
		}
	}
	// Banners name the software outright.
	for _, p := range result.OpenPorts {
		b := strings.ToLower(p.Banner)
		switch {
		case b == "":
		case strings.Contains(b, "openssh") && strings.Contains(b, "ubuntu"):
			out = append(out, OSGuess{OS: "Ubuntu Linux", Confidence: 0.85, Evidence: []string{"SSH banner " + p.Banner}})
		case strings.Contains(b, "openssh") && strings.Contains(b, "debian"):
			out = append(out, OSGuess{OS: "Debian Linux", Confidence: 0.85, Evidence: []string{"SSH banner " + p.Banner}})
		case strings.Contains(b, "openssh") && strings.Contains(b, "freebsd"):
			out = append(out, OSGuess{OS: "FreeBSD", Confidence: 0.85, Evidence: []string{"SSH banner " + p.Banner}})
		case strings.Contains(b, "dropbear"):
			out = append(out, OSGuess{OS: "Embedded Linux (Dropbear SSH)", Confidence: 0.7, Evidence: []string{"SSH banner " + p.Banner}})
		case strings.Contains(b, "microsoft-iis") || strings.Contains(b, "microsoft-httpapi"):
			out = append(out, OSGuess{OS: "Windows host", Confidence: 0.8, Evidence: []string{"HTTP server " + p.Banner}})
		case strings.Contains(b, "synology"):
			out = append(out, OSGuess{OS: "Synology NAS", Confidence: 0.9, Evidence: []string{"HTTP server " + p.Banner}})
		case strings.Contains(b, "lighttpd") && strings.Contains(vendor, "roku"):
			out = append(out, OSGuess{OS: "Roku player", Confidence: 0.8, Evidence: []string{"HTTP server " + p.Banner}})
		case strings.Contains(b, "pve-api-daemon") || strings.Contains(b, "proxmox"):
			out = append(out, OSGuess{OS: "Proxmox VE host", Confidence: 0.9, Evidence: []string{"HTTP server " + p.Banner}})
		}
	}
	return out
}
