// Package enroll identifies devices from DHCP, ARP/NDP and lease files,
// classifies them by rules, and places them in zones with tailored DNS, DHCP
// and firewall policies. Zone boundaries are enforced via pf rules and optional
// dnsmasq DHCP reservations; unidentified devices are redirected to a
// self-identification page.
package enroll

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/grioghar/flowsight/internal/core"
)

func init() { core.Register(func() core.Module { return &Module{} }) }

// Firewall interface for pf rules.
type Firewall interface {
	LoadAnchor(name, rules string) error
	FlushAnchor(name string) error
}

// txnData collects DHCP transaction information from log lines.
type txnData struct {
	mac          string
	ip           string
	hostname     string
	vendorClass  string
	fingerprint  string
	optionsList  []string // option numbers in order
	lastActivity time.Time
}

// Module is the enroll service.
type Module struct {
	ctx      *core.Context
	mu       sync.RWMutex
	devices  map[string]*Device // mac -> device
	zones    *ZonesDoc          // zones and captive settings
	rules    []*Rule            // classification rules
	identity core.Identity      // name/MAC resolution

	svcMu         sync.Mutex
	svc           map[string]*DeviceServices
	svcAt         time.Time
	svcHours      int
	firewall      Firewall // pf anchor management
	lastErr       string
	lastApplied   time.Time
	pendingAssign map[string]string     // mac -> zone for pending changes
	allocations   map[string]*Allocator // zone id -> allocator

	// DHCP log tailing
	tailer         *core.Tailer
	txnMu          sync.Mutex
	txnState       map[string]*txnData // transaction id -> accumulated data
	lastTailErr    string
	lastLogCleanup time.Time

	// Captive portal rate limiting: mac -> last change timestamp
	captiveMuRate sync.Mutex
	captiveRate   map[string]int64

	// Captive portal listener (stored for shutdown)
	captiveServer interface{}
}

// Device is one MAC address in the registry.
type ProxmoxRef struct {
	VMID int    `json:"vmid"`
	Type string `json:"type"` // qemu or lxc
	Node string `json:"node"`
	Name string `json:"name"`
	OS   string `json:"os"`
}

type Device struct {
	MAC            string `json:"mac"`
	IP             string `json:"ip"`
	IP6            string `json:"ip6,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	Vendor         string `json:"vendor,omitempty"`
	VendorClass    string `json:"vendor_class,omitempty"`
	Fingerprint    string `json:"fingerprint,omitempty"`
	Zone           string `json:"zone,omitempty"`
	Class          string `json:"class,omitempty"`
	Confidence     string `json:"confidence,omitempty"`
	Rule           string `json:"rule,omitempty"`
	Why            string `json:"why,omitempty"`
	Pinned         int    `json:"pinned"`
	Randomized     int    `json:"randomized"`
	GuestName      string `json:"guest_name,omitempty"`
	GuestKind      string `json:"guest_kind,omitempty"`
	User           string `json:"user,omitempty"`
	Iface          string `json:"iface,omitempty"`
	FirstSeen      int64  `json:"first_seen"`
	LastSeen       int64  `json:"last_seen"`
	NameSource     string `json:"name_source,omitempty"`     // where the hostname came from
	NameConfidence int    `json:"name_confidence,omitempty"` // 0-100 confidence score

	// Set on the way out of the API, never stored: whether the policy's
	// exclusion list keeps this device out of interception and inspection,
	// and which entry does it.
	Excluded   bool   `json:"excluded,omitempty"`
	ExcludedBy string `json:"excluded_by,omitempty"`

	// Proxmox reference, when the device maps to a Proxmox guest
	Proxmox *ProxmoxRef `json:"proxmox,omitempty"`
}

// ZonesDoc is zones.json.
type ZonesDoc struct {
	Mode          string       `json:"mode"` // monitor or enforce
	CaptiveZone   string       `json:"captive_zone"`
	CaptivePolicy string       `json:"captive_policy"` // self_service, approve
	Lease         string       `json:"lease"`
	HostmapURL    string       `json:"hostmap_url"`
	Zones         []*Zone      `json:"zones"`
	AlwaysAllow   *AlwaysAllow `json:"always_allow"`
}

// Zone is one address block and its policy.
type Zone struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Subnet      string    `json:"subnet"`             // CIDR
	Subnet6     string    `json:"subnet6,omitempty"`  // IPv6 CIDR
	Gateway     string    `json:"gateway"`            // IP
	Gateway6    string    `json:"gateway6,omitempty"` // IPv6 address
	Range       [2]string `json:"range"`              // start, end IPs
	Range6      [2]string `json:"range6,omitempty"`   // start, end IPv6 addresses
	DNS         []string  `json:"dns"`
	Internet    bool      `json:"internet"`
	Captive     bool      `json:"captive"`
	SelfService bool      `json:"self_service"`
	ReachZones  []string  `json:"reach_zones"`
	Block       string    `json:"block"` // firewall block CIDR
}

// AlwaysAllow lists hosts and ports always reachable.
type AlwaysAllow struct {
	Hosts []string `json:"hosts"`
	Ports []string `json:"ports"`
}

// Rule is one classification rule from rules.json.
type Rule struct {
	ID         string                 `json:"id"`
	Zone       string                 `json:"zone"`
	Confidence string                 `json:"confidence"`
	Why        string                 `json:"why"`
	When       map[string]interface{} `json:"when"`
}

func (m *Module) Info() core.ModuleInfo {
	return core.ModuleInfo{
		Name:         "enroll",
		Version:      "1.0",
		Description:  "Device identification and zone-based segmentation.",
		Capabilities: []string{core.CapHostInventory},
		After:        []string{"identity", "firewall"},
		Defaults: map[string]any{
			"enabled":                true,
			"captive_port":           8083,
			"manage_dnsmasq_logging": true,
			"reconcile_seconds":      60,
		},
		Schema: []core.SettingField{
			{Key: "enabled", Label: "Enable device enrollment", Type: "bool"},
			{Key: "captive_port", Label: "Captive portal port", Type: "int", Placeholder: "8083"},
			{Key: "manage_dnsmasq_logging", Label: "Enable dnsmasq DHCP logging", Type: "bool"},
			{Key: "reconcile_seconds", Label: "Reconcile interval (s)", Type: "int", Placeholder: "60"},
		},
	}
}

func (m *Module) Setup(ctx *core.Context) error {
	m.ctx = ctx
	m.devices = map[string]*Device{}
	m.pendingAssign = map[string]string{}
	m.allocations = map[string]*Allocator{}
	m.txnState = map[string]*txnData{}
	m.captiveRate = map[string]int64{}
	m.identity, _ = ctx.Service("identity").(core.Identity)
	m.firewall, _ = ctx.Service("firewall").(Firewall)

	// Load zones and rules
	if err := m.loadZones(); err != nil {
		ctx.Log.Warn("load zones", "error", err)
	}
	if err := m.loadRules(); err != nil {
		ctx.Log.Warn("load rules", "error", err)
	}

	// Load device registry from store
	m.loadRegistry()

	enabled := core.Bool(ctx.Settings(), "enabled", false)
	if enabled {
		every := time.Duration(core.Int(ctx.Settings(), "reconcile_seconds", 60)) * time.Second
		ctx.Every("reconcile", every, m.reconcile)
		ctx.Every("dnsmasq-log", 10*time.Second, m.parseDnsmasqLog)

		// Setup dnsmasq logging and tailer
		if ctx.Platform.Name == "opnsense" {
			ctx.Every("dnsmasq-logging", 60*time.Minute, m.setupDnsmasqLogging, core.Delayed())
			ctx.Every("dnsmasq-logging-init", 30*time.Second, func() error {
				return m.setupDnsmasqLogging()
			})
		}

		// Initialize log tailer
		logPath := "/var/log/dnsmasq/latest.log"
		if ctx.Platform.Name == "linux" {
			logPath = "/var/log/dnsmasq.log"
		}
		m.tailer = core.NewTailer(logPath)
	}

	// API routes
	ctx.Route("GET", "/api/enroll", m.apiSummary,
		core.Doc("Retrieve current enrollment status including device counts by zone and unidentified devices"),
		core.Returns("Enrollment summary with zone device counts", map[string]any{
			"unidentified": 3,
			"office":       12,
			"guest":        5,
		}))
	ctx.Route("GET", "/api/enroll/services", m.apiServices,
		core.Query("hours", "integer", "Time window in hours for service analysis (1-168, default 24)", false, 24),
		core.Doc("List applications used and ports offered by each device, keyed by MAC address"),
		core.Returns("Device services grouped by MAC", map[string]any{
			"aa:bb:cc:dd:ee:ff": map[string]any{
				"uses":   []string{"youtube", "netflix"},
				"offers": []int{22, 80},
			},
		}))
	ctx.Route("GET", "/api/enroll/devices", m.apiDevices,
		core.Query("zone", "string", "Filter results by enrollment zone name", false, "office"),
		core.Query("q", "string", "Search query for device name or MAC address", false, "macbook"),
		core.Doc("List all enrolled devices with optional filtering by zone or name search"),
		core.Returns("Device list with enrollment details", map[string]any{
			"devices": []map[string]any{
				{"mac": "aa:bb:cc:dd:ee:ff", "name": "MacBookPro", "zone": "office", "ip": "192.168.1.10"},
			},
		}))
	ctx.Route("GET", "/api/enroll/zones", m.apiGetZones,
		core.Doc("Retrieve all enrollment zones with their rules and captive portal settings"),
		core.Returns("Zone configuration list", map[string]any{
			"zones": []map[string]any{
				{"id": "zone-1", "name": "office", "rules": []map[string]any{}},
			},
		}))
	ctx.Route("GET", "/api/enroll/zones/{id}", m.apiGetZoneByID,
		core.PathParam("id", "string", "Zone identifier", "zone-1"),
		core.Doc("Retrieve a specific enrollment zone by its ID with detailed configuration"),
		core.Returns("Single zone configuration", map[string]any{
			"id":    "zone-1",
			"name":  "office",
			"rules": []map[string]any{},
		}))
	ctx.Route("POST", "/api/enroll/zones", m.apiSetZones, core.Write(),
		core.Doc("Create or replace all enrollment zones with new rules and classification"),
		core.Body(
			core.Fld("zones", "array", true, "List of zone definitions", []map[string]any{}),
		),
		core.Returns("Updated zones confirmation", map[string]any{"ok": true}))
	ctx.Route("PUT", "/api/enroll/zones/{id}", m.apiUpdateZoneByID, core.Write(),
		core.PathParam("id", "string", "Zone identifier", "zone-1"),
		core.Doc("Update a specific enrollment zone by its ID with new rules or settings"),
		core.Body(
			core.Fld("name", "string", false, "Zone display name", "office"),
			core.Fld("rules", "array", false, "Classification rules for this zone", []map[string]any{}),
		),
		core.Returns("Update confirmation", map[string]any{"ok": true}))
	ctx.Route("DELETE", "/api/enroll/zones/{id}", m.apiDeleteZoneByID, core.Write(),
		core.PathParam("id", "string", "Zone identifier", "zone-1"),
		core.Doc("Delete an enrollment zone by its ID and reassign devices to unclassified"),
		core.Returns("Deletion confirmation", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/enroll/rules", m.apiGetRules,
		core.Doc("Retrieve all device classification rules used in zone assignment"),
		core.Returns("Classification rules list", map[string]any{
			"rules": []map[string]any{
				{"name": "by-hostname", "pattern": ".*-office.*"},
			},
		}))
	ctx.Route("POST", "/api/enroll/rules", m.apiSetRules, core.Write(),
		core.Doc("Replace all device classification rules used for zone assignment"),
		core.Body(
			core.Fld("rules", "array", true, "List of classification rules", []map[string]any{}),
		),
		core.Returns("Rules update confirmation", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/enroll/devices/{mac}", m.apiGetDeviceByMAC,
		core.PathParam("mac", "string", "Device MAC address", "aa:bb:cc:dd:ee:ff"),
		core.Doc("Retrieve detailed information about a specific device by its MAC address"),
		core.Returns("Device details", map[string]any{
			"mac":  "aa:bb:cc:dd:ee:ff",
			"name": "MacBookPro",
			"zone": "office",
			"ip":   "192.168.1.10",
		}))
	ctx.Route("DELETE", "/api/enroll/devices/{mac}", m.apiDeleteDeviceByMAC, core.Write(),
		core.PathParam("mac", "string", "Device MAC address", "aa:bb:cc:dd:ee:ff"),
		core.Doc("Remove a device from the enrollment list and forget its identification"),
		core.Returns("Deletion confirmation", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/enroll/assign", m.apiAssign, core.Write(),
		core.Doc("Assign a device to a specific zone or unpin it for automatic rule-based classification"),
		core.Body(
			core.Fld("mac", "string", true, "Device MAC address", "aa:bb:cc:dd:ee:ff"),
			core.Fld("zone", "string", true, "Target zone ID (empty to unpin)", "zone-1"),
		),
		core.Returns("Assignment confirmation", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/enroll/reconcile", m.apiReconcile, core.Write(),
		core.Doc("Trigger re-evaluation of device classification against current rules"),
		core.Body(),
		core.Returns("Reconciliation confirmation", map[string]any{"ok": true}))
	ctx.Route("POST", "/api/enroll/apply", m.apiApply, core.Write(), core.Needs("device.enroll"),
		core.Doc("Apply the enrollment plan to enforce zone assignments on all devices"),
		core.Body(),
		core.Returns("Apply result", map[string]any{"ok": true}))
	ctx.Route("GET", "/api/enroll/plan", m.apiPlan,
		core.Doc("Preview what changes apply would make to device enrollment assignments"),
		core.Returns("Enrollment plan changes", map[string]any{
			"changes": []map[string]any{
				{"mac": "aa:bb:cc:dd:ee:ff", "action": "assign", "zone": "office"},
			},
		}))
	ctx.Route("POST", "/api/enroll/mode", m.apiSetMode, core.Write(),
		core.Doc("Set enrollment mode between monitor and enforce for device assignment"),
		core.Body(
			core.Fld("enforce", "boolean", true, "Enable enforcement", true),
		),
		core.Returns("Mode change confirmation", map[string]any{"ok": true}))
	// Captive portal page
	if enabled {
		captivePort := core.Int(ctx.Settings(), "captive_port", 8083)
		ctx.Route("GET", "/captive", m.captiveGet,
			core.Doc("Serve the captive portal page for device enrollment and policy acceptance"),
			core.Returns("HTML captive portal page", map[string]any{
				"content_type": "text/html",
			}))
		ctx.Route("POST", "/captive", m.captivePost, core.Write(),
			core.Doc("Handle captive portal form submission for device enrollment or policy acceptance"),
			core.Body(
				core.Fld("action", "string", true, "Action to perform", "enroll"),
			),
			core.Returns("Portal action result", map[string]any{"ok": true}))
		// Start captive portal HTTP server
		go m.serveCaptive(int(captivePort))
	}

	// Panel
	ctx.Panel(core.Panel{ID: "devices", Title: "Devices", Group: "Inventory", Order: 130, Icon: "enroll"})
	ctx.Panel(core.Panel{ID: "zones", Title: "Zones", Group: "Inventory", Order: 131, Icon: "zones"})

	// Publish the zone resolver
	m.publishZoneResolver()

	return nil
}

// Stop shuts down the module, including the captive portal listener.
func (m *Module) Stop() {
	if srv, ok := m.captiveServer.(*http.Server); ok && srv != nil {
		_ = srv.Close()
	}
}

// Health returns the module's health status.
func (m *Module) Health() core.Health {
	m.mu.RLock()
	deviceCount := len(m.devices)
	m.mu.RUnlock()

	detail := fmt.Sprintf("%d device(s) in registry", deviceCount)
	notes := []string{}

	if m.lastErr != "" {
		notes = append(notes, m.lastErr)
	}
	if m.lastTailErr != "" {
		notes = append(notes, m.lastTailErr)
	}

	if len(notes) > 0 {
		detail += "; note: " + strings.Join(notes, "; ")
	}

	return core.Health{OK: true, Detail: detail}
}

// ============================================================================
// Data loading and storage
// ============================================================================

func (m *Module) loadZones() error {
	path := filepath.Join(m.ctx.Platform.EtcDir, "zones.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			// Create default empty zones
			m.zones = &ZonesDoc{Mode: "monitor", CaptiveZone: "quarantine", Zones: []*Zone{}}
			return nil
		}
		return err
	}

	z := &ZonesDoc{}
	if err := json.Unmarshal(data, z); err != nil {
		return fmt.Errorf("parse zones: %w", err)
	}

	// Validate zones
	seen := map[string]bool{}
	for _, zone := range z.Zones {
		if zone.ID == "" {
			return fmt.Errorf("zone missing id")
		}
		if seen[zone.ID] {
			return fmt.Errorf("duplicate zone id: %s", zone.ID)
		}
		seen[zone.ID] = true

		// Validate CIDR
		if _, _, err := net.ParseCIDR(zone.Subnet); err != nil {
			return fmt.Errorf("zone %s invalid subnet: %w", zone.ID, err)
		}
		if zone.Block == "" {
			zone.Block = zone.Subnet
		}
		if _, _, err := net.ParseCIDR(zone.Block); err != nil {
			return fmt.Errorf("zone %s invalid block: %w", zone.ID, err)
		}

		// Validate range
		start := net.ParseIP(zone.Range[0])
		end := net.ParseIP(zone.Range[1])
		if start == nil || end == nil {
			return fmt.Errorf("zone %s invalid range", zone.ID)
		}

		// Initialize allocator
		m.allocations[zone.ID] = NewAllocator(zone.Subnet, zone.Range[0], zone.Range[1], m.ctx.Log)
	}

	m.zones = z
	return nil
}

func (m *Module) loadRules() error {
	path := filepath.Join(m.ctx.Platform.EtcDir, "enroll-rules.json")
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			m.rules = []*Rule{}
			return nil
		}
		return err
	}

	doc := map[string]interface{}{}
	if err := json.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("parse rules: %w", err)
	}

	rules, err := m.parseRules(doc)
	if err != nil {
		return err
	}

	m.rules = rules
	return nil
}

// parseRules turns a rules document, as read from enroll-rules.json or
// posted to the API, into rules. Both paths must share it: the conditions are
// the "when" object, not the rule that contains it. Assigning the whole rule
// put id, zone, confidence and why alongside the real conditions; combined
// with an unrecognised key counting as a match, every rule matched every
// device and the first one won. On a live network that classified all 106
// devices as infrastructure. Now that unrecognised keys fail closed, the same
// mistake would instead match nothing and send every device to the captive
// zone.
func (m *Module) parseRules(doc map[string]interface{}) ([]*Rule, error) {
	rules := []*Rule{}
	rulesRaw, _ := doc["rules"].([]interface{})
	for _, r := range rulesRaw {
		ruleMap, ok := r.(map[string]interface{})
		if !ok {
			continue
		}
		rule := &Rule{}
		if when, ok := ruleMap["when"].(map[string]interface{}); ok {
			rule.When = when
		}
		if id, ok := ruleMap["id"].(string); ok {
			rule.ID = id
		}
		if zone, ok := ruleMap["zone"].(string); ok {
			rule.Zone = zone
		}
		if conf, ok := ruleMap["confidence"].(string); ok {
			rule.Confidence = conf
		}
		if why, ok := ruleMap["why"].(string); ok {
			rule.Why = why
		}

		// Validate regexes
		if err := m.validateRuleRegexes(rule); err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}

		rules = append(rules, rule)
	}
	return rules, nil
}

func (m *Module) validateRuleRegexes(rule *Rule) error {
	for field := range rule.When {
		if strings.HasSuffix(field, "_re") {
			if val, ok := rule.When[field].(string); ok {
				if _, err := regexp.Compile(val); err != nil {
					return fmt.Errorf("invalid regex %s: %w", field, err)
				}
			}
		}
	}
	return nil
}

func (m *Module) loadRegistry() {
	// Load devices from store
	rows, err := m.ctx.Store.Rows(`SELECT mac, ip, ip6, hostname, vendor, vendor_class, fingerprint,
		zone, class, confidence, rule, why, pinned, randomized, guest_name, guest_kind, user, iface,
		first_seen, last_seen FROM devices`)
	if err != nil {
		m.ctx.Log.Error("load registry", "error", err)
		return
	}

	for _, row := range rows {
		mac := getStr(row, "mac")
		if mac == "" {
			continue
		}
		// Not a device: a DHCPv6 client ID an earlier build mistook for an
		// address. Drop it rather than list it as unidentified forever.
		if isStoredClientID(row) {
			_ = m.ctx.Store.Exec(`DELETE FROM devices WHERE mac = ?`, mac)
			continue
		}
		d := &Device{
			MAC:         mac,
			IP:          getStr(row, "ip"),
			IP6:         getStr(row, "ip6"),
			Hostname:    getStr(row, "hostname"),
			Vendor:      getStr(row, "vendor"),
			VendorClass: getStr(row, "vendor_class"),
			Fingerprint: getStr(row, "fingerprint"),
			Zone:        getStr(row, "zone"),
			Class:       getStr(row, "class"),
			Confidence:  getStr(row, "confidence"),
			Rule:        getStr(row, "rule"),
			Why:         getStr(row, "why"),
			Pinned:      getInt(row, "pinned"),
			Randomized:  getInt(row, "randomized"),
			GuestName:   getStr(row, "guest_name"),
			GuestKind:   getStr(row, "guest_kind"),
			User:        getStr(row, "user"),
			Iface:       getStr(row, "iface"),
			FirstSeen:   getInt64(row, "first_seen"),
			LastSeen:    getInt64(row, "last_seen"),
		}
		m.devices[strings.ToLower(mac)] = d
	}
}

func (m *Module) saveDevice(d *Device) error {
	d.MAC = strings.ToLower(d.MAC)
	// Last seen is when the device was heard from, which the callers that
	// hear from it set. Saving a zone or a reclassification is not a sighting.
	if d.LastSeen == 0 {
		d.LastSeen = time.Now().Unix()
	}
	if d.FirstSeen == 0 {
		d.FirstSeen = d.LastSeen
	}
	return m.ctx.Store.Exec(`INSERT OR REPLACE INTO devices
		(mac, ip, ip6, hostname, vendor, vendor_class, fingerprint, zone, class, confidence,
		 rule, why, pinned, randomized, guest_name, guest_kind, user, iface, first_seen, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		d.MAC, d.IP, d.IP6, d.Hostname, d.Vendor, d.VendorClass, d.Fingerprint,
		d.Zone, d.Class, d.Confidence, d.Rule, d.Why, d.Pinned, d.Randomized,
		d.GuestName, d.GuestKind, d.User, d.Iface, d.FirstSeen, d.LastSeen)
}

// ============================================================================
// Classification and reconciliation
// ============================================================================

func (m *Module) reconcile() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Zones are optional: without any, devices are still identified and
	// listed; they simply have no zone to be placed in.

	// Gather signals from all sources
	signals := m.gatherSignals()

	// Classify each device
	now := time.Now().Unix()
	for mac, sig := range signals {
		d, exists := m.devices[mac]
		if !exists {
			d = &Device{MAC: mac, FirstSeen: now}
			m.devices[mac] = d
		}

		// The newest sighting is the truth about where a device is and what
		// it calls itself: leases move and names get corrected, and a record
		// that kept its first address for ever showed the vacuum at the
		// address the phone has now.
		if sig.IP != "" {
			d.IP = sig.IP
		}
		if sig.IP6 != "" {
			d.IP6 = sig.IP6
		}
		// No source naming the device now means the name it had is not
		// known to be its: a lease that named it would still name it. An
		// unnamed row beats one wearing another device's name, and the
		// name comes back with the device's next lease.
		d.Hostname = sig.Hostname
		if sig.Vendor != "" && d.Vendor == "" {
			d.Vendor = sig.Vendor
		}
		if sig.VendorClass != "" && d.VendorClass == "" {
			d.VendorClass = sig.VendorClass
		}
		if sig.Fingerprint != "" && d.Fingerprint == "" {
			d.Fingerprint = sig.Fingerprint
		}

		d.LastSeen = now
		d.Randomized = boolToInt(isRandomizedMAC(mac))

		// Classify
		zone, rule, conf, why := m.classify(d, sig)
		d.Class = zone
		d.Rule = rule
		d.Confidence = conf
		d.Why = why

		// Apply pending assignments
		if pendingZone, ok := m.pendingAssign[mac]; ok {
			d.Zone = pendingZone
			d.Pinned = 1
			delete(m.pendingAssign, mac)
		} else if m.followsRules(d) {
			d.Zone = m.derivedZone(zone)
		}

		_ = m.saveDevice(d)
	}

	// An address seen this round behind one device is not also the address
	// of another. Whoever else still lists it lost it.
	holder := map[string]string{}
	for mac, sig := range signals {
		if sig.IP != "" {
			holder[sig.IP] = mac
		}
	}
	for mac, d := range m.devices {
		if d.IP != "" && holder[d.IP] != "" && holder[d.IP] != mac {
			d.IP = ""
			_ = m.saveDevice(d)
		}
	}

	// Devices not heard from this round still follow the rules, so a rule
	// change (or a classification fix) reaches the whole inventory rather
	// than only whoever renewed a lease since.
	for mac, d := range m.devices {
		if _, seen := signals[mac]; seen || !m.followsRules(d) {
			continue
		}
		zone, rule, conf, why := m.classify(d, nil)
		placed := m.derivedZone(zone)
		if d.Class == zone && d.Rule == rule && d.Confidence == conf && d.Why == why && d.Zone == placed {
			continue
		}
		d.Class, d.Rule, d.Confidence, d.Why, d.Zone = zone, rule, conf, why, placed
		_ = m.saveDevice(d)
	}

	return nil
}

// followsRules reports whether reconcile should set this device's zone from
// the classification rules. A zone someone chose (from the Devices page, the
// API or the captive page) pins the device and is never overridden. In
// monitor mode every other device follows the rules, so a rule edit takes
// effect everywhere. In enforce mode a zone is an address the device already
// holds, so only a device without one is placed; the rest stay where they
// are, as the switch to enforce promises.
func (m *Module) followsRules(d *Device) bool {
	if d.Pinned != 0 {
		return false
	}
	return d.Zone == "" || m.zones == nil || m.zones.Mode != "enforce"
}

// derivedZone is where the rules put a device whose matching rule names
// zone. An unidentified device goes to the captive zone only when such a
// zone is actually defined; with no zones at all it simply stays unassigned.
func (m *Module) derivedZone(zone string) string {
	if zone == "" && m.zones != nil && m.hasZone(m.zones.CaptiveZone) {
		return m.zones.CaptiveZone
	}
	return zone
}

// hasZone reports whether a zone with this id is defined.
func (m *Module) hasZone(id string) bool {
	if id == "" || m.zones == nil {
		return false
	}
	for _, z := range m.zones.Zones {
		if z != nil && z.ID == id {
			return true
		}
	}
	return false
}

// gatherSignals folds every source of device identity into one record per
// MAC: the hosts table (which the identity module fills from leases, ARP and
// NDP), the OUI registry, and the DHCP transactions parsed from the dnsmasq
// log, which alone carry the vendor class and option fingerprint.
func (m *Module) gatherSignals() map[string]*Signal {
	signals := map[string]*Signal{}
	rows, _ := m.ctx.Store.Rows(`SELECT ip, mac, name, vendor, last_seen FROM hosts
		WHERE mac IS NOT NULL AND mac<>'' AND is_local=1 AND last_seen >= ? ORDER BY last_seen DESC`,
		time.Now().Add(-7*24*time.Hour).Unix())
	for _, r := range rows {
		mac := strings.ToLower(getStr(r, "mac"))
		if mac == "" || isPseudoMAC(strings.ToUpper(mac)) {
			continue
		}
		sig := signals[mac]
		if sig == nil {
			sig = &Signal{MAC: mac}
			signals[mac] = sig
		}
		ip := getStr(r, "ip")
		if strings.Contains(ip, ":") {
			if sig.IP6 == "" {
				sig.IP6 = ip
			}
		} else if sig.IP == "" {
			sig.IP = ip
		}
		if sig.Hostname == "" {
			sig.Hostname = getStr(r, "name")
		}
		if sig.Vendor == "" {
			sig.Vendor = getStr(r, "vendor")
		}
	}
	if m.identity != nil {
		for mac, sig := range signals {
			if sig.Vendor == "" {
				sig.Vendor = m.identity.Vendor(mac)
			}
		}
	}
	m.txnMu.Lock()
	for _, t := range m.txnState {
		if t.mac == "" {
			continue
		}
		sig := signals[t.mac]
		if sig == nil {
			sig = &Signal{MAC: t.mac}
			signals[t.mac] = sig
		}
		if t.ip != "" && sig.IP == "" {
			sig.IP = t.ip
		}
		if t.hostname != "" {
			sig.Hostname = t.hostname
		}
		if t.vendorClass != "" {
			sig.VendorClass = t.vendorClass
		}
		if t.fingerprint != "" {
			sig.Fingerprint = t.fingerprint
		}
	}
	m.txnMu.Unlock()
	return signals
}

// Signal carries identifying information about a device.
type Signal struct {
	MAC         string
	IP          string
	IP6         string
	Hostname    string
	Vendor      string
	VendorClass string
	Fingerprint string
}

func (m *Module) classify(d *Device, sig *Signal) (zone, rule, conf, why string) {
	for _, r := range m.rules {
		if m.ruleMatches(r, d, sig) {
			return r.Zone, r.ID, r.Confidence, r.Why
		}
	}
	// No rule matched
	return "", "", "none", "No rule matched this device."
}

func (m *Module) ruleMatches(rule *Rule, d *Device, sig *Signal) bool {
	when := rule.When
	if when == nil {
		return false
	}

	// Check "any" blocks (ORed)
	if anyBlocks, ok := when["any"].([]interface{}); ok {
		matched := false
		for _, block := range anyBlocks {
			if blockMap, ok := block.(map[string]interface{}); ok {
				if m.conditionMatches(blockMap, d, sig) {
					matched = true
					break
				}
			}
		}
		if !matched {
			return false
		}
	}

	// Check regular conditions (ANDed)
	for key, want := range when {
		if key == "any" {
			continue
		}
		if !m.matchCondition(key, want, d, sig) {
			return false
		}
	}

	return true
}

func (m *Module) conditionMatches(cond map[string]interface{}, d *Device, sig *Signal) bool {
	for key, want := range cond {
		if key == "any" {
			continue
		}
		if !m.matchCondition(key, want, d, sig) {
			return false
		}
	}
	return true
}

func (m *Module) matchCondition(key string, want interface{}, d *Device, sig *Signal) bool {
	switch key {
	case "vendor":
		if vals, ok := want.([]interface{}); ok {
			vendor := strings.ToLower(d.Vendor)
			for _, v := range vals {
				if vstr, ok := v.(string); ok {
					if strings.Contains(vendor, strings.ToLower(vstr)) {
						return true
					}
				}
			}
			return false
		}
	case "hostname_re":
		if pattern, ok := want.(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(d.Hostname)
		}
	case "vendor_class_re":
		if pattern, ok := want.(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(d.VendorClass)
		}
	case "fingerprint_re":
		if pattern, ok := want.(string); ok {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			return re.MatchString(d.Fingerprint)
		}
	case "mac_prefix":
		if vals, ok := want.([]interface{}); ok {
			mac := strings.ToUpper(d.MAC)
			for _, v := range vals {
				if vstr, ok := v.(string); ok {
					if strings.HasPrefix(mac, strings.ToUpper(vstr)) {
						return true
					}
				}
			}
			return false
		}
	case "guest_kind":
		if vals, ok := want.([]interface{}); ok {
			for _, v := range vals {
				if vstr, ok := v.(string); ok {
					if d.GuestKind == vstr {
						return true
					}
				}
			}
			return false
		}
	}
	// An unrecognised condition must not match. Failing open here means one
	// typo, or one key this build does not understand yet, silently turns a
	// narrow rule into "everything", which is both wrong and invisible.
	return false
}

// ============================================================================
// Log parsing
// ============================================================================

func (m *Module) parseDnsmasqLog() error {
	if m.tailer == nil {
		return nil
	}

	// Tail the log file
	_, err := m.tailer.Lines(func(line []byte) {
		m.parseDnsmasqLogLine(string(line))
	})

	if err != nil {
		// Missing file is not an error; report in Health
		if os.IsNotExist(err) {
			m.lastTailErr = fmt.Sprintf("dnsmasq DHCP log not yet created (%s)", m.tailer.Path)
		} else {
			m.lastTailErr = err.Error()
		}
		return nil // Don't propagate; log missing is OK
	}

	// Cleanup old transactions every 5 minutes
	now := time.Now()
	if now.Sub(m.lastLogCleanup) > 5*time.Minute {
		m.txnMu.Lock()
		for txnID, txn := range m.txnState {
			if now.Sub(txn.lastActivity) > 10*time.Minute {
				delete(m.txnState, txnID)
			}
		}
		m.lastLogCleanup = now
		m.txnMu.Unlock()
	}

	return nil
}

var (
	// RFC5424 syslog prefix with dnsmasq-dhcp and optional transaction ID
	dnsmasqPrefixRe = regexp.MustCompile(`.*dnsmasq-dhcp.*\[.*\]\s+(?:(\d+)\s+)?(.+)$`)

	// DHCPv4 operation lines: "DHCPDISCOVER(if) mac", "DHCPACK(if) ip mac
	// name". The address is exactly six octets followed by a space or the end
	// of the line: DHCPv6 lines use the same operation names with a client
	// DUID in its place, and reading a DUID's first six octets as a MAC
	// invented devices that do not exist.
	dhcpOpRe = regexp.MustCompile(`^(DHCPDISCOVER|DHCPREQUEST|DHCPACK|DHCPNAK)\([^)]+\)\s+(?:(\d{1,3}(?:\.\d{1,3}){3})\s+)?([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})(?:\s|$)`)

	// Client provides name
	clientNameRe = regexp.MustCompile(`^(\d+)\s+client provides name:\s+(.+)$`)

	// Vendor class
	vendorClassRe = regexp.MustCompile(`^(\d+)\s+vendor class:\s+(.+)$`)

	// Requested options with option numbers
	requestedOptsRe = regexp.MustCompile(`^(\d+)\s+requested options:\s+(.+)$`)
)

func (m *Module) parseDnsmasqLogLine(line string) {
	// Parse RFC5424 syslog line from OPNsense dnsmasq
	// <30>1 2026-09-19T01:55:56+00:00 OPNsense.internal dnsmasq-dhcp 39072 - [meta sequenceId="8"] TEXT
	// Extract the dnsmasq text part (after the syslog prefix)

	match := dnsmasqPrefixRe.FindStringSubmatch(line)
	if match == nil {
		return
	}

	txnID := match[1]
	text := match[2]

	// Lines with transaction ID correlate DHCP data
	if txnID == "" {
		// Try to extract from DHCP operation lines without explicit ID
		txnID = extractTransactionID(text)
		if txnID == "" {
			return
		}
	}

	m.txnMu.Lock()
	defer m.txnMu.Unlock()

	txn := m.txnState[txnID]
	if txn == nil {
		txn = &txnData{}
		m.txnState[txnID] = txn
	}
	txn.lastActivity = time.Now()

	// Parse DHCP operation lines (contain MAC and IP)
	if dhcpMatch := dhcpOpRe.FindStringSubmatch(text); dhcpMatch != nil {
		mac := strings.ToUpper(dhcpMatch[3])
		if !isPseudoMAC(mac) {
			txn.mac = strings.ToLower(mac)
		}
		if dhcpMatch[2] != "" {
			txn.ip = dhcpMatch[2]
		}
		// When we get a DHCPACK with complete info, emit device
		if strings.HasPrefix(text, "DHCPACK") && txn.mac != "" {
			m.emitDeviceFromTransaction(txn)
		}
		return
	}

	// Parse client name
	if nameMatch := clientNameRe.FindStringSubmatch(text); nameMatch != nil {
		if nameMatch[1] == txnID {
			txn.hostname = nameMatch[2]
		}
		return
	}

	// Parse vendor class
	if vendorMatch := vendorClassRe.FindStringSubmatch(text); vendorMatch != nil {
		if vendorMatch[1] == txnID {
			txn.vendorClass = vendorMatch[2]
		}
		return
	}

	// Parse requested options (fingerprint)
	if optsMatch := requestedOptsRe.FindStringSubmatch(text); optsMatch != nil {
		if optsMatch[1] == txnID {
			// Parse "1:netmask, 3:router, 6:dns-server, ..."
			// Build "1,3,6,..." list
			parts := strings.Split(optsMatch[2], ",")
			var opts []string
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if idx := strings.Index(part, ":"); idx > 0 {
					opts = append(opts, part[:idx])
				}
			}
			txn.fingerprint = strings.Join(opts, ",")
		}
		return
	}
}

func extractTransactionID(text string) string {
	// Try to extract TXN ID from DHCP lines like "DHCPDISCOVER... available DHCP range"
	// These lines may have the ID embedded, but we'll just return empty
	// Proper parsing relies on the explicit transaction ID in the syslog header
	return ""
}

func (m *Module) emitDeviceFromTransaction(txn *txnData) {
	if txn.mac == "" {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	d, exists := m.devices[txn.mac]
	if !exists {
		d = &Device{MAC: txn.mac, FirstSeen: time.Now().Unix()}
		m.devices[txn.mac] = d
	}

	if txn.hostname != "" {
		d.Hostname = txn.hostname
	}
	if txn.vendorClass != "" && d.VendorClass == "" {
		d.VendorClass = txn.vendorClass
	}
	if txn.fingerprint != "" && d.Fingerprint == "" {
		d.Fingerprint = txn.fingerprint
	}
	if txn.ip != "" {
		d.IP = txn.ip
		for omac, o := range m.devices {
			if omac != txn.mac && o.IP == txn.ip {
				o.IP = ""
				_ = m.saveDevice(o)
			}
		}
	}

	d.LastSeen = time.Now().Unix()
	_ = m.saveDevice(d)
}

// ============================================================================
// API handlers
// ============================================================================

func (m *Module) apiSummary(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	counts := map[string]int{}
	unidentified := 0

	for _, d := range m.devices {
		if d.Zone == "" || d.Zone == m.zones.CaptiveZone {
			unidentified++
		} else {
			counts[d.Zone]++
		}
	}

	return map[string]any{
		"mode":         m.zones.Mode,
		"captive_zone": m.zones.CaptiveZone,
		"zones":        counts,
		"unidentified": unidentified,
		"total":        len(m.devices),
	}, nil
}

func (m *Module) apiDevices(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	zone := r.Q("zone", "")
	q := r.Q("q", "")

	var devices []*Device
	for _, d := range m.devices {
		if zone != "" && d.Zone != zone {
			continue
		}
		if q != "" && !m.matchesQuery(d, q) {
			continue
		}
		devices = append(devices, d)
	}

	sort.Slice(devices, func(i, j int) bool {
		return devices[i].MAC < devices[j].MAC
	})
	if devices == nil {
		devices = []*Device{}
	}
	out := make([]*Device, 0, len(devices))
	excl := m.exclusions()

	// Get proxmox inventory service if available
	type ProxmoxGuestRef interface {
		GuestFor(macOrIP string) (any, bool)
	}
	proxmoxSvc, _ := m.ctx.Service("proxmox").(ProxmoxGuestRef)

	for _, d := range devices {
		c := *d
		if c.Vendor == "" {
			c.Vendor = guessVendor(&c)
		}
		c.ExcludedBy = excl.covers(&c)
		c.Excluded = c.ExcludedBy != ""

		// Add name provenance from identity module
		if m.identity != nil && c.IP != "" {
			// Get the NameInfo from the identity service
			type NameInfoProvider interface {
				NameInfo(ip string) struct {
					Name       string
					Source     string
					Confidence float64
				}
			}
			if ni, ok := m.ctx.Service("identity").(NameInfoProvider); ok {
				info := ni.NameInfo(c.IP)
				c.NameSource = info.Source
				c.NameConfidence = int(info.Confidence * 100)
			}
		}

		// Look up Proxmox guest reference by MAC or IP
		if proxmoxSvc != nil {
			lookupProxmoxRef := func(identifier string) {
				if c.Proxmox != nil || identifier == "" {
					return
				}
				if ref, ok := proxmoxSvc.GuestFor(identifier); ok {
					if refMap, ok := ref.(map[string]interface{}); ok {
						vmid, _ := refMap["vmid"].(float64)
						typ, _ := refMap["type"].(string)
						node, _ := refMap["node"].(string)
						name, _ := refMap["name"].(string)
						os, _ := refMap["os"].(string)
						c.Proxmox = &ProxmoxRef{
							VMID: int(vmid),
							Type: typ,
							Node: node,
							Name: name,
							OS:   os,
						}
					}
				}
			}
			lookupProxmoxRef(c.MAC)
			lookupProxmoxRef(c.IP)
		}

		out = append(out, &c)
	}
	return map[string]any{"devices": out, "excluded": excl.entries()}, nil
}

func (m *Module) matchesQuery(d *Device, q string) bool {
	lowerQ := strings.ToLower(q)
	return strings.Contains(strings.ToLower(d.MAC), lowerQ) ||
		strings.Contains(strings.ToLower(d.Hostname), lowerQ) ||
		strings.Contains(strings.ToLower(d.Vendor), lowerQ) ||
		strings.Contains(strings.ToLower(d.IP), lowerQ)
}

func (m *Module) apiGetZones(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.zones, nil
}

func (m *Module) apiSetZones(r *core.Req) (any, error) {
	var zones ZonesDoc
	if err := r.Decode(&zones); err != nil {
		return nil, err
	}

	// Validate and normalize Subnet6 for each zone
	for _, z := range zones.Zones {
		if z.Subnet6 != "" {
			_, ipnet, err := net.ParseCIDR(z.Subnet6)
			if err != nil {
				return nil, core.BadRequest("zone %q: subnet6 must be a valid IPv6 CIDR: %v", z.ID, err)
			}
			// Normalize to network form (e.g., fd00::1/64 becomes fd00::/64)
			z.Subnet6 = ipnet.String()
		}
	}

	m.mu.Lock()
	m.zones = &zones
	m.mu.Unlock()

	// Save to file
	path := filepath.Join(m.ctx.Platform.EtcDir, "zones.json")
	data, _ := json.MarshalIndent(&zones, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, fmt.Errorf("save zones: %w", err)
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiGetRules(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return map[string]interface{}{"rules": m.rules}, nil
}

func (m *Module) apiSetRules(r *core.Req) (any, error) {
	var doc map[string]interface{}
	if err := r.Decode(&doc); err != nil {
		return nil, err
	}

	rules, err := m.parseRules(doc)
	if err != nil {
		return nil, err
	}

	m.mu.Lock()
	m.rules = rules
	m.mu.Unlock()

	// Save to file
	path := filepath.Join(m.ctx.Platform.EtcDir, "enroll-rules.json")
	data, _ := json.MarshalIndent(doc, "", "  ")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return nil, fmt.Errorf("save rules: %w", err)
	}

	return map[string]any{"ok": true}, nil
}

func (m *Module) apiAssign(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var req struct {
		MAC  string `json:"mac"`
		Zone string `json:"zone"`
	}
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	mac := strings.ToLower(req.MAC)
	d, exists := m.devices[mac]
	if !exists {
		d = &Device{MAC: mac}
		m.devices[mac] = d
	}

	// Choosing a zone pins the device there; choosing none hands it back to
	// the rules.
	if req.Zone != "" {
		d.Zone = req.Zone
		d.Pinned = 1
	} else {
		d.Pinned = 0
		d.Zone = m.derivedZone(d.Class)
	}
	_ = m.saveDevice(d)

	return d, nil
}

func (m *Module) apiReconcile(r *core.Req) (any, error) {
	if err := m.reconcile(); err != nil {
		return nil, err
	}
	return map[string]any{"ok": true}, nil
}

func (m *Module) apiApply(r *core.Req) (any, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.zones.Mode != "enforce" {
		return nil, core.BadRequest("mode is %s, not enforce", m.zones.Mode)
	}

	// Generate and apply dnsmasq config
	if err := m.applyDnsmasq(); err != nil {
		return nil, err
	}

	// Generate and apply pf rules
	if err := m.applyFirewall(); err != nil {
		return nil, err
	}

	m.lastApplied = time.Now()
	return map[string]any{"ok": true}, nil
}

func (m *Module) apiPlan(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	return map[string]any{
		"mode": m.zones.Mode,
		"note": "In " + m.zones.Mode + " mode",
	}, nil
}

func (m *Module) apiSetMode(r *core.Req) (any, error) {
	var req struct {
		Mode string `json:"mode"`
	}
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	if req.Mode != "monitor" && req.Mode != "enforce" {
		return nil, core.BadRequest("mode must be monitor or enforce")
	}
	if req.Mode == "enforce" {
		if err := m.ctx.License().Allowed("device.enroll"); err != nil {
			return nil, err
		}
	}

	m.mu.Lock()
	m.zones.Mode = req.Mode
	m.mu.Unlock()

	// Persist
	path := filepath.Join(m.ctx.Platform.EtcDir, "zones.json")
	m.mu.RLock()
	data, _ := json.MarshalIndent(m.zones, "", "  ")
	m.mu.RUnlock()
	_ = os.WriteFile(path, data, 0o644)

	return map[string]any{"mode": req.Mode}, nil
}

// ============================================================================
// Dnsmasq logging setup
// ============================================================================

func resolveDnsmasqBinary() string {
	// Try explicit paths first
	for _, path := range []string{"/usr/local/sbin/dnsmasq", "/usr/sbin/dnsmasq"} {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	// Fall back to PATH lookup
	if path, err := exec.LookPath("dnsmasq"); err == nil {
		return path
	}
	return ""
}

func (m *Module) setupDnsmasqLogging() error {
	if !m.ctx.Platform.IsOPNsense() {
		return nil
	}

	manage := core.Bool(m.ctx.Settings(), "manage_dnsmasq_logging", true)
	if !manage {
		return nil
	}

	dnsmasqBin := resolveDnsmasqBinary()
	if dnsmasqBin == "" {
		m.lastErr = "dnsmasq binary not found; skipping logging setup"
		return nil
	}

	confPath := filepath.Join(m.ctx.Platform.DnsmasqConfDir, "flowsight-enroll.conf")

	// Write or ensure the config has log-dhcp
	content := "# Generated by FlowSight enroll. Do not edit.\nlog-dhcp\n"
	tmpPath := confPath + ".tmp"

	if err := os.WriteFile(tmpPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write dnsmasq logging config: %w", err)
	}

	// Validate the main config with our addition
	mainConf := "/usr/local/etc/dnsmasq.conf"
	if _, err := core.Run(30*time.Second, dnsmasqBin, "--test", "-C", mainConf); err != nil {
		os.Remove(tmpPath)
		m.lastErr = fmt.Sprintf("dnsmasq config validation failed: %v", err)
		return nil // Report in Health instead of failing the job
	}

	// Move into place
	if err := os.Rename(tmpPath, confPath); err != nil {
		os.Remove(tmpPath)
		return err
	}

	// Restart dnsmasq
	if _, err := m.ctx.Platform.Service("dnsmasq", "restart"); err != nil {
		// Remove the file on restart failure
		os.Remove(confPath)
		return fmt.Errorf("dnsmasq restart failed: %w", err)
	}

	m.lastErr = ""
	return nil
}

// ============================================================================
// Firewall and DHCP configuration
// ============================================================================

func (m *Module) applyDnsmasq() error {
	// Generate dnsmasq include with zone DHCP ranges and device reservations
	path := filepath.Join(m.ctx.Platform.DnsmasqConfDir, "flowsight-enroll.conf")

	var buf bytes.Buffer
	buf.WriteString("# Generated by FlowSight enroll. Do not edit.\n\n")

	// Write zone ranges
	for _, zone := range m.zones.Zones {
		buf.WriteString(fmt.Sprintf("# Zone: %s - %s\n", zone.ID, zone.Name))
		// dnsmasq range syntax: dhcp-range=tag:zone,start,end,netmask,lease
		// or: dhcp-range=set:tag,start,end,netmask,lease
	}

	// Write device reservations
	for mac, d := range m.devices {
		if d.Zone != "" && d.Zone != m.zones.CaptiveZone {
			// Allocate or retrieve address for this device
			allocator := m.allocations[d.Zone]
			if allocator != nil {
				ip, err := allocator.Allocate(mac)
				if err == nil && ip != "" {
					buf.WriteString(fmt.Sprintf("dhcp-host=%s,%s,%s\n", strings.ToLower(mac), ip, d.Hostname))
				}
			}
		}
	}

	// Write file atomically
	tmpPath := path + ".tmp"
	if err := os.WriteFile(tmpPath, buf.Bytes(), 0o644); err != nil {
		return fmt.Errorf("write dnsmasq config: %w", err)
	}

	// Validate with dnsmasq --test
	if _, err := core.Run(10*time.Second, "dnsmasq", "--test", "-C", tmpPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("dnsmasq validation failed: %w", err)
	}

	return os.Rename(tmpPath, path)
}

func (m *Module) applyFirewall() error {
	// Generate pf rules for zone isolation
	var buf bytes.Buffer
	buf.WriteString("# Generated by FlowSight enroll. Do not edit.\n\n")

	// Define zone subnets as tables
	for _, zone := range m.zones.Zones {
		buf.WriteString(fmt.Sprintf("table <fs_%s> persist { %s }\n", zone.ID, zone.Subnet))
	}
	buf.WriteString("\n")

	// Zone isolation rules
	for _, zone := range m.zones.Zones {
		if zone.Captive {
			// Captive zone: block everything except gateway and DNS
			buf.WriteString(fmt.Sprintf("block return quick from <fs_%s> to any\n", zone.ID))
			buf.WriteString(fmt.Sprintf("pass quick from <fs_%s> to %s\n", zone.ID, zone.Gateway))
			continue
		}

		// Regular zone: block disallowed reaches
		for _, other := range m.zones.Zones {
			if other.ID == zone.ID || stringInSlice(other.ID, zone.ReachZones) {
				continue
			}
			buf.WriteString(fmt.Sprintf("block return quick from <fs_%s> to <fs_%s>\n", zone.ID, other.ID))
		}

		// Block internet if needed
		if !zone.Internet {
			buf.WriteString(fmt.Sprintf("block return quick from <fs_%s> to !<fs_%s>\n", zone.ID, zone.ID))
		}
	}

	rules := buf.String()
	return m.firewall.LoadAnchor("enroll", rules)
}

// ============================================================================
// Captive portal
// ============================================================================

func (m *Module) captiveGet(r *core.Req) (any, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	// Look up device by source IP to get MAC and info
	mac := ""
	var device *Device
	srcIP := r.Client

	// Find device by IP
	for _, d := range m.devices {
		if d.IP == srcIP {
			mac = d.MAC
			device = d
			break
		}
	}

	// Build available zones list (only self_service ones)
	var zoneOpts []string
	if m.zones != nil {
		for _, zone := range m.zones.Zones {
			if zone.SelfService {
				zoneOpts = append(zoneOpts, fmt.Sprintf(
					`<label><input type="radio" name="zone" value="%s"><b>%s</b><span>%s</span></label>`,
					zone.ID, zone.Name, zone.Description))
			}
		}
	}

	// Build device info display
	deviceInfo := ""
	if device != nil {
		deviceInfo = fmt.Sprintf(`<dl>
<dt>MAC Address</dt><dd>%s</dd>
<dt>Hostname</dt><dd>%s</dd>
<dt>Vendor</dt><dd>%s</dd>
</dl>`, mac, device.Hostname, device.Vendor)
	}

	html := fmt.Sprintf(`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Identify This Device</title>
<style>
:root{--accent:#C03E14}
*{box-sizing:border-box}
body{margin:0;background:#f5f5f5;color:#373736;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;justify-content:center;padding:24px 16px}
.card{background:#fff;border:1px solid #ddd;border-radius:12px;padding:24px;max-width:520px;width:100%%}
h1{margin:0 0 4px;font-size:21px}
p.sub{margin:0 0 20px;opacity:.7;font-size:14px}
dl{display:grid;grid-template-columns:auto 1fr;gap:6px 14px;margin:0 0 22px;font-size:13px}
dt{opacity:.6}
dd{margin:0;font-family:ui-monospace,Menlo,monospace}
label{display:block;border:1px solid #ddd;border-radius:9px;padding:12px 14px;margin-bottom:9px;cursor:pointer}
label:hover{border-color:var(--accent)}
label input{margin-right:9px}
label b{font-weight:600}
label span{display:block;margin-left:25px;opacity:.65;font-size:13px}
button{width:100%%;padding:13px;border:0;border-radius:9px;background:var(--accent);color:#fff;font-size:15px;font-weight:600;cursor:pointer;margin-top:10px}
</style>
</head><body><div class="card">
<h1>Identify This Device</h1>
<p class="sub">FlowSight doesn't recognize this device. What is it?</p>
%s
<form method="post">
<fieldset style="border:0;padding:0;margin:0">
<legend style="font-weight:600;margin-bottom:10px">Device Type</legend>
%s
</fieldset>
<button type="submit">Continue</button>
</form>
</div></body></html>`, deviceInfo, strings.Join(zoneOpts, ""))

	return core.Raw{ContentType: "text/html; charset=utf-8", Body: []byte(html)}, nil
}

func (m *Module) captivePost(r *core.Req) (any, error) {
	var req struct {
		Zone string `json:"zone"`
	}
	if err := r.Decode(&req); err != nil {
		return nil, err
	}

	srcIP := r.Client
	mac := ""

	m.mu.RLock()
	// Find device by source IP
	for _, d := range m.devices {
		if d.IP == srcIP {
			mac = d.MAC
			break
		}
	}
	m.mu.RUnlock()

	if mac == "" {
		return nil, core.BadRequest("device not found")
	}

	// Check rate limiting: one change per MAC per minute
	m.captiveMuRate.Lock()
	lastChange := m.captiveRate[mac]
	now := time.Now().Unix()
	if now-lastChange < 60 {
		m.captiveMuRate.Unlock()
		return nil, core.BadRequest("please wait at least 60 seconds between changes")
	}
	m.captiveRate[mac] = now
	m.captiveMuRate.Unlock()

	// Validate zone exists
	m.mu.RLock()
	zoneExists := false
	if m.zones != nil {
		for _, z := range m.zones.Zones {
			if z.ID == req.Zone {
				zoneExists = true
				break
			}
		}
	}
	m.mu.RUnlock()

	if !zoneExists {
		return nil, core.BadRequest("invalid zone")
	}

	// Record as event
	m.ctx.Event("enroll", "device self-identified", map[string]any{
		"mac":  mac,
		"zone": req.Zone,
	})

	// Assign the device
	m.mu.Lock()
	d := m.devices[strings.ToLower(mac)]
	if d != nil {
		d.Zone = req.Zone
		d.Pinned = 1
		_ = m.saveDevice(d)
	}
	m.mu.Unlock()

	// Return confirmation page
	confirmHTML := `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Device Identified</title>
<style>
:root{--accent:#C03E14}
*{box-sizing:border-box}
body{margin:0;background:#f5f5f5;color:#373736;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;justify-content:center;padding:24px 16px}
.card{background:#fff;border:1px solid #ddd;border-radius:12px;padding:24px;max-width:520px;width:100%}
.ok{border-left:3px solid var(--accent);padding-left:14px}
h1{margin:0 0 4px;font-size:21px;color:var(--accent)}
p{margin:0}
</style>
</head><body><div class="card ok">
<h1>Thank You</h1>
<p>This device has been added to your network. You can now access the internet and your network resources.</p>
</div></body></html>`

	return core.Raw{ContentType: "text/html; charset=utf-8", Body: []byte(confirmHTML)}, nil
}

func (m *Module) serveCaptive(port int) {
	// Create a simple HTTP mux for the captive portal
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.captivePortalHandler)

	addr := net.JoinHostPort("0.0.0.0", fmt.Sprintf("%d", port))
	server := &http.Server{Addr: addr, Handler: mux, ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second}

	m.captiveServer = server

	m.ctx.Log.Info("starting captive portal", "addr", addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		m.ctx.Log.Error("captive portal error", "error", err)
	}
}

func (m *Module) captivePortalHandler(w http.ResponseWriter, r *http.Request) {
	// Extract client IP
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	if host == "" {
		host = r.RemoteAddr
	}

	// Create a fake core.Req for our handlers
	req := &core.Req{Request: r, Client: host}

	var result any
	var err error

	switch r.Method {
	case "GET":
		result, err = m.captiveGet(req)
	case "POST":
		result, err = m.captivePost(req)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if err != nil {
		var e *core.Error
		if errors.As(err, &e) {
			http.Error(w, e.Error(), e.Status)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if raw, ok := result.(core.Raw); ok {
		w.Header().Set("Content-Type", raw.ContentType)
		w.WriteHeader(http.StatusOK)
		w.Write(raw.Body)
	}
}

// ============================================================================
// Zone resolution for policy
// ============================================================================

func (m *Module) publishZoneResolver() {
	// Wrap the existing member_resolver
	existing := m.ctx.Service("member_resolver")

	resolver := &zoneResolver{
		m:        m,
		delegate: existing.(core.MemberResolver),
	}

	m.ctx.Publish("member_resolver", resolver)
}

type zoneResolver struct {
	m        *Module
	delegate core.MemberResolver
}

func (zr *zoneResolver) Resolve(member string) []string {
	if strings.HasPrefix(member, "zone:") {
		// A zone is its subnet plus every device assigned to it, wherever
		// that device currently sits (a device can be filed under IoT while
		// still holding a lease on another network) and whichever address
		// family it is using; a v4 subnet alone would leave the same
		// devices' IPv6 traffic outside every rule.
		zoneID := strings.TrimPrefix(member, "zone:")
		seen := map[string]bool{}
		var out []string
		add := func(c string) {
			if c != "" && !seen[c] {
				seen[c] = true
				out = append(out, c)
			}
		}

		// Add IPv4 and IPv6 subnets
		for _, zone := range zr.m.zones.Zones {
			if zone.ID == zoneID {
				add(zone.Subnet)
				add(zone.Subnet6)
			}
		}

		// Get all device MACs in the zone
		zr.m.mu.RLock()
		var macs []string
		for _, d := range zr.m.devices {
			if d.Zone == zoneID && d.MAC != "" {
				macs = append(macs, d.MAC)
			}
		}
		zr.m.mu.RUnlock()
		sort.Strings(macs)

		// For each device, get all addresses (v4 and v6)
		ab, ok := zr.m.ctx.Service("identity").(core.AddressBook)
		for _, mac := range macs {
			// Get one IP address for this MAC from the delegate resolver
			if zr.delegate != nil {
				cidrs := zr.delegate.Resolve("mac:" + strings.ToLower(mac))
				for _, cidr := range cidrs {
					// Extract IP from CIDR notation
					ip := strings.Split(cidr, "/")[0]
					// If we have AddressBook, use it to get all addresses for this device
					if ok && ab != nil {
						for _, addr := range ab.Addresses(ip) {
							// Convert to CIDR format
							if strings.Contains(addr, ":") {
								add(addr + "/128")
							} else {
								add(addr + "/32")
							}
						}
					} else {
						// Fallback: just use the CIDR from delegate
						add(cidr)
					}
				}
			}
		}
		return out
	}

	if zr.delegate != nil {
		return zr.delegate.Resolve(member)
	}
	return nil
}

// CheckZoneIPv6Devices returns the count of devices in a zone that have IPv6 addresses
// but the zone doesn't have subnet6 defined.
func (m *Module) CheckZoneIPv6Devices(zoneID string) int {
	// Find the zone
	m.mu.RLock()
	var zone *Zone
	for _, z := range m.zones.Zones {
		if z.ID == zoneID {
			zone = z
			break
		}
	}

	// If zone doesn't exist or already has subnet6, return 0
	if zone == nil || zone.Subnet6 != "" {
		m.mu.RUnlock()
		return 0
	}

	// Get device MACs in this zone
	var macs []string
	for _, d := range m.devices {
		if d.Zone == zoneID && d.MAC != "" {
			macs = append(macs, d.MAC)
		}
	}
	m.mu.RUnlock()

	// Check if any device has IPv6 addresses
	ab, ok := m.ctx.Service("identity").(core.AddressBook)
	if !ok || ab == nil {
		return 0
	}

	ipv6Devices := 0
	for _, mac := range macs {
		m.mu.RLock()
		ips := []string{}
		if d, exists := m.devices[mac]; exists && d.IP != "" {
			ips = append(ips, d.IP)
		}
		m.mu.RUnlock()

		// Get all addresses for this device
		for _, ip := range ips {
			for _, addr := range ab.Addresses(ip) {
				if strings.Contains(addr, ":") {
					ipv6Devices++
					break
				}
			}
		}
	}

	return ipv6Devices
}

// ============================================================================
// Helpers
// ============================================================================

// isStoredClientID reports whether a stored device row is really the first
// six octets of a DHCPv6 client DUID, which builds before 0.9.8r202609240739
// read from DHCPv6 log lines as an address. A DUID starts with its type, 1 to
// 4, as two octets; the rows those builds made carry nothing else, since the
// lines they came from name no IPv4 address. Real hardware whose vendor
// prefix happens to start the same way has an address, a name or a vendor,
// and a pinned row is someone's decision, so both are kept.
func isStoredClientID(row map[string]any) bool {
	mac := strings.ToLower(getStr(row, "mac"))
	if len(mac) != 17 || !strings.HasPrefix(mac, "00:0") || mac[4] < '1' || mac[4] > '4' {
		return false
	}
	for _, k := range []string{"ip", "ip6", "hostname", "vendor", "guest_name"} {
		if getStr(row, k) != "" {
			return false
		}
	}
	return getInt(row, "pinned") == 0
}

func isPseudoMAC(mac string) bool {
	// Broadcast and multicast addresses are destinations, not devices
	mac = strings.ToUpper(mac)
	if mac == "FF:FF:FF:FF:FF:FF" || mac == "" {
		return true
	}
	if strings.HasPrefix(mac, "01:00:5E") || strings.HasPrefix(mac, "33:33") {
		return true
	}
	// Check if multicast bit (bit 0 of first octet) is set
	if len(mac) >= 2 {
		var b byte
		fmt.Sscanf(mac[0:2], "%x", &b)
		if (b & 0x01) != 0 {
			return true
		}
	}
	return false
}

func isRandomizedMAC(mac string) bool {
	mac = strings.ToLower(mac)
	if len(mac) < 2 {
		return false
	}
	// Second hex digit is bit 1 of the first byte
	// Bit 1 = 1 means locally administered
	firstByte := mac[0:2]
	var b byte
	fmt.Sscanf(firstByte, "%x", &b)
	return (b & 0x02) != 0
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func getStr(row map[string]any, key string) string {
	if v, ok := row[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

func getInt(row map[string]any, key string) int {
	if v, ok := row[key]; ok {
		if i, ok := v.(int64); ok {
			return int(i)
		}
	}
	return 0
}

func getInt64(row map[string]any, key string) int64 {
	if v, ok := row[key]; ok {
		if i, ok := v.(int64); ok {
			return i
		}
	}
	return 0
}

func stringInSlice(s string, slice []string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}
