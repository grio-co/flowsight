package visibility

// What an application is, for a reader who has just clicked its name.
//
// nDPI names the application and grades it (its breed); it does not say
// what the thing is for, what it looks like when it misbehaves, or what an
// operator should check. These notes do, for the applications that come up
// on most home and small-office networks. Anything not listed gets the
// note for its category and breed, which is thinner but never empty.

import "strings"

// AppNote is the write-up shown on an application's page.
type AppNote struct {
	Purpose string   `json:"purpose"`            // what it is used for
	Risk    string   `json:"risk"`               // what can go wrong, in one paragraph
	Issues  []string `json:"issues,omitempty"`   // common problems on a network
	LookFor []string `json:"look_for,omitempty"` // what to check on this page
	Source  string   `json:"source"`             // "curated" or "category"
}

var appNotes = map[string]AppNote{
	"TLS": {Purpose: "Encrypted web and app traffic that nDPI could not attribute to a named service. Almost everything a device does over the internet passes through TLS.",
		Risk:    "The name alone says nothing; the risk is in where it goes. A large TLS volume to an address with no server name and no known network is the pattern of data leaving quietly.",
		Issues:  []string{"Servers that pin their certificate refuse inspection and show as opaque", "Encrypted Client Hello hides the server name, so even the name is missing"},
		LookFor: []string{"Destinations with no name and unusual ports", "Sustained upload from one device", "Countries the device does not normally talk to"}},
	"QUIC": {Purpose: "Google's transport for HTTP/3 over UDP 443, used by Chrome, YouTube, Google services and increasingly others.",
		Risk:    "QUIC cannot be inspected by the web proxy, so anything carried inside it is invisible beyond its volume and its far end. It is not dangerous in itself, only opaque.",
		Issues:  []string{"Bypasses the transparent proxy entirely", "Blocking UDP 443 forces clients back to TLS, which the proxy can see"},
		LookFor: []string{"Which devices use it most", "Whether a policy should deny QUIC for inspected devices"}},
	"DNS": {Purpose: "Name resolution. Every device does it constantly; the gateway's resolver answers most of it.",
		Risk:    "DNS to servers other than the gateway bypasses the DNS blocks and the DNS report. Very long or very frequent queries to one domain can be a tunnel carrying data out.",
		Issues:  []string{"Devices with hard-coded resolvers (8.8.8.8, 1.1.1.1) ignore the gateway", "Smart TVs and IoT often bring their own"},
		LookFor: []string{"Destinations other than the gateway on port 53", "Anomalies of kind dns-tunnel on the Anomalies page"}},
	"DNS-over-HTTPS": {Purpose: "Name resolution inside HTTPS, used by browsers (Firefox, Chrome) and some apps to keep queries private.",
		Risk:    "It hides names from the gateway's DNS controls and reports. A browser with DoH on ignores every DNS block.",
		LookFor: []string{"Browsers on devices that should be filtered", "Whether Stateful Packet Inspection is decoding it for inspected devices"}},
	"BitTorrent": {Purpose: "Peer-to-peer file sharing. Downloads and, always, uploads to many peers at once.",
		Risk:    "Heavy sustained upload and hundreds of connections. Copyrighted material brings notices from the carrier. Clients expose a listening port to the internet.",
		Issues:  []string{"Saturates upload and starves everything else unless shaped", "Trackers and peers in every country make the country picture noisy"},
		LookFor: []string{"The device running it and its upload rate on the DLP page", "A Priority rule putting it in the low class"}},
	"SSH": {Purpose: "Remote shells and file copies to servers, and the transport under git and many admin tools.",
		Risk:    "An SSH session can carry anything, including a tunnel. Outbound SSH from a device that has no business with servers is worth a question.",
		LookFor: []string{"Which devices open it and to where", "Long-lived sessions with steady upload"}},
	"WireGuard": {Purpose: "A VPN. Everything inside it is invisible to inspection.",
		Risk:    "A VPN client on a device moves that device outside every control on this gateway: DNS blocks, web categories, application control.",
		LookFor: []string{"Devices other than the ones meant to run a VPN", "The DLP page's Encrypted Tunnel kind"}},
	"OpenVPN": {Purpose: "A VPN. Everything inside it is invisible to inspection.",
		Risk:    "Same as any tunnel: the device is outside every control here while it is up.",
		LookFor: []string{"Which devices, and whether that is expected"}},
	"Tailscale": {Purpose: "A mesh VPN built on WireGuard; devices reach each other directly wherever they are.",
		Risk:    "A Tailscale node can advertise this network's subnets or act as an exit node for others. Check who runs it and what it advertises.",
		LookFor: []string{"Nodes that were not set up on purpose", "Steady traffic on UDP 41641 to unknown peers"}},
	"YouTube": {Purpose: "Video streaming, most of it over QUIC.",
		Risk:    "Volume only. On a metered or slow link it is the first thing to shape.",
		LookFor: []string{"Which devices, at which hours", "Whether SafeSearch or a schedule applies for children's devices"}},
	"Netflix": {Purpose: "Video streaming from Netflix's own content network.",
		Risk: "Volume only.", LookFor: []string{"Devices and hours"}},
	"Spotify": {Purpose: "Music streaming.", Risk: "Volume only.", LookFor: []string{"Devices and hours"}},
	"WhatsApp": {Purpose: "Messaging, calls and file sharing, end-to-end encrypted.",
		Risk:    "Files leave the network through it without any inspection. Calls need UDP to work well.",
		LookFor: []string{"Large uploads on the DLP page under Messaging"}},
	"Telegram": {Purpose: "Messaging and large file sharing, with channels used for software distribution of every kind.",
		Risk:    "Files of any size leave through it uninspected; some malware families use it as a control channel.",
		LookFor: []string{"Uploads from devices that do not otherwise use it", "Telegram traffic from servers or IoT devices"}},
	"Discord": {Purpose: "Chat, voice and screen sharing, popular with gamers; file sharing built in.",
		Risk: "Files leave through it; its content network also hosts malware downloads.", LookFor: []string{"Uploads and unusual devices"}},
	"Signal": {Purpose: "Messaging and calls, end-to-end encrypted.", Risk: "Uninspectable by design; low volume.", LookFor: []string{"Nothing unusual is expected"}},
	"Dropbox": {Purpose: "File sync and sharing.", Risk: "A sync client copies whole folders out. Watched on the DLP page as Cloud Storage.",
		LookFor: []string{"Volume per device on the DLP page", "First-use events from devices that never synced before"}},
	"GoogleDrive": {Purpose: "File sync and sharing.", Risk: "As Dropbox: whole folders leave through it.", LookFor: []string{"Volume per device"}},
	"iCloud": {Purpose: "Apple's sync, backup and photo library.", Risk: "Large uploads at night are normal for backups; large uploads from a device that is not an Apple device are not.",
		LookFor: []string{"Which devices", "Private Relay traffic, which hides destinations"}},
	"Apple": {Purpose: "Apple services: updates, the App Store, push notifications, location services, telemetry.",
		Risk: "Normal for Apple devices. Steady background volume; updates arrive in bursts.", LookFor: []string{"Only whether the device is in fact an Apple device"}},
	"Microsoft": {Purpose: "Windows update, Office, telemetry and account services.",
		Risk: "Normal for Windows devices; telemetry is chatty. Large downloads are updates.", LookFor: []string{"Which devices"}},
	"Google": {Purpose: "Google services in general: search, accounts, APIs, Android services.",
		Risk: "Normal. Android devices talk to it constantly.", LookFor: []string{"Nothing unusual is expected"}},
	"Amazon": {Purpose: "Amazon's shopping, Prime Video, Alexa and the AWS endpoints that thousands of other services run on.",
		Risk:    "Most 'Amazon' traffic is someone else's service hosted on AWS. The name says where, not who.",
		LookFor: []string{"The server name on each session, which usually names the real service"}},
	"AmazonAWS": {Purpose: "Servers in Amazon Web Services: a large share of the internet's services live there.",
		Risk:    "The name says nothing about the service. Look at the domain, the port and the volume.",
		LookFor: []string{"Sessions with no server name", "Uploads to storage endpoints (s3)"}},
	"Cloudflare": {Purpose: "A content network and DNS provider in front of a large share of websites, plus its WARP VPN and 1.1.1.1 resolver.",
		Risk:    "As with Amazon, the name is the middleman. WARP is a VPN and moves the device outside this gateway's controls.",
		LookFor: []string{"WARP (cloudflareclient.com) on devices that should be filtered", "1.1.1.1 DNS bypassing the gateway"}},
	"NTP": {Purpose: "Clock synchronisation.", Risk: "None in normal use. Very frequent NTP from one device is a misconfigured client, or occasionally a tunnel.",
		LookFor: []string{"Devices asking many different servers"}},
	"HTTP": {Purpose: "Unencrypted web. Software updates, captive portals, some IoT devices, old sites.",
		Risk:    "Readable by anyone on the path. Credentials or personal data over plain HTTP are exposed.",
		LookFor: []string{"Devices sending anything but update checks", "Logins or forms over HTTP in Stateful Packet Inspection"}},
	"Steam":       {Purpose: "Game downloads and play.", Risk: "Very large downloads; shape rather than block.", LookFor: []string{"Downloads at the wrong hours"}},
	"Xbox":        {Purpose: "Game console services.", Risk: "Large downloads.", LookFor: []string{"Hours"}},
	"PlayStation": {Purpose: "Game console services.", Risk: "Large downloads.", LookFor: []string{"Hours"}},
	"Zoom":        {Purpose: "Video meetings.", Risk: "Needs steady upload; suffers first when the link is full.", LookFor: []string{"A Priority rule keeping it in the high class"}},
	"Teams":       {Purpose: "Microsoft Teams meetings and chat.", Risk: "As Zoom.", LookFor: []string{"Priority class"}},
	"FaceTime":    {Purpose: "Apple video calls.", Risk: "As Zoom.", LookFor: []string{"Priority class"}},
	"TeamViewer": {Purpose: "Remote desktop, often used by support scammers as well as by IT.",
		Risk:    "Anyone connected has the device. Unexpected TeamViewer on a family member's computer is a classic scam sign.",
		LookFor: []string{"Which device, when, and whether anyone asked for it"}},
	"AnyDesk": {Purpose: "Remote desktop; the same uses and the same abuse as TeamViewer.",
		Risk: "Unexpected sessions are a red flag.", LookFor: []string{"Which device and when"}},
	"RDP": {Purpose: "Windows remote desktop.", Risk: "Outbound RDP is rare on home networks; inbound RDP from the internet should never be open.",
		LookFor: []string{"Direction, and the far end"}},
	"SMTP": {Purpose: "Sending mail directly, as mail servers do.", Risk: "A desktop or IoT device sending SMTP directly is usually a spam bot or a compromised device.",
		LookFor: []string{"Any device that is not a mail server"}},
	"Mining": {Purpose: "Cryptocurrency mining pool traffic.", Risk: "On a device nobody set up for it, this is malware using the machine's power and electricity.",
		LookFor: []string{"The device, and stop it"}},
	"Tor": {Purpose: "Anonymity network.", Risk: "Everything inside is hidden and exits somewhere else. Legitimate for privacy; also the transport of choice for a lot of malware.",
		LookFor: []string{"Which device, and whether its owner knows"}},
	"Roku": {Purpose: "Roku streaming players and their channels.", Risk: "Volume and telemetry; Roku devices are chatty with advertising and analytics endpoints.",
		LookFor: []string{"Advertising and tracking destinations, which the ads category can block"}},
	"Alexa": {Purpose: "Amazon Echo devices.", Risk: "Always-on microphones talking to Amazon; expected traffic is small and steady.",
		LookFor: []string{"Unexpected volume or destinations outside Amazon"}},
	"Plex": {Purpose: "Media server and its clients; remote access relays through plex.direct.",
		Risk:    "Remote streaming is upload from your server to the internet; a port forward exposes the server.",
		LookFor: []string{"Upload volume on the DLP page", "Whether remote access is meant to be on"}},
}

// categoryNotes fill in for applications without a note of their own.
var categoryNotes = map[string]AppNote{
	"Web":            {Purpose: "General web browsing and web services.", Risk: "Depends entirely on the site. The web categories on the Categories page classify the names.", LookFor: []string{"Sites and categories on the Web page"}},
	"Media":          {Purpose: "Audio and video.", Risk: "Volume.", LookFor: []string{"Devices and hours"}},
	"Streaming":      {Purpose: "Live and on-demand video.", Risk: "Volume.", LookFor: []string{"Devices and hours"}},
	"Cloud":          {Purpose: "Cloud storage, sync and hosted services.", Risk: "Data leaves the network through sync and upload.", LookFor: []string{"Upload volume on the DLP page"}},
	"SoftwareUpdate": {Purpose: "Operating system and application updates.", Risk: "Bursts of download; harmless.", LookFor: []string{"Nothing unusual is expected"}},
	"Advertisement":  {Purpose: "Advertising and tracking networks.", Risk: "Privacy and bandwidth. The ads and tracking categories block most of it by name.", LookFor: []string{"Which devices see the most"}},
	"Game":           {Purpose: "Games and their services.", Risk: "Large downloads; latency-sensitive play.", LookFor: []string{"Priority class and hours"}},
	"VoIP":           {Purpose: "Voice and video calls.", Risk: "Needs steady, low-latency upload.", LookFor: []string{"Priority class"}},
	"Chat":           {Purpose: "Messaging.", Risk: "Files leave through it uninspected.", LookFor: []string{"Uploads on the DLP page"}},
	"SocialNetwork":  {Purpose: "Social networks.", Risk: "Time, privacy and uploads of photos and video.", LookFor: []string{"Devices and hours"}},
	"VPN":            {Purpose: "Tunnels.", Risk: "The device is outside every control here while the tunnel is up.", LookFor: []string{"Which devices, and whether that is expected"}},
	"RemoteAccess":   {Purpose: "Remote desktop and shells.", Risk: "Anyone connected has the device.", LookFor: []string{"Which device, when, and whether anyone asked for it"}},
	"Mining":         {Purpose: "Cryptocurrency mining.", Risk: "On a device nobody set up for it, this is malware.", LookFor: []string{"The device"}},
	"Cybersecurity":  {Purpose: "Security products calling home: antivirus updates, EDR agents.", Risk: "Expected on managed devices.", LookFor: []string{"Nothing unusual is expected"}},
	"Download":       {Purpose: "File downloads and peer-to-peer.", Risk: "Volume and, for peer-to-peer, upload and exposure.", LookFor: []string{"Upload rate and connection count"}},
	"Network":        {Purpose: "Network plumbing: DNS, NTP, DHCP, discovery.", Risk: "Low, unless a device talks to servers other than the gateway.", LookFor: []string{"DNS to outside resolvers"}},
	"System":         {Purpose: "Operating-system services.", Risk: "Low.", LookFor: []string{"Nothing unusual is expected"}},
	"Email":          {Purpose: "Mail.", Risk: "Attachments leave through it; direct SMTP from a non-server is a spam sign.", LookFor: []string{"Direct SMTP"}},
	"IoT-Scada":      {Purpose: "Devices and controllers.", Risk: "Usually unpatched and chatty; should talk to few places.", LookFor: []string{"Destinations outside the vendor's cloud, and countries"}},
	"VirtAssistant":  {Purpose: "Voice assistants.", Risk: "Always-on microphones; expected traffic is small.", LookFor: []string{"Unexpected volume or destinations"}},
	"Database":       {Purpose: "Database protocols.", Risk: "A database reachable across the internet is a breach waiting.", LookFor: []string{"Direction and far end"}},
	"RPC":            {Purpose: "Remote procedure calls between services.", Risk: "Rare across the internet.", LookFor: []string{"Far end"}},
	"Unspecified":    {Purpose: "nDPI recognised the protocol but has no category for it.", Risk: "Unknown; read the destinations.", LookFor: []string{"Destinations, ports and volume"}},
}

var breedNotes = map[string]string{
	"Safe":                  "nDPI grades it safe: infrastructure or well-known services with no known abuse pattern.",
	"Acceptable":            "nDPI grades it acceptable: ordinary applications most networks allow.",
	"Fun":                   "nDPI grades it fun: entertainment and games; a time and bandwidth question, not a security one.",
	"Unsafe":                "nDPI grades it unsafe: commonly abused or carrying risk by design (peer-to-peer, tunnels, remote control).",
	"Potentially_Dangerous": "nDPI grades it potentially dangerous: legitimate uses exist, but it is a common vehicle for abuse.",
	"Dangerous":             "nDPI grades it dangerous: malware, mining or protocols with no legitimate place on a home network.",
	"Unrated":               "nDPI has not graded it.",
}

// noteFor returns the write-up for an application: its own when it has
// one, else its category's, always with the breed's sentence.
func noteFor(app, category, breed string) AppNote {
	base := app
	if i := strings.Index(app, "."); i > 0 {
		// "TLS.Dropbox": the named service is what the reader asked about.
		base = app[i+1:]
	}
	n, ok := appNotes[base]
	if !ok {
		n, ok = appNotes[app]
	}
	if !ok && strings.Contains(app, ".") {
		n, ok = appNotes[strings.SplitN(app, ".", 2)[0]]
	}
	if ok {
		n.Source = "curated"
	} else {
		n = categoryNotes[category]
		n.Source = "category"
		if n.Purpose == "" {
			n.Purpose = "No write-up yet for this application. Read it from its destinations, its devices and its volume below."
			n.Risk = "Unknown until read."
		}
	}
	if b := breedNotes[breed]; b != "" {
		n.Risk = strings.TrimSpace(n.Risk + " " + b)
	}
	return n
}
