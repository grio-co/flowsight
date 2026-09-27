package egress

// Which destinations are worth watching, and what to call them.
//
// The question this module answers is "what is leaving, to whom, right now",
// and the answer is only useful if the destination has a name a person
// recognises. A row saying 162.125.21.2 took four gigabytes means nothing;
// a row saying Dropbox took four gigabytes means something immediately.
//
// Classification is deliberately coarse. The groups below are the ones that
// change what you would do about a large upload: a backup service moving
// data at night is expected, the same volume going to a paste site or a
// personal mail account is not. A destination that matches nothing is still
// reported, and an unnamed one is reported more loudly, because the
// destination nobody can name is the one worth looking at.

import "strings"

// Group is a coarse class of destination.
type Group struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	// Watch marks a group whose uploads are worth flagging by default.
	Watch bool `json:"watch"`
	// Desc says what the group means and why it is or is not watched; the
	// page shows it as the bubble on each pill and in the legend.
	Desc string `json:"desc"`
}

var groups = []Group{
	{"cloud-storage", "Cloud Storage", true, "Sync and object storage: Dropbox, Drive, OneDrive, iCloud, S3 and the like. Watched because a large upload here is a copy of files leaving the network."},
	{"file-transfer", "File Transfer & Paste", true, "One-shot drop sites and paste bins: WeTransfer, file.io, pastebin and similar. Watched because they exist to move a file or a secret out in one request."},
	{"code-host", "Code Hosting", true, "GitHub, GitLab, package registries. Watched because source and credentials leave this way, deliberately or not."},
	{"webmail", "Personal Mail", true, "Personal mail providers reached over the web. Watched because attachments to a personal account bypass any company mail controls."},
	{"messaging", "Messaging", true, "Chat services with file sharing: Discord, Telegram, WhatsApp, Slack. Watched for the same reason as mail."},
	{"ai", "AI Assistants", true, "Hosted language-model services. Watched because pasted documents and code become someone else's training or logs."},
	{"remote-access", "Remote Access", true, "Remote desktop and tunnelling services: TeamViewer, AnyDesk, ngrok. Watched because they carry anything, in either direction."},
	{"backup", "Backup", false, "Backup services (Backblaze, Time Machine to a provider). Large uploads here are expected, so they are measured but not flagged."},
	{"media", "Media & Streaming", false, "Video, music and game services. Mostly downloads; not flagged."},
	{"telemetry", "Telemetry & Analytics", false, "Update and analytics endpoints vendors call home to. Small and constant; not flagged."},
	{"cdn", "Content Delivery", false, "Content networks fronting many sites. The name says who serves it, not what it is; not flagged on its own."},
	{"tunnel", "Encrypted Tunnel", true, "A VPN or overlay by port: WireGuard, OpenVPN, IPsec, Tailscale. Watched because nothing inside it can be seen; the volume, the far end and the timing are all that is knowable."},
	{"unknown", "Unnamed Destination", true, "Nothing names this address: no DNS answer was seen for it, no server name in a handshake, and no reverse lookup. Ordinary traffic almost always has a name, so a nameless one is worth a look. Watched."},
	{"other", "Other", false, "Matched none of the kinds above. Split further by what is known: the application's category, the web category of the name, the network that announces the address, or failing all of those the port."},
}

// groupDesc returns the description of a group key, or of the parent when
// the key is an Other sub-group.
func groupDesc(key string) string {
	if strings.HasPrefix(key, "other:") {
		key = "other"
	}
	for _, g := range groups {
		if g.Key == key {
			return g.Desc
		}
	}
	return ""
}

// suffixes maps a domain suffix to a group. A name matches the longest
// suffix that is a whole label boundary, so "api.dropbox.com" matches
// "dropbox.com" but "notdropbox.com" does not.
var suffixes = map[string]string{
	// Cloud storage and sync
	"dropbox.com": "cloud-storage", "dropboxapi.com": "cloud-storage",
	"drive.google.com": "cloud-storage", "googleapis.com": "cloud-storage",
	"onedrive.com": "cloud-storage", "1drv.com": "cloud-storage",
	"sharepoint.com": "cloud-storage", "box.com": "cloud-storage",
	"icloud.com": "cloud-storage", "icloud-content.com": "cloud-storage",
	"mega.nz": "cloud-storage", "mega.io": "cloud-storage",
	"pcloud.com": "cloud-storage", "sync.com": "cloud-storage",
	"s3.amazonaws.com": "cloud-storage", "blob.core.windows.net": "cloud-storage",
	"storage.googleapis.com": "cloud-storage", "r2.cloudflarestorage.com": "cloud-storage",
	"wasabisys.com": "cloud-storage", "digitaloceanspaces.com": "cloud-storage",

	// Anywhere a file or a secret can be dropped in one request
	"wetransfer.com": "file-transfer", "file.io": "file-transfer",
	"transfer.sh": "file-transfer", "sendgb.com": "file-transfer",
	"pastebin.com": "file-transfer", "paste.ee": "file-transfer",
	"ghostbin.com": "file-transfer", "hastebin.com": "file-transfer",
	"anonfiles.com": "file-transfer", "gofile.io": "file-transfer",
	"catbox.moe": "file-transfer", "0x0.st": "file-transfer",
	"bashupload.com": "file-transfer", "termbin.com": "file-transfer",

	"github.com": "code-host", "githubusercontent.com": "code-host",
	"gitlab.com": "code-host", "bitbucket.org": "code-host",
	"sourceforge.net": "code-host", "codeberg.org": "code-host",
	"npmjs.org": "code-host", "pypi.org": "code-host",

	"mail.google.com": "webmail", "gmail.com": "webmail",
	"outlook.com": "webmail", "outlook.office.com": "webmail",
	"mail.yahoo.com": "webmail", "proton.me": "webmail",
	"protonmail.com": "webmail", "zoho.com": "webmail",
	"mail.ru": "webmail", "yandex.ru": "webmail",

	"discord.com": "messaging", "discordapp.com": "messaging",
	"slack.com": "messaging", "telegram.org": "messaging",
	"t.me": "messaging", "web.whatsapp.com": "messaging",
	"signal.org": "messaging", "matrix.org": "messaging",
	"facebook.com": "messaging", "messenger.com": "messaging",

	"openai.com": "ai", "chatgpt.com": "ai", "anthropic.com": "ai",
	"claude.ai": "ai", "gemini.google.com": "ai", "perplexity.ai": "ai",
	"huggingface.co": "ai", "cohere.ai": "ai", "mistral.ai": "ai",

	"teamviewer.com": "remote-access", "anydesk.com": "remote-access",
	"logmein.com": "remote-access", "gotomypc.com": "remote-access",
	"splashtop.com": "remote-access", "ngrok.io": "remote-access",
	"ngrok-free.app": "remote-access", "trycloudflare.com": "remote-access",
	"tailscale.com": "remote-access", "zerotier.com": "remote-access",
	"screenconnect.com": "remote-access", "rustdesk.com": "remote-access",

	"backblaze.com": "backup", "backblazeb2.com": "backup",
	"carbonite.com": "backup", "crashplan.com": "backup",
	"idrive.com": "backup", "tarsnap.com": "backup",

	"youtube.com": "media", "googlevideo.com": "media", "netflix.com": "media",
	"nflxvideo.net": "media", "hulu.com": "media", "spotify.com": "media",
	"scdn.co": "media", "plex.tv": "media", "twitch.tv": "media",
	"ttvnw.net": "media", "roku.com": "media", "primevideo.com": "media",

	"google-analytics.com": "telemetry", "doubleclick.net": "telemetry",
	"datadoghq.com": "telemetry", "segment.io": "telemetry",
	"mixpanel.com": "telemetry", "sentry.io": "telemetry",
	"amplitude.com": "telemetry", "telemetry.mozilla.org": "telemetry",
	"crashlytics.com": "telemetry", "app-measurement.com": "telemetry",

	"cloudfront.net": "cdn", "akamaized.net": "cdn", "akamai.net": "cdn",
	"fastly.net": "cdn", "cloudflare.com": "cdn", "cdn77.org": "cdn",
	"edgesuite.net": "cdn", "llnwd.net": "cdn",
}

// tunnelPorts are the ports that carry an encrypted tunnel, whose contents no
// amount of inspection at this layer will ever reveal. Naming them as tunnels
// is the honest thing to do: everything inside is invisible by construction.
var tunnelPorts = map[int]string{
	51820: "WireGuard", 1194: "OpenVPN", 1195: "OpenVPN",
	500: "IPsec", 4500: "IPsec NAT-T", 1701: "L2TP", 1723: "PPTP",
	3478: "STUN (mesh VPN)", 41641: "Tailscale",
}

// offNetwork reports whether an address is a real destination somewhere else,
// as opposed to a broadcast, a multicast group or a link-local address, none
// of which leave this network at all.
func offNetwork(ip string) bool {
	switch {
	case ip == "" || ip == "255.255.255.255":
		return false
	case strings.HasPrefix(ip, "224.") || strings.HasPrefix(ip, "239."):
		return false // IPv4 multicast
	case strings.HasPrefix(ip, "169.254."):
		return false // link-local
	case strings.HasPrefix(strings.ToLower(ip), "ff0") || strings.HasPrefix(strings.ToLower(ip), "ff1"):
		return false // IPv6 multicast
	case strings.HasPrefix(strings.ToLower(ip), "fe80:"):
		return false
	}
	// A broadcast address ends in .255 on the common prefix lengths.
	return !strings.HasSuffix(ip, ".255")
}

// classify names the group a destination belongs to. name may be empty, which
// is itself a finding: data is leaving to somewhere with no name at all.
func classify(name string, port int, proto string) (group, label string) {
	if t, ok := tunnelPorts[port]; ok {
		return "tunnel", t
	}
	name = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" {
		return "unknown", ""
	}
	best, bestLen := "", 0
	for suf, g := range suffixes {
		if len(suf) <= bestLen {
			continue
		}
		if name == suf || strings.HasSuffix(name, "."+suf) {
			best, bestLen = g, len(suf)
		}
	}
	if best == "" {
		return "other", registrable(name)
	}
	return best, registrable(name)
}

// registrable trims a host to the name a person would recognise, so that
// forty hostnames under one service collapse into one row.
func registrable(name string) string {
	parts := strings.Split(name, ".")
	if len(parts) <= 2 {
		return name
	}
	// Two labels, unless the last two are a public suffix of the form
	// "co.uk" or "com.au", in which case take three.
	last2 := parts[len(parts)-2]
	if len(last2) <= 3 && len(parts) >= 3 {
		switch last2 {
		case "co", "com", "net", "org", "gov", "ac", "edu":
			return strings.Join(parts[len(parts)-3:], ".")
		}
	}
	return strings.Join(parts[len(parts)-2:], ".")
}

func groupTitle(key string) string {
	for _, g := range groups {
		if g.Key == key {
			return g.Title
		}
	}
	return key
}

func watchedByDefault() []string {
	var out []string
	for _, g := range groups {
		if g.Watch {
			out = append(out, g.Key)
		}
	}
	return out
}
