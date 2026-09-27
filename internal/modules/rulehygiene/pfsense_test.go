package rulehygiene

import (
	"os"
	"path/filepath"
	"testing"
)

// From pfSense CE 2.7.2: the default LAN rules as config.xml holds them,
// and one as pfctl -vvsr prints it.
const pfSenseConfig = `<?xml version="1.0"?>
<pfsense>
	<filter>
		<rule>
			<type>pass</type>
			<ipprotocol>inet</ipprotocol>
			<descr><![CDATA[Default allow LAN to any rule]]></descr>
			<interface>lan</interface>
			<tracker>0100000101</tracker>
			<source><network>lan</network></source>
			<destination><any></any></destination>
		</rule>
	</filter>
	<revision><username>admin@10.98.0.2 (Local Database)</username></revision>
</pfsense>`

const pfSenseRule = `pass in quick on vtnet1 inet from <LAN__NETWORK:1> to any flags S/SA keep state label "USER_RULE: Default allow LAN to any rule" label "id:0100000101" ridentifier 100000101`

func TestPfSenseRulesAreDescribedByTracker(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.xml")
	if err := os.WriteFile(path, []byte(pfSenseConfig), 0o644); err != nil {
		t.Fatal(err)
	}
	labels, actor, err := loadOPNsenseConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := labels[ridentifier(pfSenseRule)]; got != "Default allow LAN to any rule" {
		t.Fatalf("description for ridentifier %q: %q (map %v)", ridentifier(pfSenseRule), got, labels)
	}
	if actor != "admin@10.98.0.2 (Local Database)" {
		t.Fatalf("actor: %q", actor)
	}
	if ridentifier(`block drop in log inet all label "Default deny rule IPv4"`) != "" {
		t.Fatal("a rule with no ridentifier has none")
	}
}
