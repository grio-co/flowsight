package web

import (
	"fmt"
	"strings"
	"testing"
)

// squid reads its configuration a line at a time with a 2048-byte limit. A
// list of client addresses must never be rendered onto one line.
func TestSquidAddressListsGoToFilesAndStayValid(t *testing.T) {
	var excl []string
	for i := 0; i < 300; i++ {
		excl = append(excl, fmt.Sprintf("2600:1700:3ab0:f43f:%x:%x:%x:%x", i, i*7, i*13, i*17))
	}
	excl = append(excl, "192.168.1.0/24", "not-an-address", "10.0.0.5", "", "10.0.0.5")
	p := squidParams{
		Dir: "/var/db/flowsight/web", LogDir: "/var/log", RunDir: "/var/run", User: "squid",
		Exclusions: excl,
		Policies: []squidPolicy{
			{ID: "kids", Members: []string{"192.168.1.20", "fe80::1", "garbage"}, Domains: []string{"example.com"}},
			{ID: "nobody", Members: []string{"garbage"}, Domains: []string{"example.com"}},
		},
	}
	conf, files := p.render()
	for i, line := range strings.Split(conf, "\n") {
		if len(line) >= 2048 {
			t.Fatalf("line %d is %d bytes: %.80s...", i+1, len(line), line)
		}
	}
	if !strings.Contains(conf, `acl fs_excluded src "/var/db/flowsight/web/excluded-hosts.acl"`) {
		t.Fatal("exclusions were not moved to a file")
	}
	list := files["excluded-hosts.acl"]
	if strings.Contains(list, "not-an-address") {
		t.Fatal("a malformed entry reached squid")
	}
	if strings.Count(list, "10.0.0.5") != 1 || !strings.Contains(list, "192.168.1.0/24") {
		t.Fatalf("list is wrong:\n%s", list)
	}
	if n := strings.Count(list, "\n"); n != 302 {
		t.Fatalf("%d entries written, want 302", n)
	}
	if !strings.Contains(conf, `acl fs_src_kids src "/var/db/flowsight/web/src-kids.acl"`) || files["src-kids.acl"] != "192.168.1.20\nfe80::1\n" {
		t.Fatalf("policy members not rendered to a file: %q", files["src-kids.acl"])
	}
	if strings.Contains(conf, "fs_src_nobody") {
		t.Fatal("a policy with no valid members produced an ACL")
	}
	// The exclusion ACL is referenced only when it was defined.
	if strings.Count(conf, "fs_excluded\n") != 2 { // ssl_bump splice + http_access allow
		t.Fatalf("fs_excluded referenced %d times", strings.Count(conf, "fs_excluded\n"))
	}
	empty, efiles := squidParams{Dir: "/d", Exclusions: []string{"garbage"}}.render()
	if strings.Contains(empty, "fs_excluded") || efiles["excluded-hosts.acl"] != "" {
		t.Fatal("an exclusion list with nothing valid still produced an ACL")
	}
}

// A client no policy inspects must receive the server's own certificate.
// Squid validates the server certificate whenever it reads it, including a
// peek at step 2 ahead of a splice, and a refused certificate makes it bump
// the client to show an error page under the FlowSight CA. So certificate
// errors may be refused only for inspected clients, and everyone else must
// be allowed through to judge the certificate themselves.
func TestSquidCertErrorsRefusedOnlyForInspectedClients(t *testing.T) {
	for _, peek := range []bool{false, true} {
		p := squidParams{
			Dir: "/d", CAPath: "/ca.pem", PeekServerCert: peek,
			Policies: []squidPolicy{
				{ID: "inspect_mac", Members: []string{"192.168.1.119/32"}, Inspect: true, Monitor: true},
				{ID: "kids", Members: []string{"192.168.1.20"}, Domains: []string{"example.com"}},
			},
		}
		conf, _ := p.render()
		var rules []string
		for _, line := range strings.Split(conf, "\n") {
			if strings.HasPrefix(line, "sslproxy_cert_error ") {
				rules = append(rules, line)
			}
		}
		want := []string{"sslproxy_cert_error deny fs_src_inspect_mac", "sslproxy_cert_error allow all"}
		if strings.Join(rules, "\n") != strings.Join(want, "\n") {
			t.Fatalf("peek=%v: certificate error rules:\n%s\nwant:\n%s", peek, strings.Join(rules, "\n"), strings.Join(want, "\n"))
		}
		// squid rejects a configuration that uses an ACL before defining it.
		if strings.Index(conf, "acl fs_src_inspect_mac ") > strings.Index(conf, "sslproxy_cert_error deny fs_src_inspect_mac") {
			t.Fatalf("peek=%v: the inspected-client ACL is used before it is defined", peek)
		}
		if got := strings.Contains(conf, "ssl_bump peek step2"); got != peek {
			t.Fatalf("peek=%v: ssl_bump peek step2 present=%v", peek, got)
		}
	}

	// Without a CA nothing is bumped by policy, so nothing refuses errors;
	// otherwise squid would bump to show them under the placeholder.
	conf, _ := squidParams{Dir: "/d", PeekServerCert: true,
		Policies: []squidPolicy{{ID: "inspect_mac", Members: []string{"192.168.1.119"}, Inspect: true}}}.render()
	if strings.Contains(conf, "sslproxy_cert_error deny") || !strings.Contains(conf, "sslproxy_cert_error allow all") {
		t.Fatal("certificate errors refused without an inspection CA")
	}
}
