package install

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func containerBed(t *testing.T, token string) *applyBed {
	b := newApplyBed(t, "linux", func(m *fakeMachine) {
		debianRoot(m)
		m.files["/.dockerenv"] = ""
		m.files["/proc/1/comm"] = "flowsightd"
		m.uid = 65532
		if token != "" {
			m.env["FLOWSIGHT_API_TOKEN"] = token
		}
	})
	return b
}

func readJSON(t *testing.T, b *applyBed, p string) map[string]any {
	t.Helper()
	doc := map[string]any{}
	if err := json.Unmarshal([]byte(b.read(t, p)), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// The first start of a container writes a configuration that listens on
// the container's interface with a generated token, shown once; no root.
func TestContainerFirstStart(t *testing.T) {
	b := containerBed(t, "")
	p := MakePlan(Detect(b.env), time.Now())
	if p.Service != "container" {
		t.Fatalf("service %q", p.Service)
	}
	r, err := Apply(b.env, p, "test", time.Now(), func(string) {})
	if err != nil {
		t.Fatalf("a container needs no root: %v", err)
	}
	doc := readJSON(t, b, "/etc/flowsight/flowsight.json")
	if doc["bind"] != "0.0.0.0" || len(r.Token) != 32 || doc["api_token"] != r.Token {
		t.Fatalf("config %v, token %q", doc, r.Token)
	}
	if err := ContainerConfig(b.env, "/etc/flowsight/flowsight.json"); err != nil {
		t.Fatal(err)
	}
}

// A token from the environment (a Kubernetes Secret) is used, not echoed,
// and replaces the stored one when the secret is rotated.
func TestContainerTokenFromEnvironment(t *testing.T) {
	b := containerBed(t, "from-the-secret-0123456789abcdef")
	r, err := Apply(b.env, MakePlan(Detect(b.env), time.Now()), "test", time.Now(), func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if r.Token != "" || strings.Contains(r.Summary(), "from-the-secret") {
		t.Fatal("a token from the environment must not be echoed")
	}
	if readJSON(t, b, "/etc/flowsight/flowsight.json")["api_token"] != "from-the-secret-0123456789abcdef" {
		t.Fatal("the environment's token was not used")
	}
	b.m.env["FLOWSIGHT_API_TOKEN"] = "rotated-secret-0123456789abcdef0"
	if err := ContainerConfig(b.env, "/etc/flowsight/flowsight.json"); err != nil {
		t.Fatal(err)
	}
	doc := readJSON(t, b, "/etc/flowsight/flowsight.json")
	if doc["api_token"] != "rotated-secret-0123456789abcdef0" || doc["bind"] != "0.0.0.0" {
		t.Fatalf("rotation: %v", doc)
	}
	st, _ := os.Stat(b.env.path("/etc/flowsight/flowsight.json"))
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("mode after rotation: %v", st.Mode().Perm())
	}
}

// Listening beyond loopback without a token is refused in a container.
func TestContainerRefusesAnOpenBindWithoutToken(t *testing.T) {
	b := containerBed(t, "")
	if err := os.MkdirAll(b.env.path("/etc/flowsight"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b.env.path("/etc/flowsight/flowsight.json"), []byte(`{"bind":"0.0.0.0"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ContainerConfig(b.env, "/etc/flowsight/flowsight.json"); err == nil || !strings.Contains(err.Error(), "no api_token") {
		t.Fatalf("open bind without a token: %v", err)
	}
}

// In the image /etc/flowsight links into the data volume; on a fresh volume
// the target is made before the configuration is written.
func TestPrepareContainerMakesTheLinkedConfigDirectory(t *testing.T) {
	b := containerBed(t, "")
	if err := os.MkdirAll(b.env.path("/var/lib/flowsight"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(b.env.path("/etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../var/lib/flowsight/etc", b.env.path("/etc/flowsight")); err != nil {
		t.Fatal(err)
	}
	if err := PrepareContainer(b.env); err != nil {
		t.Fatal(err)
	}
	if _, err := Apply(b.env, MakePlan(Detect(b.env), time.Now()), "test", time.Now(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(b.env.path("/var/lib/flowsight/etc/flowsight.json")); err != nil {
		t.Fatalf("the configuration is not on the data volume: %v", err)
	}
}

// Named tokens for providers come from the environment, one variable each,
// so a Kubernetes Secret can supply them; they are merged into api_tokens,
// replacing one of the same name and keeping the rest.
func TestContainerNamedTokensFromEnvironment(t *testing.T) {
	b := containerBed(t, "")
	if _, err := Apply(b.env, MakePlan(Detect(b.env), time.Now()), "test", time.Now(), func(string) {}); err != nil {
		t.Fatal(err)
	}
	cfg := "/etc/flowsight/flowsight.json"
	doc := readJSON(t, b, cfg)
	doc["api_tokens"] = []any{map[string]any{"name": "kept", "token": "kept-token"}, map[string]any{"name": "suricata-lab", "token": "old"}}
	out, _ := json.Marshal(doc)
	if err := os.WriteFile(b.env.path(cfg), out, 0o600); err != nil {
		t.Fatal(err)
	}
	b.m.env["FLOWSIGHT_NAMED_TOKEN_SURICATA_LAB"] = "new-lab-token"
	b.m.env["FLOWSIGHT_NAMED_TOKEN_EDGE"] = "edge-token"
	if err := ContainerConfig(b.env, cfg); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, it := range readJSON(t, b, cfg)["api_tokens"].([]any) {
		m := it.(map[string]any)
		got[m["name"].(string)] = m["token"].(string)
	}
	if got["kept"] != "kept-token" || got["suricata-lab"] != "new-lab-token" || got["edge"] != "edge-token" || len(got) != 3 {
		t.Fatalf("api_tokens: %v", got)
	}
}
