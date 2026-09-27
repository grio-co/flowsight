package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// PrepareContainer makes sure the configuration directory can be written.
// In the image /etc/flowsight is a link into the data volume
// (/var/lib/flowsight/etc), so everything that must persist lives on one
// volume; on a fresh volume the link's target does not exist yet.
func PrepareContainer(e Env) error {
	link := e.path("/etc/flowsight")
	st, err := os.Lstat(link)
	if err != nil || st.Mode()&os.ModeSymlink == 0 {
		return nil // a directory (or absent): nothing to prepare
	}
	target, err := os.Readlink(link)
	if err != nil {
		return err
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(link), target)
	} else {
		target = e.path(target)
	}
	return os.MkdirAll(target, 0o750)
}

// ContainerConfig settles the configuration of a container after the
// installer has run. FLOWSIGHT_API_TOKEN, when set (from a Kubernetes
// Secret, say), is the token: it is written into the configuration at
// every start, so rotating the secret and restarting the pod is enough. A
// configuration that listens beyond loopback without a token is refused,
// since in a container that is everyone who can reach the port.
func ContainerConfig(e Env, path string) error {
	full := e.path(path)
	b, err := os.ReadFile(full)
	if err != nil {
		return err
	}
	doc := map[string]any{}
	if err := json.Unmarshal(b, &doc); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if e.Getenv != nil {
		if tok := e.Getenv("FLOWSIGHT_API_TOKEN"); tok != "" && doc["api_token"] != tok {
			doc["api_token"] = tok
			out, _ := json.MarshalIndent(doc, "", "  ")
			tmp := full + ".tmp"
			if err := os.WriteFile(tmp, append(out, '\n'), 0o600); err != nil {
				return err
			}
			if err := os.Rename(tmp, full); err != nil {
				return err
			}
		}
	}
	bind, _ := doc["bind"].(string)
	tok, _ := doc["api_token"].(string)
	if bind != "" && bind != "127.0.0.1" && bind != "::1" && bind != "localhost" && tok == "" {
		return errors.New("the configuration listens on " + bind + " with no api_token; set FLOWSIGHT_API_TOKEN or api_token in " + path)
	}
	return nil
}

// Probe asks the daemon on loopback whether it answers, with the token from
// its configuration. It is the image's health check and the Kubernetes
// probes: it says whether the daemon is up, not whether every module is.
func Probe(e Env, path string) error {
	var cfg struct {
		Port     int    `json:"port"`
		APIToken string `json:"api_token"`
	}
	b, _ := os.ReadFile(e.path(path))
	_ = json.Unmarshal(b, &cfg)
	if cfg.Port == 0 {
		cfg.Port = 8080
	}
	get := e.Get
	if get == nil {
		get = httpGet
	}
	hdr := map[string]string{"X-Requested-With": "Flowsight"}
	if cfg.APIToken != "" {
		hdr["X-Flowsight-Token"] = cfg.APIToken
	}
	code, _, err := get(fmt.Sprintf("http://127.0.0.1:%d/api/system/health", cfg.Port), hdr)
	if err != nil {
		return err
	}
	if code != 200 {
		return fmt.Errorf("health answered %d", code)
	}
	return nil
}
