package core

import (
	"os"
	"path/filepath"
	"testing"
)

// A configuration file that comes back empty (a backup taken between the
// rename and the data reaching disk) is restored from the previous copy
// kept on every save, and the daemon does not run on defaults.
func TestConfigRecoversFromAnEmptyFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "flowsight.json")
	if err := os.WriteFile(path, []byte(`{"bind":"0.0.0.0","api_token":"abc"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	// A save keeps the previous contents beside the file.
	if err := cfg.SetCore("site_name", "home"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path + ".prev"); err != nil {
		t.Fatalf("no previous copy after a save: %v", err)
	}
	// The file is emptied, as a lost write leaves it.
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2, err := LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg2.Core().Bind != "0.0.0.0" || cfg2.Core().APIToken != "abc" {
		t.Fatalf("not recovered: %+v", cfg2.Core())
	}
	if cfg2.LoadNote == "" {
		t.Fatal("recovery not reported")
	}
	b, _ := os.ReadFile(path)
	if len(b) == 0 {
		t.Fatal("file not rewritten from the previous copy")
	}
	// A file that is merely absent is a fresh install, not a recovery.
	os.Remove(path)
	os.Remove(path + ".prev")
	cfg3, err := LoadConfig(path)
	if err != nil || cfg3.LoadNote != "" {
		t.Fatalf("fresh install: %v %q", err, cfg3.LoadNote)
	}
}
