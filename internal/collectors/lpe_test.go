package collectors

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func TestParseDpkgStatusFindsWantedPackages(t *testing.T) {
	data := `
Package: bash
Status: install ok installed
Version: 5.2.0

Package: sudo
Status: install ok installed
Architecture: amd64
Version: 1.9.5p1-1

Package: policykit-1
Status: hold ok installed
Version: 0.105-26ubuntu1.2

Package: packagekit
Status: deinstall ok config-files
Version: 1.3.4-1
`
	got := parseDpkgStatus(data, map[string]bool{
		"packagekit":  true,
		"sudo":        true,
		"policykit-1": true,
	})
	if len(got) != 2 {
		t.Fatalf("expected 2 packages, got %#v", got)
	}
	if got[0]["name"] != "policykit-1" || got[0]["version"] != "0.105-26ubuntu1.2" {
		t.Fatalf("unexpected first package: %#v", got[0])
	}
	if got[0]["status"] != "hold ok installed" {
		t.Fatalf("expected held package to remain included, got %#v", got[0])
	}
	if got[1]["name"] != "sudo" || got[1]["architecture"] != "amd64" {
		t.Fatalf("unexpected sudo package: %#v", got[1])
	}
}

func TestParseModuleNamesCapsAtMax(t *testing.T) {
	got := parseModuleNames("nf_tables 1 2 - Live 0\novl 1 2 - Live 0\n", 1)
	if len(got) != 1 || got[0] != "nf_tables" {
		t.Fatalf("unexpected modules: %#v", got)
	}
}

func TestParseKernelConfigFindsSelectedValues(t *testing.T) {
	got := parseKernelConfig(`
CONFIG_BPF_SYSCALL=y
# CONFIG_RXRPC is not set
CONFIG_CRYPTO_USER_API_AEAD=m
CONFIG_IGNORED=y
`, map[string]bool{
		"CONFIG_BPF_SYSCALL":          true,
		"CONFIG_CRYPTO_USER_API_AEAD": true,
		"CONFIG_RXRPC":                true,
	})

	if got["CONFIG_BPF_SYSCALL"] != "y" {
		t.Fatalf("expected BPF syscall config, got %#v", got)
	}
	if got["CONFIG_CRYPTO_USER_API_AEAD"] != "m" {
		t.Fatalf("expected AEAD module config, got %#v", got)
	}
	if got["CONFIG_RXRPC"] != "n" {
		t.Fatalf("expected RXRPC disabled config, got %#v", got)
	}
	if _, ok := got["CONFIG_IGNORED"]; ok {
		t.Fatalf("unexpected ignored config in result: %#v", got)
	}
}

func TestCollectLPESUIDToolsDetectsSetuid(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "usr/bin")
	if err := os.MkdirAll(path, 0755); err != nil {
		t.Fatal(err)
	}
	sudo := filepath.Join(path, "sudo")
	if err := os.WriteFile(sudo, []byte("#!/bin/sh\n"), 04755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sudo, 04755); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(sudo)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSetuid == 0 {
		t.Skip("filesystem did not preserve setuid bit")
	}

	got := collectLPESUIDTools(NewContext(modelOptionsWithRoot(root)), []map[string]any{
		{"path": "/", "fsType": "tmpfs", "options": []string{"rw", "nosuid"}},
	})
	if len(got) != 1 {
		t.Fatalf("expected one tool, got %#v", got)
	}
	if got[0]["name"] != "sudo" || got[0]["setuid"] != true {
		t.Fatalf("unexpected tool: %#v", got[0])
	}
	if got[0]["nosuid"] != true {
		t.Fatalf("expected SUID tool mount metadata to record nosuid, got %#v", got[0])
	}
}

func modelOptionsWithRoot(root string) model.Options {
	return model.Options{Root: root}
}
