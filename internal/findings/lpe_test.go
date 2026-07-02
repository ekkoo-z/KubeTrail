package findings

import (
	"strings"
	"testing"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

func TestEvaluateLPESkipsRoot(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 0}},
			{ID: "lpe.kernel", Value: map[string]any{"release": "5.15.0-57-generic"}},
		},
	}
	if got := EvaluateLPE(doc); len(got) != 0 {
		t.Fatalf("expected root target to skip LPE findings, got %#v", got)
	}
}

func TestEvaluateLPEDetectsSudoAndDirtyPipe(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.packages", Value: map[string]any{
				"manager": "dpkg",
				"packages": []map[string]string{
					{"name": "sudo", "version": "1.9.5p1-1"},
				},
			}},
			{ID: "lpe.kernel", Value: map[string]any{"release": "5.15.0-57-generic"}},
		},
	}

	got := EvaluateLPE(doc)
	if !hasFinding(got, "CVE-2021-3156") {
		t.Fatalf("expected sudo finding, got %#v", got)
	}
	if !hasFinding(got, "CVE-2022-0847") {
		t.Fatalf("expected Dirty Pipe finding, got %#v", got)
	}
}

func TestEvaluateLPESuppressesPatchedUbuntuSudo3156Backport(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{
				"release":   "5.4.0-150-generic",
				"osRelease": map[string]any{"ID": "ubuntu", "VERSION_ID": "20.04"},
			}},
			{ID: "lpe.packages", Value: map[string]any{
				"manager": "dpkg",
				"packages": []map[string]string{
					{"name": "sudo", "version": "1.8.31-1ubuntu1.2"},
				},
			}},
		},
	}

	got := EvaluateLPE(doc)
	if hasFinding(got, "CVE-2021-3156") {
		t.Fatalf("did not expect sudo finding for patched Ubuntu focal backport, got %#v", got)
	}
}

func TestEvaluateLPEDetectsNFTablePrereqs(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{"release": "6.1.0-21-amd64"}},
			{ID: "lpe.modules", Value: map[string]any{"present": []string{"nf_tables"}}},
			{ID: "lpe.sysctls", Value: map[string]string{"kernel.unprivileged_userns_clone": "1"}},
		},
	}

	got := EvaluateLPE(doc)
	if !hasFinding(got, "CVE-2024-1086") {
		t.Fatalf("expected nf_tables finding, got %#v", got)
	}
	if finding := findingByTitle(got, "CVE-2024-1086"); finding == nil || finding.Confidence != "signal" {
		t.Fatalf("expected distro-like nf_tables release to remain a signal, got %#v", finding)
	}
}

func TestEvaluateLPESuppressesPatchedNFTableStableBranch(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{"release": "6.6.15"}},
			{ID: "lpe.modules", Value: map[string]any{"present": []string{"nf_tables"}}},
			{ID: "lpe.sysctls", Value: map[string]string{"kernel.unprivileged_userns_clone": "1"}},
		},
	}

	got := EvaluateLPE(doc)
	if hasFinding(got, "CVE-2024-1086") {
		t.Fatalf("did not expect nf_tables finding for patched 6.6.15 stable branch, got %#v", got)
	}
}

func TestEvaluateLPESuppressesDirtyPipeFixedStableBranch(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{"release": "5.15.25"}},
		},
	}

	got := EvaluateLPE(doc)
	if hasFinding(got, "CVE-2022-0847") {
		t.Fatalf("did not expect Dirty Pipe finding for fixed 5.15.25 stable branch, got %#v", got)
	}
}

func TestEvaluateLPEDetectsPackageKit(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.packages", Value: map[string]any{
				"manager": "dpkg",
				"packages": []map[string]string{
					{"name": "packagekit", "version": "1.3.4-1"},
				},
			}},
		},
	}

	got := EvaluateLPE(doc)
	if !hasFinding(got, "CVE-2026-41651") {
		t.Fatalf("expected PackageKit finding, got %#v", got)
	}
	if finding := findingByTitle(got, "CVE-2026-41651"); finding == nil || finding.Confidence != "signal" {
		t.Fatalf("expected PackageKit finding to be a signal, got %#v", finding)
	}
}

func TestEvaluateLPESuppressesPatchedUbuntuPackageKitBackport(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{
				"release":   "6.8.0-60-generic",
				"osRelease": map[string]any{"ID": "ubuntu", "VERSION_ID": "24.04"},
			}},
			{ID: "lpe.packages", Value: map[string]any{
				"manager": "dpkg",
				"packages": []map[string]string{
					{"name": "packagekit", "version": "1.2.8-2ubuntu1.5"},
				},
			}},
		},
	}

	got := EvaluateLPE(doc)
	if hasFinding(got, "CVE-2026-41651") {
		t.Fatalf("did not expect PackageKit finding for patched Ubuntu noble backport, got %#v", got)
	}
}

func TestEvaluateLPEDetectsPwnKitVulnerableUbuntuFocal(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{
				"release":   "5.4.0-150-generic",
				"osRelease": map[string]any{"ID": "ubuntu", "VERSION_ID": "20.04"},
			}},
			{ID: "lpe.packages", Value: map[string]any{
				"manager": "dpkg",
				"packages": []map[string]string{
					{"name": "policykit-1", "version": "0.105-26ubuntu1"},
				},
			}},
			{ID: "lpe.suid_tools", Value: []map[string]any{
				{"name": "pkexec", "setuid": true},
			}},
		},
	}

	got := EvaluateLPE(doc)
	if !hasFinding(got, "CVE-2021-4034") {
		t.Fatalf("expected PwnKit finding for vulnerable Ubuntu focal package, got %#v", got)
	}
	if finding := findingByTitle(got, "CVE-2021-4034"); finding == nil || finding.Confidence != "probable" {
		t.Fatalf("expected usable pkexec finding to be probable, got %#v", finding)
	}
}

func TestEvaluateLPEPwnKitBlockedSUIDTransitionIsOnlySignal(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.process_security", Value: map[string]any{"noNewPrivs": "1"}},
			{ID: "lpe.kernel", Value: map[string]any{
				"release":   "5.4.0-150-generic",
				"osRelease": map[string]any{"ID": "ubuntu", "VERSION_ID": "20.04"},
			}},
			{ID: "lpe.packages", Value: map[string]any{
				"manager": "dpkg",
				"packages": []map[string]string{
					{"name": "policykit-1", "version": "0.105-26ubuntu1"},
				},
			}},
			{ID: "lpe.suid_tools", Value: []map[string]any{
				{"name": "pkexec", "setuid": true, "nosuid": true},
			}},
		},
	}

	got := EvaluateLPE(doc)
	finding := findingByTitle(got, "CVE-2021-4034")
	if finding == nil {
		t.Fatalf("expected PwnKit signal for vulnerable package, got %#v", got)
	}
	if finding.Confidence != "signal" || finding.Severity != "medium" {
		t.Fatalf("expected blocked SUID transition to be medium signal, got %#v", finding)
	}
}

func TestEvaluateLPESuppressesPatchedUbuntuPwnKitBackport(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{
				"release":   "5.4.0-150-generic",
				"osRelease": map[string]any{"ID": "ubuntu", "VERSION_ID": "20.04"},
			}},
			{ID: "lpe.packages", Value: map[string]any{
				"manager": "dpkg",
				"packages": []map[string]string{
					{"name": "policykit-1", "version": "0.105-26ubuntu1.3"},
				},
			}},
			{ID: "lpe.suid_tools", Value: []map[string]any{
				{"name": "pkexec", "setuid": true},
			}},
		},
	}

	got := EvaluateLPE(doc)
	if hasFinding(got, "CVE-2021-4034") {
		t.Fatalf("did not expect PwnKit finding for patched Ubuntu focal backport, got %#v", got)
	}
}

func TestEvaluateLPEDetectsEBPFOnlyWithPrereqs(t *testing.T) {
	baseFacts := []model.Fact{
		{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
		{ID: "lpe.kernel", Value: map[string]any{"release": "4.9.0-3-amd64"}},
		{ID: "lpe.sysctls", Value: map[string]string{"kernel.unprivileged_bpf_disabled": "0"}},
	}
	if got := EvaluateLPE(model.Document{Facts: baseFacts}); hasFinding(got, "CVE-2017-16995") {
		t.Fatalf("did not expect eBPF finding without kernel config, got %#v", got)
	}

	doc := model.Document{
		Facts: append(baseFacts, model.Fact{ID: "lpe.kernel_config", Value: map[string]any{
			"values": map[string]string{"CONFIG_BPF_SYSCALL": "y"},
		}}),
	}
	got := EvaluateLPE(doc)
	if !hasFinding(got, "CVE-2017-16995") {
		t.Fatalf("expected eBPF finding with config and sysctl prerequisites, got %#v", got)
	}
}

func TestEvaluateLPEDetectsCopyFailWithConfig(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{"release": "6.12.10-generic"}},
			{ID: "lpe.kernel_config", Value: map[string]any{
				"values": map[string]string{
					"CONFIG_CRYPTO_AUTHENC":       "m",
					"CONFIG_CRYPTO_USER_API_AEAD": "m",
				},
			}},
		},
	}

	got := EvaluateLPE(doc)
	if !hasFinding(got, "CVE-2026-31431") {
		t.Fatalf("expected Copy Fail finding, got %#v", got)
	}
}

func TestEvaluateLPEDetectsDirtyFragWithReachability(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{"release": "6.12.10-generic"}},
			{ID: "lpe.sysctls", Value: map[string]string{"kernel.unprivileged_userns_clone": "1"}},
			{ID: "lpe.kernel_config", Value: map[string]any{
				"values": map[string]string{
					"CONFIG_INET_ESP": "m",
					"CONFIG_XFRM":     "y",
				},
			}},
		},
	}

	got := EvaluateLPE(doc)
	if !hasFinding(got, "CVE-2026-43284") {
		t.Fatalf("expected Dirty Frag xfrm-ESP finding, got %#v", got)
	}
}

func TestEvaluateScanFilterIncludesLPE(t *testing.T) {
	doc := model.Document{
		Facts: []model.Fact{
			{ID: "identity.current_user", Value: map[string]any{"euid": 1000}},
			{ID: "lpe.kernel", Value: map[string]any{"release": "5.15.0-57-generic"}},
			{ID: "k8s_permissions.high_value_access", Value: []any{
				map[string]any{"id": "pods_exec", "allowed": true},
			}},
		},
	}

	got := Evaluate(doc, []string{"lpe"})
	if len(got) == 0 {
		t.Fatal("expected LPE findings")
	}
	for _, finding := range got {
		if finding.Category != "lpe" {
			t.Fatalf("lpe-only scan returned category %q", finding.Category)
		}
	}
}

func TestParseKernelVersion(t *testing.T) {
	got, ok := parseKernelVersion("5.15.0-57-generic")
	if !ok {
		t.Fatal("expected kernel version")
	}
	if got.major != 5 || got.minor != 15 || got.patch != 0 {
		t.Fatalf("unexpected kernel version: %#v", got)
	}
}

func TestCompareNumericVersionHandlesSudoPatchLevel(t *testing.T) {
	if compareNumericVersion("1.9.5p1-1", "1.9.5p2") >= 0 {
		t.Fatal("expected 1.9.5p1 to be older than 1.9.5p2")
	}
	if compareNumericVersion("1.9.10", "1.9.5p2") <= 0 {
		t.Fatal("expected 1.9.10 to be newer than 1.9.5p2")
	}
}

func hasFinding(findings []Finding, needle string) bool {
	return findingByTitle(findings, needle) != nil
}

func findingByTitle(findings []Finding, needle string) *Finding {
	for _, finding := range findings {
		if strings.Contains(finding.Title, needle) {
			return &finding
		}
	}
	return nil
}
