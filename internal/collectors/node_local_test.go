package collectors

import "testing"

func TestSummarizeCPUInfoOmitsRawAndKeepsUsefulSignals(t *testing.T) {
	got := summarizeCPUInfo("processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Test CPU\nflags\t\t: fpu vmx smep smap hypervisor\n\nprocessor\t: 1\n")

	if got["processorCount"] != 2 {
		t.Fatalf("expected processorCount=2, got %#v", got["processorCount"])
	}
	if _, ok := got["raw"]; ok {
		t.Fatalf("cpu summary should not include raw cpuinfo: %#v", got)
	}
	if got["rawBytes"] == 0 || got["rawSha256"] == "" {
		t.Fatalf("expected raw size/hash metadata: %#v", got)
	}
	flags, _ := got["flagsOfInterest"].([]string)
	for _, flag := range []string{"hypervisor", "smap", "smep", "vmx"} {
		if !stringSliceContains(flags, flag) {
			t.Fatalf("expected flag %s in %#v", flag, flags)
		}
	}
}
