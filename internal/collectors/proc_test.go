package collectors

import (
	"strings"
	"testing"
)

func TestParseCgroupsDetectsV2(t *testing.T) {
	got := parseCgroups("0::/kubepods.slice/pod123/container456\n")
	if len(got) != 1 {
		t.Fatalf("expected one cgroup, got %d", len(got))
	}
	if got[0]["version"] != "v2" {
		t.Fatalf("expected v2, got %#v", got[0])
	}
	if got[0]["path"] != "/kubepods.slice/pod123/container456" {
		t.Fatalf("unexpected path: %#v", got[0])
	}
}

func TestParseMountsUnescapesFields(t *testing.T) {
	got := parseMounts("/dev/sda1 /var/lib/my\\040data ext4 rw,nosuid 0 0\n")
	if len(got) != 1 {
		t.Fatalf("expected one mount, got %d", len(got))
	}
	if got[0]["path"] != "/var/lib/my data" {
		t.Fatalf("path was not unescaped: %#v", got[0])
	}
	options, ok := got[0]["options"].([]string)
	if !ok || len(options) != 2 || options[1] != "nosuid" {
		t.Fatalf("unexpected options: %#v", got[0]["options"])
	}
}

func TestParseMountInfoAndWritableBindMountWithoutNosuid(t *testing.T) {
	data := "40 31 8:1 /var/lib/kubelet/pods/uid/volumes/kubernetes.io~host-path/host /host rw,relatime shared:1 - ext4 /dev/sda1 rw\n"
	mounts := parseMountInfo(data)
	if len(mounts) != 1 {
		t.Fatalf("expected one mountinfo entry, got %d", len(mounts))
	}
	if mounts[0]["root"] != "/var/lib/kubelet/pods/uid/volumes/kubernetes.io~host-path/host" {
		t.Fatalf("unexpected mount root: %#v", mounts[0])
	}
	items := writableBindMountsWithoutNosuid(mounts)
	if len(items) != 1 {
		t.Fatalf("expected writable bind mount without nosuid, got %#v", items)
	}
	if items[0]["path"] != "/host" || items[0]["confidence"] != "high" {
		t.Fatalf("unexpected bind mount item: %#v", items[0])
	}
}

func TestWritableBindMountWithoutNosuidSkipsNosuid(t *testing.T) {
	data := "40 31 8:1 /var/lib/kubelet/pods/uid/volumes/kubernetes.io~host-path/host /host rw,nosuid,relatime - ext4 /dev/sda1 rw\n"
	items := writableBindMountsWithoutNosuid(parseMountInfo(data))
	if len(items) != 0 {
		t.Fatalf("expected nosuid mount to be skipped, got %#v", items)
	}
}

func TestVolumeKindDoesNotTreatProcScsiAsCSI(t *testing.T) {
	if got := volumeKind("/proc/scsi", "tmpfs"); got != "" {
		t.Fatalf("expected /proc/scsi not to be CSI, got %q", got)
	}
}

func TestVolumeKindDetectsKubernetesCSI(t *testing.T) {
	got := volumeKind("/var/lib/kubelet/pods/uid/volumes/kubernetes.io~csi/pvc/mount", "tmpfs")
	if got != "csi" {
		t.Fatalf("expected csi, got %q", got)
	}
}

func TestProcessCmdlineFieldsTruncatesLongCommandButKeepsSignals(t *testing.T) {
	cmdline := "java -classpath " + strings.Repeat("/very/long/classpath:", 80) + " -Doss.access.key=secret-value"
	got := processCmdlineFields(cmdline)

	if got["cmdlineTruncated"] != true {
		t.Fatalf("expected long cmdline to be truncated: %#v", got)
	}
	if got["cmdlineLength"] != len(cmdline) {
		t.Fatalf("expected original length, got %#v", got["cmdlineLength"])
	}
	if got["cmdlineSha256"] == "" {
		t.Fatalf("expected sha256 for truncated cmdline")
	}
	preview, _ := got["cmdline"].(string)
	if len(preview) >= len(cmdline) {
		t.Fatalf("cmdline preview was not shorter than original")
	}
	matches, _ := got["secretLikeArgs"].([]string)
	if !stringSliceContains(matches, "oss.access.key") {
		t.Fatalf("expected secret-like arg key, got %#v", matches)
	}
	indicators, _ := got["indicators"].([]string)
	if !stringSliceContains(indicators, "java") || !stringSliceContains(indicators, "classpath") {
		t.Fatalf("expected java/classpath indicators, got %#v", indicators)
	}
}

func stringSliceContains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
