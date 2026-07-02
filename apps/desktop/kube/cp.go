package kube

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type FileEntry struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	Mode   string `json:"mode"`
	Mtime  string `json:"mtime"`
	IsDir  bool   `json:"isDir"`
	IsLink bool   `json:"isLink"`
	Target string `json:"target,omitempty"`
}

const fileListShell = `
DIR=$1
if ls -lA --time-style=+%s -- "$DIR" 2>/dev/null; then exit 0; fi
if ls -lA -- "$DIR" 2>/dev/null; then exit 0; fi
cd -- "$DIR" 2>/dev/null || { echo "__KUBETRAIL_LS_FAILED__ cannot cd $DIR" >&2; exit 1; }
glob() {
  for f in "$@"; do
    [ "$f" = '*' ] && continue
    [ "$f" = '.*' ] && continue
    [ "$f" = '.[!.]*' ] && continue
    [ "$f" = '..?*' ] && continue
    [ "$f" = '.' ] && continue
    [ "$f" = '..' ] && continue
    [ -e "$f" ] || [ -L "$f" ] || continue
    if [ -L "$f" ]; then t=l; elif [ -d "$f" ]; then t=d; elif [ -f "$f" ]; then t=f; else t='?'; fi
    printf '%s|?|0|0|%s\n' "$t" "$f"
  done
}
glob * .[!.]* ..?*
`

func (c *Client) ListPodFiles(ctx context.Context, ns, pod, container, dir string) ([]FileEntry, error) {
	if dir == "" {
		dir = "/"
	}
	out, stderrBytes, err := c.ExecSimple(ctx, ns, pod, container, []string{"sh", "-c", fileListShell, "sh", dir})
	if err != nil {
		return nil, fmt.Errorf("ls %s: %w (stderr: %s)", dir, err, string(stderrBytes))
	}
	if strings.Contains(string(out), "__KUBETRAIL_LS_FAILED__") || strings.Contains(string(stderrBytes), "__KUBETRAIL_LS_FAILED__") {
		return nil, fmt.Errorf("cannot list %s in this container (no ls / cd failed)", dir)
	}
	return parseListOutput(string(out), dir), nil
}

func parseListOutput(out, dir string) []FileEntry {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	entries := []FileEntry{}
	for _, ln := range lines {
		if ln == "" || strings.HasPrefix(ln, "total ") {
			continue
		}
		if len(ln) >= 2 && ln[1] == '|' && (ln[0] == 'd' || ln[0] == 'l' || ln[0] == 'f' || ln[0] == '?') {
			f := strings.SplitN(ln, "|", 5)
			if len(f) < 5 {
				continue
			}
			size, _ := strconv.ParseInt(f[2], 10, 64)
			name := f[4]
			if name == "." || name == ".." {
				continue
			}
			entries = append(entries, FileEntry{
				Name:   name,
				Path:   path.Join(dir, name),
				Size:   size,
				Mode:   f[1],
				Mtime:  f[3],
				IsDir:  f[0] == "d",
				IsLink: f[0] == "l",
			})
			continue
		}
		if len(ln) < 1 || (ln[0] != '-' && ln[0] != 'd' && ln[0] != 'l' && ln[0] != 'b' && ln[0] != 'c' && ln[0] != 's' && ln[0] != 'p') {
			continue
		}
		parts := strings.Fields(ln)
		if len(parts) < 6 {
			continue
		}
		mode := parts[0]
		var size int64
		if len(parts) >= 5 {
			size, _ = strconv.ParseInt(parts[4], 10, 64)
		}
		nameStart := 8
		mtime := ""
		if len(parts) > 5 {
			if epoch, err := strconv.ParseInt(parts[5], 10, 64); err == nil && epoch > 100000 {
				mtime = parts[5]
				nameStart = 6
			} else if len(parts) >= 9 {
				mtime = strings.Join(parts[5:8], " ")
				nameStart = 8
			} else {
				nameStart = len(parts) - 1
			}
		}
		if nameStart >= len(parts) {
			continue
		}
		nameAndLink := strings.Join(parts[nameStart:], " ")
		name := nameAndLink
		target := ""
		isLink := mode[0] == 'l'
		if isLink {
			if idx := strings.Index(nameAndLink, " -> "); idx > 0 {
				name = nameAndLink[:idx]
				target = nameAndLink[idx+4:]
			}
		}
		if name == "." || name == ".." || name == "" {
			continue
		}
		entries = append(entries, FileEntry{
			Name:   name,
			Path:   path.Join(dir, name),
			Size:   size,
			Mode:   mode,
			Mtime:  mtime,
			IsDir:  mode[0] == 'd',
			IsLink: isLink,
			Target: target,
		})
	}
	return entries
}

func (c *Client) ReadPodFile(ctx context.Context, ns, pod, container, remotePath string, maxBytes int64) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = 1 << 20
	}
	cmd := fmt.Sprintf("head -c %d %s", maxBytes, shellQuote(remotePath))
	out, stderr, err := c.ExecSimple(ctx, ns, pod, container, []string{"sh", "-c", cmd})
	if err != nil {
		return nil, fmt.Errorf("read %s: %w (stderr: %s)", remotePath, err, string(stderr))
	}
	return out, nil
}

func (c *Client) DownloadPodFile(ctx context.Context, ns, pod, container, remotePath, localPath string) error {
	// Strategy 1: tar.
	err := c.downloadViaTar(ctx, ns, pod, container, remotePath, localPath)
	if err == nil {
		return nil
	}
	if !isExecNotFound(err) {
		return err
	}

	// Strategy 2: base64 (binary-safe).
	err = c.downloadViaBase64(ctx, ns, pod, container, remotePath, localPath)
	if err == nil {
		return nil
	}
	if !isExecNotFound(err) && !strings.Contains(err.Error(), "base64") {
		return err
	}

	// Strategy 3: plain cat.
	err = c.downloadViaCat(ctx, ns, pod, container, remotePath, localPath)
	if err == nil {
		return nil
	}
	if !isExecNotFound(err) {
		return err
	}

	// Strategy 4: ephemeral debug container.
	return c.downloadViaEphemeral(ctx, ns, pod, container, remotePath, localPath)
}

func (c *Client) downloadViaTar(ctx context.Context, ns, pod, container, remotePath, localPath string) error {
	base := path.Base(remotePath)
	dir := path.Dir(remotePath)
	pr, pw := io.Pipe()
	var stderr bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		err := c.execWithStdin(ctx, ns, pod, container,
			[]string{"tar", "cf", "-", "-C", dir, base},
			nil, pw, &stderr)
		pw.CloseWithError(err)
		errCh <- err
	}()
	if err := untar(pr, localPath); err != nil {
		<-errCh
		return fmt.Errorf("untar: %w (stderr: %s)", err, stderr.String())
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("remote tar: %w (stderr: %s)", err, stderr.String())
	}
	return nil
}

func (c *Client) downloadViaCat(ctx context.Context, ns, pod, container, remotePath, localPath string) error {
	out, stderr, err := c.ExecSimple(ctx, ns, pod, container, []string{"sh", "-c", "cat " + shellQuote(remotePath)})
	if err != nil {
		return fmt.Errorf("download via cat: %w (stderr: %s)", err, string(stderr))
	}
	dest := filepath.Join(localPath, path.Base(remotePath))
	if err := os.MkdirAll(localPath, 0o755); err != nil {
		return err
	}
	return os.WriteFile(dest, out, 0o644)
}

func untar(r io.Reader, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	absDest, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		clean := filepath.Clean(hdr.Name)
		if strings.HasPrefix(clean, "..") || strings.Contains(clean, string(filepath.Separator)+".."+string(filepath.Separator)) {
			return fmt.Errorf("unsafe tar entry: %s", hdr.Name)
		}
		target := filepath.Join(absDest, clean)
		rel, err := filepath.Rel(absDest, target)
		if err != nil || strings.HasPrefix(rel, "..") {
			return fmt.Errorf("path traversal: %s", hdr.Name)
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)|0o700); err != nil {
				return err
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(hdr.Mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			os.Remove(target)
			_ = os.Symlink(hdr.Linkname, target)
		}
	}
}

func (c *Client) UploadPodFile(ctx context.Context, ns, pod, container, localPath, remoteDir string) error {
	// Strategy 1: tar (best — supports dirs, preserves permissions).
	err := c.uploadViaTar(ctx, ns, pod, container, localPath, remoteDir)
	if err == nil {
		return nil
	}
	if !isExecNotFound(err) {
		return err
	}

	info, statErr := os.Stat(localPath)
	if statErr != nil {
		return statErr
	}
	if info.IsDir() {
		// Dirs require tar; try ephemeral container with tar.
		return c.uploadViaEphemeral(ctx, ns, pod, container, localPath, remoteDir)
	}

	// Strategy 2: base64 decode (binary-safe, only needs sh+base64).
	err = c.uploadViaBase64(ctx, ns, pod, container, localPath, remoteDir, info)
	if err == nil {
		return nil
	}
	if !isExecNotFound(err) && !strings.Contains(err.Error(), "base64") {
		return err
	}

	// Strategy 3: plain cat (works if sh exists but base64 doesn't).
	err = c.uploadViaCat(ctx, ns, pod, container, localPath, remoteDir, info)
	if err == nil {
		return nil
	}
	if !isExecNotFound(err) {
		return err
	}

	// Strategy 4: ephemeral debug container (distroless — no sh at all).
	return c.uploadViaEphemeral(ctx, ns, pod, container, localPath, remoteDir)
}

func (c *Client) uploadViaTar(ctx context.Context, ns, pod, container, localPath, remoteDir string) error {
	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		err := tarLocal(localPath, pw)
		pw.Close()
		errCh <- err
	}()
	var stderr bytes.Buffer
	if err := c.execWithStdin(ctx, ns, pod, container,
		[]string{"tar", "xf", "-", "-C", remoteDir},
		pr, nil, &stderr); err != nil {
		<-errCh
		return fmt.Errorf("remote untar: %w (stderr: %s)", err, stderr.String())
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("local tar: %w", err)
	}
	return nil
}

func (c *Client) uploadViaCat(ctx context.Context, ns, pod, container, localPath, remoteDir string, info os.FileInfo) error {
	remotePath := path.Join(remoteDir, info.Name())
	f, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer f.Close()
	var stderr bytes.Buffer
	if err := c.execWithStdin(ctx, ns, pod, container,
		[]string{"sh", "-c", "cat > " + shellQuote(remotePath)},
		f, nil, &stderr); err != nil {
		return fmt.Errorf("upload via cat: %w (stderr: %s)", err, stderr.String())
	}
	return nil
}

func tarLocal(localPath string, w io.Writer) error {
	info, err := os.Stat(localPath)
	if err != nil {
		return err
	}
	tw := tar.NewWriter(w)
	defer tw.Close()
	base := filepath.Base(localPath)
	if !info.IsDir() {
		return addPathToTar(tw, localPath, base, info)
	}
	return filepath.Walk(localPath, func(p string, fi os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(localPath, p)
		if err != nil {
			return err
		}
		name := filepath.ToSlash(filepath.Join(base, rel))
		return addPathToTar(tw, p, name, fi)
	})
}

func addPathToTar(tw *tar.Writer, p, name string, fi os.FileInfo) error {
	var link string
	if fi.Mode()&os.ModeSymlink != 0 {
		var err error
		link, err = os.Readlink(p)
		if err != nil {
			return err
		}
	}
	hdr, err := tar.FileInfoHeader(fi, link)
	if err != nil {
		return err
	}
	hdr.Name = name
	if err := tw.WriteHeader(hdr); err != nil {
		return err
	}
	if fi.Mode().IsRegular() {
		f, err := os.Open(p)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = io.Copy(tw, f)
		return err
	}
	return nil
}

func (c *Client) DeletePodFile(ctx context.Context, ns, pod, container, target string) error {
	_, stderr, err := c.ExecSimple(ctx, ns, pod, container, []string{"sh", "-c", "rm -rf " + shellQuote(target)})
	if err != nil {
		return fmt.Errorf("rm: %w (stderr: %s)", err, string(stderr))
	}
	return nil
}

func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func isExecNotFound(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "executable file not found") ||
		strings.Contains(msg, "not found in $PATH") ||
		strings.Contains(msg, "no such file or directory")
}

// --- Base64 strategies (binary-safe, needs sh + base64) ---

func (c *Client) uploadViaBase64(ctx context.Context, ns, pod, container, localPath, remoteDir string, info os.FileInfo) error {
	data, err := os.ReadFile(localPath)
	if err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	remotePath := path.Join(remoteDir, info.Name())
	cmd := fmt.Sprintf("echo %s | base64 -d > %s", shellQuote(encoded), shellQuote(remotePath))
	// For large files, pass via stdin to avoid arg length limits.
	if len(encoded) > 100000 {
		cmd = "base64 -d > " + shellQuote(remotePath)
		var stderr bytes.Buffer
		if err := c.execWithStdin(ctx, ns, pod, container,
			[]string{"sh", "-c", cmd},
			strings.NewReader(encoded), nil, &stderr); err != nil {
			return fmt.Errorf("upload via base64: %w (stderr: %s)", err, stderr.String())
		}
		return nil
	}
	_, stderr, err := c.ExecSimple(ctx, ns, pod, container, []string{"sh", "-c", cmd})
	if err != nil {
		return fmt.Errorf("upload via base64: %w (stderr: %s)", err, string(stderr))
	}
	return nil
}

func (c *Client) downloadViaBase64(ctx context.Context, ns, pod, container, remotePath, localPath string) error {
	cmd := "base64 " + shellQuote(remotePath)
	out, stderr, err := c.ExecSimple(ctx, ns, pod, container, []string{"sh", "-c", cmd})
	if err != nil {
		return fmt.Errorf("download via base64: %w (stderr: %s)", err, string(stderr))
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(out)))
	if err != nil {
		return fmt.Errorf("base64 decode: %w", err)
	}
	if err := os.MkdirAll(localPath, 0o755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(localPath, path.Base(remotePath)), decoded, 0o644)
}

// --- Ephemeral debug container strategies (for distroless) ---

const ephemeralImage = "docker.io/library/busybox:latest"
const ephemeralPrefix = "kubetrail-cp-"

func (c *Client) ensureEphemeralContainer(ctx context.Context, ns, pod, targetContainer string) (string, error) {
	ecName := ephemeralPrefix + "debug"

	// Check if it already exists and is running.
	p, err := c.Clientset.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
	if err != nil {
		return "", fmt.Errorf("get pod: %w", err)
	}
	for _, ec := range p.Spec.EphemeralContainers {
		if ec.Name == ecName {
			for _, cs := range p.Status.EphemeralContainerStatuses {
				if cs.Name == ecName && cs.State.Running != nil {
					return ecName, nil
				}
			}
			// Exists but not running yet — wait for it.
			return ecName, c.waitForEphemeralRunning(ctx, ns, pod, ecName)
		}
	}

	// Create ephemeral container sharing target's PID namespace.
	ec := corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:    ecName,
			Image:   ephemeralImage,
			Command: []string{"sh", "-c", "sleep 3600"},
			Stdin:   true,
			SecurityContext: &corev1.SecurityContext{
				Capabilities: &corev1.Capabilities{
					Add: []corev1.Capability{"SYS_PTRACE"},
				},
			},
		},
		TargetContainerName: targetContainer,
	}
	p.Spec.EphemeralContainers = append(p.Spec.EphemeralContainers, ec)
	_, err = c.Clientset.CoreV1().Pods(ns).UpdateEphemeralContainers(ctx, pod, p, metav1.UpdateOptions{})
	if err != nil {
		return "", fmt.Errorf("create ephemeral container: %w", err)
	}
	return ecName, c.waitForEphemeralRunning(ctx, ns, pod, ecName)
}

func (c *Client) waitForEphemeralRunning(ctx context.Context, ns, pod, ecName string) error {
	deadline := time.After(60 * time.Second)
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timeout waiting for ephemeral container %s to start", ecName)
		case <-ticker.C:
			p, err := c.Clientset.CoreV1().Pods(ns).Get(ctx, pod, metav1.GetOptions{})
			if err != nil {
				continue
			}
			for _, cs := range p.Status.EphemeralContainerStatuses {
				if cs.Name == ecName && cs.State.Running != nil {
					return nil
				}
			}
		}
	}
}

func (c *Client) uploadViaEphemeral(ctx context.Context, ns, pod, container, localPath, remoteDir string) error {
	ecName, err := c.ensureEphemeralContainer(ctx, ns, pod, container)
	if err != nil {
		return fmt.Errorf("ephemeral container: %w", err)
	}
	// Upload to ephemeral container via tar — busybox has tar.
	// Files land in /proc/1/root/... which is the target container's filesystem.
	targetDir := "/proc/1/root" + remoteDir
	pr, pw := io.Pipe()
	errCh := make(chan error, 1)
	go func() {
		err := tarLocal(localPath, pw)
		pw.Close()
		errCh <- err
	}()
	var stderr bytes.Buffer
	if err := c.execWithStdin(ctx, ns, pod, ecName,
		[]string{"tar", "xf", "-", "-C", targetDir},
		pr, nil, &stderr); err != nil {
		<-errCh
		return fmt.Errorf("ephemeral upload: %w (stderr: %s)", err, stderr.String())
	}
	return <-errCh
}

func (c *Client) downloadViaEphemeral(ctx context.Context, ns, pod, container, remotePath, localPath string) error {
	ecName, err := c.ensureEphemeralContainer(ctx, ns, pod, container)
	if err != nil {
		return fmt.Errorf("ephemeral container: %w", err)
	}
	// Read from target's filesystem via /proc/1/root.
	targetPath := "/proc/1/root" + remotePath
	base := path.Base(targetPath)
	dir := path.Dir(targetPath)
	pr, pw := io.Pipe()
	var stderr bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		err := c.execWithStdin(ctx, ns, pod, ecName,
			[]string{"tar", "cf", "-", "-C", dir, base},
			nil, pw, &stderr)
		pw.CloseWithError(err)
		errCh <- err
	}()
	if err := untar(pr, localPath); err != nil {
		<-errCh
		return fmt.Errorf("ephemeral download untar: %w (stderr: %s)", err, stderr.String())
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("ephemeral download: %w (stderr: %s)", err, stderr.String())
	}
	return nil
}
