package collectors

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ekkoo-z/KubeTrail/internal/model"
)

const (
	credentialSweepMaxFiles     = 256
	credentialSweepMaxReadBytes = 128 * 1024
	credentialSweepMaxFileSize  = 2 * 1024 * 1024
)

func collectCredentialSweep(ctx context.Context, cctx *Context) ([]model.Fact, []model.ErrorEntry) {
	patterns := credentialPatterns(cctx)
	paths, errs := expandCredentialPatterns(cctx, patterns)
	var findings []map[string]any

	for _, path := range paths {
		select {
		case <-ctx.Done():
			errs = append(errs, errEntry("credential sweep", ctx.Err()))
			return []model.Fact{fact("credential_sweep.files", "credentials", "filesystem", true, findings)}, errs
		default:
		}
		if len(findings) >= credentialSweepMaxFiles {
			break
		}
		item, err := readCredentialCandidate(cctx, path)
		if err != nil {
			errs = append(errs, errEntry(path, err))
			continue
		}
		if item != nil {
			findings = append(findings, item)
		}
	}

	return []model.Fact{
		fact("credential_sweep.files", "credentials", "filesystem", true, map[string]any{
			"enabled":      true,
			"patterns":     patterns,
			"files":        findings,
			"maxFiles":     credentialSweepMaxFiles,
			"maxReadBytes": credentialSweepMaxReadBytes,
			"maxFileSize":  credentialSweepMaxFileSize,
		}),
	}, errs
}

func credentialPatterns(cctx *Context) []string {
	patterns := []string{
		"/root/.kube/config",
		"/home/*/.kube/config",
		"/.kube/config",
		"/etc/kubernetes/*.conf",
		"/etc/rancher/k3s/k3s.yaml",
		"/run/secrets/kubernetes.io/serviceaccount/token",
		"/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		"/run/secrets/kubernetes.io/serviceaccount/namespace",
		"/var/run/secrets/kubernetes.io/serviceaccount/token",
		"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
		"/var/run/secrets/kubernetes.io/serviceaccount/namespace",
		"/var/run/secrets/eks.amazonaws.com/serviceaccount/token",
		"/var/run/secrets/azure/tokens/azure-identity-token",
		"/var/run/secrets/tokens/*",
		"/root/.aws/credentials",
		"/root/.aws/config",
		"/home/*/.aws/credentials",
		"/home/*/.aws/config",
		"/root/.azure/accessTokens.json",
		"/root/.azure/azureProfile.json",
		"/home/*/.azure/accessTokens.json",
		"/home/*/.azure/azureProfile.json",
		"/root/.config/gcloud/application_default_credentials.json",
		"/home/*/.config/gcloud/application_default_credentials.json",
		"/root/.docker/config.json",
		"/home/*/.docker/config.json",
		"/.dockercfg",
		"/kaniko/.docker/config.json",
		"/tekton/home/.docker/config.json",
		"/tekton/creds-secrets/*",
		"/tekton/creds/*",
		"/workspace/.docker/config.json",
		"/var/lib/kubelet/kubeconfig",
		"/etc/ssl/private/*",
	}

	for _, key := range []string{
		"KUBECONFIG",
		"AWS_SHARED_CREDENTIALS_FILE",
		"AWS_CONFIG_FILE",
		"GOOGLE_APPLICATION_CREDENTIALS",
		"AZURE_FEDERATED_TOKEN_FILE",
		"DOCKER_CONFIG",
		"NPM_CONFIG_USERCONFIG",
		"PIP_CONFIG_FILE",
		"NETRC",
	} {
		value := cctx.Env[key]
		if value == "" {
			continue
		}
		for _, part := range strings.Split(value, string(os.PathListSeparator)) {
			if part == "" {
				continue
			}
			if key == "DOCKER_CONFIG" {
				patterns = append(patterns, filepath.Join(part, "config.json"))
				continue
			}
			patterns = append(patterns, part)
		}
	}

	return uniqueStrings(patterns)
}

func expandCredentialPatterns(cctx *Context, patterns []string) ([]string, []model.ErrorEntry) {
	seen := map[string]bool{}
	var paths []string
	var errs []model.ErrorEntry
	for _, pattern := range patterns {
		rooted := cctx.RootPath(pattern)
		matches, err := filepath.Glob(rooted)
		if err != nil {
			errs = append(errs, errEntry(pattern, err))
			continue
		}
		if len(matches) == 0 && !strings.ContainsAny(pattern, "*?[") {
			matches = []string{rooted}
		}
		for _, match := range matches {
			unrooted := unrootPath(cctx, match)
			if seen[unrooted] {
				continue
			}
			seen[unrooted] = true
			paths = append(paths, unrooted)
		}
	}
	sort.Strings(paths)
	return paths, errs
}

func readCredentialCandidate(cctx *Context, path string) (map[string]any, error) {
	rooted := cctx.RootPath(path)
	info, err := os.Lstat(rooted)
	if err != nil {
		return nil, nil
	}
	if info.IsDir() {
		return nil, nil
	}

	item := map[string]any{
		"path":    path,
		"mode":    info.Mode().String(),
		"size":    info.Size(),
		"modTime": info.ModTime().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if info.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(rooted)
		if err == nil {
			item["symlinkTarget"] = target
		}
	}
	if info.Size() > credentialSweepMaxFileSize {
		item["skipped"] = true
		item["reason"] = "file too large"
		return item, nil
	}

	data, err := os.ReadFile(rooted)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	item["sha256"] = hex.EncodeToString(sum[:])
	item["bytesRead"] = len(data)
	item["truncated"] = false
	if len(data) > credentialSweepMaxReadBytes {
		data = data[:credentialSweepMaxReadBytes]
		item["bytesRead"] = len(data)
		item["truncated"] = true
	}
	item["content"] = string(data)
	return item, nil
}

func unrootPath(cctx *Context, rooted string) string {
	root := cctx.Options.Root
	if root == "" || root == "/" {
		if strings.HasPrefix(rooted, "/") {
			return rooted
		}
		return "/" + rooted
	}
	rel, err := filepath.Rel(root, rooted)
	if err != nil || strings.HasPrefix(rel, "..") {
		return rooted
	}
	return "/" + filepath.ToSlash(rel)
}
