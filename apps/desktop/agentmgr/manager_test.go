package agentmgr

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestAgentEnvPreservesAmbientCredentialWhenConfigEmpty(t *testing.T) {
	env := agentEnv([]string{"KUBETRAIL_AGENT_API_KEY=from-env"}, AgentConfig{})

	if got := envValue(env, "KUBETRAIL_AGENT_API_KEY"); got != "from-env" {
		t.Fatalf("expected ambient API key to be preserved, got %q", got)
	}
}

func TestAgentEnvConfigOverridesAmbientCredential(t *testing.T) {
	env := agentEnv([]string{"KUBETRAIL_AGENT_API_KEY=from-env"}, AgentConfig{
		APIKey: "from-config",
	})

	if got := envValue(env, "KUBETRAIL_AGENT_API_KEY"); got != "from-config" {
		t.Fatalf("expected config API key to override ambient env, got %q", got)
	}
}

func TestAgentEnvConfigSetsClaudePath(t *testing.T) {
	env := agentEnv([]string{"KUBETRAIL_AGENT_PATH_TO_CLAUDE=/env/claude"}, AgentConfig{
		ClaudePath: "/config/claude",
	})

	if got := envValue(env, "KUBETRAIL_AGENT_PATH_TO_CLAUDE"); got != "/config/claude" {
		t.Fatalf("expected config Claude path to override ambient env, got %q", got)
	}
}

func TestAgentEnvSetsDefaultRuntimeDir(t *testing.T) {
	env := agentEnv(nil, AgentConfig{})

	got := envValue(env, "KUBETRAIL_AGENT_RUNTIME_DIR")
	if got == "" {
		t.Fatal("expected KUBETRAIL_AGENT_RUNTIME_DIR")
	}
	if filepath.Base(got) != "runtime" {
		t.Fatalf("expected runtime leaf directory, got %q", got)
	}
}

func TestAgentEnvPreservesConfiguredRuntimeDir(t *testing.T) {
	env := agentEnv([]string{"KUBETRAIL_AGENT_RUNTIME_DIR=/tmp/kubetrail-runtime"}, AgentConfig{})

	if got := envValue(env, "KUBETRAIL_AGENT_RUNTIME_DIR"); got != "/tmp/kubetrail-runtime" {
		t.Fatalf("expected configured runtime dir to be preserved, got %q", got)
	}
}

func TestMergeEnvLetsLoginShellOverridePath(t *testing.T) {
	env := mergeEnv([]string{"PATH=/usr/bin:/bin", "HOME=/tmp/base"}, []string{"PATH=/custom/bin:/usr/bin"})

	if got := envValue(env, "PATH"); got != "/custom/bin:/usr/bin" {
		t.Fatalf("expected login shell PATH to win, got %q", got)
	}
	if got := envValue(env, "HOME"); got != "/tmp/base" {
		t.Fatalf("expected base HOME to be preserved, got %q", got)
	}
}

func TestAgentEnvEncodesMCPServers(t *testing.T) {
	env := agentEnv(nil, AgentConfig{
		MCPServers: []MCPServerConfig{
			{
				Name:       "filesystem",
				Type:       "stdio",
				Command:    "npx",
				Args:       []string{"-y", "@modelcontextprotocol/server-filesystem", "/tmp"},
				Env:        map[string]string{"NODE_ENV": "production"},
				Timeout:    5000,
				AlwaysLoad: true,
			},
			{
				Name:    "remote",
				Type:    "http",
				URL:     "https://mcp.example.test/mcp",
				Headers: map[string]string{"Authorization": "Bearer token"},
			},
			{
				Name:    "../bad",
				Type:    "stdio",
				Command: "bad",
			},
		},
	})

	raw := envValue(env, "KUBETRAIL_AGENT_MCP_SERVERS")
	if raw == "" {
		t.Fatal("expected KUBETRAIL_AGENT_MCP_SERVERS")
	}
	var servers map[string]map[string]any
	if err := json.Unmarshal([]byte(raw), &servers); err != nil {
		t.Fatalf("invalid MCP JSON: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 valid MCP servers, got %#v", servers)
	}
	if servers["filesystem"]["command"] != "npx" {
		t.Fatalf("unexpected stdio server: %#v", servers["filesystem"])
	}
	if servers["remote"]["url"] != "https://mcp.example.test/mcp" {
		t.Fatalf("unexpected remote server: %#v", servers["remote"])
	}
}

func TestFindAgentDirFromRepoRoot(t *testing.T) {
	root := t.TempDir()
	agentDir := filepath.Join(root, "apps", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if got := findAgentDir(root); got != agentDir {
		t.Fatalf("expected %q, got %q", agentDir, got)
	}
}

func TestFindAgentDirFromDesktopDir(t *testing.T) {
	root := t.TempDir()
	desktopDir := filepath.Join(root, "apps", "desktop")
	agentDir := filepath.Join(root, "apps", "agent")
	if err := os.MkdirAll(desktopDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}

	if got := findAgentDir(desktopDir); got != agentDir {
		t.Fatalf("expected %q, got %q", agentDir, got)
	}
}

func TestResolveClaudeFindsExecutableOnPath(t *testing.T) {
	dir := t.TempDir()
	binName := "claude"
	if runtime.GOOS == "windows" {
		binName = "claude.exe"
	}
	claudePath := filepath.Join(dir, binName)
	if err := os.WriteFile(claudePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	got, source, err := resolveClaudeForEnv(os.Environ())
	if err != nil {
		t.Fatalf("resolveClaudeForEnv failed: %v", err)
	}
	if got != claudePath {
		t.Fatalf("expected %q, got %q", claudePath, got)
	}
	if source != "PATH" {
		t.Fatalf("expected PATH source, got %q", source)
	}
}

func TestResolveClaudeUsesConfiguredPath(t *testing.T) {
	dir := t.TempDir()
	claudePath := filepath.Join(dir, "custom-claude")
	if err := os.WriteFile(claudePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, source, err := resolveClaudeForEnv([]string{"KUBETRAIL_AGENT_PATH_TO_CLAUDE=" + claudePath})
	if err != nil {
		t.Fatalf("resolveClaudeForEnv failed: %v", err)
	}
	if got != claudePath {
		t.Fatalf("expected %q, got %q", claudePath, got)
	}
	if source != "configured" {
		t.Fatalf("expected configured source, got %q", source)
	}
}

func TestResolveClaudeConfiguredCommandUsesPath(t *testing.T) {
	dir := t.TempDir()
	claudePath := filepath.Join(dir, "claude")
	if runtime.GOOS == "windows" {
		claudePath = filepath.Join(dir, "claude.exe")
	}
	if err := os.WriteFile(claudePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	got, source, err := resolveClaudeForEnv([]string{"KUBETRAIL_AGENT_PATH_TO_CLAUDE=claude"})
	if err != nil {
		t.Fatalf("resolveClaudeForEnv failed: %v", err)
	}
	if got != claudePath {
		t.Fatalf("expected %q, got %q", claudePath, got)
	}
	if source != "configured" {
		t.Fatalf("expected configured source, got %q", source)
	}
}

func TestResolveCodexConfiguredCommandUsesProvidedEnvPath(t *testing.T) {
	dir := t.TempDir()
	codexPath := filepath.Join(dir, "codex")
	if runtime.GOOS == "windows" {
		codexPath = filepath.Join(dir, "codex.exe")
	}
	if err := os.WriteFile(codexPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, source, err := resolveCodexForEnv([]string{
		"PATH=" + dir,
		"KUBETRAIL_AGENT_PATH_TO_CODEX=codex",
	})
	if err != nil {
		t.Fatalf("resolveCodexForEnv failed: %v", err)
	}
	if got != codexPath {
		t.Fatalf("expected %q, got %q", codexPath, got)
	}
	if source != "configured" {
		t.Fatalf("expected configured source, got %q", source)
	}
}

func TestEnsureCodexVendorPathAddsNpmVendorPath(t *testing.T) {
	root := t.TempDir()
	wrapper := filepath.Join(root, "bin", "codex.js")
	if err := os.MkdirAll(filepath.Dir(wrapper), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(wrapper, []byte("#!/usr/bin/env node\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	vendorPath := filepath.Join(root, "node_modules", "@openai", "codex-darwin-arm64", "vendor", "aarch64-apple-darwin", "codex-path")
	if err := os.MkdirAll(vendorPath, 0o755); err != nil {
		t.Fatal(err)
	}

	env := ensureCodexVendorPath([]string{"PATH=/usr/bin:/bin"}, wrapper)
	if !pathListContains(envValue(env, "PATH"), vendorPath) {
		t.Fatalf("expected PATH to include %q, got %q", vendorPath, envValue(env, "PATH"))
	}
}

func TestEnsureCodexVendorPathDoesNotDuplicatePath(t *testing.T) {
	targetRoot := filepath.Join(t.TempDir(), "vendor", "aarch64-apple-darwin")
	codexPath := filepath.Join(targetRoot, "bin", "codex")
	vendorPath := filepath.Join(targetRoot, "codex-path")
	if err := os.MkdirAll(filepath.Dir(codexPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(vendorPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(codexPath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	env := ensureCodexVendorPath([]string{"PATH=/usr/bin:" + vendorPath}, codexPath)

	count := 0
	for _, part := range filepath.SplitList(envValue(env, "PATH")) {
		if normalizeExecutablePath(part) == normalizeExecutablePath(vendorPath) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected vendor path once, got %d in %q", count, envValue(env, "PATH"))
	}
}

func TestResolveNodeUsesProvidedEnvPath(t *testing.T) {
	dir := t.TempDir()
	nodePath := filepath.Join(dir, "node")
	if runtime.GOOS == "windows" {
		nodePath = filepath.Join(dir, "node.exe")
	}
	if err := os.WriteFile(nodePath, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := resolveNodeForEnv([]string{"PATH=" + dir})
	if err != nil {
		t.Fatalf("resolveNodeForEnv failed: %v", err)
	}
	if got != nodePath {
		t.Fatalf("expected %q, got %q", nodePath, got)
	}
}

func pathListContains(pathValue, want string) bool {
	want = normalizeExecutablePath(want)
	for _, part := range filepath.SplitList(pathValue) {
		if normalizeExecutablePath(part) == want {
			return true
		}
	}
	return false
}

func TestEnvValueFromList(t *testing.T) {
	env := []string{"A=1", "KUBETRAIL_AGENT_PATH_TO_CLAUDE=/custom/claude"}
	if got := envValueFromList(env, "KUBETRAIL_AGENT_PATH_TO_CLAUDE"); got != "/custom/claude" {
		t.Fatalf("unexpected env value: %q", got)
	}
}

func TestSendRequestSerializesMaterializeInputPath(t *testing.T) {
	writer := &recordingWriteCloser{}
	m := NewManager("")
	m.ready = true
	m.stdin = writer

	ch, err := m.sendRequest("materialize", map[string]string{
		"inputPath": "/tmp/input.json",
		"ref":       "sensitive://fact",
	})
	if err != nil {
		t.Fatalf("sendRequest failed: %v", err)
	}
	defer closePendingForTest(m)
	_ = ch

	var req pipeRequest
	if err := json.Unmarshal(writer.bytes, &req); err != nil {
		t.Fatalf("invalid request JSON: %v", err)
	}
	if req.Method != "materialize" {
		t.Fatalf("unexpected method: %q", req.Method)
	}
	params, ok := req.Params.(map[string]any)
	if !ok {
		t.Fatalf("unexpected params: %#v", req.Params)
	}
	if params["inputPath"] != "/tmp/input.json" {
		t.Fatalf("unexpected inputPath: %#v", params["inputPath"])
	}
	if params["ref"] != "sensitive://fact" {
		t.Fatalf("unexpected ref: %#v", params["ref"])
	}
}

func TestChatWithRequestIDForksResumedSession(t *testing.T) {
	writer := &recordingWriteCloser{}
	m := NewManager("")
	m.ready = true
	m.stdin = writer

	out, err := m.ChatWithRequestID(context.Background(), "/tmp/input.json", "hi", "resume-session", "req-1")
	if err != nil {
		t.Fatalf("ChatWithRequestID failed: %v", err)
	}
	defer closePendingForTest(m)
	_ = out

	var req pipeRequest
	if err := json.Unmarshal(writer.bytes, &req); err != nil {
		t.Fatalf("invalid request JSON: %v", err)
	}
	if req.Method != "chat" {
		t.Fatalf("unexpected method: %q", req.Method)
	}
	params, ok := req.Params.(map[string]any)
	if !ok {
		t.Fatalf("unexpected params: %#v", req.Params)
	}
	if params["sessionId"] != "resume-session" {
		t.Fatalf("unexpected sessionId: %#v", params["sessionId"])
	}
	if params["forkSession"] != true {
		t.Fatalf("expected forkSession=true, got %#v", params["forkSession"])
	}
}

func TestSendRequestReturnsNotReadyWhenStdinMissing(t *testing.T) {
	m := NewManager("")
	m.ready = true

	if _, err := m.sendRequest("chat", map[string]string{"message": "hi"}); err == nil {
		t.Fatal("expected error when stdin is missing")
	}
}

func TestSkillCRUD(t *testing.T) {
	root := t.TempDir()
	agentDir := filepath.Join(root, "apps", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := NewManager(root)

	saved, err := m.SaveSkill(SkillUpsertRequest{
		Name:    "custom-rbac-review",
		Content: "# Custom RBAC Review\n\nUse only collected facts.",
	})
	if err != nil {
		t.Fatalf("SaveSkill failed: %v", err)
	}
	if saved.Name != "custom-rbac-review" {
		t.Fatalf("unexpected skill name: %q", saved.Name)
	}

	list, err := m.ListSkills()
	if err != nil {
		t.Fatalf("ListSkills failed: %v", err)
	}
	if len(list) != 1 || list[0].Name != "custom-rbac-review" || list[0].Summary != "Custom RBAC Review" {
		t.Fatalf("unexpected skills list: %#v", list)
	}

	loaded, err := m.GetSkill("custom-rbac-review")
	if err != nil {
		t.Fatalf("GetSkill failed: %v", err)
	}
	if loaded.Content != "# Custom RBAC Review\n\nUse only collected facts." {
		t.Fatalf("unexpected content: %q", loaded.Content)
	}

	if err := m.DeleteSkill("custom-rbac-review"); err != nil {
		t.Fatalf("DeleteSkill failed: %v", err)
	}
	list, err = m.ListSkills()
	if err != nil {
		t.Fatalf("ListSkills after delete failed: %v", err)
	}
	if len(list) != 0 {
		t.Fatalf("expected no skills, got %#v", list)
	}
}

func TestSkillNameRejectsPathTraversal(t *testing.T) {
	root := t.TempDir()
	agentDir := filepath.Join(root, "apps", "agent")
	if err := os.MkdirAll(agentDir, 0o755); err != nil {
		t.Fatal(err)
	}
	m := NewManager(root)

	badNames := []string{
		"../escape",
		"..",
		".hidden",
		"nested/skill",
		`nested\skill`,
		"name with spaces",
	}
	for _, name := range badNames {
		if _, err := m.SaveSkill(SkillUpsertRequest{Name: name, Content: "# Bad"}); err == nil {
			t.Fatalf("expected SaveSkill to reject %q", name)
		}
	}
}

func envValue(env []string, key string) string {
	prefix := key + "="
	for _, item := range env {
		if len(item) >= len(prefix) && item[:len(prefix)] == prefix {
			return item[len(prefix):]
		}
	}
	return ""
}

type recordingWriteCloser struct {
	bytes []byte
}

func (w *recordingWriteCloser) Write(p []byte) (int, error) {
	w.bytes = append(w.bytes, p...)
	return len(p), nil
}

func (w *recordingWriteCloser) Close() error {
	return nil
}

func closePendingForTest(m *Manager) {
	m.pendingMu.Lock()
	defer m.pendingMu.Unlock()
	for id, ch := range m.pending {
		close(ch)
		delete(m.pending, id)
	}
}
