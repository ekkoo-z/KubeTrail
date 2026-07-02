package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ekkoo-z/KubeTrail/apps/desktop/agentmgr"
)

func TestHasAgentCredentialFromConfigAPIKey(t *testing.T) {
	if !hasAgentCredential(agentmgr.AgentConfig{APIKey: "sk-test"}) {
		t.Fatal("expected config API key to count as an agent credential")
	}
}

func TestHasAgentCredentialFromEnvAuthToken(t *testing.T) {
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "token-test")

	if !hasAgentCredential(agentmgr.AgentConfig{}) {
		t.Fatal("expected ANTHROPIC_AUTH_TOKEN to count as an agent credential")
	}
}

func TestHasAgentCredentialMissing(t *testing.T) {
	t.Setenv("KUBETRAIL_AGENT_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("KUBETRAIL_AGENT_AUTH_TOKEN", "")
	t.Setenv("ANTHROPIC_AUTH_TOKEN", "")

	if hasAgentCredential(agentmgr.AgentConfig{}) {
		t.Fatal("expected no agent credential")
	}
}

func TestHasAgentCredentialCodexOfficialModeAllowsBlank(t *testing.T) {
	if !hasAgentCredential(agentmgr.AgentConfig{Provider: "codex"}) {
		t.Fatal("expected Codex official mode to allow blank API key")
	}
}

func TestHasAgentCredentialClaudeOfficialModeAllowsBlank(t *testing.T) {
	if !hasAgentCredential(agentmgr.AgentConfig{Provider: "claude"}) {
		t.Fatal("expected Claude Code official mode to allow blank API key")
	}
}

func TestClaudeOfficialModeRequiresBlankOverrides(t *testing.T) {
	clearAgentConnectionEnv(t)

	if !isClaudeOfficialMode(agentmgr.AgentConfig{Provider: "claude"}) {
		t.Fatal("expected blank Claude config to use official mode")
	}
	if isClaudeOfficialMode(agentmgr.AgentConfig{Provider: "claude", Model: "claude-sonnet-4-6"}) {
		t.Fatal("expected explicit model to disable official-mode shortcut")
	}

	t.Setenv("ANTHROPIC_API_KEY", "sk-test")
	if isClaudeOfficialMode(agentmgr.AgentConfig{Provider: "claude"}) {
		t.Fatal("expected env API key to disable official-mode shortcut")
	}
}

func TestCodexOfficialModeRequiresBlankOverrides(t *testing.T) {
	clearAgentConnectionEnv(t)

	if !isCodexOfficialMode(agentmgr.AgentConfig{Provider: "codex"}) {
		t.Fatal("expected blank Codex config to use official mode")
	}
	if isCodexOfficialMode(agentmgr.AgentConfig{Provider: "codex", Model: "gpt-5.4"}) {
		t.Fatal("expected explicit model to disable official-mode shortcut")
	}

	t.Setenv("OPENAI_BASE_URL", "https://gateway.example.test")
	if isCodexOfficialMode(agentmgr.AgentConfig{Provider: "codex"}) {
		t.Fatal("expected env base URL to disable official-mode shortcut")
	}
}

func TestTestAgentConnectionClaudeOfficialModeChecksRuntime(t *testing.T) {
	clearAgentConnectionEnv(t)

	_, err := (&App{}).TestAgentConnection(agentmgr.AgentConfig{
		Provider:   "claude",
		ClaudePath: filepath.Join(t.TempDir(), "missing-claude"),
	})
	if err == nil || !strings.Contains(err.Error(), "Claude Code 官方模式不可用") {
		t.Fatalf("expected Claude official mode runtime error, got %v", err)
	}
}

func TestTestAgentConnectionClaudeOfficialModeAcceptsConfiguredRuntime(t *testing.T) {
	clearAgentConnectionEnv(t)

	claudePath := writeExecutable(t, "claude")
	msg, err := (&App{}).TestAgentConnection(agentmgr.AgentConfig{
		Provider:   "claude",
		ClaudePath: claudePath,
	})
	if err != nil {
		t.Fatalf("TestAgentConnection failed: %v", err)
	}
	if !strings.Contains(msg, "Claude Code 官方模式可用") || !strings.Contains(msg, claudePath) {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func TestTestAgentConnectionCodexOfficialModeChecksRuntime(t *testing.T) {
	clearAgentConnectionEnv(t)

	_, err := (&App{}).TestAgentConnection(agentmgr.AgentConfig{
		Provider:  "codex",
		CodexPath: filepath.Join(t.TempDir(), "missing-codex"),
	})
	if err == nil || !strings.Contains(err.Error(), "Codex 官方模式不可用") {
		t.Fatalf("expected Codex official mode runtime error, got %v", err)
	}
}

func TestTestAgentConnectionCodexOfficialModeAcceptsConfiguredRuntime(t *testing.T) {
	clearAgentConnectionEnv(t)

	codexPath := writeExecutable(t, "codex")
	msg, err := (&App{}).TestAgentConnection(agentmgr.AgentConfig{
		Provider:  "codex",
		CodexPath: codexPath,
	})
	if err != nil {
		t.Fatalf("TestAgentConnection failed: %v", err)
	}
	if !strings.Contains(msg, "Codex 官方模式可用") || !strings.Contains(msg, codexPath) {
		t.Fatalf("unexpected message: %q", msg)
	}
}

func clearAgentConnectionEnv(t *testing.T) {
	t.Helper()
	for _, name := range []string{
		"KUBETRAIL_AGENT_API_KEY",
		"KUBETRAIL_AGENT_OPENAI_API_KEY",
		"ANTHROPIC_API_KEY",
		"KUBETRAIL_AGENT_AUTH_TOKEN",
		"ANTHROPIC_AUTH_TOKEN",
		"CODEX_API_KEY",
		"OPENAI_API_KEY",
		"KUBETRAIL_AGENT_BASE_URL",
		"KUBETRAIL_AGENT_OPENAI_BASE_URL",
		"ANTHROPIC_BASE_URL",
		"OPENAI_BASE_URL",
		"KUBETRAIL_AGENT_MODEL",
		"KUBETRAIL_AGENT_HTTPS_PROXY",
		"KUBETRAIL_AGENT_HTTP_PROXY",
		"HTTPS_PROXY",
		"HTTP_PROXY",
	} {
		t.Setenv(name, "")
	}
}

func writeExecutable(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}
