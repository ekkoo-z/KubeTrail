package agentmgr

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type AgentConfig struct {
	Provider         string                         `json:"provider,omitempty"`
	APIKey           string                         `json:"apiKey"`
	BaseURL          string                         `json:"baseUrl,omitempty"`
	Model            string                         `json:"model,omitempty"`
	AllowMaterialize bool                           `json:"allowMaterialize"`
	Proxy            string                         `json:"proxy,omitempty"`
	ClaudePath       string                         `json:"claudePath,omitempty"`
	CodexPath        string                         `json:"codexPath,omitempty"`
	CustomEnv        map[string]string              `json:"customEnv,omitempty"`
	MCPServers       []MCPServerConfig              `json:"mcpServers,omitempty"`
	ProviderConfigs  map[string]AgentProviderConfig `json:"providerConfigs,omitempty"`
}

type AgentProviderConfig struct {
	APIKey           string            `json:"apiKey,omitempty"`
	BaseURL          string            `json:"baseUrl,omitempty"`
	Model            string            `json:"model,omitempty"`
	AllowMaterialize bool              `json:"allowMaterialize"`
	Proxy            string            `json:"proxy,omitempty"`
	CustomEnv        map[string]string `json:"customEnv,omitempty"`
	MCPServers       []MCPServerConfig `json:"mcpServers,omitempty"`
}

type MCPServerConfig struct {
	Name       string            `json:"name"`
	Type       string            `json:"type"`
	Command    string            `json:"command,omitempty"`
	Args       []string          `json:"args,omitempty"`
	URL        string            `json:"url,omitempty"`
	Env        map[string]string `json:"env,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	Timeout    int               `json:"timeout,omitempty"`
	AlwaysLoad bool              `json:"alwaysLoad,omitempty"`
}

type AgentStatus struct {
	Running bool   `json:"running"`
	Ready   bool   `json:"ready"`
	PID     int    `json:"pid"`
	Error   string `json:"error,omitempty"`
}

type AgentRuntimeInfo struct {
	NodePath        string `json:"nodePath,omitempty"`
	NodeError       string `json:"nodeError,omitempty"`
	ClaudePath      string `json:"claudePath,omitempty"`
	ClaudeSource    string `json:"claudeSource,omitempty"`
	ClaudeAvailable bool   `json:"claudeAvailable"`
	ClaudeError     string `json:"claudeError,omitempty"`
	CodexPath       string `json:"codexPath,omitempty"`
	CodexSource     string `json:"codexSource,omitempty"`
	CodexAvailable  bool   `json:"codexAvailable"`
	CodexError      string `json:"codexError,omitempty"`
}

type SkillInfo struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Summary    string `json:"summary,omitempty"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modifiedAt,omitempty"`
}

type AgentSkill struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Content    string `json:"content"`
	Size       int64  `json:"size"`
	ModifiedAt string `json:"modifiedAt,omitempty"`
}

type SkillUpsertRequest struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type pipeRequest struct {
	ID     string `json:"id"`
	Method string `json:"method"`
	Params any    `json:"params,omitempty"`
}

type pipeResponse struct {
	ID    string          `json:"id"`
	Type  string          `json:"type"`
	Data  json.RawMessage `json:"data,omitempty"`
	Error string          `json:"error,omitempty"`
}

type Manager struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	stdin   io.WriteCloser
	ready   bool
	config  AgentConfig
	rootDir string
	logBuf  []string
	cancel  context.CancelFunc
	// generation invalidates stale process goroutines/read loops after restart/stop.
	generation uint64

	pendingMu sync.Mutex
	pending   map[string]chan pipeResponse
}

func NewManager(rootDir string) *Manager {
	return &Manager{
		rootDir: rootDir,
		logBuf:  make([]string, 0, 100),
		pending: make(map[string]chan pipeResponse),
	}
}

func (m *Manager) Start(config AgentConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.cmd != nil {
		m.stopLocked()
	}

	m.config = config
	m.logBuf = m.logBuf[:0]
	m.pendingMu.Lock()
	m.pending = make(map[string]chan pipeResponse)
	m.pendingMu.Unlock()
	m.generation++
	gen := m.generation

	env := agentEnv(agentBaseEnv(), config)
	provider := normalizeAgentProvider(config.Provider)

	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel

	if bundlePath := findBundle(); bundlePath != "" {
		nodePath, err := resolveNodeForEnv(env)
		if err != nil {
			cancel()
			return fmt.Errorf("找不到 node: %w", err)
		}
		if provider == "claude" {
			claudePath, _, err := resolveClaudeForEnv(env)
			if err != nil {
				cancel()
				return err
			}
			env = appendEnv(env, "KUBETRAIL_AGENT_PATH_TO_CLAUDE", claudePath)
		} else {
			codexPath, _, err := resolveCodexForEnv(env)
			if err != nil {
				cancel()
				return err
			}
			env = ensureCodexVendorPath(env, codexPath)
			env = appendEnv(env, "KUBETRAIL_AGENT_PATH_TO_CODEX", codexPath)
		}
		m.cmd = exec.CommandContext(ctx, nodePath, bundlePath, "pipe")
	} else if agentDir := findAgentDir(m.rootDir); agentDir != "" {
		npxPath, err := resolveNpxForEnv(env)
		if err != nil {
			cancel()
			return fmt.Errorf("找不到 npx: %w", err)
		}
		m.cmd = exec.CommandContext(ctx, npxPath, "tsx", "src/cli.ts", "pipe")
		m.cmd.Dir = agentDir
	} else {
		cancel()
		return fmt.Errorf("找不到 agent-bundle.mjs 或 apps/agent 目录")
	}
	m.cmd.Env = ensureNodeInPath(env)

	stdinPipe, err := m.cmd.StdinPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("stdin pipe: %w", err)
	}
	m.stdin = stdinPipe

	stdout, err := m.cmd.StdoutPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("stdout pipe: %w", err)
	}

	stderr, err := m.cmd.StderrPipe()
	if err != nil {
		cancel()
		return fmt.Errorf("stderr pipe: %w", err)
	}

	// Register _ready handler BEFORE starting readLoop to avoid race
	readyCh := make(chan pipeResponse, 1)
	m.pendingMu.Lock()
	m.pending["_ready"] = readyCh
	m.pendingMu.Unlock()

	if err := m.cmd.Start(); err != nil {
		cancel()
		m.cmd = nil
		m.pendingMu.Lock()
		delete(m.pending, "_ready")
		m.pendingMu.Unlock()
		return fmt.Errorf("start agent: %w", err)
	}

	go m.collectOutput(stderr)
	go m.readLoop(stdout, gen)
	go func(cmd *exec.Cmd, generation uint64) {
		cmd.Wait()
		m.mu.Lock()
		if m.generation == generation {
			m.ready = false
			m.cmd = nil
			m.stdin = nil
			m.cancel = nil
		}
		m.mu.Unlock()
	}(m.cmd, gen)

	// Release mu before blocking on _ready to avoid deadlock
	m.mu.Unlock()
	var startErr error
	select {
	case resp, ok := <-readyCh:
		m.mu.Lock()
		if !ok {
			startErr = fmt.Errorf("agent 启动失败")
		} else if resp.Type == "error" {
			startErr = fmt.Errorf("agent 启动失败: %s", resp.Error)
		} else {
			m.ready = true
		}
	case <-time.After(30 * time.Second):
		m.mu.Lock()
		m.stopLocked()
		startErr = fmt.Errorf("agent 启动超时")
	case <-ctx.Done():
		m.mu.Lock()
		startErr = fmt.Errorf("agent 启动被取消")
	}
	// mu is re-acquired; defer will unlock
	return startErr
}

func agentEnv(base []string, config AgentConfig) []string {
	env := append([]string(nil), base...)
	env = appendEnv(env, "KUBETRAIL_AGENT_PROVIDER", normalizeAgentProvider(config.Provider))
	if strings.TrimSpace(envValueFromList(env, "KUBETRAIL_AGENT_RUNTIME_DIR")) == "" {
		if dir := defaultAgentRuntimeDir(); dir != "" {
			env = appendEnv(env, "KUBETRAIL_AGENT_RUNTIME_DIR", dir)
		}
	}
	if strings.TrimSpace(config.APIKey) != "" {
		env = appendEnv(env, "KUBETRAIL_AGENT_API_KEY", config.APIKey)
	}
	if strings.TrimSpace(config.BaseURL) != "" {
		env = appendEnv(env, "KUBETRAIL_AGENT_BASE_URL", config.BaseURL)
	}
	if strings.TrimSpace(config.Model) != "" {
		env = appendEnv(env, "KUBETRAIL_AGENT_MODEL", config.Model)
	}
	if config.AllowMaterialize {
		env = appendEnv(env, "KUBETRAIL_AGENT_ALLOW_MATERIALIZE", "1")
	}
	if strings.TrimSpace(config.Proxy) != "" {
		env = appendEnv(env, "KUBETRAIL_AGENT_HTTPS_PROXY", config.Proxy)
	}
	if strings.TrimSpace(config.ClaudePath) != "" {
		env = appendEnv(env, "KUBETRAIL_AGENT_PATH_TO_CLAUDE", config.ClaudePath)
	}
	if strings.TrimSpace(config.CodexPath) != "" {
		env = appendEnv(env, "KUBETRAIL_AGENT_PATH_TO_CODEX", config.CodexPath)
	}
	if data := encodeMCPServers(config.MCPServers); data != "" {
		env = appendEnv(env, "KUBETRAIL_AGENT_MCP_SERVERS", data)
	}
	for k, v := range config.CustomEnv {
		if strings.TrimSpace(k) != "" && strings.TrimSpace(v) != "" {
			env = appendEnv(env, strings.TrimSpace(k), strings.TrimSpace(v))
		}
	}
	return env
}

func agentBaseEnv() []string {
	return mergeEnv(os.Environ(), loginShellEnv())
}

func mergeEnv(base, overlay []string) []string {
	env := append([]string(nil), base...)
	for _, item := range overlay {
		key, value, ok := splitEnvItem(item)
		if ok {
			env = appendEnv(env, key, value)
		}
	}
	return env
}

var loginShellEnvOnce sync.Once
var loginShellEnvCached []string

func loginShellEnv() []string {
	loginShellEnvOnce.Do(func() {
		loginShellEnvCached = loadLoginShellEnv()
	})
	return append([]string(nil), loginShellEnvCached...)
}

func loadLoginShellEnv() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	for _, shell := range loginShellCandidates() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		cmd := exec.CommandContext(ctx, shell, "-l", "-i", "-c", "command env")
		cmd.Env = loginShellSeedEnv(shell)
		out, err := cmd.Output()
		cancel()
		if err != nil || len(out) == 0 {
			continue
		}
		env := parseEnvOutput(string(out))
		if len(env) > 0 {
			return env
		}
	}
	return nil
}

func loginShellSeedEnv(shell string) []string {
	env := []string{
		"PATH=/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin",
		"SHELL=" + shell,
		"TERM=dumb",
	}
	for _, key := range []string{"HOME", "USER", "LOGNAME", "TMPDIR", "LANG", "LC_ALL", "LC_CTYPE"} {
		if value := strings.TrimSpace(os.Getenv(key)); value != "" {
			env = appendEnv(env, key, value)
		}
	}
	return env
}

func loginShellCandidates() []string {
	var candidates []string
	seen := map[string]bool{}
	add := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" || seen[path] || !isExecutableFile(path) {
			return
		}
		seen[path] = true
		candidates = append(candidates, path)
	}
	add(os.Getenv("SHELL"))
	add("/bin/zsh")
	add("/bin/bash")
	add("/bin/sh")
	return candidates
}

func parseEnvOutput(output string) []string {
	var env []string
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		key, value, ok := splitEnvItem(line)
		if ok {
			env = appendEnv(env, key, value)
		}
	}
	return env
}

func splitEnvItem(item string) (string, string, bool) {
	idx := strings.IndexByte(item, '=')
	if idx <= 0 {
		return "", "", false
	}
	key := item[:idx]
	if strings.ContainsAny(key, "\x00 \t\r\n") {
		return "", "", false
	}
	return key, item[idx+1:], true
}

func normalizeAgentProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "codex":
		return "codex"
	default:
		return "claude"
	}
}

func defaultAgentRuntimeDir() string {
	base := defaultUserDataDir()
	if base == "" {
		return ""
	}
	return filepath.Join(base, "runtime")
}

func defaultUserDataDir() string {
	switch runtime.GOOS {
	case "darwin":
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, "Library", "Application Support", "KubeTrail")
		}
	case "windows":
		if appData := strings.TrimSpace(os.Getenv("APPDATA")); appData != "" {
			return filepath.Join(appData, "KubeTrail")
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, "AppData", "Roaming", "KubeTrail")
		}
	default:
		if dataHome := strings.TrimSpace(os.Getenv("XDG_DATA_HOME")); dataHome != "" {
			return filepath.Join(dataHome, "kubetrail")
		}
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, ".local", "share", "kubetrail")
		}
	}
	return ""
}

func encodeMCPServers(servers []MCPServerConfig) string {
	out := map[string]map[string]any{}
	for _, server := range servers {
		name := strings.TrimSpace(server.Name)
		if err := validateMCPServerName(name); err != nil {
			continue
		}
		typ := strings.TrimSpace(server.Type)
		if typ == "" {
			typ = "stdio"
		}
		entry := map[string]any{"type": typ}
		switch typ {
		case "stdio":
			command := strings.TrimSpace(server.Command)
			if command == "" {
				continue
			}
			entry["command"] = command
			if len(server.Args) > 0 {
				entry["args"] = server.Args
			}
			if len(server.Env) > 0 {
				entry["env"] = server.Env
			}
		case "http", "sse":
			url := strings.TrimSpace(server.URL)
			if url == "" {
				continue
			}
			entry["url"] = url
			if len(server.Headers) > 0 {
				entry["headers"] = server.Headers
			}
		default:
			continue
		}
		if server.Timeout > 0 {
			entry["timeout"] = server.Timeout
		}
		if server.AlwaysLoad {
			entry["alwaysLoad"] = true
		}
		out[name] = entry
	}
	if len(out) == 0 {
		return ""
	}
	data, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(data)
}

func (m *Manager) readLoop(stdout io.Reader, generation uint64) {
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 4*1024*1024), 4*1024*1024)
	for scanner.Scan() {
		if !m.isCurrentGeneration(generation) {
			return
		}
		line := scanner.Bytes()
		var env pipeResponse
		if err := json.Unmarshal(line, &env); err != nil {
			continue
		}

		m.pendingMu.Lock()
		ch, ok := m.pending[env.ID]
		m.pendingMu.Unlock()

		if !ok {
			continue
		}

		ch <- env

		if env.Type == "end" || env.Type == "result" && env.ID == "_ready" {
			m.pendingMu.Lock()
			delete(m.pending, env.ID)
			m.pendingMu.Unlock()
			close(ch)
		}
	}

	// Process died — close all pending channels
	if !m.isCurrentGeneration(generation) {
		return
	}
	m.pendingMu.Lock()
	for id, ch := range m.pending {
		close(ch)
		delete(m.pending, id)
	}
	m.pendingMu.Unlock()

	m.mu.Lock()
	if m.generation == generation {
		m.ready = false
		m.cmd = nil
		m.stdin = nil
		m.cancel = nil
	}
	m.mu.Unlock()
}

func (m *Manager) isCurrentGeneration(generation uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.generation == generation
}

func (m *Manager) sendRequest(method string, params any) (<-chan pipeResponse, error) {
	return m.sendRequestWithID(uuid.NewString(), method, params)
}

func (m *Manager) sendRequestWithID(id, method string, params any) (<-chan pipeResponse, error) {
	if strings.TrimSpace(id) == "" {
		id = uuid.NewString()
	}
	req := pipeRequest{ID: id, Method: method, Params: params}
	data, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')

	ch := make(chan pipeResponse, 128)
	m.mu.Lock()
	if !m.ready || m.stdin == nil {
		m.mu.Unlock()
		close(ch)
		return nil, fmt.Errorf("agent not ready")
	}
	m.pendingMu.Lock()
	m.pending[id] = ch
	m.pendingMu.Unlock()

	_, err = m.stdin.Write(data)
	m.mu.Unlock()
	if err != nil {
		m.pendingMu.Lock()
		delete(m.pending, id)
		m.pendingMu.Unlock()
		close(ch)
		return nil, fmt.Errorf("write to agent: %w", err)
	}

	return ch, nil
}

func (m *Manager) CancelRequest(id string) error {
	if strings.TrimSpace(id) == "" {
		return fmt.Errorf("missing request id")
	}
	ch, err := m.sendRequest("cancel", map[string]string{"id": id})
	if err != nil {
		return err
	}
	go func() {
		for range ch {
		}
	}()
	return nil
}

func (m *Manager) collectResult(ch <-chan pipeResponse) (json.RawMessage, error) {
	for resp := range ch {
		switch resp.Type {
		case "result":
			return resp.Data, nil
		case "error":
			return nil, fmt.Errorf("agent: %s", resp.Error)
		case "end":
			return nil, fmt.Errorf("agent: unexpected end without result")
		}
	}
	return nil, fmt.Errorf("agent: channel closed (process died?)")
}

func (m *Manager) Stop() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopLocked()
}

func (m *Manager) stopLocked() error {
	m.generation++
	if m.cancel != nil {
		m.cancel()
	}
	if m.stdin != nil {
		m.stdin.Close()
	}
	if m.cmd != nil && m.cmd.Process != nil {
		m.cmd.Process.Kill()
	}
	m.cmd = nil
	m.stdin = nil
	m.cancel = nil
	m.ready = false
	return nil
}

func (m *Manager) Status() AgentStatus {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := AgentStatus{
		Running: m.cmd != nil,
		Ready:   m.ready,
	}
	if m.cmd != nil && m.cmd.Process != nil {
		s.PID = m.cmd.Process.Pid
	}
	return s
}

func (m *Manager) IsReady() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ready
}

func (m *Manager) GetConfig() AgentConfig {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.config
}

func (m *Manager) Logs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.logBuf))
	copy(out, m.logBuf)
	return out
}

func (m *Manager) Chat(ctx context.Context, inputPath, message, resumeSessionID string) (<-chan string, error) {
	return m.ChatWithRequestID(ctx, inputPath, message, resumeSessionID, "")
}

func (m *Manager) ChatWithRequestID(ctx context.Context, inputPath, message, resumeSessionID, requestID string) (<-chan string, error) {
	return m.ChatWithRequestIDLanguage(ctx, inputPath, message, resumeSessionID, requestID, "")
}

func (m *Manager) ChatWithRequestIDLanguage(ctx context.Context, inputPath, message, resumeSessionID, requestID, language string) (<-chan string, error) {
	params := map[string]any{
		"inputPath": inputPath,
		"message":   message,
		"sessionId": resumeSessionID,
	}
	if normalized := normalizeChatLanguage(language); normalized != "" {
		params["language"] = normalized
	}
	if strings.TrimSpace(resumeSessionID) != "" {
		// Fork resumed Claude sessions so provider/model config changes apply to the next turn.
		params["forkSession"] = true
	}
	ch, err := m.sendRequestWithID(requestID, "chat", params)
	if err != nil {
		return nil, err
	}

	out := make(chan string, 64)
	go func() {
		defer close(out)
		sawResultEvent := false
		for resp := range ch {
			switch resp.Type {
			case "stream":
				var event struct {
					Type string `json:"type"`
				}
				if err := json.Unmarshal(resp.Data, &event); err == nil && event.Type == "result" {
					sawResultEvent = true
				}
				select {
				case out <- string(resp.Data):
				case <-ctx.Done():
					return
				}
			case "result":
				if !sawResultEvent && len(resp.Data) > 0 {
					data := map[string]any{"type": "result"}
					var payload map[string]any
					if err := json.Unmarshal(resp.Data, &payload); err == nil {
						for key, value := range payload {
							data[key] = value
						}
					} else {
						data["text"] = string(resp.Data)
					}
					if !sendAgentEvent(ctx, out, data) {
						return
					}
				}
			case "error":
				sendAgentEvent(ctx, out, map[string]any{"type": "error", "message": resp.Error})
				return
			case "end":
				return
			}
		}
		if ctx.Err() == nil {
			sendAgentEvent(ctx, out, map[string]any{"type": "error", "message": "agent process closed before completing chat"})
		}
	}()
	return out, nil
}

func normalizeChatLanguage(language string) string {
	switch strings.ToLower(strings.TrimSpace(language)) {
	case "en", "en-us":
		return "en-US"
	case "zh", "zh-cn":
		return "zh-CN"
	default:
		return ""
	}
}

func sendAgentEvent(ctx context.Context, out chan<- string, event any) bool {
	data, err := json.Marshal(event)
	if err != nil {
		data = []byte(`{"type":"error","message":"failed to encode agent event"}`)
	}
	select {
	case out <- string(data):
		return true
	case <-ctx.Done():
		return false
	}
}

func (m *Manager) GetGraph(inputPath string) (json.RawMessage, error) {
	ch, err := m.sendRequest("graph", map[string]string{"inputPath": inputPath})
	if err != nil {
		return nil, err
	}
	return m.collectResult(ch)
}

func (m *Manager) Materialize(inputPath, ref string) (json.RawMessage, error) {
	ch, err := m.sendRequest("materialize", map[string]string{"inputPath": inputPath, "ref": ref})
	if err != nil {
		return nil, err
	}
	return m.collectResult(ch)
}

func (m *Manager) GetAgentConfig() (json.RawMessage, error) {
	ch, err := m.sendRequest("config", nil)
	if err != nil {
		return nil, err
	}
	return m.collectResult(ch)
}

func (m *Manager) ListExpTemplates() (json.RawMessage, error) {
	ch, err := m.sendRequest("list-exp-templates", nil)
	if err != nil {
		return nil, err
	}
	return m.collectResult(ch)
}

func (m *Manager) GenerateExp(params map[string]interface{}) (json.RawMessage, error) {
	ch, err := m.sendRequest("generate-exp", params)
	if err != nil {
		return nil, err
	}
	return m.collectResult(ch)
}

func (m *Manager) ExportReport(inputPath, format string) (json.RawMessage, error) {
	ch, err := m.sendRequest("export-report", map[string]string{
		"inputPath": inputPath,
		"format":    format,
	})
	if err != nil {
		return nil, err
	}
	return m.collectResult(ch)
}

func (m *Manager) ListSkills() ([]SkillInfo, error) {
	skillsDir, err := m.skillsDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(skillsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return []SkillInfo{}, nil
		}
		return nil, err
	}
	out := make([]SkillInfo, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if err := validateSkillName(name); err != nil {
			continue
		}
		path := filepath.Join(skillsDir, name, "SKILL.md")
		info, err := os.Stat(path)
		if err != nil || info.IsDir() {
			continue
		}
		content, _ := os.ReadFile(path)
		out = append(out, SkillInfo{
			Name:       name,
			Path:       path,
			Summary:    skillSummary(string(content)),
			Size:       info.Size(),
			ModifiedAt: info.ModTime().Format(time.RFC3339),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (m *Manager) GetSkill(name string) (AgentSkill, error) {
	path, err := m.skillFilePath(name)
	if err != nil {
		return AgentSkill{}, err
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return AgentSkill{}, err
	}
	info, err := os.Stat(path)
	if err != nil {
		return AgentSkill{}, err
	}
	return AgentSkill{
		Name:       strings.TrimSpace(name),
		Path:       path,
		Content:    string(content),
		Size:       info.Size(),
		ModifiedAt: info.ModTime().Format(time.RFC3339),
	}, nil
}

func (m *Manager) SaveSkill(req SkillUpsertRequest) (AgentSkill, error) {
	name := strings.TrimSpace(req.Name)
	if err := validateSkillName(name); err != nil {
		return AgentSkill{}, err
	}
	if strings.TrimSpace(req.Content) == "" {
		return AgentSkill{}, fmt.Errorf("skill content is empty")
	}
	path, err := m.skillFilePath(name)
	if err != nil {
		return AgentSkill{}, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return AgentSkill{}, err
	}
	if err := os.WriteFile(path, []byte(req.Content), 0o644); err != nil {
		return AgentSkill{}, err
	}
	return m.GetSkill(name)
}

func (m *Manager) DeleteSkill(name string) error {
	dir, err := m.skillDir(name)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "SKILL.md")
	if _, err := os.Stat(path); err != nil {
		return err
	}
	return os.RemoveAll(dir)
}

func (m *Manager) collectOutput(r io.Reader) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		m.mu.Lock()
		if len(m.logBuf) >= 500 {
			m.logBuf = m.logBuf[len(m.logBuf)-400:]
		}
		m.logBuf = append(m.logBuf, line)
		m.mu.Unlock()
	}
}

func (m *Manager) skillsDir() (string, error) {
	agentDir := findAgentDir(m.rootDir)
	if agentDir == "" {
		return "", fmt.Errorf("找不到 apps/agent 目录")
	}
	return filepath.Join(agentDir, ".claude", "skills"), nil
}

func (m *Manager) skillDir(name string) (string, error) {
	name = strings.TrimSpace(name)
	if err := validateSkillName(name); err != nil {
		return "", err
	}
	skillsDir, err := m.skillsDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(skillsDir, name)
	if err := ensureWithin(skillsDir, dir); err != nil {
		return "", err
	}
	return dir, nil
}

func (m *Manager) skillFilePath(name string) (string, error) {
	dir, err := m.skillDir(name)
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "SKILL.md")
	if err := ensureWithin(dir, path); err != nil {
		return "", err
	}
	return path, nil
}

func validateSkillName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("skill name is empty")
	}
	if name == "." || name == ".." || strings.HasPrefix(name, ".") {
		return fmt.Errorf("invalid skill name: %s", name)
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("invalid skill name: %s", name)
	}
	if len(name) > 80 {
		return fmt.Errorf("skill name is too long")
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("invalid skill name: %s", name)
	}
	return nil
}

func validateMCPServerName(name string) error {
	name = strings.TrimSpace(name)
	if name == "" {
		return fmt.Errorf("mcp server name is empty")
	}
	if len(name) > 80 {
		return fmt.Errorf("mcp server name is too long")
	}
	for _, r := range name {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
			continue
		}
		return fmt.Errorf("invalid mcp server name: %s", name)
	}
	return nil
}

func ensureWithin(root, target string) error {
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(target)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(rootAbs, targetAbs)
	if err != nil {
		return err
	}
	if rel == "." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." {
		return fmt.Errorf("path escapes skills directory")
	}
	return nil
}

func skillSummary(content string) string {
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "#"))
		if line != "" {
			if len(line) > 140 {
				return line[:140]
			}
			return line
		}
	}
	return ""
}

// --- Utilities (unchanged) ---

func findBundle() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exe, _ = filepath.EvalSymlinks(exe)
	candidates := []string{
		filepath.Join(filepath.Dir(exe), "..", "Resources", "agent-bundle.mjs"),
		filepath.Join(filepath.Dir(exe), "agent-bundle.mjs"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode()&0o111 != 0
}

func ResolveRuntimeInfo(config AgentConfig) AgentRuntimeInfo {
	info := AgentRuntimeInfo{}
	env := agentEnv(agentBaseEnv(), config)
	if nodePath, err := resolveNodeForEnv(env); err != nil {
		info.NodeError = err.Error()
	} else {
		info.NodePath = nodePath
	}
	claudePath, source, err := resolveClaudeForEnv(env)
	if err != nil {
		info.ClaudeError = err.Error()
	} else {
		info.ClaudePath = claudePath
		info.ClaudeSource = source
		info.ClaudeAvailable = true
	}
	codexPath, codexSource, codexErr := resolveCodexForEnv(env)
	if codexErr != nil {
		info.CodexError = codexErr.Error()
	} else {
		info.CodexPath = codexPath
		info.CodexSource = codexSource
		info.CodexAvailable = true
	}
	return info
}

func resolveCodexForEnv(env []string) (string, string, error) {
	if explicit := strings.TrimSpace(envValueFromList(env, "KUBETRAIL_AGENT_PATH_TO_CODEX")); explicit != "" {
		path := resolveConfiguredExecutablePathForEnv(explicit, env)
		if isExecutableFile(path) {
			return path, "configured", nil
		}
		return "", "configured", fmt.Errorf("Codex CLI 路径不可执行或不存在: %s", path)
	}
	if path, source, err := findCodexExecutableForEnv(env); err == nil {
		return path, source, nil
	}
	if findBundle() != "" {
		return "", "", fmt.Errorf("找不到 Codex CLI；请安装 codex 并确保它在 PATH 中，或设置 KUBETRAIL_AGENT_PATH_TO_CODEX")
	}
	return "bundled @openai/codex-sdk", "sdk", nil
}

func findCodexExecutableForEnv(env []string) (string, string, error) {
	for _, name := range codexExecutableNames() {
		if p, ok := lookPathInEnv(name, env); ok {
			return normalizeExecutablePath(p), "PATH", nil
		}
	}
	return findCodexExecutable()
}

func findCodexExecutable() (string, string, error) {
	for _, name := range codexExecutableNames() {
		if p, err := exec.LookPath(name); err == nil {
			return normalizeExecutablePath(p), "PATH", nil
		}
	}
	for _, shell := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
		out, err := exec.Command(shell, "-l", "-c", "command -v codex").Output()
		if err == nil {
			p := strings.TrimSpace(string(out))
			if p != "" && isExecutableFile(p) {
				return normalizeExecutablePath(p), filepath.Base(shell) + " login shell", nil
			}
		}
	}
	for _, candidate := range codexCommonCandidates() {
		path := normalizeExecutablePath(candidate)
		if isExecutableFile(path) {
			return path, "common path", nil
		}
	}
	return "", "", fmt.Errorf("找不到 Codex CLI")
}

func codexExecutableNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"codex.exe", "codex.cmd", "codex.bat", "codex"}
	}
	return []string{"codex"}
}

func codexCommonCandidates() []string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		var candidates []string
		var dirs []string
		if appData := os.Getenv("APPDATA"); appData != "" {
			dirs = append(dirs, filepath.Join(appData, "npm"))
		}
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			dirs = append(dirs,
				filepath.Join(localAppData, "pnpm"),
				filepath.Join(localAppData, "Programs", "OpenAI", "Codex"),
			)
		}
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, "scoop", "shims"),
				filepath.Join(home, ".volta", "bin"),
				filepath.Join(home, ".fnm", "current", "bin"),
			)
		}
		for _, dir := range dirs {
			candidates = appendCodexNames(candidates, dir)
		}
		return candidates
	}
	candidates := []string{
		"/opt/homebrew/bin/codex",
		"/usr/local/bin/codex",
		"/usr/bin/codex",
	}
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".local", "bin", "codex"),
			filepath.Join(home, ".npm-global", "bin", "codex"),
			filepath.Join(home, ".volta", "bin", "codex"),
			filepath.Join(home, ".fnm", "current", "bin", "codex"),
			filepath.Join(home, ".local", "share", "pnpm", "codex"),
		)
	}
	return candidates
}

func appendCodexNames(candidates []string, dir string) []string {
	if strings.TrimSpace(dir) == "" || dir == "." {
		return candidates
	}
	for _, name := range codexExecutableNames() {
		candidates = append(candidates, filepath.Join(dir, name))
	}
	return candidates
}

func ensureCodexVendorPath(env []string, codexPath string) []string {
	for _, dir := range codexVendorPathCandidates(codexPath) {
		env = appendPathDir(env, dir)
	}
	return env
}

func codexVendorPathCandidates(codexPath string) []string {
	var candidates []string
	seen := map[string]bool{}
	add := func(path string) {
		path = normalizeExecutablePath(path)
		if path == "" || seen[path] || !dirExists(path) {
			return
		}
		seen[path] = true
		candidates = append(candidates, path)
	}
	addGlob := func(pattern string) {
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return
		}
		sort.Strings(matches)
		for _, match := range matches {
			add(match)
		}
	}

	paths := []string{normalizeExecutablePath(codexPath)}
	if realPath, err := filepath.EvalSymlinks(paths[0]); err == nil && realPath != "" && realPath != paths[0] {
		paths = append(paths, realPath)
	}
	for _, path := range paths {
		if path == "" {
			continue
		}
		if filepath.Base(filepath.Dir(path)) == "bin" {
			add(filepath.Join(filepath.Dir(filepath.Dir(path)), "codex-path"))
		}
		packageRoot := filepath.Dir(filepath.Dir(path))
		addGlob(filepath.Join(packageRoot, "node_modules", "@openai", "codex-*", "vendor", "*", "codex-path"))
		addGlob(filepath.Join(packageRoot, "vendor", "*", "codex-path"))
	}
	return candidates
}

func appendPathDir(env []string, dir string) []string {
	dir = normalizeExecutablePath(dir)
	if !dirExists(dir) {
		return env
	}
	pathValue := envValueFromList(env, "PATH")
	var parts []string
	if strings.TrimSpace(pathValue) != "" {
		for _, part := range filepath.SplitList(pathValue) {
			if part != "" {
				parts = append(parts, part)
			}
		}
	}
	for _, part := range parts {
		if normalizeExecutablePath(part) == dir {
			return env
		}
	}
	parts = append(parts, dir)
	return appendEnv(env, "PATH", strings.Join(parts, string(os.PathListSeparator)))
}

func resolveClaudeForEnv(env []string) (string, string, error) {
	if explicit := strings.TrimSpace(envValueFromList(env, "KUBETRAIL_AGENT_PATH_TO_CLAUDE")); explicit != "" {
		path := resolveConfiguredExecutablePathForEnv(explicit, env)
		if isExecutableFile(path) {
			return path, "configured", nil
		}
		return "", "configured", fmt.Errorf("Claude CLI 路径不可执行或不存在: %s", path)
	}
	return findClaudeExecutableForEnv(env)
}

func findClaudeExecutableForEnv(env []string) (string, string, error) {
	for _, name := range claudeExecutableNames() {
		if p, ok := lookPathInEnv(name, env); ok {
			return normalizeExecutablePath(p), "PATH", nil
		}
	}
	return findClaudeExecutable()
}

func findClaudeExecutable() (string, string, error) {
	for _, name := range claudeExecutableNames() {
		if p, err := exec.LookPath(name); err == nil {
			return normalizeExecutablePath(p), "PATH", nil
		}
	}
	for _, shell := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
		out, err := exec.Command(shell, "-l", "-c", "command -v claude").Output()
		if err == nil {
			p := strings.TrimSpace(string(out))
			if p != "" && isExecutableFile(p) {
				return normalizeExecutablePath(p), filepath.Base(shell) + " login shell", nil
			}
		}
	}
	for _, candidate := range claudeCommonCandidates() {
		path := normalizeExecutablePath(candidate)
		if isExecutableFile(path) {
			return path, "common path", nil
		}
	}
	return "", "", fmt.Errorf("找不到 Claude CLI；请安装 claude 并确保它在 PATH 中，或设置 KUBETRAIL_AGENT_PATH_TO_CLAUDE")
}

func claudeExecutableNames() []string {
	if runtime.GOOS == "windows" {
		return []string{"claude.exe", "claude.cmd", "claude.bat", "claude"}
	}
	return []string{"claude"}
}

func claudeCommonCandidates() []string {
	home, _ := os.UserHomeDir()
	if runtime.GOOS == "windows" {
		var candidates []string
		var dirs []string
		if appData := os.Getenv("APPDATA"); appData != "" {
			dirs = append(dirs, filepath.Join(appData, "npm"))
		}
		if localAppData := os.Getenv("LOCALAPPDATA"); localAppData != "" {
			dirs = append(dirs,
				filepath.Join(localAppData, "pnpm"),
				filepath.Join(localAppData, "Programs", "Claude"),
			)
		}
		if home != "" {
			dirs = append(dirs,
				filepath.Join(home, "scoop", "shims"),
				filepath.Join(home, ".volta", "bin"),
				filepath.Join(home, ".fnm", "current", "bin"),
			)
		}
		if programFiles := os.Getenv("ProgramFiles"); programFiles != "" {
			dirs = append(dirs, filepath.Join(programFiles, "Claude"))
		}
		if programFilesX86 := os.Getenv("ProgramFiles(x86)"); programFilesX86 != "" {
			dirs = append(dirs, filepath.Join(programFilesX86, "Claude"))
		}
		for _, dir := range dirs {
			candidates = appendClaudeNames(candidates, dir)
		}
		return candidates
	}
	candidates := []string{
		"/opt/homebrew/bin/claude",
		"/usr/local/bin/claude",
		"/usr/bin/claude",
	}
	if home != "" {
		candidates = append(candidates,
			filepath.Join(home, ".local/bin/claude"),
			filepath.Join(home, ".npm-global/bin/claude"),
			filepath.Join(home, ".volta/bin/claude"),
			filepath.Join(home, ".fnm/current/bin/claude"),
			filepath.Join(home, ".local/share/pnpm/claude"),
		)
	}
	return candidates
}

func appendClaudeNames(candidates []string, dir string) []string {
	if strings.TrimSpace(dir) == "" || dir == "." {
		return candidates
	}
	for _, name := range claudeExecutableNames() {
		candidates = append(candidates, filepath.Join(dir, name))
	}
	return candidates
}

func normalizeExecutablePath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if path == "~" {
				path = home
			} else {
				path = filepath.Join(home, path[2:])
			}
		}
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return filepath.Clean(path)
}

func resolveConfiguredExecutablePath(path string) string {
	return resolveConfiguredExecutablePathForEnv(path, nil)
}

func resolveConfiguredExecutablePathForEnv(path string, env []string) string {
	path = strings.TrimSpace(path)
	if path != "" && !filepath.IsAbs(path) && !strings.ContainsAny(path, `/\`) {
		if resolved, ok := lookPathInEnv(path, env); ok {
			return normalizeExecutablePath(resolved)
		}
		if resolved, err := exec.LookPath(path); err == nil {
			return normalizeExecutablePath(resolved)
		}
	}
	return normalizeExecutablePath(path)
}

func lookPathInEnv(name string, env []string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" || strings.ContainsAny(name, `/\`) {
		return "", false
	}
	pathValue := envValueFromList(env, "PATH")
	if strings.TrimSpace(pathValue) == "" {
		return "", false
	}
	for _, dir := range filepath.SplitList(pathValue) {
		if dir == "" {
			dir = "."
		}
		for _, candidateName := range executableNameCandidates(name, env) {
			path := filepath.Join(dir, candidateName)
			if isExecutableFile(path) {
				return path, true
			}
		}
	}
	return "", false
}

func executableNameCandidates(name string, env []string) []string {
	if runtime.GOOS != "windows" || filepath.Ext(name) != "" {
		return []string{name}
	}
	pathExt := envValueFromList(env, "PATHEXT")
	if strings.TrimSpace(pathExt) == "" {
		pathExt = ".COM;.EXE;.BAT;.CMD"
	}
	var candidates []string
	for _, ext := range strings.Split(pathExt, ";") {
		ext = strings.TrimSpace(ext)
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		candidates = append(candidates, name+ext)
	}
	return append([]string{name}, candidates...)
}

var nodeOnce sync.Once
var nodeCached string
var nodeErr error

func resolveNodeForEnv(env []string) (string, error) {
	if p, ok := lookPathInEnv("node", env); ok {
		return normalizeExecutablePath(p), nil
	}
	return resolveNode()
}

func resolveNode() (string, error) {
	nodeOnce.Do(func() {
		if p, err := exec.LookPath("node"); err == nil {
			nodeCached = p
			return
		}
		for _, shell := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
			out, err := exec.Command(shell, "-l", "-c", "which node").Output()
			if err == nil {
				p := strings.TrimSpace(string(out))
				if p != "" {
					nodeCached = p
					return
				}
			}
		}
		for _, c := range []string{"/opt/homebrew/bin/node", "/usr/local/bin/node"} {
			if _, err := os.Stat(c); err == nil {
				nodeCached = c
				return
			}
		}
		nodeErr = fmt.Errorf("node not found; please install Node.js")
	})
	return nodeCached, nodeErr
}

var npxOnce sync.Once
var npxCached string
var npxErr error

func resolveNpxForEnv(env []string) (string, error) {
	if p, ok := lookPathInEnv("npx", env); ok {
		return normalizeExecutablePath(p), nil
	}
	return resolveNpx()
}

func resolveNpx() (string, error) {
	npxOnce.Do(func() {
		if p, err := exec.LookPath("npx"); err == nil {
			npxCached = p
			return
		}
		for _, shell := range []string{"/bin/zsh", "/bin/bash", "/bin/sh"} {
			out, err := exec.Command(shell, "-l", "-c", "which npx").Output()
			if err == nil {
				p := strings.TrimSpace(string(out))
				if p != "" {
					npxCached = p
					return
				}
			}
		}
		home, _ := os.UserHomeDir()
		candidates := []string{
			"/opt/homebrew/bin/npx",
			"/usr/local/bin/npx",
		}
		if home != "" {
			candidates = append(candidates,
				filepath.Join(home, ".volta/bin/npx"),
				filepath.Join(home, ".fnm/current/bin/npx"),
			)
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				npxCached = c
				return
			}
		}
		npxErr = fmt.Errorf("npx not found; please install Node.js")
	})
	return npxCached, npxErr
}

func findAgentDir(rootDir string) string {
	candidates := []string{
		filepath.Join(rootDir, "apps", "agent"),
		filepath.Join(rootDir, "..", "agent"),
		filepath.Join(rootDir, "..", "..", "apps", "agent"),
	}
	if runtimeDir := defaultAgentRuntimeDir(); runtimeDir != "" {
		candidates = append(candidates, filepath.Join(runtimeDir, "workspace"))
	}
	for _, candidate := range candidates {
		if dirExists(candidate) {
			return filepath.Clean(candidate)
		}
	}
	exe, err := os.Executable()
	if err == nil {
		exe, _ = filepath.EvalSymlinks(exe)
		dir := filepath.Dir(exe)
		if candidate := filepath.Join(dir, "..", "Resources", "agent-context"); dirExists(candidate) {
			return filepath.Clean(candidate)
		}
		for range 10 {
			if candidate := filepath.Join(dir, "apps", "agent"); dirExists(candidate) {
				return candidate
			}
			parent := filepath.Dir(dir)
			if parent == dir {
				break
			}
			dir = parent
		}
	}
	return ""
}

func dirExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func ensureNodeInPath(env []string) []string {
	nodePath, err := resolveNodeForEnv(env)
	if err != nil {
		return env
	}
	nodeDir := filepath.Dir(nodePath)
	for i, e := range env {
		if strings.HasPrefix(e, "PATH=") {
			if !strings.Contains(e, nodeDir) {
				env[i] = e + ":" + nodeDir
			}
			return env
		}
	}
	return append(env, "PATH=/usr/bin:/bin:"+nodeDir)
}

func appendEnv(env []string, key, value string) []string {
	prefix := key + "="
	for i, e := range env {
		if strings.HasPrefix(e, prefix) {
			env[i] = prefix + value
			return env
		}
	}
	return append(env, prefix+value)
}

func envValueFromList(env []string, key string) string {
	prefix := key + "="
	for _, item := range env {
		if strings.HasPrefix(item, prefix) {
			return item[len(prefix):]
		}
	}
	return ""
}
