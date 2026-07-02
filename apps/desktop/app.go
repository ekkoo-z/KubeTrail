package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ekkoo-z/KubeTrail/apps/desktop/agentmgr"
	"github.com/ekkoo-z/KubeTrail/apps/desktop/kube"
	"github.com/ekkoo-z/KubeTrail/apps/desktop/scanner"
	"github.com/ekkoo-z/KubeTrail/apps/desktop/session"
	"github.com/ekkoo-z/KubeTrail/apps/desktop/store"

	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

type App struct {
	ctx          context.Context
	store        *store.Store
	sessions     *session.Manager
	scan         *scanner.Scanner
	agentMgr     *agentmgr.Manager
	execSessions sync.Map
	chatCancels  sync.Map
	mu           sync.Mutex
	clients      map[string]*kube.Client
}

func NewApp() *App {
	rootDir, _ := os.Getwd()
	return &App{
		clients:  map[string]*kube.Client{},
		sessions: session.NewManager(),
		scan:     scanner.NewScanner(),
		agentMgr: agentmgr.NewManager(rootDir),
	}
}

func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
	st, err := store.New()
	if err != nil {
		wruntime.LogErrorf(ctx, "store init: %v", err)
		return
	}
	a.store = st
	a.loadAgentConfig()
}

func (a *App) shutdown(_ context.Context) {
	a.sessions.StopAll()
	a.agentMgr.Stop()
}

// ==================== Cluster Persistence ====================

type ClusterDTO struct {
	ID                string `json:"id"`
	Name              string `json:"name"`
	Type              string `json:"type"`
	APIServer         string `json:"apiServer,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	Insecure          bool   `json:"insecure,omitempty"`
	APIPathPrefix     string `json:"apiPathPrefix,omitempty"`
	KubeconfigContent string `json:"kubeconfigContent,omitempty"`
	Token             string `json:"token,omitempty"`
	CAData            string `json:"caData,omitempty"`
}

type ClusterInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	Namespace string `json:"namespace"`
	APIServer string `json:"apiServer"`
}

func (a *App) ListClusters() ([]store.ClusterEntry, error) {
	if a.store == nil {
		return nil, fmt.Errorf("store not initialised")
	}
	return a.store.List()
}

func (a *App) SaveCluster(dto ClusterDTO) (string, error) {
	if a.store == nil {
		return "", fmt.Errorf("store not initialised")
	}
	entry := store.ClusterEntry{
		ID: dto.ID, Name: dto.Name,
		Type: store.AuthType(dto.Type), APIServer: dto.APIServer,
		Namespace: dto.Namespace, Insecure: dto.Insecure,
		APIPathPrefix: dto.APIPathPrefix,
	}
	sec := store.ClusterSecret{
		KubeconfigContent: dto.KubeconfigContent,
		Token:             dto.Token, CAData: dto.CAData,
	}
	return a.store.Save(entry, sec)
}

func (a *App) DeleteCluster(id string) error {
	if a.store == nil {
		return fmt.Errorf("store not initialised")
	}
	a.disconnect(id)
	return a.store.Delete(id)
}

func (a *App) TestConnection(dto ClusterDTO) (string, error) {
	c, err := buildClientFromDTO(dto)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return c.ServerVersion(ctx)
}

func (a *App) ConnectCluster(id string) (*ClusterInfo, error) {
	if a.store == nil {
		return nil, fmt.Errorf("store not initialised")
	}
	entry, sec, err := a.store.Reveal(id)
	if err != nil {
		return nil, err
	}
	dto := ClusterDTO{
		ID: entry.ID, Name: entry.Name, Type: string(entry.Type),
		APIServer: entry.APIServer, Namespace: entry.Namespace,
		Insecure: entry.Insecure, APIPathPrefix: entry.APIPathPrefix,
		KubeconfigContent: sec.KubeconfigContent,
		Token:             sec.Token, CAData: sec.CAData,
	}
	c, err := buildClientFromDTO(dto)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ver, err := c.ServerVersion(ctx)
	if err != nil {
		return nil, fmt.Errorf("server version: %w", err)
	}
	a.mu.Lock()
	a.clients[id] = c
	a.mu.Unlock()
	return &ClusterInfo{
		ID: id, Name: entry.Name, Version: ver,
		Namespace: c.Namespace, APIServer: c.Config.Host,
	}, nil
}

func (a *App) DisconnectCluster(id string) { a.disconnect(id) }

func (a *App) disconnect(id string) {
	a.mu.Lock()
	delete(a.clients, id)
	a.mu.Unlock()
}

func (a *App) clientFor(id string) (*kube.Client, error) {
	a.mu.Lock()
	c, ok := a.clients[id]
	a.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("cluster %s not connected", id)
	}
	return c, nil
}

func buildClientFromDTO(dto ClusterDTO) (*kube.Client, error) {
	return kube.New(buildOptsFromDTO(dto))
}

func buildOptsFromDTO(dto ClusterDTO) kube.ConnectOptions {
	opts := kube.ConnectOptions{
		Type: kube.AuthType(dto.Type), Namespace: dto.Namespace,
		APIServer: dto.APIServer, Token: dto.Token,
		Insecure: dto.Insecure, APIPathPrefix: dto.APIPathPrefix,
	}
	if dto.KubeconfigContent != "" {
		opts.KubeconfigBytes = []byte(dto.KubeconfigContent)
	}
	if dto.CAData != "" {
		if b, err := base64.StdEncoding.DecodeString(dto.CAData); err == nil {
			opts.CAData = b
		} else {
			opts.CAData = []byte(dto.CAData)
		}
	}
	return opts
}

func (a *App) ListClusterExtensions(dto ClusterDTO) ([]kube.ClusterExtensionInfo, error) {
	dto.APIPathPrefix = ""
	opts := buildOptsFromDTO(dto)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return kube.ListClusterExtensions(ctx, opts)
}

func (a *App) ClusterExtensionProxyPath(name string) string {
	return kube.ClusterExtensionProxyPath(name)
}

// ==================== Dialogs ====================

func (a *App) OpenKubeconfigDialog() (map[string]string, error) {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "选择 kubeconfig 文件",
	})
	if err != nil {
		return nil, err
	}
	if path == "" {
		return map[string]string{}, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return map[string]string{"path": path, "content": string(b)}, nil
}

func (a *App) PickSaveFile(defaultName string) (string, error) {
	return wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		DefaultFilename: defaultName, Title: "保存到",
	})
}

func (a *App) PickOpenFile() (string, error) {
	return wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{Title: "选择本地文件"})
}

func (a *App) PickDirectory() (string, error) {
	return wruntime.OpenDirectoryDialog(a.ctx, wruntime.OpenDialogOptions{Title: "选择本地目录"})
}

// ==================== Resources ====================

func (a *App) ListNamespaces(clusterID string) ([]kube.Namespace, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.ListNamespaces(ctx)
}

func (a *App) ListPods(clusterID, namespace string) ([]kube.PodInfo, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return c.ListPods(ctx, namespace)
}

func (a *App) ListNodes(clusterID string) ([]kube.NodeInfo, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.ListNodes(ctx)
}

func (a *App) DescribePod(clusterID, ns, name string) (*kube.PodDetail, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.DescribePod(ctx, ns, name)
}

// ==================== Terminal ====================

type TerminalStartRequest struct {
	ClusterID string   `json:"clusterID"`
	Namespace string   `json:"namespace"`
	Pod       string   `json:"pod"`
	Container string   `json:"container"`
	Command   []string `json:"command"`
}

func (a *App) StartTerminal(req TerminalStartRequest) (string, error) {
	c, err := a.clientFor(req.ClusterID)
	if err != nil {
		return "", err
	}
	cmd := interactivePodShellCommand(req.Command)
	holder := struct {
		mu sync.Mutex
		id string
	}{}
	get := func() string { holder.mu.Lock(); defer holder.mu.Unlock(); return holder.id }
	sess, err := c.StartExec(context.Background(), req.Namespace, req.Pod, req.Container, cmd, true, kube.ExecCallbacks{
		OnData: func(b []byte) {
			if id := get(); id != "" {
				wruntime.EventsEmit(a.ctx, eventName("terminal", id, "data"), base64.StdEncoding.EncodeToString(b))
			}
		},
		OnExit: func(err error) {
			if id := get(); id != "" {
				msg := ""
				if err != nil {
					msg = err.Error()
				}
				wruntime.EventsEmit(a.ctx, eventName("terminal", id, "exit"), msg)
				a.execSessions.Delete(id)
			}
		},
	})
	if err != nil {
		return "", err
	}
	id := a.sessions.Add(session.KindExec, sess.Stop, map[string]interface{}{
		"pod": req.Pod, "ns": req.Namespace, "container": req.Container,
	})
	holder.mu.Lock()
	holder.id = id
	holder.mu.Unlock()
	a.execSessions.Store(id, sess)
	return id, nil
}

func (a *App) WriteTerminal(sessionID, b64data string) error {
	v, ok := a.execSessions.Load(sessionID)
	if !ok {
		return fmt.Errorf("terminal session %s not found", sessionID)
	}
	data, err := base64.StdEncoding.DecodeString(b64data)
	if err != nil {
		return err
	}
	v.(*kube.ExecSession).Write(data)
	return nil
}

func (a *App) ResizeTerminal(sessionID string, cols, rows int) error {
	v, ok := a.execSessions.Load(sessionID)
	if !ok {
		return fmt.Errorf("terminal session %s not found", sessionID)
	}
	if cols < 32 || rows < 1 {
		return nil
	}
	if cols > 1000 {
		cols = 1000
	}
	if rows > 1000 {
		rows = 1000
	}
	v.(*kube.ExecSession).Resize(uint16(cols), uint16(rows))
	return nil
}

func (a *App) StopTerminal(sessionID string) bool {
	a.execSessions.Delete(sessionID)
	return a.sessions.Stop(sessionID)
}

func interactivePodShellCommand(cmd []string) []string {
	if len(cmd) == 0 {
		return []string{"/bin/sh", "-c", interactiveShellBootstrap("auto")}
	}
	if len(cmd) != 1 {
		return cmd
	}

	shellPath := strings.TrimSpace(cmd[0])
	if shellPath == "" || shellPath == "auto" {
		return []string{"/bin/sh", "-c", interactiveShellBootstrap("auto")}
	}

	shellName := filepath.Base(shellPath)
	switch shellName {
	case "bash":
		return []string{shellPath, "-c", interactiveShellBootstrap("bash")}
	case "ash":
		return []string{shellPath, "-c", interactiveShellBootstrap("ash")}
	case "sh":
		return []string{shellPath, "-c", interactiveShellBootstrap("sh")}
	default:
		return cmd
	}
}

func interactiveShellBootstrap(prefer string) string {
	common := `export TERM="${TERM:-xterm-256color}"
export HISTCONTROL="${HISTCONTROL:-ignoredups}"
__kt_user="$(id -un 2>/dev/null || whoami 2>/dev/null || printf root)"
__kt_host="$(hostname 2>/dev/null || cat /etc/hostname 2>/dev/null || printf node)"
: "${USER:=$__kt_user}"
: "${HOSTNAME:=$__kt_host}"
export USER HOSTNAME
`
	bash := `if command -v bash >/dev/null 2>&1; then
  export PS1='\[\033[1;32m\]\u@\h\[\033[0m\]:\[\033[1;34m\]\w\[\033[0m\]\$ '
  exec bash --noprofile --norc -i
fi
`
	ash := `if command -v ash >/dev/null 2>&1; then
  export PS1='${USER}@${HOSTNAME}:${PWD}\$ '
  exec ash -i
fi
`
	sh := `export PS1='${USER}@${HOSTNAME}:${PWD}\$ '
exec sh -i
`

	switch prefer {
	case "bash":
		return common + bash + sh
	case "ash":
		return common + ash + sh
	case "sh":
		return common + sh
	default:
		return common + bash + ash + sh
	}
}

// ==================== Logs ====================

type LogStartRequest struct {
	ClusterID    string `json:"clusterID"`
	Namespace    string `json:"namespace"`
	Pod          string `json:"pod"`
	Container    string `json:"container"`
	Follow       bool   `json:"follow"`
	TailLines    int64  `json:"tailLines"`
	SinceSeconds int64  `json:"sinceSeconds"`
}

func (a *App) StartLogs(req LogStartRequest) (string, error) {
	c, err := a.clientFor(req.ClusterID)
	if err != nil {
		return "", err
	}
	holder := struct {
		mu sync.Mutex
		id string
	}{}
	get := func() string { holder.mu.Lock(); defer holder.mu.Unlock(); return holder.id }
	sess, err := c.StartLogs(context.Background(), req.Namespace, req.Pod, req.Container, req.Follow, req.TailLines, req.SinceSeconds, kube.LogsCallbacks{
		OnLine: func(line string) {
			if id := get(); id != "" {
				wruntime.EventsEmit(a.ctx, eventName("logs", id, "line"), line)
			}
		},
		OnEnd: func(err error) {
			if id := get(); id != "" {
				msg := ""
				if err != nil {
					msg = err.Error()
				}
				wruntime.EventsEmit(a.ctx, eventName("logs", id, "end"), msg)
			}
		},
	})
	if err != nil {
		return "", err
	}
	id := a.sessions.Add(session.KindLogs, sess.Stop, map[string]interface{}{
		"pod": req.Pod, "ns": req.Namespace, "container": req.Container,
	})
	holder.mu.Lock()
	holder.id = id
	holder.mu.Unlock()
	return id, nil
}

func (a *App) StopLogs(sessionID string) bool {
	return a.sessions.Stop(sessionID)
}

// ==================== Pod Files ====================

func (a *App) ListPodFiles(clusterID, ns, pod, container, dir string) ([]kube.FileEntry, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.ListPodFiles(ctx, ns, pod, container, dir)
}

func (a *App) ReadPodFile(clusterID, ns, pod, container, path string, maxBytes int64) (string, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	b, err := c.ReadPodFile(ctx, ns, pod, container, path, maxBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

func (a *App) DownloadPodFile(clusterID, ns, pod, container, remotePath, localDir string) error {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return c.DownloadPodFile(ctx, ns, pod, container, remotePath, localDir)
}

func (a *App) UploadPodFile(clusterID, ns, pod, container, localPath, remoteDir string) error {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return c.UploadPodFile(ctx, ns, pod, container, localPath, remoteDir)
}

func (a *App) DeletePodFile(clusterID, ns, pod, container, target string) error {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.DeletePodFile(ctx, ns, pod, container, target)
}

// ==================== Node Shell ====================

func (a *App) CheckNodeShellAccess(clusterID, nodeName string) (*kube.NodeShellAccess, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.CheckNodeShellAccess(ctx, nodeName)
}

func (a *App) StartNodeTerminal(clusterID, nodeName, shellMode string) (string, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	ns, pod, container, err := c.EnsureNodeShellPod(ctx, nodeName)
	if err != nil {
		return "", err
	}
	var cmd []string
	switch shellMode {
	case "bash":
		cmd = []string{"chroot", "/host", "/bin/bash", "-c", interactiveShellBootstrap("bash")}
	case "nsenter":
		cmd = []string{"nsenter", "-t", "1", "-m", "-u", "-i", "-n", "-p", "--", "/bin/sh", "-c", interactiveShellBootstrap("auto")}
	case "helper":
		cmd = []string{"/bin/sh", "-c", interactiveShellBootstrap("auto")}
	default:
		cmd = []string{"chroot", "/host", "/bin/sh", "-c", interactiveShellBootstrap("auto")}
	}
	holder := struct {
		mu sync.Mutex
		id string
	}{}
	get := func() string { holder.mu.Lock(); defer holder.mu.Unlock(); return holder.id }
	sess, err := c.StartExec(context.Background(), ns, pod, container, cmd, true, kube.ExecCallbacks{
		OnData: func(b []byte) {
			if id := get(); id != "" {
				wruntime.EventsEmit(a.ctx, eventName("terminal", id, "data"), base64.StdEncoding.EncodeToString(b))
			}
		},
		OnExit: func(err error) {
			if id := get(); id != "" {
				msg := ""
				if err != nil {
					msg = err.Error()
				}
				wruntime.EventsEmit(a.ctx, eventName("terminal", id, "exit"), msg)
				a.execSessions.Delete(id)
			}
		},
	})
	if err != nil {
		return "", err
	}
	id := a.sessions.Add(session.KindExec, sess.Stop, map[string]interface{}{
		"node": nodeName, "ns": ns, "pod": pod,
	})
	holder.mu.Lock()
	holder.id = id
	holder.mu.Unlock()
	a.execSessions.Store(id, sess)
	return id, nil
}

func (a *App) DeleteNodeShellPod(clusterID, nodeName string) error {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	return c.DeleteNodeShellPod(ctx, nodeName)
}

func (a *App) ListNodeFiles(clusterID, nodeName, dir string) ([]kube.FileEntry, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	return c.ListNodeFiles(ctx, nodeName, dir)
}

func (a *App) ReadNodeFile(clusterID, nodeName, remotePath string, maxBytes int64) (string, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	data, err := c.ReadNodeFile(ctx, nodeName, remotePath, maxBytes)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(data), nil
}

func (a *App) DownloadNodeFile(clusterID, nodeName, remotePath, localDir string) error {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return c.DownloadNodeFile(ctx, nodeName, remotePath, localDir)
}

func (a *App) UploadNodeFile(clusterID, nodeName, localPath, remoteDir string) error {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	return c.UploadNodeFile(ctx, nodeName, localPath, remoteDir)
}

func (a *App) DeleteNodeFile(clusterID, nodeName, target string) error {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.DeleteNodeFile(ctx, nodeName, target)
}

// ==================== Recon ====================

func (a *App) ReconCatalog() []kube.ReconPreset { return kube.ReconCatalog() }

func (a *App) ReconRead(clusterID, ns, pod, container, preset string) (string, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.ReconRead(ctx, ns, pod, container, preset)
}

// ==================== Port Forward ====================

type PFInfo struct {
	SessionID string `json:"sessionID"`
	Namespace string `json:"namespace"`
	Pod       string `json:"pod"`
	LocalPort int    `json:"localPort"`
	PodPort   int    `json:"podPort"`
	Ready     bool   `json:"ready"`
}

func (a *App) StartPortForward(clusterID, ns, pod string, localPort, podPort int) (string, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return "", err
	}
	holder := struct {
		mu sync.Mutex
		id string
	}{}
	get := func() string { holder.mu.Lock(); defer holder.mu.Unlock(); return holder.id }
	sess, err := c.StartPortForward(context.Background(), ns, pod, localPort, podPort, kube.PFCallbacks{
		OnReady: func(actualLocal int) {
			if id := get(); id != "" {
				wruntime.EventsEmit(a.ctx, eventName("pf", id, "status"), map[string]interface{}{
					"ready": true, "localPort": actualLocal,
				})
				if e := a.sessions.Get(id); e != nil {
					if m, ok := e.Meta.(map[string]interface{}); ok {
						m["localPort"] = actualLocal
						m["ready"] = true
					}
				}
			}
		},
		OnError: func(err error) {
			if id := get(); id != "" {
				wruntime.EventsEmit(a.ctx, eventName("pf", id, "error"), err.Error())
			}
		},
		OnLog: func(line string) {
			if id := get(); id != "" {
				wruntime.EventsEmit(a.ctx, eventName("pf", id, "log"), line)
			}
		},
	})
	if err != nil {
		return "", err
	}
	meta := map[string]interface{}{
		"ns": ns, "pod": pod, "localPort": localPort, "podPort": podPort, "ready": false,
	}
	id := a.sessions.Add(session.KindPF, sess.Stop, meta)
	holder.mu.Lock()
	holder.id = id
	holder.mu.Unlock()
	return id, nil
}

func (a *App) StopPortForward(sessionID string) bool {
	return a.sessions.Stop(sessionID)
}

func (a *App) ListPortForwards() []PFInfo {
	out := []PFInfo{}
	for _, e := range a.sessions.List(session.KindPF) {
		info := PFInfo{SessionID: e.ID}
		if m, ok := e.Meta.(map[string]interface{}); ok {
			info.Namespace, _ = m["ns"].(string)
			info.Pod, _ = m["pod"].(string)
			if v, ok := m["localPort"].(int); ok {
				info.LocalPort = v
			}
			if v, ok := m["podPort"].(int); ok {
				info.PodPort = v
			}
			info.Ready, _ = m["ready"].(bool)
		}
		out = append(out, info)
	}
	return out
}

// ==================== Scanner ====================

func (a *App) ImportScanResult() (*scanner.ScanResult, error) {
	path, err := wruntime.OpenFileDialog(a.ctx, wruntime.OpenDialogOptions{
		Title: "选择 KubeTrail 扫描结果 (dbus.json)",
		Filters: []wruntime.FileFilter{
			{DisplayName: "JSON 文件", Pattern: "*.json"},
		},
	})
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}
	return a.scan.ImportResult(path)
}

func (a *App) ImportScanResultPath(path string) (*scanner.ScanResult, error) {
	return a.scan.ImportResult(path)
}

func (a *App) StartClusterScan(clusterID string, opts scanner.ScanOptions) (string, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return "", err
	}
	wruntime.EventsEmit(a.ctx, "scan:progress", scanner.ScanProgress{
		Phase: "starting", Message: "正在启动扫描...", Percent: 0,
	})
	go func() {
		result, err := a.scan.StartScan(context.Background(), c.Config, c.Namespace, opts)
		if err != nil {
			wruntime.EventsEmit(a.ctx, "scan:error", err.Error())
			return
		}
		wruntime.EventsEmit(a.ctx, "scan:complete", result)
	}()
	return "scanning", nil
}

func (a *App) GetScanResult(scanID string) *scanner.ScanResult {
	return a.scan.GetResult(scanID)
}

func (a *App) ListScanResults() []*scanner.ScanResult {
	return a.scan.ListResults()
}

func (a *App) ExportScanResult(scanID string) error {
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		DefaultFilename: "kubetrail-scan.json",
		Title:           "导出扫描结果",
	})
	if err != nil {
		return err
	}
	if path == "" {
		return nil
	}
	return a.scan.ExportResult(scanID, path)
}

func (a *App) DeleteScanResult(scanID string) {
	a.scan.DeleteResult(scanID)
}

// ==================== Agent ====================

func (a *App) ConfigureAgent(config agentmgr.AgentConfig) error {
	if err := a.saveAgentConfig(config); err != nil {
		return err
	}
	return a.agentMgr.Start(config)
}

func (a *App) GetAgentStatus() agentmgr.AgentStatus {
	return a.agentMgr.Status()
}

func (a *App) GetAgentDisplayConfig() agentmgr.AgentConfig {
	return a.loadFullAgentConfig()
}

func (a *App) GetAgentRuntimeInfo() agentmgr.AgentRuntimeInfo {
	return agentmgr.ResolveRuntimeInfo(a.loadFullAgentConfig())
}

func (a *App) CheckAgentRuntime(config agentmgr.AgentConfig) agentmgr.AgentRuntimeInfo {
	return agentmgr.ResolveRuntimeInfo(config)
}

func (a *App) StopAgent() error {
	return a.agentMgr.Stop()
}

func (a *App) RestartAgent() error {
	cfg := a.loadFullAgentConfig()
	return a.agentMgr.Start(cfg)
}

func (a *App) AgentLogs() []string {
	return a.agentMgr.Logs()
}

func (a *App) ListAgentSkills() ([]agentmgr.SkillInfo, error) {
	return a.agentMgr.ListSkills()
}

func (a *App) GetAgentSkill(name string) (agentmgr.AgentSkill, error) {
	return a.agentMgr.GetSkill(name)
}

func (a *App) SaveAgentSkill(req agentmgr.SkillUpsertRequest) (agentmgr.AgentSkill, error) {
	skill, err := a.agentMgr.SaveSkill(req)
	if err != nil {
		return agentmgr.AgentSkill{}, err
	}
	_ = a.agentMgr.Stop()
	return skill, nil
}

func (a *App) DeleteAgentSkill(name string) error {
	if err := a.agentMgr.DeleteSkill(name); err != nil {
		return err
	}
	_ = a.agentMgr.Stop()
	return nil
}

func (a *App) StartAgentChat(scanID, message, uiSessionID, resumeSessionID string) error {
	if err := a.ensureAgentRunning(true); err != nil {
		return err
	}
	a.StopAgentChat(uiSessionID)
	var inputPath string
	if scanID != "" {
		var err error
		inputPath, err = a.scan.ResultToTempFile(scanID)
		if err != nil {
			return err
		}
	}
	requestID := fmt.Sprintf("%s:%d", uiSessionID, time.Now().UnixNano())
	ctx, cancel := context.WithCancel(context.Background())
	a.chatCancels.Store(uiSessionID, chatCancel{
		cancel:    cancel,
		requestID: requestID,
	})
	go func() {
		defer func() {
			cancel()
			a.chatCancels.Delete(uiSessionID)
		}()
		ch, err := a.agentMgr.ChatWithRequestID(ctx, inputPath, message, resumeSessionID, requestID)
		if err != nil {
			wruntime.EventsEmit(a.ctx, eventName("agent", uiSessionID, "error"), err.Error())
			return
		}
		for line := range ch {
			wruntime.EventsEmit(a.ctx, eventName("agent", uiSessionID, "message"), line)
		}
		wruntime.EventsEmit(a.ctx, eventName("agent", uiSessionID, "done"), "")
	}()
	return nil
}

type chatCancel struct {
	cancel    context.CancelFunc
	requestID string
}

func (a *App) StopAgentChat(uiSessionID string) bool {
	value, ok := a.chatCancels.Load(uiSessionID)
	if !ok {
		return false
	}
	entry, ok := value.(chatCancel)
	if !ok {
		a.chatCancels.Delete(uiSessionID)
		return false
	}
	entry.cancel()
	if err := a.agentMgr.CancelRequest(entry.requestID); err != nil {
		wruntime.EventsEmit(a.ctx, eventName("agent", uiSessionID, "error"), err.Error())
	}
	a.chatCancels.Delete(uiSessionID)
	wruntime.EventsEmit(a.ctx, eventName("agent", uiSessionID, "done"), "")
	return true
}

func (a *App) GetAttackGraph(scanID string) (json.RawMessage, error) {
	if err := a.ensureAgentRunning(false); err != nil {
		return nil, err
	}
	inputPath, err := a.scan.ResultToTempFile(scanID)
	if err != nil {
		return nil, err
	}
	return a.agentMgr.GetGraph(inputPath)
}

func (a *App) MaterializeSensitive(scanID, ref string) (json.RawMessage, error) {
	if err := a.ensureAgentRunning(false); err != nil {
		return nil, err
	}
	inputPath, err := a.scan.ResultToTempFile(scanID)
	if err != nil {
		return nil, err
	}
	return a.agentMgr.Materialize(inputPath, ref)
}

// ==================== EXP Forge ====================

type GenerateExpRequest struct {
	TemplateID    string                 `json:"templateId"`
	OutDir        string                 `json:"outDir,omitempty"`
	Params        map[string]interface{} `json:"params,omitempty"`
	FindingIDs    []string               `json:"findingIds,omitempty"`
	FactIDs       []string               `json:"factIds,omitempty"`
	SensitiveRefs []string               `json:"sensitiveRefs,omitempty"`
}

func (a *App) ListExpTemplates() (json.RawMessage, error) {
	if err := a.ensureAgentRunning(false); err != nil {
		return nil, err
	}
	return a.agentMgr.ListExpTemplates()
}

func (a *App) GenerateExp(req GenerateExpRequest) (json.RawMessage, error) {
	if err := a.ensureAgentRunning(false); err != nil {
		return nil, err
	}
	params := map[string]interface{}{
		"templateId": req.TemplateID,
	}
	if req.OutDir != "" {
		params["outDir"] = req.OutDir
	}
	if req.Params != nil {
		params["params"] = req.Params
	}
	if len(req.FindingIDs) > 0 {
		params["findingIds"] = req.FindingIDs
	}
	if len(req.FactIDs) > 0 {
		params["factIds"] = req.FactIDs
	}
	if len(req.SensitiveRefs) > 0 {
		params["sensitiveRefs"] = req.SensitiveRefs
	}
	return a.agentMgr.GenerateExp(params)
}

// ==================== Report Export ====================

func (a *App) ExportAnalysisReport(scanID, format string) error {
	if err := a.ensureAgentRunning(false); err != nil {
		return err
	}
	inputPath, err := a.scan.ResultToTempFile(scanID)
	if err != nil {
		return err
	}
	data, err := a.agentMgr.ExportReport(inputPath, format)
	if err != nil {
		return err
	}

	ext := ".json"
	if format == "markdown" {
		ext = ".md"
	}
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		DefaultFilename: "kubetrail-report" + ext,
		Title:           "导出分析报告",
	})
	if err != nil {
		return err
	}
	if path == "" {
		return nil
	}

	if format == "markdown" {
		var envelope struct {
			Content string `json:"content"`
		}
		if err := json.Unmarshal(data, &envelope); err != nil {
			return err
		}
		return os.WriteFile(path, []byte(envelope.Content), 0o644)
	}
	return os.WriteFile(path, data, 0o644)
}

// ==================== Persistence ====================

// PersistenceCatalogItem describes a single persistence technique for the frontend catalog.
type PersistenceCatalogItem struct {
	ID          string `json:"id"`
	Technique   string `json:"technique"`
	Label       string `json:"label"`
	Category    string `json:"category"`
	RiskLevel   string `json:"riskLevel"`
	Description string `json:"description"`
}

// PersistenceCatalog returns the static catalog of available persistence techniques.
func (a *App) PersistenceCatalog() []PersistenceCatalogItem {
	return []PersistenceCatalogItem{
		{
			ID:          "sa-cluster-admin",
			Technique:   string(kube.TechniqueServiceAccount),
			Label:       "ServiceAccount + ClusterRoleBinding",
			Category:    "rbac",
			RiskLevel:   string(kube.RiskLow),
			Description: "创建高权限 ServiceAccount 并绑定 cluster-admin，仅留下 RBAC 产物，不影响集群工作负载",
		},
		{
			ID:          "shadow-kubeconfig",
			Technique:   string(kube.TechniqueShadowKubeconfig),
			Label:       "影子 Kubeconfig",
			Category:    "credential",
			RiskLevel:   string(kube.RiskLow),
			Description: "创建高权 SA + 拉取 token，生成立即可用的 kubeconfig 文件",
		},
		{
			ID:          "token-request",
			Technique:   string(kube.TechniqueTokenRequest),
			Label:       "TokenRequest 令牌请求",
			Category:    "credential",
			RiskLevel:   string(kube.RiskLow),
			Description: "对已有 SA 调用 TokenRequest API，创建有时效的临时 token",
		},
		{
			ID:          "cronjob-beacon",
			Technique:   string(kube.TechniqueCronJob),
			Label:       "CronJob 定时信标",
			Category:    "workload",
			RiskLevel:   string(kube.RiskMedium),
			Description: "部署 CronJob 周期性执行命令/回调，可配 schedule + 资源限制",
		},
		{
			ID:          "deployment-backdoor",
			Technique:   string(kube.TechniqueDeployment),
			Label:       "Deployment 后门",
			Category:    "workload",
			RiskLevel:   string(kube.RiskMedium),
			Description: "创建常驻 Deployment Pod，可配副本数 + 资源限制",
		},
		{
			ID:          "daemonset-backdoor",
			Technique:   string(kube.TechniqueDaemonSet),
			Label:       "DaemonSet 全节点后门",
			Category:    "workload",
			RiskLevel:   string(kube.RiskHigh),
			Description: "在每个节点运行一个 Pod，高风险操作，可能影响集群稳定性",
		},
		{
			ID:          "pull-secret",
			Technique:   string(kube.TechniquePullSecret),
			Label:       "ImagePullSecret 注入",
			Category:    "credential",
			RiskLevel:   string(kube.RiskMedium),
			Description: "创建 dockerconfigjson Secret 并挂到 default ServiceAccount 的 imagePullSecrets",
		},
	}
}

func (a *App) CreatePersistenceSA(clusterID string, req kube.SACreationRequest) (*kube.PersistenceResult, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.CreatePersistenceSA(ctx, req)
}

func (a *App) CreatePersistenceCronJob(clusterID string, req kube.WorkloadCreationRequest) (*kube.PersistenceResult, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.CreatePersistenceCronJob(ctx, req)
}

func (a *App) CreatePersistenceDeployment(clusterID string, req kube.WorkloadCreationRequest) (*kube.PersistenceResult, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.CreatePersistenceDeployment(ctx, req)
}

func (a *App) CreatePersistenceDaemonSet(clusterID string, req kube.WorkloadCreationRequest) (*kube.PersistenceResult, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.CreatePersistenceDaemonSet(ctx, req)
}

func (a *App) GenerateShadowKubeconfig(clusterID string, req kube.SACreationRequest) (*kube.KubeconfigResult, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return c.GenerateShadowKubeconfig(ctx, req)
}

func (a *App) RequestSAToken(clusterID string, req kube.TokenRequestParams) (*kube.TokenResult, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.RequestToken(ctx, req)
}

func (a *App) InjectPullSecret(clusterID string, namespace string) (*kube.PersistenceResult, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.InjectPullSecret(ctx, namespace)
}

func (a *App) ListPersistenceResources(clusterID string) ([]kube.PersistenceResourceInfo, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.ListPersistenceResources(ctx)
}

func (a *App) DeletePersistenceResource(clusterID string, technique kube.PersistenceTechnique, namespace, name string) error {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.DeletePersistenceResource(ctx, technique, namespace, name)
}

func (a *App) GetSAKubeconfig(clusterID, namespace, saName string) (*kube.KubeconfigResult, error) {
	c, err := a.clientFor(clusterID)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return c.GetSAKubeconfig(ctx, namespace, saName)
}

func (a *App) SaveKubeconfigFile(data *kube.KubeconfigResult) error {
	if data == nil || data.Kubeconfig == "" {
		return fmt.Errorf("no kubeconfig data to save")
	}
	path, err := wruntime.SaveFileDialog(a.ctx, wruntime.SaveDialogOptions{
		DefaultFilename: data.SA + "-kubeconfig.yaml",
		Title:           "保存影子 Kubeconfig",
	})
	if err != nil {
		return err
	}
	if path == "" {
		return nil
	}
	return os.WriteFile(path, []byte(data.Kubeconfig), 0o600)
}

// ==================== Agent Config ====================

func (a *App) SaveAgentConfigOnly(config agentmgr.AgentConfig) error {
	return a.saveAgentConfig(config)
}

func (a *App) TestAgentConnection(config agentmgr.AgentConfig) (string, error) {
	client := &http.Client{Timeout: 15 * time.Second}
	proxy := strings.TrimSpace(config.Proxy)
	if proxy == "" {
		proxy = firstNonEmptyEnv("KUBETRAIL_AGENT_HTTPS_PROXY", "KUBETRAIL_AGENT_HTTP_PROXY", "HTTPS_PROXY", "HTTP_PROXY")
	}
	if proxy != "" {
		proxyURL, err := url.Parse(proxy)
		if err != nil {
			return "", fmt.Errorf("proxy URL 无效: %v", err)
		}
		client.Transport = &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	}
	if strings.EqualFold(strings.TrimSpace(config.Provider), "codex") {
		return testCodexConnection(client, config)
	}

	if isClaudeOfficialMode(config) {
		return testClaudeOfficialConnection(config)
	}

	baseURL := "https://api.anthropic.com"
	if config.BaseURL != "" {
		baseURL = strings.TrimRight(config.BaseURL, "/")
	} else if envBaseURL := firstNonEmptyEnv("KUBETRAIL_AGENT_BASE_URL", "ANTHROPIC_BASE_URL"); envBaseURL != "" {
		baseURL = strings.TrimRight(envBaseURL, "/")
	}

	mdl := config.Model
	if mdl == "" {
		mdl = firstNonEmptyEnv("KUBETRAIL_AGENT_MODEL")
		if mdl == "" {
			mdl = "(claude default)"
		}
	}

	apiKey := strings.TrimSpace(config.APIKey)
	if apiKey == "" {
		apiKey = firstNonEmptyEnv("KUBETRAIL_AGENT_API_KEY", "ANTHROPIC_API_KEY")
	}
	authToken := firstNonEmptyEnv("KUBETRAIL_AGENT_AUTH_TOKEN", "ANTHROPIC_AUTH_TOKEN")
	if apiKey == "" && authToken == "" {
		return "", fmt.Errorf("请配置 API Key 或 Auth Token")
	}

	body := fmt.Sprintf(`{"model":"%s","max_tokens":1,"messages":[{"role":"user","content":"hi"}]}`, mdl)
	req, err := http.NewRequestWithContext(context.Background(), "POST", baseURL+"/v1/messages", strings.NewReader(body))
	if err != nil {
		return "", err
	}
	if apiKey != "" {
		req.Header.Set("x-api-key", apiKey)
	}
	if authToken != "" {
		req.Header.Set("authorization", "Bearer "+authToken)
	}
	req.Header.Set("anthropic-version", "2023-06-01")
	req.Header.Set("content-type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("连接失败: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 200 {
		return fmt.Sprintf("连接成功 (model: %s)", mdl), nil
	}

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 401 {
		return "", fmt.Errorf("API Key 无效")
	}
	return "", fmt.Errorf("API 返回 %d: %s", resp.StatusCode, string(respBody))
}

func (a *App) EnsureAgentRunning() error {
	return a.ensureAgentRunning(true)
}

func (a *App) ensureAgentRunning(requireCredential bool) error {
	if a.agentMgr.IsReady() {
		return nil
	}
	cfg := a.loadFullAgentConfig()
	if requireCredential && !hasAgentCredential(cfg) {
		return fmt.Errorf("请先在设置页面选择 Claude Code 或 Codex；官方模式可将 API Key、Base URL、Model 留空并使用本机 CLI 登录态，自定义网关才需要填写密钥或环境变量")
	}
	if err := a.agentMgr.Start(cfg); err != nil {
		return fmt.Errorf("Agent 启动失败: %w", err)
	}
	return nil
}

// ==================== Agent Config Persistence ====================

const agentConfigFile = "agent-config.json"

func (a *App) agentConfigPath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".kubetrail", agentConfigFile)
}

func (a *App) saveAgentConfig(config agentmgr.AgentConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.agentConfigPath()), 0o700); err != nil {
		return err
	}
	return os.WriteFile(a.agentConfigPath(), data, 0o600)
}

func (a *App) loadAgentConfig() {
	cfg := a.loadFullAgentConfig()
	if hasAgentCredential(cfg) {
		go a.agentMgr.Start(cfg)
	}
}

func (a *App) loadFullAgentConfig() agentmgr.AgentConfig {
	data, err := os.ReadFile(a.agentConfigPath())
	if err != nil {
		return agentmgr.AgentConfig{}
	}
	var cfg agentmgr.AgentConfig
	json.Unmarshal(data, &cfg)
	return cfg
}

func (a *App) OpenExternalURL(url string) {
	wruntime.BrowserOpenURL(a.ctx, url)
}

func (a *App) OpenDirectoryPath(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("path is empty")
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		path = filepath.Dir(path)
	}
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", path).Start()
	case "windows":
		return exec.Command("explorer", path).Start()
	default:
		return exec.Command("xdg-open", path).Start()
	}
}

// ==================== Misc ====================

func eventName(prefix, id, suffix string) string {
	return fmt.Sprintf("%s:%s:%s", prefix, id, suffix)
}

func hasAgentCredential(config agentmgr.AgentConfig) bool {
	switch strings.ToLower(strings.TrimSpace(config.Provider)) {
	case "claude", "codex":
		return true
	}
	if strings.TrimSpace(config.APIKey) != "" {
		return true
	}
	return firstNonEmptyEnv(
		"KUBETRAIL_AGENT_API_KEY",
		"ANTHROPIC_API_KEY",
		"KUBETRAIL_AGENT_AUTH_TOKEN",
		"ANTHROPIC_AUTH_TOKEN",
	) != ""
}

func isClaudeOfficialMode(config agentmgr.AgentConfig) bool {
	return strings.TrimSpace(config.APIKey) == "" &&
		strings.TrimSpace(config.BaseURL) == "" &&
		strings.TrimSpace(config.Model) == "" &&
		firstNonEmptyEnv(
			"KUBETRAIL_AGENT_API_KEY",
			"ANTHROPIC_API_KEY",
			"KUBETRAIL_AGENT_AUTH_TOKEN",
			"ANTHROPIC_AUTH_TOKEN",
			"KUBETRAIL_AGENT_BASE_URL",
			"ANTHROPIC_BASE_URL",
			"KUBETRAIL_AGENT_MODEL",
		) == ""
}

func testClaudeOfficialConnection(config agentmgr.AgentConfig) (string, error) {
	info := agentmgr.ResolveRuntimeInfo(config)
	if !info.ClaudeAvailable {
		if strings.TrimSpace(info.ClaudeError) != "" {
			return "", fmt.Errorf("Claude Code 官方模式不可用: %s", info.ClaudeError)
		}
		return "", fmt.Errorf("Claude Code 官方模式不可用: 找不到 claude CLI")
	}
	source := strings.TrimSpace(info.ClaudeSource)
	if source == "" {
		source = "auto"
	}
	return fmt.Sprintf("Claude Code 官方模式可用 (CLI: %s, source: %s)。将使用本机 claude 登录态和默认模型配置", info.ClaudePath, source), nil
}

func isCodexOfficialMode(config agentmgr.AgentConfig) bool {
	return strings.TrimSpace(config.APIKey) == "" &&
		strings.TrimSpace(config.BaseURL) == "" &&
		strings.TrimSpace(config.Model) == "" &&
		firstNonEmptyEnv(
			"KUBETRAIL_AGENT_API_KEY",
			"KUBETRAIL_AGENT_OPENAI_API_KEY",
			"CODEX_API_KEY",
			"OPENAI_API_KEY",
			"KUBETRAIL_AGENT_BASE_URL",
			"KUBETRAIL_AGENT_OPENAI_BASE_URL",
			"OPENAI_BASE_URL",
			"KUBETRAIL_AGENT_MODEL",
		) == ""
}

func testCodexOfficialConnection(config agentmgr.AgentConfig) (string, error) {
	info := agentmgr.ResolveRuntimeInfo(config)
	if !info.CodexAvailable {
		if strings.TrimSpace(info.CodexError) != "" {
			return "", fmt.Errorf("Codex 官方模式不可用: %s", info.CodexError)
		}
		return "", fmt.Errorf("Codex 官方模式不可用: 找不到 codex CLI")
	}
	source := strings.TrimSpace(info.CodexSource)
	if source == "" {
		source = "auto"
	}
	return fmt.Sprintf("Codex 官方模式可用 (runtime: %s, source: %s)。将使用本机 codex 登录态和默认模型配置", info.CodexPath, source), nil
}

func testCodexConnection(client *http.Client, config agentmgr.AgentConfig) (string, error) {
	if isCodexOfficialMode(config) {
		return testCodexOfficialConnection(config)
	}
	baseURL := "https://api.openai.com"
	if config.BaseURL != "" {
		baseURL = strings.TrimRight(config.BaseURL, "/")
	} else if envBaseURL := firstNonEmptyEnv("KUBETRAIL_AGENT_BASE_URL", "KUBETRAIL_AGENT_OPENAI_BASE_URL", "OPENAI_BASE_URL"); envBaseURL != "" {
		baseURL = strings.TrimRight(envBaseURL, "/")
	}
	mdl := strings.TrimSpace(config.Model)
	if mdl == "" {
		mdl = firstNonEmptyEnv("KUBETRAIL_AGENT_MODEL")
		if mdl == "" {
			mdl = "(codex default)"
		}
	}
	apiKey := strings.TrimSpace(config.APIKey)
	if apiKey == "" {
		apiKey = firstNonEmptyEnv("KUBETRAIL_AGENT_API_KEY", "KUBETRAIL_AGENT_OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_API_KEY")
	}
	if apiKey == "" {
		return "", fmt.Errorf("请配置 OpenAI/Codex API Key")
	}
	req, err := http.NewRequestWithContext(context.Background(), "GET", baseURL+"/v1/models", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("authorization", "Bearer "+apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("连接失败: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return fmt.Sprintf("连接成功 (provider: codex, model: %s)", mdl), nil
	}
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode == 401 {
		return "", fmt.Errorf("API Key 无效")
	}
	return "", fmt.Errorf("API 返回 %d: %s", resp.StatusCode, string(respBody))
}

func firstNonEmptyEnv(names ...string) string {
	for _, name := range names {
		if value := strings.TrimSpace(os.Getenv(name)); value != "" {
			return value
		}
	}
	return ""
}
