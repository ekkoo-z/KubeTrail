package model

import "time"

const SchemaVersion = "kubetrail.server/v1"
const SATokenAuditSchemaVersion = "kubetrail.sa-token-audit/v1"

type Mode string

const (
	ModeSafe Mode = "safe"
	ModeFull Mode = "full"
)

type SensitiveMode string

const (
	SensitiveRaw      SensitiveMode = "raw"
	SensitiveRedact   SensitiveMode = "redact"
	SensitiveMetadata SensitiveMode = "metadata"
)

type APIScope string

const (
	APIScopePermitted APIScope = "permitted"
	APIScopeCurrent   APIScope = "current"
)

type RBACMode string

const (
	RBACModeFocused RBACMode = "focused"
	RBACModeFull    RBACMode = "full"
)

type Options struct {
	Mode               Mode
	Output             string
	OutputPretty       bool
	SATokenAuditOutput string
	Timeout            time.Duration
	SensitiveMode      SensitiveMode
	APIScope           APIScope
	RBACMode           RBACMode
	Kubeconfig         string
	KubeQPS            float32
	KubeBurst          int
	Root               string
	MaxItems           int
	CredentialSweep    bool
	Scans              []string
	Args               []string
	RemoteOnly         bool
}

type Document struct {
	SchemaVersion string            `json:"schemaVersion"`
	Run           RunInfo           `json:"run"`
	Target        TargetInfo        `json:"target"`
	Mode          Mode              `json:"mode"`
	Collectors    []CollectorResult `json:"collectors"`
	Facts         []Fact            `json:"facts"`
	Findings      []Finding         `json:"findings"`
	Errors        []ErrorEntry      `json:"errors,omitempty"`
}

type RunInfo struct {
	ID          string   `json:"id"`
	StartedAt   string   `json:"startedAt"`
	FinishedAt  string   `json:"finishedAt"`
	DurationMs  int64    `json:"durationMs"`
	Hostname    string   `json:"hostname,omitempty"`
	ToolVersion string   `json:"toolVersion"`
	Args        []string `json:"args,omitempty"`
}

type TargetInfo struct {
	InKubernetes bool   `json:"inKubernetes"`
	Namespace    string `json:"namespace,omitempty"`
	PodName      string `json:"podName,omitempty"`
	APIServer    string `json:"apiServer,omitempty"`
}

type CollectorResult struct {
	ID          string       `json:"id"`
	Mode        Mode         `json:"mode"`
	SideEffects []string     `json:"sideEffects,omitempty"`
	Status      string       `json:"status"`
	DurationMs  int64        `json:"durationMs"`
	FactCount   int          `json:"factCount,omitempty"`
	Facts       []Fact       `json:"facts,omitempty"`
	Errors      []ErrorEntry `json:"errors,omitempty"`
}

type Fact struct {
	ID        string `json:"id"`
	Collector string `json:"collector"`
	Category  string `json:"category"`
	Source    string `json:"source,omitempty"`
	Sensitive bool   `json:"sensitive,omitempty"`
	Value     any    `json:"value"`
}

type ErrorEntry struct {
	Collector string `json:"collector,omitempty"`
	Source    string `json:"source,omitempty"`
	Message   string `json:"message"`
}

type Finding struct {
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Confidence  string `json:"confidence,omitempty"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

type SATokenAuditDocument struct {
	SchemaVersion string             `json:"schemaVersion"`
	Run           RunInfo            `json:"run"`
	Target        TargetInfo         `json:"target"`
	Mode          Mode               `json:"mode"`
	Source        SATokenAuditSource `json:"source"`
	Items         []SATokenAuditItem `json:"items"`
	Errors        []ErrorEntry       `json:"errors,omitempty"`
}

type SATokenAuditSource struct {
	ResourceTypes []string `json:"resourceTypes"`
	Namespaces    []string `json:"namespaces"`
	Note          string   `json:"note,omitempty"`
}

type SATokenAuditItem struct {
	Namespace       string                 `json:"namespace"`
	ServiceAccount  string                 `json:"serviceAccount,omitempty"`
	SecretName      string                 `json:"secretName"`
	SecretUID       string                 `json:"secretUid,omitempty"`
	SecretCreatedAt string                 `json:"secretCreatedAt,omitempty"`
	Token           string                 `json:"token"`
	TokenSHA256     string                 `json:"tokenSha256"`
	TokenBytes      int                    `json:"tokenBytes"`
	JWTClaims       map[string]any         `json:"jwtClaims,omitempty"`
	JWTError        string                 `json:"jwtError,omitempty"`
	Permissions     SATokenAuditPermission `json:"permissions"`
	Errors          []ErrorEntry           `json:"errors,omitempty"`
}

type SATokenAuditPermission struct {
	Namespace          string           `json:"namespace,omitempty"`
	RBACMode           RBACMode         `json:"rbacMode,omitempty"`
	SelfSubjectRules   any              `json:"selfSubjectRules,omitempty"`
	HighValueAccess    []map[string]any `json:"highValueAccess,omitempty"`
	ExpandedWildcards  []map[string]any `json:"expandedWildcards,omitempty"`
	DiscoveryResources int              `json:"discoveryResources,omitempty"`
}
