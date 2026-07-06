export namespace agentmgr {

	export class AgentProviderConfig {
	    apiKey?: string;
	    baseUrl?: string;
	    model?: string;
	    allowMaterialize: boolean;
	    proxy?: string;
	    customEnv?: Record<string, string>;
	    mcpServers?: MCPServerConfig[];

	    static createFrom(source: any = {}) {
	        return new AgentProviderConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.apiKey = source["apiKey"];
	        this.baseUrl = source["baseUrl"];
	        this.model = source["model"];
	        this.allowMaterialize = source["allowMaterialize"];
	        this.proxy = source["proxy"];
	        this.customEnv = source["customEnv"];
	        this.mcpServers = this.convertValues(source["mcpServers"], MCPServerConfig);
	    }

		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class MCPServerConfig {
	    name: string;
	    type: string;
	    command?: string;
	    args?: string[];
	    url?: string;
	    env?: Record<string, string>;
	    headers?: Record<string, string>;
	    timeout?: number;
	    alwaysLoad?: boolean;

	    static createFrom(source: any = {}) {
	        return new MCPServerConfig(source);
	    }

	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.type = source["type"];
	        this.command = source["command"];
	        this.args = source["args"];
	        this.url = source["url"];
	        this.env = source["env"];
	        this.headers = source["headers"];
	        this.timeout = source["timeout"];
	        this.alwaysLoad = source["alwaysLoad"];
	    }
	}
	export class AgentConfig {
	    provider?: string;
	    apiKey: string;
	    baseUrl?: string;
	    model?: string;
	    allowMaterialize: boolean;
	    proxy?: string;
	    claudePath?: string;
	    codexPath?: string;
	    customEnv?: Record<string, string>;
	    mcpServers?: MCPServerConfig[];
	    providerConfigs?: Record<string, AgentProviderConfig>;

	    static createFrom(source: any = {}) {
	        return new AgentConfig(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.provider = source["provider"];
	        this.apiKey = source["apiKey"];
	        this.baseUrl = source["baseUrl"];
	        this.model = source["model"];
	        this.allowMaterialize = source["allowMaterialize"];
	        this.proxy = source["proxy"];
	        this.claudePath = source["claudePath"];
	        this.codexPath = source["codexPath"];
	        this.customEnv = source["customEnv"];
	        this.mcpServers = this.convertValues(source["mcpServers"], MCPServerConfig);
	        this.providerConfigs = this.convertValues(source["providerConfigs"], AgentProviderConfig, true);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

	export class AgentRuntimeInfo {
	    nodePath?: string;
	    nodeError?: string;
	    claudePath?: string;
	    claudeSource?: string;
	    claudeAvailable: boolean;
	    claudeError?: string;
	    codexPath?: string;
	    codexSource?: string;
	    codexAvailable: boolean;
	    codexError?: string;
	
	    static createFrom(source: any = {}) {
	        return new AgentRuntimeInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.nodePath = source["nodePath"];
	        this.nodeError = source["nodeError"];
	        this.claudePath = source["claudePath"];
	        this.claudeSource = source["claudeSource"];
	        this.claudeAvailable = source["claudeAvailable"];
	        this.claudeError = source["claudeError"];
	        this.codexPath = source["codexPath"];
	        this.codexSource = source["codexSource"];
	        this.codexAvailable = source["codexAvailable"];
	        this.codexError = source["codexError"];
	    }
	}
	export class AgentSkill {
	    name: string;
	    path: string;
	    content: string;
	    size: number;
	    modifiedAt?: string;
	
	    static createFrom(source: any = {}) {
	        return new AgentSkill(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.path = source["path"];
	        this.content = source["content"];
	        this.size = source["size"];
	        this.modifiedAt = source["modifiedAt"];
	    }
	}
	export class AgentStatus {
	    running: boolean;
	    ready: boolean;
	    pid: number;
	    error?: string;
	
	    static createFrom(source: any = {}) {
	        return new AgentStatus(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.running = source["running"];
	        this.ready = source["ready"];
	        this.pid = source["pid"];
	        this.error = source["error"];
	    }
	}
	
	export class SkillInfo {
	    name: string;
	    path: string;
	    summary?: string;
	    size: number;
	    modifiedAt?: string;
	
	    static createFrom(source: any = {}) {
	        return new SkillInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.path = source["path"];
	        this.summary = source["summary"];
	        this.size = source["size"];
	        this.modifiedAt = source["modifiedAt"];
	    }
	}
	export class SkillUpsertRequest {
	    name: string;
	    content: string;
	
	    static createFrom(source: any = {}) {
	        return new SkillUpsertRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.content = source["content"];
	    }
	}

}
export namespace kube {
	
	export class ClusterExtensionInfo {
	    name: string;
	    namespace?: string;
	    endpoint?: string;
	    proxyPath: string;
	    status?: string;
	
	    static createFrom(source: any = {}) {
	        return new ClusterExtensionInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.namespace = source["namespace"];
	        this.endpoint = source["endpoint"];
	        this.proxyPath = source["proxyPath"];
	        this.status = source["status"];
	    }
	}
	export class FileEntry {
	    name: string;
	    path: string;
	    size: number;
	    mode: string;
	    mtime: string;
	    isDir: boolean;
	    isLink: boolean;
	    target?: string;
	
	    static createFrom(source: any = {}) {
	        return new FileEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.path = source["path"];
	        this.size = source["size"];
	        this.mode = source["mode"];
	        this.mtime = source["mtime"];
	        this.isDir = source["isDir"];
	        this.isLink = source["isLink"];
	        this.target = source["target"];
	    }
	}
	export class KubeconfigResult {
	    sa: string;
	    namespace: string;
	    token: string;
	    kubeconfig: string;
	
	    static createFrom(source: any = {}) {
	        return new KubeconfigResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sa = source["sa"];
	        this.namespace = source["namespace"];
	        this.token = source["token"];
	        this.kubeconfig = source["kubeconfig"];
	    }
	}
	export class Namespace {
	    name: string;
	    status: string;
	    age: string;
	
	    static createFrom(source: any = {}) {
	        return new Namespace(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.status = source["status"];
	        this.age = source["age"];
	    }
	}
	export class NodeInfo {
	    name: string;
	    status: string;
	    roles: string;
	    age: string;
	    version: string;
	    internalIP: string;
	    os: string;
	    kernel: string;
	    runtime: string;
	
	    static createFrom(source: any = {}) {
	        return new NodeInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.status = source["status"];
	        this.roles = source["roles"];
	        this.age = source["age"];
	        this.version = source["version"];
	        this.internalIP = source["internalIP"];
	        this.os = source["os"];
	        this.kernel = source["kernel"];
	        this.runtime = source["runtime"];
	    }
	}
	export class NodeShellAccess {
	    namespace: string;
	    helperPod: string;
	    image: string;
	    helperRunning: boolean;
	    requiresCreate: boolean;
	    getPodAllowed: boolean;
	    createPodAllowed: boolean;
	    execAllowed: boolean;
	    getPodReason?: string;
	    createPodReason?: string;
	    execReason?: string;
	
	    static createFrom(source: any = {}) {
	        return new NodeShellAccess(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.namespace = source["namespace"];
	        this.helperPod = source["helperPod"];
	        this.image = source["image"];
	        this.helperRunning = source["helperRunning"];
	        this.requiresCreate = source["requiresCreate"];
	        this.getPodAllowed = source["getPodAllowed"];
	        this.createPodAllowed = source["createPodAllowed"];
	        this.execAllowed = source["execAllowed"];
	        this.getPodReason = source["getPodReason"];
	        this.createPodReason = source["createPodReason"];
	        this.execReason = source["execReason"];
	    }
	}
	export class PersistenceResourceInfo {
	    id: string;
	    technique: string;
	    resourceName: string;
	    namespace: string;
	    createdAt: string;
	    status: string;
	    detail: string;
	
	    static createFrom(source: any = {}) {
	        return new PersistenceResourceInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.technique = source["technique"];
	        this.resourceName = source["resourceName"];
	        this.namespace = source["namespace"];
	        this.createdAt = source["createdAt"];
	        this.status = source["status"];
	        this.detail = source["detail"];
	    }
	}
	export class PersistenceResult {
	    technique: string;
	    success: boolean;
	    resourceName?: string;
	    namespace?: string;
	    detail?: string;
	    error?: string;
	    permissions?: Record<string, boolean>;
	
	    static createFrom(source: any = {}) {
	        return new PersistenceResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.technique = source["technique"];
	        this.success = source["success"];
	        this.resourceName = source["resourceName"];
	        this.namespace = source["namespace"];
	        this.detail = source["detail"];
	        this.error = source["error"];
	        this.permissions = source["permissions"];
	    }
	}
	export class PodInfo {
	    namespace: string;
	    name: string;
	    status: string;
	    ready: string;
	    restarts: number;
	    age: string;
	    node: string;
	    podIP: string;
	    containers: string[];
	    hostNetwork: boolean;
	    hostPID: boolean;
	    privileged: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PodInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.namespace = source["namespace"];
	        this.name = source["name"];
	        this.status = source["status"];
	        this.ready = source["ready"];
	        this.restarts = source["restarts"];
	        this.age = source["age"];
	        this.node = source["node"];
	        this.podIP = source["podIP"];
	        this.containers = source["containers"];
	        this.hostNetwork = source["hostNetwork"];
	        this.hostPID = source["hostPID"];
	        this.privileged = source["privileged"];
	    }
	}
	export class PodDetail {
	    pod: PodInfo;
	    labels: Record<string, string>;
	    annotations: Record<string, string>;
	    conditions: string[];
	    events: string[];
	    serviceAccount: string;
	    volumes: string[];
	
	    static createFrom(source: any = {}) {
	        return new PodDetail(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.pod = this.convertValues(source["pod"], PodInfo);
	        this.labels = source["labels"];
	        this.annotations = source["annotations"];
	        this.conditions = source["conditions"];
	        this.events = source["events"];
	        this.serviceAccount = source["serviceAccount"];
	        this.volumes = source["volumes"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	export class ReconPreset {
	    key: string;
	    label: string;
	    category: string;
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new ReconPreset(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.key = source["key"];
	        this.label = source["label"];
	        this.category = source["category"];
	        this.description = source["description"];
	    }
	}
	export class SACreationRequest {
	    name: string;
	    namespace: string;
	    clusterAdmin: boolean;
	
	    static createFrom(source: any = {}) {
	        return new SACreationRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.namespace = source["namespace"];
	        this.clusterAdmin = source["clusterAdmin"];
	    }
	}
	export class TokenRequestParams {
	    namespace: string;
	    saName: string;
	    durationSeconds: number;
	
	    static createFrom(source: any = {}) {
	        return new TokenRequestParams(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.namespace = source["namespace"];
	        this.saName = source["saName"];
	        this.durationSeconds = source["durationSeconds"];
	    }
	}
	export class TokenResult {
	    token: string;
	    expiresAt: string;
	
	    static createFrom(source: any = {}) {
	        return new TokenResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.token = source["token"];
	        this.expiresAt = source["expiresAt"];
	    }
	}
	export class WorkloadCreationRequest {
	    name: string;
	    namespace: string;
	    image: string;
	    command?: string[];
	    schedule?: string;
	
	    static createFrom(source: any = {}) {
	        return new WorkloadCreationRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.name = source["name"];
	        this.namespace = source["namespace"];
	        this.image = source["image"];
	        this.command = source["command"];
	        this.schedule = source["schedule"];
	    }
	}

}
export namespace main {
	
	export class ClusterDTO {
	    id: string;
	    name: string;
	    type: string;
	    apiServer?: string;
	    namespace?: string;
	    insecure?: boolean;
	    apiPathPrefix?: string;
	    kubeconfigContent?: string;
	    token?: string;
	    caData?: string;
	
	    static createFrom(source: any = {}) {
	        return new ClusterDTO(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.apiServer = source["apiServer"];
	        this.namespace = source["namespace"];
	        this.insecure = source["insecure"];
	        this.apiPathPrefix = source["apiPathPrefix"];
	        this.kubeconfigContent = source["kubeconfigContent"];
	        this.token = source["token"];
	        this.caData = source["caData"];
	    }
	}
	export class ClusterInfo {
	    id: string;
	    name: string;
	    version: string;
	    namespace: string;
	    apiServer: string;
	
	    static createFrom(source: any = {}) {
	        return new ClusterInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.version = source["version"];
	        this.namespace = source["namespace"];
	        this.apiServer = source["apiServer"];
	    }
	}
	export class GenerateExpRequest {
	    templateId: string;
	    outDir?: string;
	    params?: Record<string, any>;
	    findingIds?: string[];
	    factIds?: string[];
	    sensitiveRefs?: string[];
	
	    static createFrom(source: any = {}) {
	        return new GenerateExpRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.templateId = source["templateId"];
	        this.outDir = source["outDir"];
	        this.params = source["params"];
	        this.findingIds = source["findingIds"];
	        this.factIds = source["factIds"];
	        this.sensitiveRefs = source["sensitiveRefs"];
	    }
	}
	export class LogStartRequest {
	    clusterID: string;
	    namespace: string;
	    pod: string;
	    container: string;
	    follow: boolean;
	    tailLines: number;
	    sinceSeconds: number;
	
	    static createFrom(source: any = {}) {
	        return new LogStartRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.clusterID = source["clusterID"];
	        this.namespace = source["namespace"];
	        this.pod = source["pod"];
	        this.container = source["container"];
	        this.follow = source["follow"];
	        this.tailLines = source["tailLines"];
	        this.sinceSeconds = source["sinceSeconds"];
	    }
	}
	export class PFInfo {
	    sessionID: string;
	    namespace: string;
	    pod: string;
	    localPort: number;
	    podPort: number;
	    ready: boolean;
	
	    static createFrom(source: any = {}) {
	        return new PFInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.sessionID = source["sessionID"];
	        this.namespace = source["namespace"];
	        this.pod = source["pod"];
	        this.localPort = source["localPort"];
	        this.podPort = source["podPort"];
	        this.ready = source["ready"];
	    }
	}
	export class PersistenceCatalogItem {
	    id: string;
	    technique: string;
	    label: string;
	    category: string;
	    riskLevel: string;
	    description: string;
	
	    static createFrom(source: any = {}) {
	        return new PersistenceCatalogItem(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.technique = source["technique"];
	        this.label = source["label"];
	        this.category = source["category"];
	        this.riskLevel = source["riskLevel"];
	        this.description = source["description"];
	    }
	}
	export class TerminalStartRequest {
	    clusterID: string;
	    namespace: string;
	    pod: string;
	    container: string;
	    command: string[];
	
	    static createFrom(source: any = {}) {
	        return new TerminalStartRequest(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.clusterID = source["clusterID"];
	        this.namespace = source["namespace"];
	        this.pod = source["pod"];
	        this.container = source["container"];
	        this.command = source["command"];
	    }
	}

}

export namespace model {
	
	export class ErrorEntry {
	    collector?: string;
	    source?: string;
	    message: string;
	
	    static createFrom(source: any = {}) {
	        return new ErrorEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.collector = source["collector"];
	        this.source = source["source"];
	        this.message = source["message"];
	    }
	}
	export class Fact {
	    id: string;
	    collector: string;
	    category: string;
	    source?: string;
	    sensitive?: boolean;
	    value: any;
	
	    static createFrom(source: any = {}) {
	        return new Fact(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.collector = source["collector"];
	        this.category = source["category"];
	        this.source = source["source"];
	        this.sensitive = source["sensitive"];
	        this.value = source["value"];
	    }
	}
	export class CollectorResult {
	    id: string;
	    mode: string;
	    sideEffects?: string[];
	    status: string;
	    durationMs: number;
	    factCount?: number;
	    facts?: Fact[];
	    errors?: ErrorEntry[];
	
	    static createFrom(source: any = {}) {
	        return new CollectorResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.mode = source["mode"];
	        this.sideEffects = source["sideEffects"];
	        this.status = source["status"];
	        this.durationMs = source["durationMs"];
	        this.factCount = source["factCount"];
	        this.facts = this.convertValues(source["facts"], Fact);
	        this.errors = this.convertValues(source["errors"], ErrorEntry);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	export class Finding {
	    severity: string;
	    category: string;
	    confidence?: string;
	    title: string;
	    description: string;
	    evidence: string;
	
	    static createFrom(source: any = {}) {
	        return new Finding(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.severity = source["severity"];
	        this.category = source["category"];
	        this.confidence = source["confidence"];
	        this.title = source["title"];
	        this.description = source["description"];
	        this.evidence = source["evidence"];
	    }
	}
	export class TargetInfo {
	    inKubernetes: boolean;
	    namespace?: string;
	    podName?: string;
	    apiServer?: string;
	
	    static createFrom(source: any = {}) {
	        return new TargetInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.inKubernetes = source["inKubernetes"];
	        this.namespace = source["namespace"];
	        this.podName = source["podName"];
	        this.apiServer = source["apiServer"];
	    }
	}
	export class RunInfo {
	    id: string;
	    startedAt: string;
	    finishedAt: string;
	    durationMs: number;
	    hostname?: string;
	    toolVersion: string;
	    args?: string[];
	
	    static createFrom(source: any = {}) {
	        return new RunInfo(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.startedAt = source["startedAt"];
	        this.finishedAt = source["finishedAt"];
	        this.durationMs = source["durationMs"];
	        this.hostname = source["hostname"];
	        this.toolVersion = source["toolVersion"];
	        this.args = source["args"];
	    }
	}
	export class Document {
	    schemaVersion: string;
	    run: RunInfo;
	    target: TargetInfo;
	    mode: string;
	    collectors: CollectorResult[];
	    facts: Fact[];
	    findings: Finding[];
	    errors?: ErrorEntry[];
	
	    static createFrom(source: any = {}) {
	        return new Document(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.schemaVersion = source["schemaVersion"];
	        this.run = this.convertValues(source["run"], RunInfo);
	        this.target = this.convertValues(source["target"], TargetInfo);
	        this.mode = source["mode"];
	        this.collectors = this.convertValues(source["collectors"], CollectorResult);
	        this.facts = this.convertValues(source["facts"], Fact);
	        this.findings = this.convertValues(source["findings"], Finding);
	        this.errors = this.convertValues(source["errors"], ErrorEntry);
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}
	
	
	
	

}

export namespace scanner {
	
	export class ScanOptions {
	    mode: string;
	    timeout: number;
	    sensitive: string;
	    rbacMode: string;
	    credentialSweep: boolean;
	    maxItems: number;
	
	    static createFrom(source: any = {}) {
	        return new ScanOptions(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.mode = source["mode"];
	        this.timeout = source["timeout"];
	        this.sensitive = source["sensitive"];
	        this.rbacMode = source["rbacMode"];
	        this.credentialSweep = source["credentialSweep"];
	        this.maxItems = source["maxItems"];
	    }
	}
	export class ScanResult {
	    id: string;
	    source: string;
	    sourcePath?: string;
	    document?: model.Document;
	    loadedAt: string;
	    factCount: number;
	    errorCount: number;
	
	    static createFrom(source: any = {}) {
	        return new ScanResult(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.source = source["source"];
	        this.sourcePath = source["sourcePath"];
	        this.document = this.convertValues(source["document"], model.Document);
	        this.loadedAt = source["loadedAt"];
	        this.factCount = source["factCount"];
	        this.errorCount = source["errorCount"];
	    }
	
		convertValues(a: any, classs: any, asMap: boolean = false): any {
		    if (!a) {
		        return a;
		    }
		    if (a.slice && a.map) {
		        return (a as any[]).map(elem => this.convertValues(elem, classs));
		    } else if ("object" === typeof a) {
		        if (asMap) {
		            for (const key of Object.keys(a)) {
		                a[key] = new classs(a[key]);
		            }
		            return a;
		        }
		        return new classs(a);
		    }
		    return a;
		}
	}

}

export namespace store {
	
	export class ClusterEntry {
	    id: string;
	    name: string;
	    type: string;
	    apiServer?: string;
	    namespace?: string;
	    insecure?: boolean;
	    apiPathPrefix?: string;
	    ciphertext: string;
	    nonce: string;
	
	    static createFrom(source: any = {}) {
	        return new ClusterEntry(source);
	    }
	
	    constructor(source: any = {}) {
	        if ('string' === typeof source) source = JSON.parse(source);
	        this.id = source["id"];
	        this.name = source["name"];
	        this.type = source["type"];
	        this.apiServer = source["apiServer"];
	        this.namespace = source["namespace"];
	        this.insecure = source["insecure"];
	        this.apiPathPrefix = source["apiPathPrefix"];
	        this.ciphertext = source["ciphertext"];
	        this.nonce = source["nonce"];
	    }
	}

}
