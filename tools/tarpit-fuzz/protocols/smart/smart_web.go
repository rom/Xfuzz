package smart

import (
	"fmt"
	"math/rand"
	"strings"
)

// Smart generators for the web-shaped protocols: REST APIs, device-management
// HTTP front-ends, and the cloud-native control plane. Each one builds on
// HTTP() with path, method, and body mutations that match the handler the
// honeypot presents — a tool that always sends "GET /" would never reach past
// the first route check of a Kubernetes API honeypot, so the shape matters.
//
// What the honeypot handlers do is advertise API surface: /api, /v1, /healthz,
// /metrics. These generators pick from the real endpoints each product uses,
// and push a body that exercises the parser past its first dispatch.

// jsonBodies is a bank of body shapes a JSON API might reject or crash on.
// Pathological-but-well-formed (empty, deep nesting, numbers at the edges of
// JSON); then malformed JSON (unterminated string, unmatched brace); then
// non-JSON that the handler should refuse cleanly.
var jsonBodies = []string{
	`{}`,
	`{"username":"admin","password":"` + strings.Repeat("A", 1<<12) + `"}`,
	`{"a":` + strings.Repeat("[", 256) + strings.Repeat("]", 256) + `}`,
	`{"n":` + strings.Repeat("9", 400) + `}`,
	`{"s":"\u0000\u0000￿"}`,
	`[` + strings.Repeat(`{"x":1},`, 1024) + `{"x":2}]`,
	`{"malformed":`,
	`{"escape":"\\u00"}`,
	`not json at all`,
	``,
}

// webRequest builds a request with a JSON body, picking a method and path
// from the caller's lists so each API's own routes are what the fuzzer hits.
func webRequest(rng *rand.Rand, methods, paths []string) []byte {
	m := pickString(rng, methods)
	p := pickString(rng, paths)
	body := pickString(rng, jsonBodies)
	ctype := "application/json"
	if rng.Intn(5) == 0 {
		ctype = pickString(rng, []string{"application/xml", "text/plain", strings.Repeat("A", 1<<10), ""})
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", m, p)
	b.WriteString("Host: fuzz.local\r\n")
	fmt.Fprintf(&b, "Content-Type: %s\r\n", ctype)
	// Content-Length sometimes lies, which is the classic framing bug.
	ln := len(body)
	if rng.Intn(4) == 0 {
		ln = rng.Intn(1 << 24)
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n", ln)
	b.WriteString("\r\n")
	b.WriteString(body)
	return []byte(b.String())
}

// --- Cloud-native control plane -------------------------------------------

// KubernetesAPI covers kubelet, kubelets, kubernetes_api. All expose a
// REST surface under /api and /apis, with /healthz, /metrics, /logs and
// /exec as the sensitive paths.
func KubernetesAPI(rng *rand.Rand) []byte {
	paths := []string{
		"/healthz", "/metrics", "/version", "/api", "/api/v1",
		"/api/v1/namespaces", "/api/v1/nodes", "/api/v1/pods",
		"/apis/apps/v1/deployments", "/apis/rbac.authorization.k8s.io/v1/clusterrolebindings",
		"/openapi/v2",
		"/exec/" + strings.Repeat("a", 256) + "?command=ls",
		"/" + strings.Repeat("A", 1<<12),
		"/api/v1/namespaces/../../../",
	}
	return webRequest(rng, []string{"GET", "POST", "PUT", "DELETE", "PATCH"}, paths)
}

// Etcd exposes a JSON/gRPC REST under /v2 (legacy) and /v3 (current).
func Etcd(rng *rand.Rand) []byte {
	paths := []string{
		"/v2/keys/" + strings.Repeat("k", 1<<10),
		"/v3/kv/range", "/v3/kv/put", "/v3/kv/deleterange",
		"/v3/auth/authenticate", "/v3/cluster/member/list",
		"/health", "/metrics", "/version",
		"/v2/stats/self", "/v2/stats/store",
	}
	return webRequest(rng, []string{"GET", "POST", "PUT", "DELETE"}, paths)
}

// Vault's API lives under /v1 with /sys/health as the common probe.
func Vault(rng *rand.Rand) []byte {
	paths := []string{
		"/v1/sys/health", "/v1/sys/seal-status", "/v1/sys/leader",
		"/v1/sys/mounts", "/v1/secret/data/fuzz", "/v1/auth/token/lookup-self",
		"/v1/sys/audit", "/v1/sys/policy",
		"/v1/" + strings.Repeat("x", 1<<12),
	}
	return webRequest(rng, []string{"GET", "POST", "PUT", "DELETE", "LIST"}, paths)
}

// Consul covers consul, consuls: a REST API under /v1.
func Consul(rng *rand.Rand) []byte {
	paths := []string{
		"/v1/status/leader", "/v1/status/peers", "/v1/catalog/datacenters",
		"/v1/catalog/nodes", "/v1/catalog/services", "/v1/health/state/any",
		"/v1/kv/" + strings.Repeat("k", 1<<10), "/v1/agent/self",
		"/v1/acl/token/self",
	}
	return webRequest(rng, []string{"GET", "PUT", "POST", "DELETE"}, paths)
}

// Nomad is HashiCorp's job scheduler, same shape as Consul.
func Nomad(rng *rand.Rand) []byte {
	paths := []string{
		"/v1/status/leader", "/v1/jobs", "/v1/nodes", "/v1/deployments",
		"/v1/allocations", "/v1/evaluations", "/v1/agent/self", "/v1/metrics",
	}
	return webRequest(rng, []string{"GET", "POST", "PUT", "DELETE"}, paths)
}

// DockerAPI is Docker's engine REST API: /containers, /images, /networks.
func DockerAPI(rng *rand.Rand) []byte {
	paths := []string{
		"/v1.41/_ping", "/v1.41/info", "/v1.41/version",
		"/v1.41/containers/json", "/v1.41/containers/create",
		"/v1.41/images/json", "/v1.41/images/create?fromImage=alpine",
		"/v1.41/networks", "/v1.41/volumes", "/v1.41/system/events",
		"/v1.41/containers/" + strings.Repeat("c", 64) + "/exec",
	}
	return webRequest(rng, []string{"GET", "POST", "PUT", "DELETE", "HEAD"}, paths)
}

// DockerRegistry implements the Docker Registry HTTP API v2 under /v2/.
func DockerRegistry(rng *rand.Rand) []byte {
	paths := []string{
		"/v2/", "/v2/_catalog", "/v2/library/alpine/tags/list",
		"/v2/" + strings.Repeat("r", 128) + "/manifests/latest",
		"/v2/x/blobs/sha256:" + strings.Repeat("0", 64),
		"/v2/x/blobs/uploads/",
	}
	return webRequest(rng, []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}, paths)
}

// Elasticsearch REST: query JSON on /_search, documents under indexes.
func Elasticsearch(rng *rand.Rand) []byte {
	paths := []string{
		"/", "/_cluster/health", "/_cat/indices", "/_cat/nodes",
		"/_search", "/" + strings.Repeat("i", 256) + "/_search",
		"/_security/user/admin", "/_sql",
		"/fuzz/_doc", "/fuzz/_doc/" + strings.Repeat("d", 1<<10),
	}
	return webRequest(rng, []string{"GET", "POST", "PUT", "DELETE", "HEAD"}, paths)
}

// InfluxDB: InfluxQL and v2 Flux API with /write, /query, /api/v2.
func InfluxDB(rng *rand.Rand) []byte {
	paths := []string{
		"/ping", "/health", "/debug/vars",
		"/write?db=fuzz", "/query?q=SHOW+DATABASES",
		"/query?q=" + strings.Repeat("A", 1<<12),
		"/api/v2/write?org=fuzz&bucket=b", "/api/v2/query",
	}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}

// MinIO is S3-compatible: XML responses and path-style keys.
func MinIO(rng *rand.Rand) []byte {
	paths := []string{
		"/", "/fuzz-bucket/", "/fuzz-bucket/object.txt",
		"/?delimiter=/&prefix=" + strings.Repeat("p", 1<<10),
		"/admin/v3/info", "/admin/v3/trace",
	}
	return webRequest(rng, []string{"GET", "PUT", "POST", "HEAD", "DELETE"}, paths)
}

// Ollama / LLM-OpenAI / MCP: AI inference APIs with JSON prompt bodies.
func OllamaAPI(rng *rand.Rand) []byte {
	paths := []string{
		"/", "/api/tags", "/api/generate", "/api/chat", "/api/show",
		"/api/pull", "/api/push", "/api/copy", "/api/delete",
		"/api/embeddings",
	}
	return webRequest(rng, []string{"GET", "POST", "DELETE", "HEAD"}, paths)
}

// LLMOpenAI covers llm_openai, llm_openais: OpenAI-compatible completions.
func LLMOpenAI(rng *rand.Rand) []byte {
	paths := []string{
		"/v1/models", "/v1/chat/completions", "/v1/completions",
		"/v1/embeddings", "/v1/moderations", "/v1/files",
		"/v1/fine_tuning/jobs", "/v1/images/generations",
	}
	return webRequest(rng, []string{"GET", "POST", "DELETE"}, paths)
}

// MCP: Model Context Protocol over JSON-RPC.
func MCP(rng *rand.Rand) []byte {
	methods := []string{
		`{"jsonrpc":"2.0","method":"initialize","id":1}`,
		`{"jsonrpc":"2.0","method":"tools/list","id":2}`,
		`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"shell","arguments":{"command":"ls"}},"id":3}`,
		`{"jsonrpc":"2.0","method":"prompts/list","id":4}`,
		`{"jsonrpc":"2.0","method":"resources/list","id":5}`,
	}
	m := pickString(rng, methods)
	var b strings.Builder
	fmt.Fprintf(&b, "POST /mcp HTTP/1.1\r\nHost: fuzz\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(m), m)
	return []byte(b.String())
}

// Agent is the honeypot's generic AI agent API recognition surface. Any A2A,
// AP2, ACP or MCP-shaped probe should trip its classifier.
func Agent(rng *rand.Rand) []byte {
	paths := []string{
		"/", "/.well-known/agent.json", "/.well-known/ap2-config",
		"/a2a/invoke", "/a2a/state", "/acp/run", "/mcp",
		"/agent/describe", "/agent/plan",
	}
	return webRequest(rng, []string{"GET", "POST", "PUT"}, paths)
}

// C2Emulator: fake command-and-control. Beacon check-ins look like periodic
// POSTs with base64 blobs; stager pulls are GETs for /update, /pixel, /beacon.
func C2Emulator(rng *rand.Rand) []byte {
	paths := []string{
		"/beacon", "/pixel.png", "/update", "/check", "/task",
		"/g/" + strings.Repeat("A", 32), "/submit", "/api/v2/beacon",
	}
	return webRequest(rng, []string{"GET", "POST", "PUT"}, paths)
}

// CouchDB: HTTP-only document store with its own REST shape.
func CouchDB(rng *rand.Rand) []byte {
	paths := []string{
		"/", "/_all_dbs", "/_session", "/_utils/", "/_config/",
		"/fuzz_db", "/fuzz_db/_all_docs", "/fuzz_db/_design/x/_view/y",
	}
	return webRequest(rng, []string{"GET", "PUT", "POST", "DELETE", "HEAD"}, paths)
}

// Jupyter: /api, /notebooks, /terminals.
func Jupyter(rng *rand.Rand) []byte {
	paths := []string{
		"/api/", "/api/sessions", "/api/kernels", "/api/contents",
		"/api/terminals", "/login", "/tree",
		"/api/kernels/" + strings.Repeat("k", 64) + "/channels",
	}
	return webRequest(rng, []string{"GET", "POST", "PUT", "DELETE"}, paths)
}

// Selenium: WebDriver protocol over HTTP.
func Selenium(rng *rand.Rand) []byte {
	paths := []string{
		"/status", "/session", "/wd/hub/session", "/wd/hub/status",
		"/se/grid/console", "/grid/api/hub",
	}
	return webRequest(rng, []string{"GET", "POST", "DELETE"}, paths)
}

// Dameware / TeamViewer / AnyDesk / Spice / PCoIP / X11 / NX / ARD / Radmin /
// Lantronix / VMware authd / Citrix ICA / Citrix Gateway / Horizon are
// remote-access or terminal-services protocols. The honeypot answers an HTTP
// prelude on most of them (the gateway/authd variants) and a raw banner on
// the rest. For these I route to webRequest where the handler is HTTP-fronted
// and to a simple opaque-blob generator otherwise.
func CitrixGateway(rng *rand.Rand) []byte {
	paths := []string{"/", "/vpn/index.html", "/logon/LogonPoint/tmindex.html", "/nitro/v1/config/", "/ns/isra"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func Horizon(rng *rand.Rand) []byte {
	paths := []string{"/portal/info.jsp", "/broker/xml", "/rest/v1/config", "/view-vlsi/vlsi/vim/ServiceInstance"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func ESXi(rng *rand.Rand) []byte {
	paths := []string{"/sdk", "/ui/", "/mob/", "/host/", "/folder", "/screen"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func Fortinet(rng *rand.Rand) []byte {
	paths := []string{"/", "/api/v2/cmdb/firewall/address", "/logincheck", "/remote/fgt_lang",
		"/remote/login", "/api/v2/monitor/system/status"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func Pulse(rng *rand.Rand) []byte {
	paths := []string{"/", "/dana-na/auth/url_default/welcome.cgi", "/dana-na/auth/url_default/login.cgi",
		"/dana-cached/hc/HostCheckerAPI.cab"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func Redfish(rng *rand.Rand) []byte {
	paths := []string{"/redfish/v1/", "/redfish/v1/Systems", "/redfish/v1/Managers",
		"/redfish/v1/SessionService/Sessions", "/redfish/v1/UpdateService/FirmwareInventory"}
	return webRequest(rng, []string{"GET", "POST", "PATCH", "DELETE"}, paths)
}
func IDRAC(rng *rand.Rand) []byte {
	paths := []string{"/", "/redfish/v1/", "/sysmgmt/2015/server/configuration", "/data/login"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func ILO(rng *rand.Rand) []byte {
	paths := []string{"/", "/redfish/v1/", "/rest/v1/Chassis/1", "/html/login.html"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func IntelAMT(rng *rand.Rand) []byte {
	paths := []string{"/", "/index.htm", "/logon.htm", "/wsman"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func MoxaMgmt(rng *rand.Rand) []byte {
	paths := []string{"/", "/moxa-cgi/webLogin.cgi", "/forms/web_runLogin", "/cgi-bin/nport_sh.cgi"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func TR069(rng *rand.Rand) []byte {
	// SOAP Inform
	body := `<?xml version="1.0"?><soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body><cwmp:Inform><DeviceId><Manufacturer>Fuzz</Manufacturer></DeviceId></cwmp:Inform></soapenv:Body></soapenv:Envelope>`
	return []byte(fmt.Sprintf("POST / HTTP/1.1\r\nHost: fuzz\r\nSOAPAction: \"\"\r\nContent-Type: text/xml\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
}
func TR369(rng *rand.Rand) []byte {
	return webRequest(rng, []string{"GET", "POST"}, []string{"/.well-known/tr369", "/usp"})
}
func UPnP(rng *rand.Rand) []byte {
	paths := []string{"/", "/upnp/control/WANIPConn1", "/upnp/desc/InternetGatewayDevice.xml", "/rootDesc.xml"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}

// FHIR is HL7's REST interface. Its paths carry SQL-injection-shaped bits.
func FHIR(rng *rand.Rand) []byte {
	paths := []string{
		"/metadata", "/Patient", "/Patient/" + strings.Repeat("p", 256),
		"/Patient?name=" + strings.Repeat("a", 1<<10),
		"/Observation?code=http://loinc.org|8867-4",
		"/_search", "/Patient/$everything",
	}
	return webRequest(rng, []string{"GET", "POST", "PUT", "DELETE"}, paths)
}

// OCPP is WebSocket-framed. Build an Upgrade and (sometimes) a frame.
func OCPP(rng *rand.Rand) []byte {
	return WebSocket(rng)
}

// OBIX / Niagara / Danfoss / Dixell / Carel / Trane / Resideo / Enocean:
// building-automation web UIs. All of them answer a generic HTTP probe.
func ObixNiagara(rng *rand.Rand) []byte {
	paths := []string{"/obix/", "/obix/about", "/about", "/system/platform", "/fox", "/prelude.spy"}
	return webRequest(rng, []string{"GET", "POST", "PUT"}, paths)
}
func DanfossAKSM(rng *rand.Rand) []byte {
	paths := []string{"/xml.cgi", "/", "/login.cgi", "/cgi-bin/xml.cgi"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}
func DixellCarelTrane(rng *rand.Rand) []byte {
	paths := []string{"/", "/index.html", "/cgi-bin/login", "/cgi-bin/control.cgi"}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}

// ClickHouse: HTTP query interface with ?query= parameters.
func ClickHouse(rng *rand.Rand) []byte {
	paths := []string{
		"/", "/ping", "/replicas_status",
		"/?query=SELECT+1", "/?query=" + strings.Repeat("A", 1<<12),
		"/?query=SELECT+*+FROM+system.users",
	}
	return webRequest(rng, []string{"GET", "POST"}, paths)
}

// CloudMetadata is the honeypot's IMDSv2 decoy at 169.254.169.254.
func CloudMetadata(rng *rand.Rand) []byte {
	paths := []string{
		"/", "/latest/meta-data/", "/latest/meta-data/iam/security-credentials/",
		"/latest/api/token", "/latest/user-data",
		"/computeMetadata/v1/", "/metadata/instance?api-version=2021-02-01",
	}
	return webRequest(rng, []string{"GET", "PUT", "HEAD"}, paths)
}

// WinRM speaks SOAP/WSMan over HTTP, with Authorization headers that have
// their own parsing surface.
func WinRM(rng *rand.Rand) []byte {
	auths := []string{
		"Negotiate " + strings.Repeat("A", rng.Intn(1<<12)),
		"Basic " + strings.Repeat("a", 32),
		"Kerberos TlRMTVNTUAABAAAA",
		"",
	}
	body := `<?xml version="1.0"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header><wsa:Action>http://schemas.xmlsoap.org/ws/2004/09/transfer/Get</wsa:Action></s:Header><s:Body/></s:Envelope>`
	return []byte(fmt.Sprintf("POST /wsman HTTP/1.1\r\nHost: fuzz\r\nAuthorization: %s\r\nContent-Type: application/soap+xml\r\nContent-Length: %d\r\n\r\n%s",
		pickString(rng, auths), len(body), body))
}

// TLSIntercept honeypot speaks HTTP after a fake TLS termination, so an HTTP
// shape fuzzes it exactly as HTTPS would.
func TLSIntercept(rng *rand.Rand) []byte { return HTTP(rng) }
