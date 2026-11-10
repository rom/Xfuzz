// Package protocols holds the catalogue of handlers a tarpit-honeypot exposes.
//
// Every TCP + UDP handler the honeypot's config whitelist accepts is listed
// here, so a fuzzing run can be as wide as the sensor itself. The honeypot's
// own catalogue is in internal/config/load.go: this list is kept in sync by
// hand (the two files have a drift test over `tarpit-honeypot list-handlers`
// in the repository's CI). Each row names its IANA port; a deployment that
// binds the handler elsewhere overrides it in the YAML config.
//
// A seed is a short recognisable packet, picked so the honeypot's parser
// does not dismiss the connection at byte one: that is what makes a byte-level
// mutation worth sending at all. Protocols with no documented shape (raw,
// auto, scripted, lua, echo, discard, daytime, chargen, qotd) carry no seed;
// the engine falls back to pure random bytes for those, which is exactly
// what dumb fuzzing is for.
package protocols

import (
	"github.com/rom/Xfuzz/tools/tarpit-fuzz/engine"
	"github.com/rom/Xfuzz/tools/tarpit-fuzz/protocols/smart"
)

// All returns the full catalogue, with the smart generators from the smart
// package wired in and the seeds attached. The slice is a fresh copy each
// call: the registry stays immutable, the caller may re-order.
func All() []engine.Protocol {
	return append(append([]engine.Protocol(nil), tcp()...), udp()...)
}

// tcp returns the TCP handlers.
func tcp() []engine.Protocol {
	return []engine.Protocol{
		// --- Shell and remote-login ---
		{Name: "ssh", Transport: "tcp", DefaultPort: 22, ServerFirst: true, Seeds: seedSSH, Smart: smart.SSH},
		{Name: "ssh_interactive", Transport: "tcp", DefaultPort: 22, ServerFirst: true, Seeds: seedSSH, Smart: smart.SSH},
		{Name: "telnet", Transport: "tcp", DefaultPort: 23, ServerFirst: true, Seeds: seedTelnet, Smart: smart.Telnet},
		{Name: "rlogin", Transport: "tcp", DefaultPort: 513, Seeds: seedRlogin, Smart: smart.Rlogin},
		{Name: "rsh", Transport: "tcp", DefaultPort: 514, Seeds: seedRsh, Smart: smart.Rsh},
		{Name: "rexec", Transport: "tcp", DefaultPort: 512, Seeds: seedRexec, Smart: smart.Rexec},
		{Name: "pcanywhere", Transport: "tcp", DefaultPort: 5631, Seeds: seedPCAnywhere, Smart: smart.PCAnywhere},
		{Name: "radmin", Transport: "tcp", DefaultPort: 4899, Seeds: seedRadmin, Smart: smart.Radmin},
		{Name: "dameware", Transport: "tcp", DefaultPort: 6129, Smart: smart.Dameware},
		{Name: "pcoip", Transport: "tcp", DefaultPort: 4172, Smart: smart.PCoIP},
		{Name: "spice", Transport: "tcp", DefaultPort: 5900, Smart: smart.Spice},
		{Name: "lantronix", Transport: "tcp", DefaultPort: 9999, Seeds: seedLantronix, Smart: smart.Lantronix},
		{Name: "tn3270", Transport: "tcp", DefaultPort: 23, Seeds: seedTn3270, Smart: smart.Tn3270},
		{Name: "ard", Transport: "tcp", DefaultPort: 3283, Smart: smart.ARD},

		// --- Web / HTTP family ---
		{Name: "http", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP, Smart: smart.HTTP},
		{Name: "https", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP, Smart: smart.HTTP},
		{Name: "websocket", Transport: "tcp", DefaultPort: 8080, Seeds: seedWebSocket, Smart: smart.WebSocket},
		{Name: "grpc", Transport: "tcp", DefaultPort: 50051, Seeds: seedGRPC, Smart: smart.GRPC},
		{Name: "ssrf_canary", Transport: "tcp", DefaultPort: 8081, Seeds: seedHTTP, Smart: smart.SSRFCanary},
		{Name: "rtsp", Transport: "tcp", DefaultPort: 554, Seeds: seedRTSP, Smart: smart.RTSP},
		{Name: "sip_tcp", Transport: "tcp", DefaultPort: 5060, Seeds: seedSIP, Smart: smart.SIP},
		{Name: "xmpp", Transport: "tcp", DefaultPort: 5222, Seeds: seedXMPP, Smart: smart.XMPP},
		{Name: "irc", Transport: "tcp", DefaultPort: 6667, ServerFirst: true, Seeds: seedIRC, Smart: smart.IRC},
		{Name: "nntp", Transport: "tcp", DefaultPort: 119, ServerFirst: true, Seeds: seedNNTP, Smart: smart.NNTP},
		{Name: "finger", Transport: "tcp", DefaultPort: 79, Seeds: seedFinger, Smart: smart.Finger},
		{Name: "gopher", Transport: "tcp", DefaultPort: 70, Seeds: seedGopher, Smart: smart.Gopher},
		{Name: "stomp", Transport: "tcp", DefaultPort: 61613, Seeds: seedSTOMP, Smart: smart.STOMP},
		{Name: "mbus", Transport: "tcp", DefaultPort: 10001, Seeds: seedMbus, Smart: smart.Mbus},

		// --- Mail ---
		{Name: "smtp_recv", Transport: "tcp", DefaultPort: 25, ServerFirst: true, Seeds: seedSMTP, Smart: smart.SMTP},
		{Name: "pop3", Transport: "tcp", DefaultPort: 110, ServerFirst: true, Seeds: seedPOP3, Smart: smart.POP3},
		{Name: "imap", Transport: "tcp", DefaultPort: 143, ServerFirst: true, Seeds: seedIMAP, Smart: smart.IMAP},
		{Name: "smtps", Transport: "tcp", DefaultPort: 465, TLS: true, ServerFirst: true, Seeds: seedSMTP, Smart: smart.SMTP},
		{Name: "pop3s", Transport: "tcp", DefaultPort: 995, TLS: true, ServerFirst: true, Seeds: seedPOP3, Smart: smart.POP3S},
		{Name: "imaps", Transport: "tcp", DefaultPort: 993, TLS: true, ServerFirst: true, Seeds: seedIMAP, Smart: smart.IMAPS},

		// --- File transfer ---
		{Name: "ftp", Transport: "tcp", DefaultPort: 21, ServerFirst: true, Seeds: seedFTP, Smart: smart.FTP},
		{Name: "ftps", Transport: "tcp", DefaultPort: 990, TLS: true, ServerFirst: true, Seeds: seedFTP, Smart: smart.FTPS},
		{Name: "ftp_files", Transport: "tcp", DefaultPort: 21, ServerFirst: true, Seeds: seedFTP, Smart: smart.FTP},
		{Name: "rsync", Transport: "tcp", DefaultPort: 873, ServerFirst: true, Seeds: seedRsync, Smart: smart.Rsync},
		{Name: "lpd", Transport: "tcp", DefaultPort: 515, Seeds: seedLPD, Smart: smart.LPD},
		{Name: "pjl", Transport: "tcp", DefaultPort: 9100, Seeds: seedPJL, Smart: smart.PJL},
		{Name: "ipp", Transport: "tcp", DefaultPort: 631, Seeds: seedIPP, Smart: smart.IPP},
		{Name: "afp", Transport: "tcp", DefaultPort: 548, Seeds: seedAFP, Smart: smart.AFP},
		{Name: "nbd", Transport: "tcp", DefaultPort: 10809, Seeds: seedNBD, Smart: smart.NBD},
		{Name: "git", Transport: "tcp", DefaultPort: 9418, Seeds: seedGit, Smart: smart.Git},
		{Name: "svn", Transport: "tcp", DefaultPort: 3690, ServerFirst: true, Seeds: seedSVN, Smart: smart.SVN},

		// --- Windows / AD ---
		{Name: "smb", Transport: "tcp", DefaultPort: 445, Seeds: seedSMB, Smart: smart.SMB},
		{Name: "rdp", Transport: "tcp", DefaultPort: 3389, Seeds: seedRDP, Smart: smart.RDP},
		{Name: "winrm", Transport: "tcp", DefaultPort: 5985, Seeds: seedWinRM, Smart: smart.WinRM},
		{Name: "dcerpc", Transport: "tcp", DefaultPort: 135, Seeds: seedDCERPC, Smart: smart.DCERPC},
		{Name: "ldap", Transport: "tcp", DefaultPort: 389, Seeds: seedLDAP, Smart: smart.LDAP},
		{Name: "ldaps", Transport: "tcp", DefaultPort: 636, TLS: true, Seeds: seedLDAP, Smart: smart.LDAP},
		{Name: "kerberos", Transport: "tcp", DefaultPort: 88, Seeds: seedKerberos, Smart: smart.Kerberos},

		// --- Databases ---
		{Name: "mysql", Transport: "tcp", DefaultPort: 3306, ServerFirst: true, Seeds: seedMySQL, Smart: smart.MySQL},
		{Name: "postgres", Transport: "tcp", DefaultPort: 5432, Seeds: seedPostgres, Smart: smart.Postgres},
		{Name: "mssql", Transport: "tcp", DefaultPort: 1433, Seeds: seedMSSQL, Smart: smart.MSSQL},
		{Name: "oracle_tns", Transport: "tcp", DefaultPort: 1521, Seeds: seedOracleTNS, Smart: smart.OracleTNS},
		{Name: "redis", Transport: "tcp", DefaultPort: 6379, Seeds: seedRedis, Smart: smart.Redis},
		{Name: "memcached", Transport: "tcp", DefaultPort: 11211, Seeds: seedMemcached, Smart: smart.Memcached},
		{Name: "mongodb", Transport: "tcp", DefaultPort: 27017, Seeds: seedMongoDB, Smart: smart.MongoDB},
		{Name: "elasticsearch", Transport: "tcp", DefaultPort: 9200, Seeds: seedHTTP, Smart: smart.Elasticsearch},
		{Name: "neo4j", Transport: "tcp", DefaultPort: 7687, Seeds: seedNeo4j, Smart: smart.Neo4j},
		{Name: "rethinkdb", Transport: "tcp", DefaultPort: 28015, Seeds: seedRethinkDB, Smart: smart.RethinkDB},
		{Name: "couchdb", Transport: "tcp", DefaultPort: 5984, Seeds: seedHTTP, Smart: smart.CouchDB},
		{Name: "influxdb", Transport: "tcp", DefaultPort: 8086, Seeds: seedHTTP, Smart: smart.InfluxDB},
		{Name: "cassandra", Transport: "tcp", DefaultPort: 9042, Seeds: seedCassandra, Smart: smart.Cassandra},
		{Name: "clickhouse", Transport: "tcp", DefaultPort: 9000, Seeds: seedHTTP, Smart: smart.ClickHouse},
		{Name: "clickhouses", Transport: "tcp", DefaultPort: 8443, TLS: true, Seeds: seedHTTP, Smart: smart.ClickHouse},

		// --- DNS ---
		{Name: "dns", Transport: "tcp", DefaultPort: 53, Seeds: seedDNSTCP, Smart: smart.DNSTCP},

		// --- OT / ICS / SCADA ---
		{Name: "modbus", Transport: "tcp", DefaultPort: 502, Seeds: seedModbus, Smart: smart.Modbus},
		{Name: "modbus_security", Transport: "tcp", DefaultPort: 802, TLS: true, Seeds: seedModbus, Smart: smart.Modbus},
		{Name: "modbuss", Transport: "tcp", DefaultPort: 802, TLS: true, Seeds: seedModbus, Smart: smart.Modbus},
		{Name: "s7", Transport: "tcp", DefaultPort: 102, Seeds: seedS7, Smart: smart.S7},
		{Name: "s7comm_plus", Transport: "tcp", DefaultPort: 102, Seeds: seedS7, Smart: smart.S7},
		{Name: "iec104", Transport: "tcp", DefaultPort: 2404, Seeds: seedIEC104, Smart: smart.IEC104},
		{Name: "iccp_secure", Transport: "tcp", DefaultPort: 102, Seeds: seedS7, Smart: smart.ICCPSecure},
		{Name: "dnp3", Transport: "tcp", DefaultPort: 20000, Seeds: seedDNP3, Smart: smart.DNP3},
		{Name: "ge_srtp", Transport: "tcp", DefaultPort: 18245, Seeds: seedGESRTP, Smart: smart.GESRTP},
		{Name: "codesys", Transport: "tcp", DefaultPort: 2455, Seeds: seedCodesys, Smart: smart.Codesys},
		{Name: "c37118", Transport: "tcp", DefaultPort: 4712, Seeds: seedC37118, Smart: smart.C37118},
		{Name: "osdp", Transport: "tcp", DefaultPort: 49152, Seeds: seedOSDP, Smart: smart.OSDP},
		{Name: "focas", Transport: "tcp", DefaultPort: 8193, Seeds: seedFocas, Smart: smart.Focas},
		{Name: "proconos", Transport: "tcp", DefaultPort: 20547, Smart: smart.Proconos},
		{Name: "osisoft_pi", Transport: "tcp", DefaultPort: 5450, Smart: smart.GenericLengthTCP},
		{Name: "proficy_historian", Transport: "tcp", DefaultPort: 14000, Smart: smart.GenericLengthTCP},
		{Name: "canary_historian", Transport: "tcp", DefaultPort: 54811, Smart: smart.GenericLengthTCP},
		{Name: "aspen_ip21", Transport: "tcp", DefaultPort: 10014, Smart: smart.GenericLengthTCP},
		{Name: "atg", Transport: "tcp", DefaultPort: 10001, Seeds: seedATG, Smart: smart.ATG},
		{Name: "fox", Transport: "tcp", DefaultPort: 1911, Seeds: seedFox, Smart: smart.ObixNiagara},
		{Name: "hartip", Transport: "tcp", DefaultPort: 5094, Seeds: seedHARTIP, Smart: smart.HARTIP},
		{Name: "pcworx", Transport: "tcp", DefaultPort: 1962, Seeds: seedPCWorx, Smart: smart.PCWorx},
		{Name: "mms", Transport: "tcp", DefaultPort: 102, Seeds: seedMMS, Smart: smart.MMS},
		{Name: "opcua", Transport: "tcp", DefaultPort: 4840, Seeds: seedOPCUA, Smart: smart.OPCUA},
		{Name: "ethernetip", Transport: "tcp", DefaultPort: 44818, Seeds: seedEtherNetIP, Smart: smart.EtherNetIP},
		{Name: "melsec", Transport: "tcp", DefaultPort: 5007, Seeds: seedMelsec, Smart: smart.Melsec},
		{Name: "fins_tcp", Transport: "tcp", DefaultPort: 9600, Seeds: seedFINS, Smart: smart.FINSTCP},
		{Name: "secs_gem", Transport: "tcp", DefaultPort: 5000, Seeds: seedSECSGEM, Smart: smart.SECSGEM},
		{Name: "pcom", Transport: "tcp", DefaultPort: 20256, Seeds: seedPCOM, Smart: smart.PCOM},
		{Name: "roc_plus", Transport: "tcp", DefaultPort: 4000, Seeds: seedROCPlus, Smart: smart.ROCPlus},
		{Name: "crimson", Transport: "tcp", DefaultPort: 789, Smart: smart.Crimson},
		{Name: "danfoss_aksm", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP, Smart: smart.DanfossAKSM},
		{Name: "danfoss_aksms", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP, Smart: smart.DanfossAKSM},

		// --- Messaging / queuing ---
		{Name: "mqtt", Transport: "tcp", DefaultPort: 1883, Seeds: seedMQTT, Smart: smart.MQTT},
		{Name: "mqtts", Transport: "tcp", DefaultPort: 8883, TLS: true, Seeds: seedMQTT, Smart: smart.MQTT},
		{Name: "amqp", Transport: "tcp", DefaultPort: 5672, Seeds: seedAMQP, Smart: smart.AMQP},
		{Name: "ibmmq", Transport: "tcp", DefaultPort: 1414, Seeds: seedIBMMQ, Smart: smart.IBMMQ},
		{Name: "mq", Transport: "tcp", DefaultPort: 1414, Seeds: seedIBMMQ, Smart: smart.IBMMQ},
		{Name: "websphere_mq", Transport: "tcp", DefaultPort: 1414, Seeds: seedIBMMQ, Smart: smart.WebSphereMQ},
		{Name: "nats", Transport: "tcp", DefaultPort: 4222, ServerFirst: true, Seeds: seedNATS, Smart: smart.NATS},
		{Name: "kafka", Transport: "tcp", DefaultPort: 9092, Seeds: seedKafka, Smart: smart.Kafka},
		{Name: "zookeeper", Transport: "tcp", DefaultPort: 2181, Seeds: seedZookeeper, Smart: smart.Zookeeper},
		{Name: "beanstalkd", Transport: "tcp", DefaultPort: 11300, Seeds: seedBeanstalkd, Smart: smart.Beanstalkd},

		// --- Logging / telemetry ---
		{Name: "syslog_tcp", Transport: "tcp", DefaultPort: 601, Seeds: seedSyslog, Smart: smart.SyslogTCP},

		// --- Java / enterprise ---
		{Name: "jdwp", Transport: "tcp", DefaultPort: 8000, ServerFirst: true, Seeds: seedJDWP, Smart: smart.JDWP},
		{Name: "rmi", Transport: "tcp", DefaultPort: 1099, Seeds: seedRMI, Smart: smart.RMI},
		{Name: "jupyter", Transport: "tcp", DefaultPort: 8888, Seeds: seedHTTP, Smart: smart.Jupyter},
		{Name: "jupyters", Transport: "tcp", DefaultPort: 8888, TLS: true, Seeds: seedHTTP, Smart: smart.Jupyter},
		{Name: "selenium", Transport: "tcp", DefaultPort: 4444, Seeds: seedHTTP, Smart: smart.Selenium},

		// --- Cloud native / DevOps ---
		{Name: "kubernetes_api", Transport: "tcp", DefaultPort: 6443, TLS: true, Seeds: seedHTTP, Smart: smart.KubernetesAPI},
		{Name: "kubelet", Transport: "tcp", DefaultPort: 10255, Seeds: seedHTTP, Smart: smart.KubernetesAPI},
		{Name: "kubelets", Transport: "tcp", DefaultPort: 10250, TLS: true, Seeds: seedHTTP, Smart: smart.KubernetesAPI},
		{Name: "etcd", Transport: "tcp", DefaultPort: 2379, Seeds: seedHTTP, Smart: smart.Etcd},
		{Name: "vault", Transport: "tcp", DefaultPort: 8200, Seeds: seedHTTP, Smart: smart.Vault},
		{Name: "consul", Transport: "tcp", DefaultPort: 8500, Seeds: seedHTTP, Smart: smart.Consul},
		{Name: "consuls", Transport: "tcp", DefaultPort: 8501, TLS: true, Seeds: seedHTTP, Smart: smart.Consul},
		{Name: "nomad", Transport: "tcp", DefaultPort: 4646, Seeds: seedHTTP, Smart: smart.Nomad},
		{Name: "minio", Transport: "tcp", DefaultPort: 9001, Seeds: seedHTTP, Smart: smart.MinIO},
		{Name: "minios", Transport: "tcp", DefaultPort: 9000, TLS: true, Seeds: seedHTTP, Smart: smart.MinIO},
		{Name: "cloud_metadata", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP, Smart: smart.CloudMetadata},
		{Name: "docker_registry", Transport: "tcp", DefaultPort: 5000, Seeds: seedHTTP, Smart: smart.DockerRegistry},
		{Name: "dockerapi", Transport: "tcp", DefaultPort: 2375, Seeds: seedHTTP, Smart: smart.DockerAPI},

		// --- AI / LLM / MCP ---
		{Name: "ollama", Transport: "tcp", DefaultPort: 11434, Seeds: seedHTTP, Smart: smart.OllamaAPI},
		{Name: "ollamas", Transport: "tcp", DefaultPort: 11435, TLS: true, Seeds: seedHTTP, Smart: smart.OllamaAPI},
		{Name: "llm_openai", Transport: "tcp", DefaultPort: 8080, Seeds: seedHTTP, Smart: smart.LLMOpenAI},
		{Name: "llm_openais", Transport: "tcp", DefaultPort: 8443, TLS: true, Seeds: seedHTTP, Smart: smart.LLMOpenAI},
		{Name: "mcp", Transport: "tcp", DefaultPort: 7777, Seeds: seedHTTP, Smart: smart.MCP},
		{Name: "mcps", Transport: "tcp", DefaultPort: 7778, TLS: true, Seeds: seedHTTP, Smart: smart.MCP},
		{Name: "agent", Transport: "tcp", DefaultPort: 8686, Seeds: seedHTTP, Smart: smart.Agent},

		// --- Classic small services ---
		{Name: "echo", Transport: "tcp", DefaultPort: 7, Smart: smart.EchoSmall},
		{Name: "discard", Transport: "tcp", DefaultPort: 9, Smart: smart.DiscardSmall},
		{Name: "daytime", Transport: "tcp", DefaultPort: 13, ServerFirst: true, Smart: smart.DaytimeSmall},
		{Name: "qotd", Transport: "tcp", DefaultPort: 17, ServerFirst: true, Smart: smart.QotdSmall},
		{Name: "chargen", Transport: "tcp", DefaultPort: 19, ServerFirst: true, Smart: smart.ChargenSmall},
		{Name: "time", Transport: "tcp", DefaultPort: 37, ServerFirst: true, Smart: smart.TimeSmall},
		{Name: "ident", Transport: "tcp", DefaultPort: 113, Seeds: seedIdent, Smart: smart.Ident},

		// --- AMQP family / scientific ---
		{Name: "dlms", Transport: "tcp", DefaultPort: 4059, Seeds: seedDLMS, Smart: smart.DLMS},
		{Name: "ads", Transport: "tcp", DefaultPort: 48898, Seeds: seedADS, Smart: smart.ADS},
		{Name: "nts", Transport: "tcp", DefaultPort: 4460, TLS: true, Smart: smart.NTS},

		// --- Remote-access / VDI ---
		{Name: "vnc", Transport: "tcp", DefaultPort: 5900, ServerFirst: true, Seeds: seedVNC, Smart: smart.VNC},
		{Name: "teamviewer", Transport: "tcp", DefaultPort: 5938, Seeds: seedTeamViewer, Smart: smart.TeamViewer},
		{Name: "anydesk", Transport: "tcp", DefaultPort: 7070, Seeds: seedAnyDesk, Smart: smart.AnyDesk},
		{Name: "openvpn", Transport: "tcp", DefaultPort: 1194, Seeds: seedOpenVPN, Smart: smart.OpenVPN},
		{Name: "citrix_ica", Transport: "tcp", DefaultPort: 1494, Seeds: seedCitrixICA, Smart: smart.CitrixICA},
		{Name: "citrix_gateway", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP, Smart: smart.CitrixGateway},
		{Name: "vmware_authd", Transport: "tcp", DefaultPort: 902, ServerFirst: true, Seeds: seedVMwareAuthd, Smart: smart.VMwareAuthd},
		{Name: "x11", Transport: "tcp", DefaultPort: 6000, Seeds: seedX11, Smart: smart.X11},
		{Name: "horizon", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP, Smart: smart.Horizon},
		{Name: "nx", Transport: "tcp", DefaultPort: 4000, Seeds: seedNX, Smart: smart.NX},
		{Name: "redfish", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP, Smart: smart.Redfish},

		// --- Device management ---
		{Name: "tr069", Transport: "tcp", DefaultPort: 7547, Seeds: seedHTTP, Smart: smart.TR069},
		{Name: "upnp", Transport: "tcp", DefaultPort: 5000, Seeds: seedHTTP, Smart: smart.UPnP},
		{Name: "tr369", Transport: "tcp", DefaultPort: 8085, Seeds: seedHTTP, Smart: smart.TR369},
		{Name: "intel_amt", Transport: "tcp", DefaultPort: 16992, Seeds: seedHTTP, Smart: smart.IntelAMT},
		{Name: "ilo", Transport: "tcp", DefaultPort: 17988, Seeds: seedHTTP, Smart: smart.ILO},
		{Name: "idrac", Transport: "tcp", DefaultPort: 5900, Seeds: seedHTTP, Smart: smart.IDRAC},
		{Name: "esxi", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP, Smart: smart.ESXi},
		{Name: "fortinet", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP, Smart: smart.Fortinet},
		{Name: "pulse", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP, Smart: smart.Pulse},
		{Name: "moxa_mgmt", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP, Smart: smart.MoxaMgmt},

		// --- Voice / H.323 / SIP ---
		{Name: "sccp", Transport: "tcp", DefaultPort: 2000, Seeds: seedSCCP, Smart: smart.SCCP},
		{Name: "h323", Transport: "tcp", DefaultPort: 1720, Seeds: seedH323, Smart: smart.H323},
		{Name: "asterisk_ami", Transport: "tcp", DefaultPort: 5038, ServerFirst: true, Seeds: seedAsteriskAMI, Smart: smart.AsteriskAMI},

		// --- Fake C2 / adversary ---
		{Name: "c2_emulator", Transport: "tcp", DefaultPort: 8282, Seeds: seedHTTP, Smart: smart.C2Emulator},

		// --- Classic Unix ---
		{Name: "rpcbind", Transport: "tcp", DefaultPort: 111, Seeds: seedRpcbind, Smart: smart.RPCBind},
		{Name: "nfs", Transport: "tcp", DefaultPort: 2049, Seeds: seedNFS, Smart: smart.NFS},
		{Name: "pptp", Transport: "tcp", DefaultPort: 1723, Seeds: seedPPTP, Smart: smart.PPTP},
		{Name: "adb", Transport: "tcp", DefaultPort: 5555, Seeds: seedADB, Smart: smart.ADB},
		{Name: "ajp13", Transport: "tcp", DefaultPort: 8009, Seeds: seedAJP13, Smart: smart.AJP13},
		{Name: "epmd", Transport: "tcp", DefaultPort: 4369, Seeds: seedEPMD, Smart: smart.EPMD},
		{Name: "tacacs", Transport: "tcp", DefaultPort: 49, Seeds: seedTACACS, Smart: smart.TACACS},

		// --- BACnet Secure Connect ---
		{Name: "bacnet_sc", Transport: "tcp", DefaultPort: 47808, Seeds: seedBACnetSC, Smart: smart.BACnetSC},
		{Name: "bacnet_scs", Transport: "tcp", DefaultPort: 47809, TLS: true, Seeds: seedBACnetSC, Smart: smart.BACnetSC},

		// --- Healthcare ---
		{Name: "hl7", Transport: "tcp", DefaultPort: 2575, Seeds: seedHL7, Smart: smart.DICOM},
		{Name: "hl7s", Transport: "tcp", DefaultPort: 2576, TLS: true, Seeds: seedHL7, Smart: smart.DICOM},
		{Name: "dicom", Transport: "tcp", DefaultPort: 104, Seeds: seedDICOM, Smart: smart.DICOM},
		{Name: "dicoms", Transport: "tcp", DefaultPort: 2762, TLS: true, Seeds: seedDICOM, Smart: smart.DICOM},
		{Name: "astm", Transport: "tcp", DefaultPort: 12001, Seeds: seedASTM, Smart: smart.ASTM},
		{Name: "poct1", Transport: "tcp", DefaultPort: 12002, Smart: smart.POCT1},
		{Name: "fhir", Transport: "tcp", DefaultPort: 8080, Seeds: seedHTTP, Smart: smart.FHIR},
		{Name: "fhirs", Transport: "tcp", DefaultPort: 8443, TLS: true, Seeds: seedHTTP, Smart: smart.FHIR},

		// --- BAS / building automation ---
		{Name: "niagara_platform", Transport: "tcp", DefaultPort: 3011, Seeds: seedNiagara, Smart: smart.ObixNiagara},
		{Name: "obix", Transport: "tcp", DefaultPort: 8080, Seeds: seedHTTP, Smart: smart.ObixNiagara},
		{Name: "enocean", Transport: "tcp", DefaultPort: 2080, Smart: smart.GenericLengthTCP},
		{Name: "dixell", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP, Smart: smart.DixellCarelTrane},
		{Name: "carel", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP, Smart: smart.DixellCarelTrane},
		{Name: "trane", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP, Smart: smart.DixellCarelTrane},
		{Name: "resideo", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP, Smart: smart.DixellCarelTrane},
		{Name: "ocpp", Transport: "tcp", DefaultPort: 80, Seeds: seedWebSocket, Smart: smart.OCPP},

		// --- BGP / routing ---
		{Name: "bgp", Transport: "tcp", DefaultPort: 179, Seeds: seedBGP, Smart: smart.BGP},
		{Name: "socks", Transport: "tcp", DefaultPort: 1080, Seeds: seedSOCKS, Smart: smart.Socks},

		// --- Fall-throughs / scripted ---
		{Name: "raw", Transport: "tcp", DefaultPort: 9000, Smart: smart.RawFallthrough},
		{Name: "auto", Transport: "tcp", DefaultPort: 29999, Smart: smart.RawFallthrough},
		{Name: "scripted", Transport: "tcp", DefaultPort: 9001, Smart: smart.RawFallthrough},
		{Name: "lua", Transport: "tcp", DefaultPort: 9002, Smart: smart.RawFallthrough},
		{Name: "tls_intercept", Transport: "tcp", DefaultPort: 8443, TLS: true, Seeds: seedHTTP, Smart: smart.TLSIntercept},
	}
}

// udp returns the UDP handlers.
func udp() []engine.Protocol {
	return []engine.Protocol{
		{Name: "dns", Transport: "udp", DefaultPort: 53, Seeds: seedDNSUDP, Smart: smart.DNS},
		{Name: "mdns", Transport: "udp", DefaultPort: 5353, Seeds: seedMDNS, Smart: smart.MDNS},
		{Name: "llmnr", Transport: "udp", DefaultPort: 5355, Seeds: seedLLMNR, Smart: smart.LLMNR},
		{Name: "nbns", Transport: "udp", DefaultPort: 137, Seeds: seedNBNS, Smart: smart.NBNS},
		{Name: "ssdp", Transport: "udp", DefaultPort: 1900, Seeds: seedSSDP, Smart: smart.SSDP},
		{Name: "cldap", Transport: "udp", DefaultPort: 389, Seeds: seedLDAP, Smart: smart.CLDAP},
		{Name: "netbios_dgram", Transport: "udp", DefaultPort: 138, Seeds: seedNBNS, Smart: smart.NetBIOSDgram},

		{Name: "snmp", Transport: "udp", DefaultPort: 161, Seeds: seedSNMP, Smart: smart.SNMP},
		{Name: "snmptrap", Transport: "udp", DefaultPort: 162, Seeds: seedSNMP, Smart: smart.SNMP},
		{Name: "ntp", Transport: "udp", DefaultPort: 123, Seeds: seedNTP, Smart: smart.NTP},
		{Name: "chronyd", Transport: "udp", DefaultPort: 323, Seeds: seedNTP, Smart: smart.Chronyd},
		{Name: "syslog_udp", Transport: "udp", DefaultPort: 514, Seeds: seedSyslog, Smart: smart.SyslogUDP},
		{Name: "tftp", Transport: "udp", DefaultPort: 69, Seeds: seedTFTP, Smart: smart.TFTP},
		{Name: "radius", Transport: "udp", DefaultPort: 1812, Seeds: seedRADIUS, Smart: smart.RADIUS},
		{Name: "radius_acct", Transport: "udp", DefaultPort: 1813, Seeds: seedRADIUS, Smart: smart.RADIUS},
		{Name: "ipmi", Transport: "udp", DefaultPort: 623, Seeds: seedIPMI, Smart: smart.IPMI},
		{Name: "bacnet", Transport: "udp", DefaultPort: 47808, Seeds: seedBACnetUDP, Smart: smart.BACnet},
		{Name: "dhcp", Transport: "udp", DefaultPort: 67, Seeds: seedDHCP, Smart: smart.DHCP},
		{Name: "dhcpv6", Transport: "udp", DefaultPort: 547, Seeds: seedDHCPv6, Smart: smart.DHCPv6},
		{Name: "coap", Transport: "udp", DefaultPort: 5683, Seeds: seedCoAP, Smart: smart.CoAP},
		{Name: "sip", Transport: "udp", DefaultPort: 5060, Seeds: seedSIP, Smart: smart.SIP},
		{Name: "mgcp", Transport: "udp", DefaultPort: 2427, Seeds: seedMGCP, Smart: smart.MGCPSmart},
		{Name: "ethercat", Transport: "udp", DefaultPort: 34980, Smart: smart.Ethercat},

		{Name: "fins", Transport: "udp", DefaultPort: 9600, Seeds: seedFINS, Smart: smart.Fins},
		{Name: "knx", Transport: "udp", DefaultPort: 3671, Seeds: seedKNX, Smart: smart.KNX},
		{Name: "isakmp", Transport: "udp", DefaultPort: 500, Seeds: seedISAKMP, Smart: smart.ISAKMP},
		{Name: "stun", Transport: "udp", DefaultPort: 3478, Seeds: seedSTUN, Smart: smart.STUN},

		{Name: "mssql_browser", Transport: "udp", DefaultPort: 1434, Seeds: seedMSSQLBrowser, Smart: smart.MSSQLBrowser},
		{Name: "profinet", Transport: "udp", DefaultPort: 34964, Seeds: seedProfinet, Smart: smart.ProfinetSmart},
		{Name: "wdbrpc", Transport: "udp", DefaultPort: 17185, Smart: smart.WDBRPC},
		{Name: "iax2", Transport: "udp", DefaultPort: 4569, Seeds: seedIAX2, Smart: smart.IAX2},
		{Name: "ads_discovery", Transport: "udp", DefaultPort: 48899, Smart: smart.ADSDiscovery},

		{Name: "dtls", Transport: "udp", DefaultPort: 443, Seeds: seedDTLS, Smart: smart.DTLSSmart},
		{Name: "quic", Transport: "udp", DefaultPort: 443, Seeds: seedQUIC, Smart: smart.QUICSmart},
		{Name: "netflow", Transport: "udp", DefaultPort: 2055, Seeds: seedNetflow, Smart: smart.NetFlowSmart},
		{Name: "sflow", Transport: "udp", DefaultPort: 6343, Seeds: seedSflow, Smart: smart.SflowSmart},
		{Name: "statsd", Transport: "udp", DefaultPort: 8125, Seeds: seedStatsD, Smart: smart.StatsDSmart},
		{Name: "tristation", Transport: "udp", DefaultPort: 1502, Seeds: seedTristation, Smart: smart.Tristation},
		{Name: "ge_egd", Transport: "udp", DefaultPort: 18246, Smart: smart.GEEgD},
		{Name: "bsap", Transport: "udp", DefaultPort: 1234, Smart: smart.BSAP},
		{Name: "lontalk", Transport: "udp", DefaultPort: 1628, Smart: smart.Lontalk},
		{Name: "siprotec_en100", Transport: "udp", DefaultPort: 50000, Smart: smart.SiprotecEN100},
		{Name: "wsdiscovery", Transport: "udp", DefaultPort: 3702, Seeds: seedWSDiscovery, Smart: smart.WSDiscoverySmart},
		{Name: "memcached_udp", Transport: "udp", DefaultPort: 11211, Seeds: seedMemcached, Smart: smart.MemcachedUDPSmart},
		{Name: "natpmp", Transport: "udp", DefaultPort: 5351, Seeds: seedNATPMP, Smart: smart.NATPMP},
		{Name: "ubiquiti", Transport: "udp", DefaultPort: 10001, Seeds: seedUbiquiti, Smart: smart.Ubiquiti},
		{Name: "wireguard", Transport: "udp", DefaultPort: 51820, Seeds: seedWireGuard, Smart: smart.WireGuard},
		{Name: "openvpn_udp", Transport: "udp", DefaultPort: 1194, Seeds: seedOpenVPN, Smart: smart.OpenVPNUDP},
		{Name: "l2tp", Transport: "udp", DefaultPort: 1701, Seeds: seedL2TP, Smart: smart.L2TP},
		{Name: "rip", Transport: "udp", DefaultPort: 520, Seeds: seedRIP, Smart: smart.RIPSmart},
		{Name: "steam", Transport: "udp", DefaultPort: 27015, Seeds: seedSteam, Smart: smart.Steam},
		{Name: "sentinel_hasp", Transport: "udp", DefaultPort: 1947, Smart: smart.SentinelHASP},
		{Name: "mqtt_sn", Transport: "udp", DefaultPort: 1884, Seeds: seedMQTTSN, Smart: smart.MQTTSNSmart},
		{Name: "tplink_kasa", Transport: "udp", DefaultPort: 9999, Seeds: seedTPLinkKasa, Smart: smart.TPLinkKasa},
		{Name: "tuya", Transport: "udp", DefaultPort: 6667, Seeds: seedTuya, Smart: smart.Tuya},
		{Name: "miio", Transport: "udp", DefaultPort: 54321, Seeds: seedMiIO, Smart: smart.MiIO},
		{Name: "lwm2m", Transport: "udp", DefaultPort: 5683, Seeds: seedCoAP, Smart: smart.CoAP},
		{Name: "modbus_udp", Transport: "udp", DefaultPort: 502, Seeds: seedModbus, Smart: smart.Modbus},
		{Name: "enip_udp", Transport: "udp", DefaultPort: 44818, Seeds: seedEtherNetIP, Smart: smart.EnipUDP},
		{Name: "opcua_pubsub", Transport: "udp", DefaultPort: 4840, Seeds: seedOPCUA, Smart: smart.OPCUAPubSub},
		{Name: "dds_rtps", Transport: "udp", DefaultPort: 7400, Seeds: seedDDSRTPS, Smart: smart.DDSRtps},
		{Name: "hartip_udp", Transport: "udp", DefaultPort: 5094, Seeds: seedHARTIP, Smart: smart.HARTIPUDP},
		{Name: "crestron", Transport: "udp", DefaultPort: 41794, Seeds: seedCrestron, Smart: smart.Crestron},
		{Name: "pjlink", Transport: "udp", DefaultPort: 4352, Seeds: seedPJLink, Smart: smart.PJLink},
		{Name: "cbus", Transport: "udp", DefaultPort: 10001, Seeds: seedCBus, Smart: smart.CBus},
		{Name: "dnp3_udp", Transport: "udp", DefaultPort: 20000, Seeds: seedDNP3, Smart: smart.DNP3UDP},
		{Name: "saia_sbus", Transport: "udp", DefaultPort: 5050, Smart: smart.SaiaSBus},
		{Name: "slp", Transport: "udp", DefaultPort: 427, Seeds: seedSLP, Smart: smart.SLPSmart},
		{Name: "xdmcp", Transport: "udp", DefaultPort: 177, Seeds: seedXDMCP, Smart: smart.XDMCPSmart},
		{Name: "db_lsp", Transport: "udp", DefaultPort: 17500, Seeds: seedDropboxLSP, Smart: smart.DropboxLSP},
		{Name: "kerberos_udp", Transport: "udp", DefaultPort: 88, Seeds: seedKerberos, Smart: smart.KerberosUDP},
		{Name: "lantronix_disc", Transport: "udp", DefaultPort: 30718, Smart: smart.LantronixDisc},
		{Name: "pcanywhere_stat", Transport: "udp", DefaultPort: 5632, Smart: smart.PCAnywhereStat},
		{Name: "gamespy", Transport: "udp", DefaultPort: 27900, Seeds: seedGameSpy, Smart: smart.GameSpyUDP},
		{Name: "db2_disc", Transport: "udp", DefaultPort: 523, Smart: smart.DB2Disc},
		{Name: "bt_dht", Transport: "udp", DefaultPort: 6881, Seeds: seedBTDHT, Smart: smart.BTDHT},
		{Name: "rdp_udp", Transport: "udp", DefaultPort: 3389, Seeds: seedRDPUDP, Smart: smart.RDPUDPSmart},
		{Name: "matter", Transport: "udp", DefaultPort: 5540, Smart: smart.Matter},
		{Name: "wiz", Transport: "udp", DefaultPort: 38899, Seeds: seedWiZ, Smart: smart.WiZ},
		{Name: "yeelight", Transport: "udp", DefaultPort: 1982, Seeds: seedYeelight, Smart: smart.Yeelight},
		{Name: "dahua_disc", Transport: "udp", DefaultPort: 37810, Seeds: seedDahuaDisc, Smart: smart.DahuaDisc},
		{Name: "hikvision_sadp", Transport: "udp", DefaultPort: 37020, Seeds: seedHikvisionSADP, Smart: smart.HikvisionSADP},
		{Name: "powerlink", Transport: "udp", DefaultPort: 3819, Smart: smart.Powerlink},
		{Name: "slmp", Transport: "udp", DefaultPort: 47808, Seeds: seedSLMP, Smart: smart.SLMP},
		{Name: "cip_io", Transport: "udp", DefaultPort: 2222, Smart: smart.CIPIO},
		{Name: "ff_hse", Transport: "udp", DefaultPort: 1089, Smart: smart.FFHSE},
		{Name: "ads_udp", Transport: "udp", DefaultPort: 48899, Smart: smart.ADSUDP},
		{Name: "pcom_udp", Transport: "udp", DefaultPort: 20256, Seeds: seedPCOM, Smart: smart.PCOMUDP},
		{Name: "synchrophasor", Transport: "udp", DefaultPort: 4713, Smart: smart.Synchrophasor},
		{Name: "loxone", Transport: "udp", DefaultPort: 7700, Smart: smart.Loxone},
		{Name: "amx_netlinx", Transport: "udp", DefaultPort: 1319, Smart: smart.AMXNetlinx},
		{Name: "vantage", Transport: "udp", DefaultPort: 3001, Smart: smart.Vantage},
		{Name: "gtp_c", Transport: "udp", DefaultPort: 2123, Seeds: seedGTPC, Smart: smart.GTPCSmart},
		{Name: "gtp_u", Transport: "udp", DefaultPort: 2152, Seeds: seedGTPU, Smart: smart.GTPUSmart},
		{Name: "vxlan", Transport: "udp", DefaultPort: 4789, Seeds: seedVXLAN, Smart: smart.VXLANSmart},
		{Name: "geneve", Transport: "udp", DefaultPort: 6081, Seeds: seedGeneve, Smart: smart.GeneveSmart},
		{Name: "wccp", Transport: "udp", DefaultPort: 2048, Smart: smart.WCCPSmart},
		{Name: "ripng", Transport: "udp", DefaultPort: 521, Seeds: seedRIPng, Smart: smart.RIPngSmart},
		{Name: "babel", Transport: "udp", DefaultPort: 6696, Seeds: seedBabel, Smart: smart.BabelSmart},
		{Name: "bfd", Transport: "udp", DefaultPort: 3784, Seeds: seedBFD, Smart: smart.BFDSmart},
		{Name: "ldp", Transport: "udp", DefaultPort: 646, Seeds: seedLDP, Smart: smart.LDPSmart},
		{Name: "teredo", Transport: "udp", DefaultPort: 3544, Seeds: seedTeredo, Smart: smart.Teredo},
		{Name: "ike_natt", Transport: "udp", DefaultPort: 4500, Seeds: seedISAKMP, Smart: smart.IKENATT},
		{Name: "mndp", Transport: "udp", DefaultPort: 5678, Seeds: seedMNDP, Smart: smart.MNDP},
		{Name: "aruba_papi", Transport: "udp", DefaultPort: 8211, Smart: smart.ArubaPAPI},
		{Name: "artnet", Transport: "udp", DefaultPort: 6454, Seeds: seedArtNet, Smart: smart.ArtNet},
		{Name: "sacn", Transport: "udp", DefaultPort: 5568, Seeds: seedSACN, Smart: smart.SACN},
		{Name: "collectd", Transport: "udp", DefaultPort: 25826, Seeds: seedCollectd, Smart: smart.CollectdSmart},
		{Name: "plex_gdm", Transport: "udp", DefaultPort: 32414, Seeds: seedPlexGDM, Smart: smart.PlexGDM},
		{Name: "c1222", Transport: "udp", DefaultPort: 1153, Seeds: seedC1222, Smart: smart.C1222},

		{Name: "echo", Transport: "udp", DefaultPort: 7, Smart: smart.EchoSmall},
		{Name: "discard", Transport: "udp", DefaultPort: 9, Smart: smart.DiscardSmall},
		{Name: "daytime", Transport: "udp", DefaultPort: 13, Smart: smart.DaytimeSmall},
		{Name: "qotd", Transport: "udp", DefaultPort: 17, Smart: smart.QotdSmall},
		{Name: "chargen", Transport: "udp", DefaultPort: 19, Smart: smart.ChargenSmall},
		{Name: "time", Transport: "udp", DefaultPort: 37, Smart: smart.TimeSmall},

		{Name: "raw", Transport: "udp", DefaultPort: 29998, Smart: smart.RawFallthrough},
		{Name: "auto", Transport: "udp", DefaultPort: 29997, Smart: smart.RawFallthrough},
	}
}
