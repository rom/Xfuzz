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
		{Name: "rlogin", Transport: "tcp", DefaultPort: 513, Seeds: seedRlogin},
		{Name: "rsh", Transport: "tcp", DefaultPort: 514, Seeds: seedRsh},
		{Name: "rexec", Transport: "tcp", DefaultPort: 512, Seeds: seedRexec},
		{Name: "pcanywhere", Transport: "tcp", DefaultPort: 5631, Seeds: seedPCAnywhere},
		{Name: "radmin", Transport: "tcp", DefaultPort: 4899, Seeds: seedRadmin},
		{Name: "dameware", Transport: "tcp", DefaultPort: 6129},
		{Name: "pcoip", Transport: "tcp", DefaultPort: 4172},
		{Name: "spice", Transport: "tcp", DefaultPort: 5900},
		{Name: "lantronix", Transport: "tcp", DefaultPort: 9999, Seeds: seedLantronix},
		{Name: "tn3270", Transport: "tcp", DefaultPort: 23, Seeds: seedTn3270},
		{Name: "ard", Transport: "tcp", DefaultPort: 3283},

		// --- Web / HTTP family ---
		{Name: "http", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP, Smart: smart.HTTP},
		{Name: "https", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP, Smart: smart.HTTP},
		{Name: "websocket", Transport: "tcp", DefaultPort: 8080, Seeds: seedWebSocket, Smart: smart.WebSocket},
		{Name: "grpc", Transport: "tcp", DefaultPort: 50051, Seeds: seedGRPC},
		{Name: "ssrf_canary", Transport: "tcp", DefaultPort: 8081, Seeds: seedHTTP},
		{Name: "rtsp", Transport: "tcp", DefaultPort: 554, Seeds: seedRTSP, Smart: smart.RTSP},
		{Name: "sip_tcp", Transport: "tcp", DefaultPort: 5060, Seeds: seedSIP, Smart: smart.SIP},
		{Name: "xmpp", Transport: "tcp", DefaultPort: 5222, Seeds: seedXMPP},
		{Name: "irc", Transport: "tcp", DefaultPort: 6667, ServerFirst: true, Seeds: seedIRC},
		{Name: "nntp", Transport: "tcp", DefaultPort: 119, ServerFirst: true, Seeds: seedNNTP},
		{Name: "finger", Transport: "tcp", DefaultPort: 79, Seeds: seedFinger},
		{Name: "gopher", Transport: "tcp", DefaultPort: 70, Seeds: seedGopher},
		{Name: "stomp", Transport: "tcp", DefaultPort: 61613, Seeds: seedSTOMP},
		{Name: "mbus", Transport: "tcp", DefaultPort: 10001, Seeds: seedMbus},

		// --- Mail ---
		{Name: "smtp_recv", Transport: "tcp", DefaultPort: 25, ServerFirst: true, Seeds: seedSMTP, Smart: smart.SMTP},
		{Name: "pop3", Transport: "tcp", DefaultPort: 110, ServerFirst: true, Seeds: seedPOP3, Smart: smart.POP3},
		{Name: "imap", Transport: "tcp", DefaultPort: 143, ServerFirst: true, Seeds: seedIMAP, Smart: smart.IMAP},
		{Name: "smtps", Transport: "tcp", DefaultPort: 465, TLS: true, ServerFirst: true, Seeds: seedSMTP, Smart: smart.SMTP},
		{Name: "pop3s", Transport: "tcp", DefaultPort: 995, TLS: true, ServerFirst: true, Seeds: seedPOP3},
		{Name: "imaps", Transport: "tcp", DefaultPort: 993, TLS: true, ServerFirst: true, Seeds: seedIMAP},

		// --- File transfer ---
		{Name: "ftp", Transport: "tcp", DefaultPort: 21, ServerFirst: true, Seeds: seedFTP, Smart: smart.FTP},
		{Name: "ftps", Transport: "tcp", DefaultPort: 990, TLS: true, ServerFirst: true, Seeds: seedFTP},
		{Name: "ftp_files", Transport: "tcp", DefaultPort: 21, ServerFirst: true, Seeds: seedFTP, Smart: smart.FTP},
		{Name: "rsync", Transport: "tcp", DefaultPort: 873, ServerFirst: true, Seeds: seedRsync},
		{Name: "lpd", Transport: "tcp", DefaultPort: 515, Seeds: seedLPD},
		{Name: "pjl", Transport: "tcp", DefaultPort: 9100, Seeds: seedPJL},
		{Name: "ipp", Transport: "tcp", DefaultPort: 631, Seeds: seedIPP},
		{Name: "afp", Transport: "tcp", DefaultPort: 548, Seeds: seedAFP},
		{Name: "nbd", Transport: "tcp", DefaultPort: 10809, Seeds: seedNBD},
		{Name: "git", Transport: "tcp", DefaultPort: 9418, Seeds: seedGit},
		{Name: "svn", Transport: "tcp", DefaultPort: 3690, ServerFirst: true, Seeds: seedSVN},

		// --- Windows / AD ---
		{Name: "smb", Transport: "tcp", DefaultPort: 445, Seeds: seedSMB, Smart: smart.SMB},
		{Name: "rdp", Transport: "tcp", DefaultPort: 3389, Seeds: seedRDP, Smart: smart.RDP},
		{Name: "winrm", Transport: "tcp", DefaultPort: 5985, Seeds: seedWinRM},
		{Name: "dcerpc", Transport: "tcp", DefaultPort: 135, Seeds: seedDCERPC, Smart: smart.DCERPC},
		{Name: "ldap", Transport: "tcp", DefaultPort: 389, Seeds: seedLDAP, Smart: smart.LDAP},
		{Name: "ldaps", Transport: "tcp", DefaultPort: 636, TLS: true, Seeds: seedLDAP, Smart: smart.LDAP},
		{Name: "kerberos", Transport: "tcp", DefaultPort: 88, Seeds: seedKerberos, Smart: smart.Kerberos},

		// --- Databases ---
		{Name: "mysql", Transport: "tcp", DefaultPort: 3306, ServerFirst: true, Seeds: seedMySQL, Smart: smart.MySQL},
		{Name: "postgres", Transport: "tcp", DefaultPort: 5432, Seeds: seedPostgres, Smart: smart.Postgres},
		{Name: "mssql", Transport: "tcp", DefaultPort: 1433, Seeds: seedMSSQL, Smart: smart.MSSQL},
		{Name: "oracle_tns", Transport: "tcp", DefaultPort: 1521, Seeds: seedOracleTNS},
		{Name: "redis", Transport: "tcp", DefaultPort: 6379, Seeds: seedRedis, Smart: smart.Redis},
		{Name: "memcached", Transport: "tcp", DefaultPort: 11211, Seeds: seedMemcached, Smart: smart.Memcached},
		{Name: "mongodb", Transport: "tcp", DefaultPort: 27017, Seeds: seedMongoDB, Smart: smart.MongoDB},
		{Name: "elasticsearch", Transport: "tcp", DefaultPort: 9200, Seeds: seedHTTP},
		{Name: "neo4j", Transport: "tcp", DefaultPort: 7687, Seeds: seedNeo4j},
		{Name: "rethinkdb", Transport: "tcp", DefaultPort: 28015, Seeds: seedRethinkDB},
		{Name: "couchdb", Transport: "tcp", DefaultPort: 5984, Seeds: seedHTTP},
		{Name: "influxdb", Transport: "tcp", DefaultPort: 8086, Seeds: seedHTTP},
		{Name: "cassandra", Transport: "tcp", DefaultPort: 9042, Seeds: seedCassandra},
		{Name: "clickhouse", Transport: "tcp", DefaultPort: 9000, Seeds: seedHTTP},
		{Name: "clickhouses", Transport: "tcp", DefaultPort: 8443, TLS: true, Seeds: seedHTTP},

		// --- DNS ---
		{Name: "dns", Transport: "tcp", DefaultPort: 53, Seeds: seedDNSTCP, Smart: smart.DNSTCP},

		// --- OT / ICS / SCADA ---
		{Name: "modbus", Transport: "tcp", DefaultPort: 502, Seeds: seedModbus, Smart: smart.Modbus},
		{Name: "modbus_security", Transport: "tcp", DefaultPort: 802, TLS: true, Seeds: seedModbus, Smart: smart.Modbus},
		{Name: "modbuss", Transport: "tcp", DefaultPort: 802, TLS: true, Seeds: seedModbus, Smart: smart.Modbus},
		{Name: "s7", Transport: "tcp", DefaultPort: 102, Seeds: seedS7, Smart: smart.S7},
		{Name: "s7comm_plus", Transport: "tcp", DefaultPort: 102, Seeds: seedS7, Smart: smart.S7},
		{Name: "iec104", Transport: "tcp", DefaultPort: 2404, Seeds: seedIEC104, Smart: smart.IEC104},
		{Name: "iccp_secure", Transport: "tcp", DefaultPort: 102, Seeds: seedS7},
		{Name: "dnp3", Transport: "tcp", DefaultPort: 20000, Seeds: seedDNP3, Smart: smart.DNP3},
		{Name: "ge_srtp", Transport: "tcp", DefaultPort: 18245, Seeds: seedGESRTP},
		{Name: "codesys", Transport: "tcp", DefaultPort: 2455, Seeds: seedCodesys},
		{Name: "c37118", Transport: "tcp", DefaultPort: 4712, Seeds: seedC37118},
		{Name: "osdp", Transport: "tcp", DefaultPort: 49152, Seeds: seedOSDP},
		{Name: "focas", Transport: "tcp", DefaultPort: 8193, Seeds: seedFocas},
		{Name: "proconos", Transport: "tcp", DefaultPort: 20547},
		{Name: "osisoft_pi", Transport: "tcp", DefaultPort: 5450},
		{Name: "proficy_historian", Transport: "tcp", DefaultPort: 14000},
		{Name: "canary_historian", Transport: "tcp", DefaultPort: 54811},
		{Name: "aspen_ip21", Transport: "tcp", DefaultPort: 10014},
		{Name: "atg", Transport: "tcp", DefaultPort: 10001, Seeds: seedATG},
		{Name: "fox", Transport: "tcp", DefaultPort: 1911, Seeds: seedFox},
		{Name: "hartip", Transport: "tcp", DefaultPort: 5094, Seeds: seedHARTIP},
		{Name: "pcworx", Transport: "tcp", DefaultPort: 1962, Seeds: seedPCWorx},
		{Name: "mms", Transport: "tcp", DefaultPort: 102, Seeds: seedMMS},
		{Name: "opcua", Transport: "tcp", DefaultPort: 4840, Seeds: seedOPCUA, Smart: smart.OPCUA},
		{Name: "ethernetip", Transport: "tcp", DefaultPort: 44818, Seeds: seedEtherNetIP, Smart: smart.EtherNetIP},
		{Name: "melsec", Transport: "tcp", DefaultPort: 5007, Seeds: seedMelsec},
		{Name: "fins_tcp", Transport: "tcp", DefaultPort: 9600, Seeds: seedFINS},
		{Name: "secs_gem", Transport: "tcp", DefaultPort: 5000, Seeds: seedSECSGEM},
		{Name: "pcom", Transport: "tcp", DefaultPort: 20256, Seeds: seedPCOM},
		{Name: "roc_plus", Transport: "tcp", DefaultPort: 4000, Seeds: seedROCPlus},
		{Name: "crimson", Transport: "tcp", DefaultPort: 789},
		{Name: "danfoss_aksm", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP},
		{Name: "danfoss_aksms", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP},

		// --- Messaging / queuing ---
		{Name: "mqtt", Transport: "tcp", DefaultPort: 1883, Seeds: seedMQTT, Smart: smart.MQTT},
		{Name: "mqtts", Transport: "tcp", DefaultPort: 8883, TLS: true, Seeds: seedMQTT, Smart: smart.MQTT},
		{Name: "amqp", Transport: "tcp", DefaultPort: 5672, Seeds: seedAMQP, Smart: smart.AMQP},
		{Name: "ibmmq", Transport: "tcp", DefaultPort: 1414, Seeds: seedIBMMQ},
		{Name: "mq", Transport: "tcp", DefaultPort: 1414, Seeds: seedIBMMQ},
		{Name: "websphere_mq", Transport: "tcp", DefaultPort: 1414, Seeds: seedIBMMQ},
		{Name: "nats", Transport: "tcp", DefaultPort: 4222, ServerFirst: true, Seeds: seedNATS},
		{Name: "kafka", Transport: "tcp", DefaultPort: 9092, Seeds: seedKafka},
		{Name: "zookeeper", Transport: "tcp", DefaultPort: 2181, Seeds: seedZookeeper},
		{Name: "beanstalkd", Transport: "tcp", DefaultPort: 11300, Seeds: seedBeanstalkd},

		// --- Logging / telemetry ---
		{Name: "syslog_tcp", Transport: "tcp", DefaultPort: 601, Seeds: seedSyslog},

		// --- Java / enterprise ---
		{Name: "jdwp", Transport: "tcp", DefaultPort: 8000, ServerFirst: true, Seeds: seedJDWP},
		{Name: "rmi", Transport: "tcp", DefaultPort: 1099, Seeds: seedRMI},
		{Name: "jupyter", Transport: "tcp", DefaultPort: 8888, Seeds: seedHTTP},
		{Name: "jupyters", Transport: "tcp", DefaultPort: 8888, TLS: true, Seeds: seedHTTP},
		{Name: "selenium", Transport: "tcp", DefaultPort: 4444, Seeds: seedHTTP},

		// --- Cloud native / DevOps ---
		{Name: "kubernetes_api", Transport: "tcp", DefaultPort: 6443, TLS: true, Seeds: seedHTTP},
		{Name: "kubelet", Transport: "tcp", DefaultPort: 10255, Seeds: seedHTTP},
		{Name: "kubelets", Transport: "tcp", DefaultPort: 10250, TLS: true, Seeds: seedHTTP},
		{Name: "etcd", Transport: "tcp", DefaultPort: 2379, Seeds: seedHTTP},
		{Name: "vault", Transport: "tcp", DefaultPort: 8200, Seeds: seedHTTP},
		{Name: "consul", Transport: "tcp", DefaultPort: 8500, Seeds: seedHTTP},
		{Name: "consuls", Transport: "tcp", DefaultPort: 8501, TLS: true, Seeds: seedHTTP},
		{Name: "nomad", Transport: "tcp", DefaultPort: 4646, Seeds: seedHTTP},
		{Name: "minio", Transport: "tcp", DefaultPort: 9001, Seeds: seedHTTP},
		{Name: "minios", Transport: "tcp", DefaultPort: 9000, TLS: true, Seeds: seedHTTP},
		{Name: "cloud_metadata", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP},
		{Name: "docker_registry", Transport: "tcp", DefaultPort: 5000, Seeds: seedHTTP},
		{Name: "dockerapi", Transport: "tcp", DefaultPort: 2375, Seeds: seedHTTP},

		// --- AI / LLM / MCP ---
		{Name: "ollama", Transport: "tcp", DefaultPort: 11434, Seeds: seedHTTP},
		{Name: "ollamas", Transport: "tcp", DefaultPort: 11435, TLS: true, Seeds: seedHTTP},
		{Name: "llm_openai", Transport: "tcp", DefaultPort: 8080, Seeds: seedHTTP},
		{Name: "llm_openais", Transport: "tcp", DefaultPort: 8443, TLS: true, Seeds: seedHTTP},
		{Name: "mcp", Transport: "tcp", DefaultPort: 7777, Seeds: seedHTTP},
		{Name: "mcps", Transport: "tcp", DefaultPort: 7778, TLS: true, Seeds: seedHTTP},
		{Name: "agent", Transport: "tcp", DefaultPort: 8686, Seeds: seedHTTP},

		// --- Classic small services ---
		{Name: "echo", Transport: "tcp", DefaultPort: 7},
		{Name: "discard", Transport: "tcp", DefaultPort: 9},
		{Name: "daytime", Transport: "tcp", DefaultPort: 13, ServerFirst: true},
		{Name: "qotd", Transport: "tcp", DefaultPort: 17, ServerFirst: true},
		{Name: "chargen", Transport: "tcp", DefaultPort: 19, ServerFirst: true},
		{Name: "time", Transport: "tcp", DefaultPort: 37, ServerFirst: true},
		{Name: "ident", Transport: "tcp", DefaultPort: 113, Seeds: seedIdent},

		// --- AMQP family / scientific ---
		{Name: "dlms", Transport: "tcp", DefaultPort: 4059, Seeds: seedDLMS},
		{Name: "ads", Transport: "tcp", DefaultPort: 48898, Seeds: seedADS},
		{Name: "nts", Transport: "tcp", DefaultPort: 4460, TLS: true},

		// --- Remote-access / VDI ---
		{Name: "vnc", Transport: "tcp", DefaultPort: 5900, ServerFirst: true, Seeds: seedVNC, Smart: smart.VNC},
		{Name: "teamviewer", Transport: "tcp", DefaultPort: 5938, Seeds: seedTeamViewer},
		{Name: "anydesk", Transport: "tcp", DefaultPort: 7070, Seeds: seedAnyDesk},
		{Name: "openvpn", Transport: "tcp", DefaultPort: 1194, Seeds: seedOpenVPN},
		{Name: "citrix_ica", Transport: "tcp", DefaultPort: 1494, Seeds: seedCitrixICA},
		{Name: "citrix_gateway", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP},
		{Name: "vmware_authd", Transport: "tcp", DefaultPort: 902, ServerFirst: true, Seeds: seedVMwareAuthd},
		{Name: "x11", Transport: "tcp", DefaultPort: 6000, Seeds: seedX11},
		{Name: "horizon", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP},
		{Name: "nx", Transport: "tcp", DefaultPort: 4000, Seeds: seedNX},
		{Name: "redfish", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP},

		// --- Device management ---
		{Name: "tr069", Transport: "tcp", DefaultPort: 7547, Seeds: seedHTTP},
		{Name: "upnp", Transport: "tcp", DefaultPort: 5000, Seeds: seedHTTP},
		{Name: "tr369", Transport: "tcp", DefaultPort: 8085, Seeds: seedHTTP},
		{Name: "intel_amt", Transport: "tcp", DefaultPort: 16992, Seeds: seedHTTP},
		{Name: "ilo", Transport: "tcp", DefaultPort: 17988, Seeds: seedHTTP},
		{Name: "idrac", Transport: "tcp", DefaultPort: 5900, Seeds: seedHTTP},
		{Name: "esxi", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP},
		{Name: "fortinet", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP},
		{Name: "pulse", Transport: "tcp", DefaultPort: 443, TLS: true, Seeds: seedHTTP},
		{Name: "moxa_mgmt", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP},

		// --- Voice / H.323 / SIP ---
		{Name: "sccp", Transport: "tcp", DefaultPort: 2000, Seeds: seedSCCP},
		{Name: "h323", Transport: "tcp", DefaultPort: 1720, Seeds: seedH323},
		{Name: "asterisk_ami", Transport: "tcp", DefaultPort: 5038, ServerFirst: true, Seeds: seedAsteriskAMI},

		// --- Fake C2 / adversary ---
		{Name: "c2_emulator", Transport: "tcp", DefaultPort: 8282, Seeds: seedHTTP},

		// --- Classic Unix ---
		{Name: "rpcbind", Transport: "tcp", DefaultPort: 111, Seeds: seedRpcbind},
		{Name: "nfs", Transport: "tcp", DefaultPort: 2049, Seeds: seedNFS},
		{Name: "pptp", Transport: "tcp", DefaultPort: 1723, Seeds: seedPPTP},
		{Name: "adb", Transport: "tcp", DefaultPort: 5555, Seeds: seedADB},
		{Name: "ajp13", Transport: "tcp", DefaultPort: 8009, Seeds: seedAJP13},
		{Name: "epmd", Transport: "tcp", DefaultPort: 4369, Seeds: seedEPMD},
		{Name: "tacacs", Transport: "tcp", DefaultPort: 49, Seeds: seedTACACS},

		// --- BACnet Secure Connect ---
		{Name: "bacnet_sc", Transport: "tcp", DefaultPort: 47808, Seeds: seedBACnetSC},
		{Name: "bacnet_scs", Transport: "tcp", DefaultPort: 47809, TLS: true, Seeds: seedBACnetSC},

		// --- Healthcare ---
		{Name: "hl7", Transport: "tcp", DefaultPort: 2575, Seeds: seedHL7},
		{Name: "hl7s", Transport: "tcp", DefaultPort: 2576, TLS: true, Seeds: seedHL7},
		{Name: "dicom", Transport: "tcp", DefaultPort: 104, Seeds: seedDICOM},
		{Name: "dicoms", Transport: "tcp", DefaultPort: 2762, TLS: true, Seeds: seedDICOM},
		{Name: "astm", Transport: "tcp", DefaultPort: 12001, Seeds: seedASTM},
		{Name: "poct1", Transport: "tcp", DefaultPort: 12002},
		{Name: "fhir", Transport: "tcp", DefaultPort: 8080, Seeds: seedHTTP},
		{Name: "fhirs", Transport: "tcp", DefaultPort: 8443, TLS: true, Seeds: seedHTTP},

		// --- BAS / building automation ---
		{Name: "niagara_platform", Transport: "tcp", DefaultPort: 3011, Seeds: seedNiagara},
		{Name: "obix", Transport: "tcp", DefaultPort: 8080, Seeds: seedHTTP},
		{Name: "enocean", Transport: "tcp", DefaultPort: 2080},
		{Name: "dixell", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP},
		{Name: "carel", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP},
		{Name: "trane", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP},
		{Name: "resideo", Transport: "tcp", DefaultPort: 80, Seeds: seedHTTP},
		{Name: "ocpp", Transport: "tcp", DefaultPort: 80, Seeds: seedWebSocket},

		// --- BGP / routing ---
		{Name: "bgp", Transport: "tcp", DefaultPort: 179, Seeds: seedBGP},
		{Name: "socks", Transport: "tcp", DefaultPort: 1080, Seeds: seedSOCKS},

		// --- Fall-throughs / scripted ---
		{Name: "raw", Transport: "tcp", DefaultPort: 9000},
		{Name: "auto", Transport: "tcp", DefaultPort: 29999},
		{Name: "scripted", Transport: "tcp", DefaultPort: 9001},
		{Name: "lua", Transport: "tcp", DefaultPort: 9002},
		{Name: "tls_intercept", Transport: "tcp", DefaultPort: 8443, TLS: true, Seeds: seedHTTP},
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
		{Name: "cldap", Transport: "udp", DefaultPort: 389, Seeds: seedLDAP},
		{Name: "netbios_dgram", Transport: "udp", DefaultPort: 138, Seeds: seedNBNS},

		{Name: "snmp", Transport: "udp", DefaultPort: 161, Seeds: seedSNMP, Smart: smart.SNMP},
		{Name: "snmptrap", Transport: "udp", DefaultPort: 162, Seeds: seedSNMP, Smart: smart.SNMP},
		{Name: "ntp", Transport: "udp", DefaultPort: 123, Seeds: seedNTP, Smart: smart.NTP},
		{Name: "chronyd", Transport: "udp", DefaultPort: 323, Seeds: seedNTP},
		{Name: "syslog_udp", Transport: "udp", DefaultPort: 514, Seeds: seedSyslog},
		{Name: "tftp", Transport: "udp", DefaultPort: 69, Seeds: seedTFTP, Smart: smart.TFTP},
		{Name: "radius", Transport: "udp", DefaultPort: 1812, Seeds: seedRADIUS, Smart: smart.RADIUS},
		{Name: "radius_acct", Transport: "udp", DefaultPort: 1813, Seeds: seedRADIUS, Smart: smart.RADIUS},
		{Name: "ipmi", Transport: "udp", DefaultPort: 623, Seeds: seedIPMI, Smart: smart.IPMI},
		{Name: "bacnet", Transport: "udp", DefaultPort: 47808, Seeds: seedBACnetUDP, Smart: smart.BACnet},
		{Name: "dhcp", Transport: "udp", DefaultPort: 67, Seeds: seedDHCP, Smart: smart.DHCP},
		{Name: "dhcpv6", Transport: "udp", DefaultPort: 547, Seeds: seedDHCPv6, Smart: smart.DHCPv6},
		{Name: "coap", Transport: "udp", DefaultPort: 5683, Seeds: seedCoAP, Smart: smart.CoAP},
		{Name: "sip", Transport: "udp", DefaultPort: 5060, Seeds: seedSIP, Smart: smart.SIP},
		{Name: "mgcp", Transport: "udp", DefaultPort: 2427, Seeds: seedMGCP},
		{Name: "ethercat", Transport: "udp", DefaultPort: 34980},

		{Name: "fins", Transport: "udp", DefaultPort: 9600, Seeds: seedFINS},
		{Name: "knx", Transport: "udp", DefaultPort: 3671, Seeds: seedKNX, Smart: smart.KNX},
		{Name: "isakmp", Transport: "udp", DefaultPort: 500, Seeds: seedISAKMP},
		{Name: "stun", Transport: "udp", DefaultPort: 3478, Seeds: seedSTUN, Smart: smart.STUN},

		{Name: "mssql_browser", Transport: "udp", DefaultPort: 1434, Seeds: seedMSSQLBrowser},
		{Name: "profinet", Transport: "udp", DefaultPort: 34964, Seeds: seedProfinet},
		{Name: "wdbrpc", Transport: "udp", DefaultPort: 17185},
		{Name: "iax2", Transport: "udp", DefaultPort: 4569, Seeds: seedIAX2},
		{Name: "ads_discovery", Transport: "udp", DefaultPort: 48899},

		{Name: "dtls", Transport: "udp", DefaultPort: 443, Seeds: seedDTLS},
		{Name: "quic", Transport: "udp", DefaultPort: 443, Seeds: seedQUIC},
		{Name: "netflow", Transport: "udp", DefaultPort: 2055, Seeds: seedNetflow},
		{Name: "sflow", Transport: "udp", DefaultPort: 6343, Seeds: seedSflow},
		{Name: "statsd", Transport: "udp", DefaultPort: 8125, Seeds: seedStatsD},
		{Name: "tristation", Transport: "udp", DefaultPort: 1502, Seeds: seedTristation},
		{Name: "ge_egd", Transport: "udp", DefaultPort: 18246},
		{Name: "bsap", Transport: "udp", DefaultPort: 1234},
		{Name: "lontalk", Transport: "udp", DefaultPort: 1628},
		{Name: "siprotec_en100", Transport: "udp", DefaultPort: 50000},
		{Name: "wsdiscovery", Transport: "udp", DefaultPort: 3702, Seeds: seedWSDiscovery},
		{Name: "memcached_udp", Transport: "udp", DefaultPort: 11211, Seeds: seedMemcached},
		{Name: "natpmp", Transport: "udp", DefaultPort: 5351, Seeds: seedNATPMP},
		{Name: "ubiquiti", Transport: "udp", DefaultPort: 10001, Seeds: seedUbiquiti},
		{Name: "wireguard", Transport: "udp", DefaultPort: 51820, Seeds: seedWireGuard},
		{Name: "openvpn_udp", Transport: "udp", DefaultPort: 1194, Seeds: seedOpenVPN},
		{Name: "l2tp", Transport: "udp", DefaultPort: 1701, Seeds: seedL2TP},
		{Name: "rip", Transport: "udp", DefaultPort: 520, Seeds: seedRIP},
		{Name: "steam", Transport: "udp", DefaultPort: 27015, Seeds: seedSteam},
		{Name: "sentinel_hasp", Transport: "udp", DefaultPort: 1947},
		{Name: "mqtt_sn", Transport: "udp", DefaultPort: 1884, Seeds: seedMQTTSN},
		{Name: "tplink_kasa", Transport: "udp", DefaultPort: 9999, Seeds: seedTPLinkKasa},
		{Name: "tuya", Transport: "udp", DefaultPort: 6667, Seeds: seedTuya},
		{Name: "miio", Transport: "udp", DefaultPort: 54321, Seeds: seedMiIO},
		{Name: "lwm2m", Transport: "udp", DefaultPort: 5683, Seeds: seedCoAP, Smart: smart.CoAP},
		{Name: "modbus_udp", Transport: "udp", DefaultPort: 502, Seeds: seedModbus, Smart: smart.Modbus},
		{Name: "enip_udp", Transport: "udp", DefaultPort: 44818, Seeds: seedEtherNetIP},
		{Name: "opcua_pubsub", Transport: "udp", DefaultPort: 4840, Seeds: seedOPCUA},
		{Name: "dds_rtps", Transport: "udp", DefaultPort: 7400, Seeds: seedDDSRTPS},
		{Name: "hartip_udp", Transport: "udp", DefaultPort: 5094, Seeds: seedHARTIP},
		{Name: "crestron", Transport: "udp", DefaultPort: 41794, Seeds: seedCrestron},
		{Name: "pjlink", Transport: "udp", DefaultPort: 4352, Seeds: seedPJLink},
		{Name: "cbus", Transport: "udp", DefaultPort: 10001, Seeds: seedCBus},
		{Name: "dnp3_udp", Transport: "udp", DefaultPort: 20000, Seeds: seedDNP3},
		{Name: "saia_sbus", Transport: "udp", DefaultPort: 5050},
		{Name: "slp", Transport: "udp", DefaultPort: 427, Seeds: seedSLP},
		{Name: "xdmcp", Transport: "udp", DefaultPort: 177, Seeds: seedXDMCP},
		{Name: "db_lsp", Transport: "udp", DefaultPort: 17500, Seeds: seedDropboxLSP},
		{Name: "kerberos_udp", Transport: "udp", DefaultPort: 88, Seeds: seedKerberos},
		{Name: "lantronix_disc", Transport: "udp", DefaultPort: 30718},
		{Name: "pcanywhere_stat", Transport: "udp", DefaultPort: 5632},
		{Name: "gamespy", Transport: "udp", DefaultPort: 27900, Seeds: seedGameSpy},
		{Name: "db2_disc", Transport: "udp", DefaultPort: 523},
		{Name: "bt_dht", Transport: "udp", DefaultPort: 6881, Seeds: seedBTDHT},
		{Name: "rdp_udp", Transport: "udp", DefaultPort: 3389, Seeds: seedRDPUDP},
		{Name: "matter", Transport: "udp", DefaultPort: 5540},
		{Name: "wiz", Transport: "udp", DefaultPort: 38899, Seeds: seedWiZ},
		{Name: "yeelight", Transport: "udp", DefaultPort: 1982, Seeds: seedYeelight},
		{Name: "dahua_disc", Transport: "udp", DefaultPort: 37810, Seeds: seedDahuaDisc},
		{Name: "hikvision_sadp", Transport: "udp", DefaultPort: 37020, Seeds: seedHikvisionSADP},
		{Name: "powerlink", Transport: "udp", DefaultPort: 3819},
		{Name: "slmp", Transport: "udp", DefaultPort: 47808, Seeds: seedSLMP},
		{Name: "cip_io", Transport: "udp", DefaultPort: 2222},
		{Name: "ff_hse", Transport: "udp", DefaultPort: 1089},
		{Name: "ads_udp", Transport: "udp", DefaultPort: 48899},
		{Name: "pcom_udp", Transport: "udp", DefaultPort: 20256, Seeds: seedPCOM},
		{Name: "synchrophasor", Transport: "udp", DefaultPort: 4713},
		{Name: "loxone", Transport: "udp", DefaultPort: 7700},
		{Name: "amx_netlinx", Transport: "udp", DefaultPort: 1319},
		{Name: "vantage", Transport: "udp", DefaultPort: 3001},
		{Name: "gtp_c", Transport: "udp", DefaultPort: 2123, Seeds: seedGTPC},
		{Name: "gtp_u", Transport: "udp", DefaultPort: 2152, Seeds: seedGTPU},
		{Name: "vxlan", Transport: "udp", DefaultPort: 4789, Seeds: seedVXLAN},
		{Name: "geneve", Transport: "udp", DefaultPort: 6081, Seeds: seedGeneve},
		{Name: "wccp", Transport: "udp", DefaultPort: 2048},
		{Name: "ripng", Transport: "udp", DefaultPort: 521, Seeds: seedRIPng},
		{Name: "babel", Transport: "udp", DefaultPort: 6696, Seeds: seedBabel},
		{Name: "bfd", Transport: "udp", DefaultPort: 3784, Seeds: seedBFD},
		{Name: "ldp", Transport: "udp", DefaultPort: 646, Seeds: seedLDP},
		{Name: "teredo", Transport: "udp", DefaultPort: 3544, Seeds: seedTeredo},
		{Name: "ike_natt", Transport: "udp", DefaultPort: 4500, Seeds: seedISAKMP},
		{Name: "mndp", Transport: "udp", DefaultPort: 5678, Seeds: seedMNDP},
		{Name: "aruba_papi", Transport: "udp", DefaultPort: 8211},
		{Name: "artnet", Transport: "udp", DefaultPort: 6454, Seeds: seedArtNet},
		{Name: "sacn", Transport: "udp", DefaultPort: 5568, Seeds: seedSACN},
		{Name: "collectd", Transport: "udp", DefaultPort: 25826, Seeds: seedCollectd},
		{Name: "plex_gdm", Transport: "udp", DefaultPort: 32414, Seeds: seedPlexGDM},
		{Name: "c1222", Transport: "udp", DefaultPort: 1153, Seeds: seedC1222},

		{Name: "echo", Transport: "udp", DefaultPort: 7},
		{Name: "discard", Transport: "udp", DefaultPort: 9},
		{Name: "daytime", Transport: "udp", DefaultPort: 13},
		{Name: "qotd", Transport: "udp", DefaultPort: 17},
		{Name: "chargen", Transport: "udp", DefaultPort: 19},
		{Name: "time", Transport: "udp", DefaultPort: 37},

		{Name: "raw", Transport: "udp", DefaultPort: 29998},
		{Name: "auto", Transport: "udp", DefaultPort: 29997},
	}
}
