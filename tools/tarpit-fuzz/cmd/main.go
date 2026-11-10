// Command tarpit-fuzz drives dumb + smart fuzzing campaigns against a running
// tarpit-honeypot sensor.
//
// It covers every one of the 315 protocol handlers the sensor accepts in its
// config (197 TCP + 118 UDP). Each handler is one entry in a registry with a
// transport, a default port, one or more seed packets, and (for a growing
// subset) a protocol-aware smart generator. A YAML config toggles handlers on
// and off; command-line flags override a config and accept the shorthand that
// a shell makes convenient — "--enable modbus,dns" or "--disable udp:*".
//
// Usage:
//
//	tarpit-fuzz -c protocols.yaml --target 127.0.0.1 --rounds 10
//	tarpit-fuzz --target 127.0.0.1 --enable tcp:ssh,tcp:http --iterations 1024
//	tarpit-fuzz --target 127.0.0.1 --kind smart --liveness http://127.0.0.1:8088/healthz
//
// The default config is tools/tarpit-fuzz/configs/protocols.yaml, which lists
// every handler with enabled: true and the sensor's example port. Edit it to
// turn a protocol off, pin a port, or restrict the run to one family.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rom/Xfuzz/tools/tarpit-fuzz/engine"
	"github.com/rom/Xfuzz/tools/tarpit-fuzz/protocols"
)

// cliFlags are everything the command line accepts.
type cliFlags struct {
	configPath  string
	target      string
	liveness    string
	kind        string
	iterations  int
	rounds      int
	concurrency int
	timeout     time.Duration
	seed        int64
	enable      string
	disable     string
	list        bool
	verbose     bool
}

func main() {
	var fl cliFlags
	flag.StringVar(&fl.configPath, "c", "", "YAML config file (overridden by flags)")
	flag.StringVar(&fl.target, "target", "127.0.0.1", "honeypot host")
	flag.StringVar(&fl.liveness, "liveness", "", "HTTP /healthz URL for the sensor (optional; cheaper than re-dialing)")
	flag.StringVar(&fl.kind, "kind", "", "dumb, smart, or empty for both")
	flag.IntVar(&fl.iterations, "iterations", 0, "payloads per protocol per round (0 = config / default 128)")
	flag.IntVar(&fl.rounds, "rounds", 0, "how many passes (0 = config / default 1)")
	flag.IntVar(&fl.concurrency, "concurrency", 0, "parallel protocols (0 = config / default 8)")
	flag.DurationVar(&fl.timeout, "timeout", 0, "per-exchange timeout (0 = config / default 800ms)")
	flag.Int64Var(&fl.seed, "seed", 0, "PRNG seed; reuse this to replay a crash")
	flag.StringVar(&fl.enable, "enable", "", "comma-separated handler list; qualified names like 'udp:dns' restrict to one transport")
	flag.StringVar(&fl.disable, "disable", "", "comma-separated handler list to subtract from --enable")
	flag.BoolVar(&fl.list, "list", false, "print the catalogue and exit")
	flag.BoolVar(&fl.verbose, "verbose", false, "log each finding as it happens")
	flag.Parse()

	if fl.list {
		printCatalogue(os.Stdout)
		return
	}

	cfg, ports, err := buildConfig(fl)
	if err != nil {
		fmt.Fprintf(os.Stderr, "tarpit-fuzz: %v\n", err)
		os.Exit(2)
	}
	cat := protocols.All()
	for i, pp := range cat {
		if port, ok := ports[pp.Transport+":"+pp.Name]; ok {
			cat[i].DefaultPort = port
		} else if port, ok := ports[pp.Name]; ok {
			cat[i].DefaultPort = port
		}
	}

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	eng := engine.New(cfg, cat)
	fmt.Printf("tarpit-fuzz: target=%s rounds=%d iters=%d concurrency=%d seed=%d kinds=%v\n",
		cfg.Target, cfg.Rounds, cfg.Iterations, cfg.Concurrency, cfg.Seed, cfg.Kinds)
	s := eng.Run(ctx)
	printSummary(os.Stdout, s)

	if len(s.Findings) > 0 {
		os.Exit(1)
	}
}

// yamlConfig is the on-disk form of a run's settings.
type yamlConfig struct {
	Target      string              `yaml:"target"`
	Liveness    string              `yaml:"liveness,omitempty"`
	Iterations  int                 `yaml:"iterations,omitempty"`
	Rounds      int                 `yaml:"rounds,omitempty"`
	Concurrency int                 `yaml:"concurrency,omitempty"`
	Timeout     string              `yaml:"timeout,omitempty"`
	Seed        int64               `yaml:"seed,omitempty"`
	Kinds       []string            `yaml:"kinds,omitempty"`
	Protocols   []protocolOverrides `yaml:"protocols,omitempty"`
}

// protocolOverrides is one entry in the per-protocol list.
type protocolOverrides struct {
	Name      string `yaml:"name"`
	Transport string `yaml:"transport,omitempty"`
	Enabled   *bool  `yaml:"enabled,omitempty"`
	Port      int    `yaml:"port,omitempty"`
}

// buildConfig merges the YAML file (if any) with command-line flags.
func buildConfig(fl cliFlags) (engine.Config, map[string]int, error) {
	var yc yamlConfig
	if fl.configPath != "" {
		b, err := os.ReadFile(fl.configPath)
		if err != nil {
			return engine.Config{}, nil, fmt.Errorf("reading %s: %w", fl.configPath, err)
		}
		if err := yaml.Unmarshal(b, &yc); err != nil {
			return engine.Config{}, nil, fmt.Errorf("parsing %s: %w", fl.configPath, err)
		}
	}
	cfg := engine.Config{
		Target:      firstNonEmpty(fl.target, yc.Target, "127.0.0.1"),
		LivenessURL: firstNonEmpty(fl.liveness, yc.Liveness),
		Iterations:  firstPositive(fl.iterations, yc.Iterations, 256),
		Rounds:      firstPositive(fl.rounds, yc.Rounds, 1),
		Concurrency: firstPositive(fl.concurrency, yc.Concurrency, 8),
		Seed:        firstNonZero(fl.seed, yc.Seed),
	}
	if fl.timeout > 0 {
		cfg.Timeout = fl.timeout
	} else if yc.Timeout != "" {
		d, err := time.ParseDuration(yc.Timeout)
		if err != nil {
			return cfg, nil, fmt.Errorf("timeout: %w", err)
		}
		cfg.Timeout = d
	}
	// Kinds.
	kinds := yc.Kinds
	if fl.kind != "" {
		kinds = strings.Split(fl.kind, ",")
	}
	for _, k := range kinds {
		switch strings.TrimSpace(k) {
		case "dumb":
			cfg.Kinds = append(cfg.Kinds, engine.KindDumb)
		case "smart":
			cfg.Kinds = append(cfg.Kinds, engine.KindSmart)
		case "":
		default:
			return cfg, nil, fmt.Errorf("kind: %q must be dumb or smart", k)
		}
	}
	// Enable / disable from the YAML file.
	enabled := map[string]bool{}
	ports := map[string]int{}
	disabled := map[string]bool{}
	for _, p := range yc.Protocols {
		key := p.Name
		if p.Transport != "" {
			key = p.Transport + ":" + p.Name
		}
		if p.Port > 0 {
			ports[key] = p.Port
		}
		if p.Enabled != nil {
			if *p.Enabled {
				enabled[key] = true
			} else {
				disabled[key] = true
			}
		}
	}
	// Enable / disable from command-line flags: they replace the YAML's set
	// when a flag is non-empty.
	if fl.enable != "" {
		enabled = parseList(fl.enable)
	}
	if fl.disable != "" {
		for k := range parseList(fl.disable) {
			disabled[k] = true
		}
	}
	cfg.Enabled = enabled
	cfg.Disabled = disabled
	return cfg, ports, nil
}

// parseList splits a comma-separated list into a map[string]bool.
func parseList(s string) map[string]bool {
	out := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out[p] = true
		}
	}
	return out
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func firstPositive(xs ...int) int {
	for _, x := range xs {
		if x > 0 {
			return x
		}
	}
	return 0
}

func firstNonZero(xs ...int64) int64 {
	for _, x := range xs {
		if x != 0 {
			return x
		}
	}
	return 0
}

// printCatalogue dumps the registry: three columns, one row per protocol.
func printCatalogue(w *os.File) {
	cat := protocols.All()
	sort.Slice(cat, func(i, j int) bool {
		if cat[i].Transport != cat[j].Transport {
			return cat[i].Transport < cat[j].Transport
		}
		return cat[i].Name < cat[j].Name
	})
	fmt.Fprintln(w, "TRANSPORT  NAME                 PORT   TLS  SMART")
	for _, p := range cat {
		smart := "no"
		if p.Smart != nil {
			smart = "yes"
		}
		tls := "no"
		if p.TLS {
			tls = "yes"
		}
		fmt.Fprintf(w, "%-10s %-20s %-6d %-4s %s\n", p.Transport, p.Name, p.DefaultPort, tls, smart)
	}
	fmt.Fprintf(w, "\n%d total\n", len(cat))
}

// printSummary writes the run's outcome.
func printSummary(w *os.File, s engine.Summary) {
	fmt.Fprintf(w, "\ntarpit-fuzz summary\n")
	fmt.Fprintf(w, "  catalogue    : %d protocols\n", s.Protocols)
	fmt.Fprintf(w, "  exercised    : %d\n", s.Ran)
	fmt.Fprintf(w, "  payloads sent: %d\n", s.Sent)
	fmt.Fprintf(w, "  responses    : %d\n", s.Responses)
	fmt.Fprintf(w, "  skipped      : %d (port unreachable)\n", s.Skipped)
	if len(s.SkippedList) > 0 {
		fmt.Fprintf(w, "                 %s\n", strings.Join(s.SkippedList, " "))
	}
	fmt.Fprintf(w, "  elapsed      : %s\n", s.Elapsed.Round(time.Millisecond))
	if len(s.Findings) == 0 {
		fmt.Fprintf(w, "  findings     : 0 — the sensor survived the campaign\n")
		return
	}
	fmt.Fprintf(w, "  findings     : %d (crashes=%d hangs=%d)\n", len(s.Findings), s.Crashes, s.Hangs)
	for i, f := range s.Findings {
		fmt.Fprintf(w, "    [%d] %-16s kind=%-5s iter=%d reason=%q\n",
			i+1, f.Protocol, f.Kind, f.Iteration, f.Reason)
		if f.PayloadLen > 0 {
			fmt.Fprintf(w, "        payload[%dB]: %x\n", f.PayloadLen, trimHex(f.Payload, 64))
		}
	}
}

// trimHex returns at most n bytes of b, for a compact payload printout.
func trimHex(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}
