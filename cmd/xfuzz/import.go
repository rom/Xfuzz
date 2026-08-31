package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/rom/Xfuzz/pkg/capture"
	"github.com/rom/Xfuzz/pkg/schemaio"
)

func init() {
	register(&Command{
		Name: "capture", Group: "inspection",
		Short: "Turn a recorded session into a seed, its dependencies, and its secrets",
		Usage: "capture FILE [-o SESSION] [--secrets FILE] [--links]",
		// Local: reading a HAR and writing a session file involves no daemon,
		// and the credentials it separates out must not travel over an API.
		Run: runCapture,
	})
}

// runGrammarImport turns a foreign format description into an Xfuzz grammar.
//
// Local, because it is a file-to-file translation: there is no campaign, no
// target and nothing for a daemon to do. It prints the report on standard
// error and the grammar on standard output, so `xfuzz grammar import x.proto >
// x.xfg` writes the grammar and still shows what could not be translated.
func runGrammarImport(ctx context.Context, args []string) error {
	fs, _ := flags(commands["grammar"])
	as := fs.String("as", "", "importer to use: "+strings.Join(schemaio.Names(), ", ")+
		" (default: chosen from the file)")
	root := fs.String("root", "", "type to generate from (default: the importer's own choice)")
	out := fs.String("o", "", "write the grammar here instead of standard output")
	quiet := fs.Bool("quiet", false, "do not print what could not be translated")
	if err := parse(fs, args); err != nil {
		return err
	}
	_ = ctx
	path, err := onePath(fs.Args())
	if err != nil {
		return fmt.Errorf("expected exactly one description to import")
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	imp, ok := schemaio.For(*as)
	if *as == "" {
		imp, ok = schemaio.Detect(path, src)
	}
	if !ok {
		return fmt.Errorf("nothing imports %s; name one with --as (%s)",
			filepath.Ext(path), strings.Join(schemaio.Names(), ", "))
	}

	sch, rep, err := imp.Import(src, path)
	if err != nil {
		return err
	}
	if *root != "" {
		if err := schemaio.Reroot(sch, *root); err != nil {
			return err
		}
	}

	if !*quiet {
		// To standard error, so the grammar can be redirected and the report
		// still read. What an importer left out is the thing somebody has to
		// decide about, and printing it where a redirect swallows it would
		// make every import look complete.
		fmt.Fprint(os.Stderr, rep)
	}
	text := sch.String()
	if *out == "" {
		fmt.Print(text)
		return nil
	}
	if err := os.WriteFile(*out, []byte(text), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s: %d type(s), root %s\n", *out, len(sch.Types), sch.Root)
	return nil
}

// runCapture prepares a recorded session for a campaign.
//
// Three outputs from one input, and they are separate on purpose. The redacted
// session is the seed and can be committed; the secrets file holds the
// credentials and must not be; the dependency report is what an operator reads
// to decide whether inference found what the session actually chains on.
func runCapture(ctx context.Context, args []string) error {
	fs, _ := flags(commands["capture"])
	out := fs.String("o", "", "write the redacted session here instead of standard output")
	secretsPath := fs.String("secrets", "", "write the credentials here, as placeholder=value")
	showLinks := fs.Bool("links", false, "print the inferred dependencies")
	if err := parse(fs, args); err != nil {
		return err
	}
	_ = ctx
	path, err := onePath(fs.Args())
	if err != nil {
		return fmt.Errorf("expected exactly one capture file")
	}
	src, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	c, err := capture.Read(path, src)
	if err != nil {
		return err
	}

	redacted, secrets := capture.Redact(c)
	fmt.Fprintf(os.Stderr, "%s: %d exchange(s) across %d host(s); %d credential(s)\n",
		path, len(c.Exchanges), len(c.Hosts()), secrets.Len())
	for _, note := range c.Notes {
		fmt.Fprintf(os.Stderr, "  note: %s\n", note)
	}

	if *showLinks {
		links := capture.Infer(redacted)
		fmt.Fprintf(os.Stderr, "  %d dependenc(ies) inferred\n", len(links))
		for _, l := range links {
			fmt.Fprintf(os.Stderr, "    %s\n", l)
		}
	}

	if secrets.Len() > 0 {
		if *secretsPath == "" {
			fmt.Fprintf(os.Stderr, "  %d credential(s) were replaced with placeholders and "+
				"are not written anywhere; pass --secrets FILE to keep them\n", secrets.Len())
		} else {
			// 0600, because this is the file that holds the tokens. The
			// redacted session beside it is what goes in a repository.
			var b strings.Builder
			b.WriteString("# credentials for a captured session, written by xfuzz capture.\n")
			b.WriteString("# the redacted session holds the placeholders; this holds the values.\n")
			for _, ph := range secrets.Placeholders() {
				v, _ := secrets.Value(ph)
				fmt.Fprintf(&b, "%s=%s\n", ph, v)
			}
			if err := os.WriteFile(*secretsPath, []byte(b.String()), 0o600); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "  wrote %s (mode 0600)\n", *secretsPath)
		}
	}

	session := redacted.Session()
	if *out == "" {
		os.Stdout.Write(session)
		return nil
	}
	if err := os.WriteFile(*out, session, 0o644); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "  wrote %s (%d bytes)\n", *out, len(session))
	return nil
}
