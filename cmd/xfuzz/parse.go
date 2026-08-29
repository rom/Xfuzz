package main

import (
	"flag"
	"strings"
)

// parse reads flags whether they come before or after the positional
// arguments.
//
// Go's flag package stops at the first argument that is not a flag, so
// `xfuzz validate campaign.yaml --json` would silently ignore --json and treat
// it as a second file. That is exactly what people type, and a tool that
// quietly does the wrong thing with it is worse than one that refuses.
//
// So the arguments are permuted first: flags to the front, positionals to the
// back. A "--" argument ends flag parsing, as everywhere else, so a file whose
// name begins with a dash is still reachable.
func parse(fs *flag.FlagSet, args []string) error {
	var flags, positional []string

	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			i++
			goto rest
		case strings.HasPrefix(a, "-") && a != "-":
			flags = append(flags, a)
			// A flag written as --name value consumes the next argument, unless
			// it is boolean or was written as --name=value.
			if !strings.Contains(a, "=") && takesValue(fs, a) && i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		default:
			positional = append(positional, a)
		}
	}
rest:
	positional = append(positional, args[i:]...)

	return fs.Parse(append(flags, append([]string{"--"}, positional...)...))
}

// takesValue reports whether a flag consumes the next argument.
func takesValue(fs *flag.FlagSet, arg string) bool {
	name := strings.TrimLeft(arg, "-")
	f := fs.Lookup(name)
	if f == nil {
		// Unknown: let flag report it, and assume it takes a value so the
		// argument after it is not mistaken for a file.
		return true
	}
	b, ok := f.Value.(interface{ IsBoolFlag() bool })
	return !ok || !b.IsBoolFlag()
}
