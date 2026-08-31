// Package schemaio imports foreign format descriptions into Xfuzz grammars.
//
// The argument for it is arithmetic. Writing a grammar for a real format takes
// hours and most people will not do it, so a fuzzer whose structured mode
// requires one runs unstructured against almost every target it meets. But the
// descriptions already exist: a service has a .proto, a standard has an ABNF
// grammar in its RFC, a binary format has a Kaitai .ksy somebody wrote for a
// hex editor, an API has an OpenAPI document. Reading those is the difference
// between structured fuzzing being a feature people use and one they mean to
// get around to.
//
// # What an import is not
//
// It is not a translation. Every one of these languages can say things the
// Xfuzz grammar cannot, and some of them can say things nothing can generate —
// an ABNF prose-val is a sentence in English, a Kaitai instance is an
// expression over parsed values, an ASN.1 constraint is a first-order formula.
// So an importer produces two things: the schema, and a report of everything it
// left out and why.
//
// The report is the part that makes this trustworthy. A converter that silently
// drops what it cannot handle produces a grammar that looks complete and
// generates inputs a parser rejects at the first field, and the campaign spends
// its budget discovering that. Every importer here is a documented subset with
// its edges stated, and `xfuzz grammar import` prints them.
//
// # The variable-length integer
//
// Two of these formats — protobuf and DER — are built on integers whose width
// depends on their value, and the Xfuzz schema language has only fixed-width
// ones. The importers handle the case that covers most real messages (a value
// below 128 is one byte, and a one-byte length derivation encodes exactly that)
// and report the limit rather than emitting something that looks right and is
// not. It is the single largest gap in this package and it is named in every
// report that hits it.
package schemaio
