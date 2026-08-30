# Writing a grammar

> The `.xfg` language: how to describe a format so a campaign mutates it the way
> the format allows, and reaches the code behind the checks.

A fuzzer with no idea what an input is spends most of its budget on inputs the
target rejects at the first check. If a format has a magic number, a length
field and a checksum, then random bytes fail all three, and every bug behind
them is unreachable no matter how long the campaign runs.

A grammar fixes that by saying which parts are structure and which are payload,
and which fields are *derived* from others. Xfuzz mutates the payload and
recomputes the derived fields afterwards, so a mutated input still passes the
target's own consistency checks — and the bug behind them becomes reachable.

That is the whole argument, and it is measurable. The `chunked_format` target in
`testdata/targets/` puts every planted bug behind a CRC. A campaign driven by
the grammar in `chunked_format.xfg` finds them; the same campaign driven by byte
mutation does not.

## A first grammar

```xfg
# chunked.xfg
format chunked {
  magic:   magic "XCHK"
  version: u8 = 1
  chunks:  repeat<1..8> chunk
}

struct chunk {
  tag:     bytes[4]
  length:  u32be   = len(^payload)
  payload: bytes<0..128>
  crc:     u32be   = crc32(^tag..^payload)
}
```

Point a campaign at it:

```yaml
format:
  grammar: ./chunked.xfg
```

That one line does two things. It generates seeds when you have none, and — the
part that matters — it becomes the **codec**: inputs are decoded into the tree
the grammar describes, mutated as a tree, and repaired by the fixup pass before
they are executed. Setting `codec: raw` beside a grammar turns the second half
off, which is a meaningful thing to ask for when you want to measure what the
structure is buying.

And see what it produces before running anything:

```console
$ xfuzz grammar ./chunked.xfg -n 4
```

## The shape of a file

A grammar is a sequence of declarations. Exactly one is a `format`, which is the
root — the thing an input *is*. Everything else is a `struct`, named and
referred to by name.

```xfg
format name { ...fields... }
struct name { ...fields... }
```

Comments start with `#` or `//` and run to the end of the line.

Each field is `name: type`, optionally followed by `= value` — a literal or a
derivation. Field order is byte order: the fields are laid out in the order they
are written.

## Types

### Integers

Width and byte order are always explicit, because a format's fields are, and
leaving either implicit is how a schema silently describes the wrong layout.

```
u8   i8
u16be u16le   i16be i16le
u32be u32le   i32be i32le
u64be u64le   i64be i64le
```

### Bytes and text

```xfg
tag:     bytes[4]          # exactly four bytes
payload: bytes<0..128>     # between none and 128
name:    str<1..64>        # the same, marked as text
blob:    bytes             # unbounded
```

`str` differs from `bytes` only in what mutation does to it: text operators
apply, so it stays plausible as text rather than becoming arbitrary binary.

Bounds are not decoration. They are what stops a mutator producing something no
parser would ever see: a PNG chunk type is exactly four bytes, and a five-byte
one is not a deeper exploration of PNG, it is an input every reader rejects at
offset four. Deliberate violation of a format's rules is expressed by relaxing
the schema or by `format.suppress`, not by hoping a mutator ignores the model.

### Magic

```xfg
signature: magic "\x89PNG\r\n\x1a\n"
```

A fixed literal, off-limits to mutation. A signature a target compares byte for
byte is not worth spending executions on; declaring it as `magic` says so once
rather than hoping the scheduler works it out.

### Repetition, choice, optionality

```xfg
chunks:  repeat<1..8> chunk    # between one and eight, by name
trailer: opt footer            # present or not

body: choice {
  text:   str<0..64>
  number: u32le
  nested: subrecord
}
```

`repeat` takes a declared type by name. `choice` picks one alternative;
mutation can switch between them, which is how a campaign explores a tagged
union rather than only the arm the seeds happened to use.

### References to declared types

Any other name is a reference:

```xfg
struct header { version: u8 }

format msg {
  head: header
  body: bytes<0..64>
}
```

## Derived fields

This is the part that matters, and the reason a schema beats a set of example
inputs. A derived field is recomputed after every mutation, so a mutated input
is still internally consistent.

```xfg
length: u32be = len(^payload)             # bytes in one field
count:  u16le = count(^items)             # elements in a repeat
at:     u32le = offset(^data)             # where a field starts
crc:    u32be = crc32(^tag..^payload)     # over a range
```

### References

A derivation names its subject with a reference:

| Form | Means |
| --- | --- |
| `^field` | a sibling |
| `^^parent.field` | one level up, then down |
| `/root.path[0].field` | from the root of the input |
| `.` | this field itself |

A range is two references joined by `..`, covering everything from the start of
the first to the end of the last:

```xfg
crc: u32be = crc32(^tag..^payload)
```

### Adjustments

```xfg
length: u32be = len(^payload) + 8     # "length including the header"
size:   u32be = len(^body) - 1        # "length excluding the terminator"
crc:    u32be = crc32(^header..^body) selfzero
```

`selfzero` treats the checksum field itself as zero while computing it, which is
what protocols do when the checksum lies inside the range it covers — IP and
ICMP among them.

### Checksums

`crc32`, `crc32c`, `crc16ccitt`, `adler32`, `internet`, `sum8`, `sum16`,
`sum32`, `xor8`, `len`, `zero`.

`internet` is the one's-complement sum used by IP, UDP and TCP. `zero` is for a
field a format reserves and never checks.

## Literals

```xfg
version: u8 = 1
kind:    bytes[4] = "IDAT"
```

A literal is a starting value, not a constant: mutation may change it, which is
usually what you want for a version byte or a chunk type. Use `magic` for a
value that must not change.

## Writing one for a real format

Work outside in, and measure as you go.

1. **Start with the envelope.** Signature, version, a repeat of records. Do not
   describe the records yet — `bytes<0..N>` is a perfectly good placeholder and
   a campaign can start against it immediately.
2. **Check it round-trips.** `xfuzz grammar ./f.xfg -n 8 --raw` prints what it
   generates. If the target rejects all eight, the envelope is wrong and no
   amount of detail below it will help.
3. **Add the derivations next, not the detail.** Lengths and checksums are what
   unlock the code behind them, and they pay off long before field-level detail
   does.
4. **Then refine the records that matter.** A campaign's coverage tells you
   which branch it cannot reach; describe *that* record.
5. **Stop before the format does.** A grammar that describes every field of a
   complex format constrains mutation so tightly that it stops finding the bugs
   that live in fields a parser mishandles. The goal is not a specification, it
   is a description accurate enough that inputs survive validation and loose
   enough that they still surprise.

## When the schema is in the way

Some bugs are *in* the consistency checks — the length field that is trusted
over the buffer, the checksum verified after the copy rather than before. A
grammar that always makes those fields correct will never find them.

`format.suppress` turns off a class of derivation for a campaign, leaving the
field to be mutated like any other:

```yaml
format:
  grammar: ./chunked.xfg
  suppress: [length]     # length, count, offset, checksum
```

Run one campaign with them and one without. The first reaches the code behind
the checks; the second attacks the checks themselves.

## Diagnosing a grammar

```console
$ xfuzz grammar ./f.xfg              # compile it, and show what it generates
$ xfuzz grammar ./f.xfg -n 16 --raw  # sixteen samples, raw bytes
$ xfuzz grammar ./f.xfg --seed 7     # the same samples every time
```

The console has the same thing under **Grammar**, where the samples are
regenerated as you edit.

Parse errors name the file, the line and the column. A grammar that parses but
does not validate — a reference to a type that is not declared, a cycle with no
base case — is refused with the same precision, before a campaign starts rather
than during one.

## What a grammar is not

- **Not a parser.** It describes layout so mutation can respect it. A format
  whose structure depends on values Xfuzz cannot compute — a compression stream,
  an encrypted section — is described down to that point and left as `bytes`
  below it.
- **Not required.** A campaign with no grammar mutates bytes, which is the right
  answer for a format with no checks worth passing, and the only answer for one
  nobody has documented.
- **Not a guarantee.** A grammar makes valid inputs cheap, not certain: mutation
  deliberately produces some that are not, because a parser's handling of a
  malformed input is exactly what a fuzzer is for.

## Related

- [DESIGN.md](DESIGN.md) — the input IR and why structure is the core model.
- [adr/ADR-0005](adr/ADR-0005-unified-structured-input-ir.md) — why one IR
  serves every domain.
- [GUIDE.md](GUIDE.md) — running the campaign the grammar feeds.
