# A worked example of Xfuzz's script tier.
#
# Starlark, which is Python-shaped and hermetic: no filesystem, no network, no
# clock, no imports. That is not a limitation to work around — it is what keeps
# a campaign reproducible and what makes running someone else's campaign file
# safe. Every call is bounded by a step and an allocation budget.
#
# Three things are predeclared:
#
#   config    the settings from the campaign file, as a dict of strings
#   seed      the campaign seed, as an integer
#   finding() the constructor for reporting a bug
#
# Use it from a campaign like this:
#
#   scripts:
#     - name: oracle
#       path: ./oracle.star
#       config:
#         forbidden: "root:x:0:0"
#       objectives: [leaked_secret, mismatched_length]
#       mutators: [flip_high_bit]

# An oracle: the target must never echo a string it was never given.
#
# This is the case the tier exists for. No fuzzer can know what a leak looks
# like in your system, and a crash-only campaign against a target that answers
# every request politely finds nothing at all.
def leaked_secret(x):
    if config["forbidden"] in x.stdout or config["forbidden"] in x.stderr:
        return finding(
            summary = "the target echoed something it was never sent",
            detail = x.stdout + x.stderr,
        )
    return None

# An oracle over the input as well as the output: a length-prefixed protocol
# whose reply disagrees with what was actually read.
#
# Return None for "not a bug", a string when the summary is the whole answer,
# or finding(...) when there is more to say. Anything else is an error rather
# than a guess, so a mistake here is loud.
def mismatched_length(x):
    if len(x.input) < 2:
        return None
    declared = list(x.input.elems())[0]
    if declared > len(x.input) - 1 and "read %d" % declared in x.stdout:
        return "the target read past the end of its own frame"
    return None

# A mutator: flip the high bit of one byte.
#
# Asked for `count` variants at once, because the interpreter call and the
# conversion of the payload cost more than the mutation does. Every random
# choice comes from `seed`, which the host varies per call — a script that had
# its own source of entropy would make the campaign unreproducible, and a crash
# nobody can reproduce is not a finding.
def flip_high_bit(input, seed, count, max_bytes):
    if len(input) == 0:
        return []
    bs = list(input.elems())
    out = []
    for i in range(count):
        at = (seed + i * 2654435761) % len(bs)
        v = list(bs)
        v[at] = v[at] ^ 0x80
        out.append(bytes(v))
    return out

# A state function: label a protocol response so the campaign can build a state
# machine out of it (ADR-0006). Return an empty string or None for "cannot
# tell", which the trace records as unknown rather than guessing.
#
#   state:
#     fn: script
#     script: oracle:label
def label(resp):
    if len(resp) < 3:
        return None
    return "status-%d" % list(resp.elems())[0]
