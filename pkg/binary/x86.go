package binary

// An x86-64 instruction length decoder, and just enough classification to
// recover control flow.
//
// This is the smallest thing that can turn a byte range into a set of basic
// blocks. It answers two questions per instruction — how long is it, and does it
// change the flow of control — and refuses to answer any others. A full
// disassembler would be an order of magnitude more code, would need maintaining
// against every new instruction set extension, and would tell the fuzzer nothing
// it uses.
//
// Length decoding is nevertheless exact, not approximate. An off-by-one puts the
// walker inside an instruction, and from there every subsequent length is
// garbage; there is no way to notice from the inside, and the coverage map
// silently gets breakpoints in the middle of instructions. The decoder is
// therefore checked against objdump over real binaries rather than against
// hand-written expectations alone.

// Kind classifies an instruction by what it does to the program counter.
type Kind uint8

// The kinds. Everything the walker does not need to distinguish is KindOther.
const (
	KindOther        Kind = iota // falls through
	KindJump                     // unconditional, direct: control leaves and does not return
	KindCondJump                 // conditional, direct: two successors
	KindCall                     // direct call: falls through, and starts a block elsewhere
	KindIndirectJump             // jmp rax, jmp [rax*8+table]: successors unknown
	KindIndirectCall             // call rax: falls through, callee unknown
	KindReturn                   // ret, retf
	KindTrap                     // int3, ud2, hlt: control does not continue
)

// Terminates reports whether an instruction ends its basic block.
func (k Kind) Terminates() bool {
	switch k {
	case KindJump, KindCondJump, KindIndirectJump, KindReturn, KindTrap:
		return true
	}
	return false
}

// FallsThrough reports whether the next instruction is a successor.
func (k Kind) FallsThrough() bool {
	switch k {
	case KindJump, KindIndirectJump, KindReturn, KindTrap:
		return false
	}
	return true
}

var kindNames = [...]string{
	KindOther: "other", KindJump: "jump", KindCondJump: "cond-jump",
	KindCall: "call", KindIndirectJump: "indirect-jump",
	KindIndirectCall: "indirect-call", KindReturn: "return", KindTrap: "trap",
}

func (k Kind) String() string {
	if int(k) < len(kindNames) && kindNames[k] != "" {
		return kindNames[k]
	}
	return "unknown"
}

// Inst is one decoded instruction: its length, what it does to control flow,
// and where it goes when that is knowable from the encoding alone.
type Inst struct {
	Len  int
	Kind Kind

	// Target is the absolute address a direct branch or call transfers to. Valid
	// only when HasTarget is set, which excludes every indirect form — those are
	// exactly the addresses static analysis cannot supply.
	Target    uint64
	HasTarget bool

	// Ref is the absolute address a RIP-relative operand names, valid when
	// HasRef is set. RefIsAddress distinguishes lea, which computes the address
	// itself, from every other form, which dereferences it.
	//
	// This is how a stripped binary gives up the location of a function nothing
	// calls directly: _start does not call main, it loads main's address with a
	// lea and passes it on. Without this, recursive descent stops two
	// instructions into the program.
	Ref          uint64
	HasRef       bool
	RefIsAddress bool
}

// operand encodings, as flags on the opcode tables.
const (
	fModRM   = 1 << iota // an addressing byte follows the opcode
	fImm8                // ib
	fImm16               // iw
	fImmZ                // iz: 4 bytes, or 2 under a 66 prefix
	fImmV                // io: 8 under REX.W, 2 under 66, else 4
	fMoffs               // a full address-size immediate (8, or 4 under a 67 prefix)
	fGroup1              // F6/F7: /0 and /1 carry an immediate, the rest do not
	fInvalid             // not encodable in 64-bit mode
	fEnter               // C8: iw then ib
)

// oneByte is the primary opcode map for 64-bit mode.
//
// Written out rather than generated because it is read far more often than it is
// changed, and because a generator would need the same table as its input.
var oneByte = [256]uint16{
	// 00-0F: ADD, OR, and the two-byte escape.
	0x00: fModRM, 0x01: fModRM, 0x02: fModRM, 0x03: fModRM, 0x04: fImm8, 0x05: fImmZ,
	0x06: fInvalid, 0x07: fInvalid,
	0x08: fModRM, 0x09: fModRM, 0x0A: fModRM, 0x0B: fModRM, 0x0C: fImm8, 0x0D: fImmZ,
	0x0E: fInvalid, 0x0F: 0, // escape, handled before the table

	// 10-1F: ADC, SBB.
	0x10: fModRM, 0x11: fModRM, 0x12: fModRM, 0x13: fModRM, 0x14: fImm8, 0x15: fImmZ,
	0x16: fInvalid, 0x17: fInvalid,
	0x18: fModRM, 0x19: fModRM, 0x1A: fModRM, 0x1B: fModRM, 0x1C: fImm8, 0x1D: fImmZ,
	0x1E: fInvalid, 0x1F: fInvalid,

	// 20-2F: AND, SUB. 26 and 2E are segment prefixes, consumed earlier.
	0x20: fModRM, 0x21: fModRM, 0x22: fModRM, 0x23: fModRM, 0x24: fImm8, 0x25: fImmZ,
	0x27: fInvalid,
	0x28: fModRM, 0x29: fModRM, 0x2A: fModRM, 0x2B: fModRM, 0x2C: fImm8, 0x2D: fImmZ,
	0x2F: fInvalid,

	// 30-3F: XOR, CMP.
	0x30: fModRM, 0x31: fModRM, 0x32: fModRM, 0x33: fModRM, 0x34: fImm8, 0x35: fImmZ,
	0x37: fInvalid,
	0x38: fModRM, 0x39: fModRM, 0x3A: fModRM, 0x3B: fModRM, 0x3C: fImm8, 0x3D: fImmZ,
	0x3F: fInvalid,

	// 40-4F are REX prefixes and 50-5F are PUSH/POP r64: no operand bytes.

	0x60: fInvalid, 0x61: fInvalid,
	0x62: 0,      // EVEX; handled before the table
	0x63: fModRM, // MOVSXD
	0x68: fImmZ,  // PUSH imm
	0x69: fModRM | fImmZ,
	0x6A: fImm8,
	0x6B: fModRM | fImm8,

	// 70-7F: Jcc rel8.
	0x70: fImm8, 0x71: fImm8, 0x72: fImm8, 0x73: fImm8,
	0x74: fImm8, 0x75: fImm8, 0x76: fImm8, 0x77: fImm8,
	0x78: fImm8, 0x79: fImm8, 0x7A: fImm8, 0x7B: fImm8,
	0x7C: fImm8, 0x7D: fImm8, 0x7E: fImm8, 0x7F: fImm8,

	0x80: fModRM | fImm8,
	0x81: fModRM | fImmZ,
	0x82: fInvalid,
	0x83: fModRM | fImm8,
	0x84: fModRM, 0x85: fModRM, 0x86: fModRM, 0x87: fModRM,
	0x88: fModRM, 0x89: fModRM, 0x8A: fModRM, 0x8B: fModRM,
	0x8C: fModRM, 0x8D: fModRM, 0x8E: fModRM, 0x8F: fModRM,

	0x9A: fInvalid,

	0xA0: fMoffs, 0xA1: fMoffs, 0xA2: fMoffs, 0xA3: fMoffs,
	0xA8: fImm8, 0xA9: fImmZ,

	0xB0: fImm8, 0xB1: fImm8, 0xB2: fImm8, 0xB3: fImm8,
	0xB4: fImm8, 0xB5: fImm8, 0xB6: fImm8, 0xB7: fImm8,
	0xB8: fImmV, 0xB9: fImmV, 0xBA: fImmV, 0xBB: fImmV,
	0xBC: fImmV, 0xBD: fImmV, 0xBE: fImmV, 0xBF: fImmV,

	0xC0: fModRM | fImm8, 0xC1: fModRM | fImm8,
	0xC2: fImm16,                   // RET imm16
	0xC4: fInvalid, 0xC5: fInvalid, // VEX; handled before the table
	0xC6: fModRM | fImm8,
	0xC7: fModRM | fImmZ,
	0xC8: fEnter,
	0xCA: fImm16,
	0xCD: fImm8,
	0xCE: fInvalid,

	0xD0: fModRM, 0xD1: fModRM, 0xD2: fModRM, 0xD3: fModRM,
	0xD4: fInvalid, 0xD5: fInvalid, 0xD6: fInvalid,
	0xD8: fModRM, 0xD9: fModRM, 0xDA: fModRM, 0xDB: fModRM,
	0xDC: fModRM, 0xDD: fModRM, 0xDE: fModRM, 0xDF: fModRM,

	0xE0: fImm8, 0xE1: fImm8, 0xE2: fImm8, 0xE3: fImm8,
	0xE4: fImm8, 0xE5: fImm8, 0xE6: fImm8, 0xE7: fImm8,
	0xE8: fImmZ, 0xE9: fImmZ,
	0xEA: fInvalid,
	0xEB: fImm8,

	0xF6: fModRM | fGroup1, 0xF7: fModRM | fGroup1,
	0xFE: fModRM, 0xFF: fModRM,
}

// twoByte is the 0F xx map.
var twoByte = [256]uint16{
	0x00: fModRM, 0x01: fModRM, 0x02: fModRM, 0x03: fModRM,
	0x04: fInvalid, 0x0A: fInvalid, 0x0C: fInvalid,
	0x0D: fModRM, 0x0F: fModRM | fImm8, // 3DNow!

	0x10: fModRM, 0x11: fModRM, 0x12: fModRM, 0x13: fModRM,
	0x14: fModRM, 0x15: fModRM, 0x16: fModRM, 0x17: fModRM,
	0x18: fModRM, 0x19: fModRM, 0x1A: fModRM, 0x1B: fModRM,
	0x1C: fModRM, 0x1D: fModRM, 0x1E: fModRM, 0x1F: fModRM,

	0x20: fModRM, 0x21: fModRM, 0x22: fModRM, 0x23: fModRM,
	0x24: fInvalid, 0x25: fInvalid, 0x26: fInvalid, 0x27: fInvalid,
	0x28: fModRM, 0x29: fModRM, 0x2A: fModRM, 0x2B: fModRM,
	0x2C: fModRM, 0x2D: fModRM, 0x2E: fModRM, 0x2F: fModRM,

	0x36: fInvalid, 0x39: fInvalid,
	0x3B: fInvalid, 0x3C: fInvalid, 0x3D: fInvalid, 0x3E: fInvalid, 0x3F: fInvalid,

	0x40: fModRM, 0x41: fModRM, 0x42: fModRM, 0x43: fModRM,
	0x44: fModRM, 0x45: fModRM, 0x46: fModRM, 0x47: fModRM,
	0x48: fModRM, 0x49: fModRM, 0x4A: fModRM, 0x4B: fModRM,
	0x4C: fModRM, 0x4D: fModRM, 0x4E: fModRM, 0x4F: fModRM,

	0x50: fModRM, 0x51: fModRM, 0x52: fModRM, 0x53: fModRM,
	0x54: fModRM, 0x55: fModRM, 0x56: fModRM, 0x57: fModRM,
	0x58: fModRM, 0x59: fModRM, 0x5A: fModRM, 0x5B: fModRM,
	0x5C: fModRM, 0x5D: fModRM, 0x5E: fModRM, 0x5F: fModRM,
	0x60: fModRM, 0x61: fModRM, 0x62: fModRM, 0x63: fModRM,
	0x64: fModRM, 0x65: fModRM, 0x66: fModRM, 0x67: fModRM,
	0x68: fModRM, 0x69: fModRM, 0x6A: fModRM, 0x6B: fModRM,
	0x6C: fModRM, 0x6D: fModRM, 0x6E: fModRM, 0x6F: fModRM,

	0x70: fModRM | fImm8, 0x71: fModRM | fImm8, 0x72: fModRM | fImm8, 0x73: fModRM | fImm8,
	0x74: fModRM, 0x75: fModRM, 0x76: fModRM,
	0x78: fModRM, 0x79: fModRM, 0x7A: fInvalid, 0x7B: fInvalid,
	0x7C: fModRM, 0x7D: fModRM, 0x7E: fModRM, 0x7F: fModRM,

	// 80-8F: Jcc rel32.
	0x80: fImmZ, 0x81: fImmZ, 0x82: fImmZ, 0x83: fImmZ,
	0x84: fImmZ, 0x85: fImmZ, 0x86: fImmZ, 0x87: fImmZ,
	0x88: fImmZ, 0x89: fImmZ, 0x8A: fImmZ, 0x8B: fImmZ,
	0x8C: fImmZ, 0x8D: fImmZ, 0x8E: fImmZ, 0x8F: fImmZ,

	// 90-9F: SETcc.
	0x90: fModRM, 0x91: fModRM, 0x92: fModRM, 0x93: fModRM,
	0x94: fModRM, 0x95: fModRM, 0x96: fModRM, 0x97: fModRM,
	0x98: fModRM, 0x99: fModRM, 0x9A: fModRM, 0x9B: fModRM,
	0x9C: fModRM, 0x9D: fModRM, 0x9E: fModRM, 0x9F: fModRM,

	0xA3: fModRM, 0xA4: fModRM | fImm8, 0xA5: fModRM,
	0xA6: fInvalid, 0xA7: fInvalid,
	0xAB: fModRM, 0xAC: fModRM | fImm8, 0xAD: fModRM, 0xAE: fModRM, 0xAF: fModRM,

	0xB0: fModRM, 0xB1: fModRM, 0xB2: fModRM, 0xB3: fModRM,
	0xB4: fModRM, 0xB5: fModRM, 0xB6: fModRM, 0xB7: fModRM,
	0xB8: fModRM, 0xB9: fModRM, 0xBA: fModRM | fImm8, 0xBB: fModRM,
	0xBC: fModRM, 0xBD: fModRM, 0xBE: fModRM, 0xBF: fModRM,

	0xC0: fModRM, 0xC1: fModRM, 0xC2: fModRM | fImm8, 0xC3: fModRM,
	0xC4: fModRM | fImm8, 0xC5: fModRM | fImm8, 0xC6: fModRM | fImm8, 0xC7: fModRM,

	0xD0: fModRM, 0xD1: fModRM, 0xD2: fModRM, 0xD3: fModRM,
	0xD4: fModRM, 0xD5: fModRM, 0xD6: fModRM, 0xD7: fModRM,
	0xD8: fModRM, 0xD9: fModRM, 0xDA: fModRM, 0xDB: fModRM,
	0xDC: fModRM, 0xDD: fModRM, 0xDE: fModRM, 0xDF: fModRM,
	0xE0: fModRM, 0xE1: fModRM, 0xE2: fModRM, 0xE3: fModRM,
	0xE4: fModRM, 0xE5: fModRM, 0xE6: fModRM, 0xE7: fModRM,
	0xE8: fModRM, 0xE9: fModRM, 0xEA: fModRM, 0xEB: fModRM,
	0xEC: fModRM, 0xED: fModRM, 0xEE: fModRM, 0xEF: fModRM,
	0xF0: fModRM, 0xF1: fModRM, 0xF2: fModRM, 0xF3: fModRM,
	0xF4: fModRM, 0xF5: fModRM, 0xF6: fModRM, 0xF7: fModRM,
	0xF8: fModRM, 0xF9: fModRM, 0xFA: fModRM, 0xFB: fModRM,
	0xFC: fModRM, 0xFD: fModRM, 0xFE: fModRM, 0xFF: fInvalid,
}
