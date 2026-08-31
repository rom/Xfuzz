package binary

import "encoding/binary"

// ErrUndecodable is what Decode reports for bytes it will not guess at.
//
// A length decoder that guesses is worse than one that stops: a wrong length
// desynchronises the walk, and every instruction after it is nonsense that still
// looks like instructions. Refusing is recoverable — the caller drops the sweep
// and relies on the entry points it knows.
type decodeError string

func (e decodeError) Error() string { return string(e) }

// ErrUndecodable is returned for an encoding this decoder does not cover.
const ErrUndecodable = decodeError("binary: undecodable instruction")

// ErrTruncated is returned when an instruction runs past the end of the buffer.
const ErrTruncated = decodeError("binary: instruction truncated")

// maxInstLen is the architectural limit. Anything longer is a decode that has
// gone wrong, and bounding it stops a runaway prefix loop.
const maxInstLen = 15

// Decode decodes one x86-64 instruction at the start of code, which is located
// at virtual address pc.
//
// pc is needed only to resolve the target of a relative branch; the length does
// not depend on it. It returns ErrUndecodable rather than a guess for anything
// outside the covered encodings, and ErrTruncated when the instruction would run
// past the end of the buffer.
func Decode(code []byte, pc uint64) (Inst, error) {
	if len(code) == 0 {
		return Inst{}, ErrTruncated
	}

	var (
		i        int
		opsize16 bool // a 66 prefix is present
		addr32   bool // a 67 prefix is present
		rexW     bool
		sawRex   bool
	)

	// Legacy prefixes, then REX. REX must be the last prefix before the opcode,
	// so a prefix appearing after one cancels it — which real encoders do not
	// emit, but which decoders must not mis-measure.
prefixes:
	for ; i < len(code) && i < maxInstLen; i++ {
		switch c := code[i]; {
		case c == 0x66:
			opsize16, sawRex, rexW = true, false, false
		case c == 0x67:
			addr32, sawRex, rexW = true, false, false
		case c == 0xF0 || c == 0xF2 || c == 0xF3,
			c == 0x2E || c == 0x36 || c == 0x3E || c == 0x26,
			c == 0x64 || c == 0x65:
			sawRex, rexW = false, false
		case c >= 0x40 && c <= 0x4F:
			sawRex, rexW = true, c&0x08 != 0
		default:
			break prefixes
		}
	}
	_ = sawRex
	if i >= len(code) {
		return Inst{}, ErrTruncated
	}

	op := code[i]
	i++

	// VEX-encoded instructions. The prefix carries its own length, and none of
	// them are branches, so the classification is KindOther and only the length
	// matters. C4/C5 are only prefixes when the following byte's top bits make
	// the legacy LES/LDS encoding invalid, which in 64-bit mode is always.
	if op == 0xC4 || op == 0xC5 {
		return decodeVEX(code, i, op)
	}
	if op == 0x62 {
		return decodeEVEX(code, i)
	}

	table, flags := &oneByte, uint16(0)
	twoByteOp := false
	switch op {
	case 0x0F:
		if i >= len(code) {
			return Inst{}, ErrTruncated
		}
		op = code[i]
		i++
		twoByteOp = true
		switch op {
		case 0x38:
			// Three-byte escape: every 0F 38 opcode takes a ModRM and no
			// immediate.
			if i >= len(code) {
				return Inst{}, ErrTruncated
			}
			i++
			flags = fModRM
		case 0x3A:
			// Three-byte escape: ModRM and an 8-bit immediate throughout.
			if i >= len(code) {
				return Inst{}, ErrTruncated
			}
			i++
			flags = fModRM | fImm8
		default:
			flags = twoByte[op]
		}
	default:
		flags = table[op]
		if op >= 0x50 && op <= 0x5F { // PUSH/POP r64
			flags = 0
		}
	}

	if flags&fInvalid != 0 {
		return Inst{}, ErrUndecodable
	}
	// An opcode with no table entry and no operands is only correct if it really
	// takes none. The maps above list every 64-bit encoding that does take one,
	// so a zero entry means a bare opcode — but three-byte-escape bytes and the
	// prefixes have already been consumed, so a zero here is trustworthy.

	var modrmReg byte
	var modrmMod byte
	ripAt := -1
	haveModRM := flags&fModRM != 0
	if haveModRM {
		if i >= len(code) {
			return Inst{}, ErrTruncated
		}
		modrm := code[i]
		i++
		modrmMod = modrm >> 6
		modrmReg = (modrm >> 3) & 7
		rm := modrm & 7

		if modrmMod != 3 {
			if rm == 4 { // a SIB byte follows
				if i >= len(code) {
					return Inst{}, ErrTruncated
				}
				sib := code[i]
				i++
				// base == 5 with mod == 0 means a disp32 and no base register.
				if modrmMod == 0 && sib&7 == 5 {
					i += 4
				}
			} else if modrmMod == 0 && rm == 5 {
				// RIP-relative: always a 32-bit displacement, and the one
				// addressing form whose target this package resolves.
				ripAt = i
				i += 4
			}
			switch modrmMod {
			case 1:
				i++
			case 2:
				i += 4
			}
		}
	}

	// F6 and F7 carry an immediate only for /0 and /1 (TEST).
	if flags&fGroup1 != 0 && modrmReg <= 1 {
		if op == 0xF6 {
			flags |= fImm8
		} else {
			flags |= fImmZ
		}
	}

	immAt := i
	switch {
	case flags&fEnter != 0:
		i += 3
	case flags&fImm8 != 0:
		i++
	case flags&fImm16 != 0:
		i += 2
	case flags&fImmZ != 0:
		if opsize16 {
			i += 2
		} else {
			i += 4
		}
	case flags&fImmV != 0:
		switch {
		case rexW:
			i += 8
		case opsize16:
			i += 2
		default:
			i += 4
		}
	case flags&fMoffs != 0:
		if addr32 {
			i += 4
		} else {
			i += 8
		}
	}

	if i > len(code) {
		return Inst{}, ErrTruncated
	}
	if i > maxInstLen {
		return Inst{}, ErrUndecodable
	}

	in := Inst{Len: i}
	if ripAt >= 0 {
		d := int64(int32(binary.LittleEndian.Uint32(code[ripAt:])))
		in.Ref = uint64(int64(pc) + int64(i) + d)
		in.HasRef = true
		// LEA is the encoding that takes an address rather than dereferencing
		// one, so its target is a pointer to something rather than the something
		// itself. That distinction is what separates "this function's address is
		// being loaded" from "this global is being read".
		in.RefIsAddress = op == 0x8D && !twoByteOp
	}
	classify(&in, code, op, twoByteOp, immAt, opsize16, modrmMod, modrmReg, pc)
	return in, nil
}

// classify fills in the control-flow fields. Length is already decided; this
// only reads bytes the length decode has already validated.
func classify(in *Inst, code []byte, op byte, twoByteOp bool,
	immAt int, opsize16 bool, mod, reg byte, pc uint64) {

	rel := func(size int) {
		var d int64
		switch size {
		case 1:
			d = int64(int8(code[immAt]))
		case 2:
			d = int64(int16(binary.LittleEndian.Uint16(code[immAt:])))
		default:
			d = int64(int32(binary.LittleEndian.Uint32(code[immAt:])))
		}
		in.Target = uint64(int64(pc) + int64(in.Len) + d)
		in.HasTarget = true
	}
	zsize := 4
	if opsize16 {
		zsize = 2
	}

	if twoByteOp {
		switch {
		case op >= 0x80 && op <= 0x8F: // Jcc rel32
			in.Kind = KindCondJump
			rel(zsize)
		case op == 0x0B: // UD2
			in.Kind = KindTrap
		case op == 0x05, op == 0x07, op == 0x34, op == 0x35: // SYSCALL/SYSRET/SYSENTER/SYSEXIT
			in.Kind = KindOther
		}
		return
	}

	switch {
	case op >= 0x70 && op <= 0x7F: // Jcc rel8
		in.Kind = KindCondJump
		rel(1)
	case op >= 0xE0 && op <= 0xE3: // LOOP, LOOPE, LOOPNE, JrCXZ
		in.Kind = KindCondJump
		rel(1)
	case op == 0xEB:
		in.Kind = KindJump
		rel(1)
	case op == 0xE9:
		in.Kind = KindJump
		rel(zsize)
	case op == 0xE8:
		in.Kind = KindCall
		rel(zsize)
	case op == 0xC3, op == 0xC2, op == 0xCB, op == 0xCA:
		in.Kind = KindReturn
	case op == 0xCC, op == 0xF4, op == 0xF1:
		in.Kind = KindTrap
	case op == 0xCF: // IRET
		in.Kind = KindReturn
	case op == 0xFF:
		// Group 5. The register field of the addressing byte selects, and this
		// is the only place an indirect branch is encoded.
		switch reg {
		case 2:
			in.Kind = KindIndirectCall
		case 3:
			in.Kind = KindIndirectCall // CALL far
		case 4:
			in.Kind = KindIndirectJump
		case 5:
			in.Kind = KindIndirectJump // JMP far
		}
		_ = mod
	}
}

// decodeVEX measures a VEX-prefixed instruction.
//
// None of them branch, so only the length is at stake: a two-byte VEX is C5
// followed by one payload byte, a three-byte VEX is C4 followed by two, and both
// are followed by an opcode and a full addressing byte. The map select in the
// three-byte form decides whether an 8-bit immediate follows, which is the one
// place the length actually varies.
func decodeVEX(code []byte, i int, prefix byte) (Inst, error) {
	mapSelect := 1
	if prefix == 0xC4 {
		if i+1 >= len(code) {
			return Inst{}, ErrTruncated
		}
		// map_select lives in the low five bits of the first payload byte, and
		// selects which legacy escape space the opcode belongs to. A two-byte
		// VEX has no room for it and is always the 0F space.
		mapSelect = int(code[i] & 0x1F)
		i += 2
	} else {
		if i >= len(code) {
			return Inst{}, ErrTruncated
		}
		i++
	}
	if i >= len(code) {
		return Inst{}, ErrTruncated
	}
	op := code[i]
	i++

	// VZEROUPPER and VZEROALL are the one pair of VEX encodings with no
	// addressing byte: they take no operands at all. Consuming one anyway
	// over-measures them by a byte, which desynchronises the sweep for the rest
	// of the function — found by the objdump comparison, 630 times in one Go
	// binary and never in a C one, because Go's assembler emits vzeroupper at
	// every transition out of vector code.
	if mapSelect == 1 && op == 0x77 {
		if i > maxInstLen {
			return Inst{}, ErrUndecodable
		}
		return Inst{Len: i, Kind: KindOther}, nil
	}

	imm8 := vexImm8(mapSelect, op)

	if i >= len(code) {
		return Inst{}, ErrTruncated
	}
	modrm := code[i]
	i++
	mod, rm := modrm>>6, modrm&7
	if mod != 3 {
		if rm == 4 {
			if i >= len(code) {
				return Inst{}, ErrTruncated
			}
			sib := code[i]
			i++
			if mod == 0 && sib&7 == 5 {
				i += 4
			}
		} else if mod == 0 && rm == 5 {
			i += 4
		}
		switch mod {
		case 1:
			i++
		case 2:
			i += 4
		}
	}
	if imm8 {
		i++
	}
	if i > len(code) {
		return Inst{}, ErrTruncated
	}
	if i > maxInstLen {
		return Inst{}, ErrUndecodable
	}
	return Inst{Len: i, Kind: KindOther}, nil
}

// decodeEVEX measures an AVX-512 instruction.
//
// The EVEX prefix is a fixed 0x62 followed by three payload bytes, then an
// opcode and a full addressing byte. Only the map select in the low three bits
// of the first payload byte changes the length, and only by deciding whether an
// 8-bit immediate follows. Displacement compression scales the displacement's
// *value* by the vector width and leaves its width alone, so it does not enter
// here.
//
// Maps beyond the three classical escape spaces are the APX promotions, whose
// operand encodings follow the legacy opcode they promote. Those are refused
// rather than guessed: a wrong length here desynchronises everything after it.
func decodeEVEX(code []byte, i int) (Inst, error) {
	if i+2 >= len(code) {
		return Inst{}, ErrTruncated
	}
	mapSelect := int(code[i] & 0x07)
	i += 3
	if mapSelect < 1 || mapSelect > 3 {
		return Inst{}, ErrUndecodable
	}
	if i >= len(code) {
		return Inst{}, ErrTruncated
	}
	op := code[i]
	i++

	if i >= len(code) {
		return Inst{}, ErrTruncated
	}
	modrm := code[i]
	i++
	mod, rm := modrm>>6, modrm&7
	if mod != 3 {
		if rm == 4 {
			if i >= len(code) {
				return Inst{}, ErrTruncated
			}
			sib := code[i]
			i++
			if mod == 0 && sib&7 == 5 {
				i += 4
			}
		} else if mod == 0 && rm == 5 {
			i += 4
		}
		switch mod {
		case 1:
			i++
		case 2:
			i += 4
		}
	}
	if vexImm8(mapSelect, op) {
		i++
	}
	if i > len(code) {
		return Inst{}, ErrTruncated
	}
	if i > maxInstLen {
		return Inst{}, ErrUndecodable
	}
	return Inst{Len: i, Kind: KindOther}, nil
}

// vexImm8 reports whether a VEX- or EVEX-encoded opcode carries an 8-bit
// immediate.
//
// The vector encodings inherit their operand shape from the legacy escape space
// their map select names, so the answer for the 0F space is the answer the
// two-byte opcode map already holds — VPSHUFD is 0F 70 with or without a VEX in
// front of it. Reading it from that table rather than from a second list means
// the two cannot drift apart. The 0F 3A space takes an immediate throughout, and
// the 0F 38 space takes none.
func vexImm8(mapSelect int, op byte) bool {
	switch mapSelect {
	case 1:
		return twoByte[op]&fImm8 != 0
	case 3:
		return true
	}
	return false
}
