package vt

import "sort"

// RuneWidth returns how many screen columns a rune occupies: 0 for a combining
// mark, 2 for a wide character, 1 for everything else.
//
// A compact table rather than the Unicode database. The full tables are large,
// change with every Unicode revision, and would make the emulator's behaviour
// depend on which revision Xfuzz was built against — which is a reproducibility
// problem (ASR-0008), since a screen hash would then differ between two hosts
// running the same campaign. These ranges cover the wide and combining
// characters a TUI actually draws: CJK, Hangul, the fullwidth forms, and the
// emoji blocks. A rune outside them is one column, which is what a terminal
// without a width table does too.
func RuneWidth(r rune) int {
	switch {
	case r == 0:
		return 1
	case r < 0x20:
		return 0 // a control character is not drawn
	case r < 0x7f:
		return 1
	case r == 0x7f:
		return 0
	}
	if inRanges(r, combining) {
		return 0
	}
	if inRanges(r, wide) {
		return 2
	}
	return 1
}

// StringWidth is RuneWidth summed, which is what a caller measuring a label
// against a column count wants.
func StringWidth(s string) int {
	n := 0
	for _, r := range s {
		n += RuneWidth(r)
	}
	return n
}

type rng struct{ lo, hi rune }

func inRanges(r rune, rs []rng) bool {
	i := sort.Search(len(rs), func(i int) bool { return rs[i].hi >= r })
	return i < len(rs) && r >= rs[i].lo
}

// combining is the zero-width ranges: Mn/Me marks and the format characters a
// terminal does not advance for.
var combining = []rng{
	{0x0300, 0x036F}, // combining diacritical marks
	{0x0483, 0x0489},
	{0x0591, 0x05BD}, {0x05BF, 0x05BF}, {0x05C1, 0x05C2}, {0x05C4, 0x05C5}, {0x05C7, 0x05C7},
	{0x0610, 0x061A}, {0x064B, 0x065F}, {0x0670, 0x0670}, {0x06D6, 0x06DC},
	{0x06DF, 0x06E4}, {0x06E7, 0x06E8}, {0x06EA, 0x06ED},
	{0x0711, 0x0711}, {0x0730, 0x074A}, {0x07A6, 0x07B0}, {0x07EB, 0x07F3},
	{0x0816, 0x0819}, {0x081B, 0x0823}, {0x0825, 0x0827}, {0x0829, 0x082D},
	{0x0900, 0x0902}, {0x093A, 0x093A}, {0x093C, 0x093C}, {0x0941, 0x0948},
	{0x094D, 0x094D}, {0x0951, 0x0957}, {0x0962, 0x0963},
	{0x0981, 0x0981}, {0x09BC, 0x09BC}, {0x09C1, 0x09C4}, {0x09CD, 0x09CD},
	{0x0A01, 0x0A02}, {0x0A3C, 0x0A3C}, {0x0A41, 0x0A42}, {0x0A47, 0x0A48},
	{0x0A4B, 0x0A4D}, {0x0A70, 0x0A71},
	{0x0E31, 0x0E31}, {0x0E34, 0x0E3A}, {0x0E47, 0x0E4E},
	{0x0EB1, 0x0EB1}, {0x0EB4, 0x0EBC}, {0x0EC8, 0x0ECD},
	{0x0F35, 0x0F35}, {0x0F37, 0x0F37}, {0x0F39, 0x0F39}, {0x0F71, 0x0F7E},
	{0x0F80, 0x0F84}, {0x0F86, 0x0F87},
	{0x1AB0, 0x1AFF}, {0x1DC0, 0x1DFF},
	{0x200B, 0x200F}, // zero-width space and the bidi controls
	{0x2028, 0x202E}, {0x2060, 0x2064}, {0x206A, 0x206F},
	{0x20D0, 0x20F0}, // combining marks for symbols
	{0xFE00, 0xFE0F}, // variation selectors
	{0xFE20, 0xFE2F}, {0xFEFF, 0xFEFF},
	{0xFFF9, 0xFFFB},
	{0xE0100, 0xE01EF}, // variation selectors supplement
}

// wide is the two-column ranges.
var wide = []rng{
	{0x1100, 0x115F}, // Hangul Jamo initial consonants
	{0x2329, 0x232A}, // angle brackets
	{0x2E80, 0x303E}, // CJK radicals, Kangxi, CJK symbols
	{0x3041, 0x33FF}, // kana, Bopomofo, Hangul compatibility, CJK compatibility
	{0x3400, 0x4DBF}, // CJK extension A
	{0x4E00, 0x9FFF}, // CJK unified ideographs
	{0xA000, 0xA4CF}, // Yi
	{0xA960, 0xA97F}, // Hangul Jamo extended A
	{0xAC00, 0xD7A3}, // Hangul syllables
	{0xF900, 0xFAFF}, // CJK compatibility ideographs
	{0xFE10, 0xFE19}, // vertical forms
	{0xFE30, 0xFE6F}, // CJK compatibility forms, small form variants
	{0xFF00, 0xFF60}, // fullwidth forms
	{0xFFE0, 0xFFE6}, // fullwidth signs
	{0x1F004, 0x1F004}, {0x1F0CF, 0x1F0CF},
	{0x1F300, 0x1F64F}, // emoji: symbols, pictographs, emoticons
	{0x1F680, 0x1F6FF}, // transport and map
	{0x1F900, 0x1F9FF}, // supplemental symbols and pictographs
	{0x20000, 0x2FFFD}, // CJK extensions B and beyond
	{0x30000, 0x3FFFD},
}
