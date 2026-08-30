// How numbers are written, in one place.
//
// A console shows the same quantities in six views, and the reason they are
// formatted here rather than at each call site is that "1.2k" in one view and
// "1234" in another makes a reader check whether they are the same number.

export function count(n: number | undefined): string {
  if (n === undefined || Number.isNaN(n)) return "—";
  // Rounded, because a rate is a float and a count is not: printing a peak of
  // 209.94420193630316 where "210" was meant is the sort of number that makes
  // a reader stop and wonder what the extra digits mean.
  if (n < 1000) return String(Math.round(n));
  if (n < 1_000_000) return `${(n / 1000).toFixed(n < 10_000 ? 1 : 0)}k`;
  return `${(n / 1_000_000).toFixed(n < 10_000_000 ? 1 : 0)}M`;
}

export function rate(n: number | undefined): string {
  if (!n) return "0/s";
  return `${count(Math.round(n))}/s`;
}

export function percent(fraction: number | undefined, digits = 0): string {
  if (fraction === undefined || Number.isNaN(fraction)) return "—";
  return `${(fraction * 100).toFixed(digits)}%`;
}

export function bytes(n: number | undefined): string {
  if (n === undefined) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KiB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MiB`;
}

export function duration(ms: number | undefined): string {
  if (!ms) return "—";
  const s = Math.floor(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

export function ago(iso: string | undefined): string {
  if (!iso) return "—";
  const then = Date.parse(iso);
  if (Number.isNaN(then)) return "—";
  return `${duration(Date.now() - then)} ago`;
}

/** hex renders bytes the way somebody reading a bug report wants them. */
export function hex(raw: Uint8Array, limit = 512): string {
  const shown = raw.subarray(0, limit);
  const lines: string[] = [];
  for (let i = 0; i < shown.length; i += 16) {
    const chunk = shown.subarray(i, i + 16);
    const off = i.toString(16).padStart(8, "0");
    const cells = Array.from(chunk, (b) => b.toString(16).padStart(2, "0"));
    while (cells.length < 16) cells.push("  ");
    const ascii = Array.from(chunk, (b) => (b >= 0x20 && b < 0x7f ? String.fromCharCode(b) : "."));
    lines.push(`${off}  ${cells.join(" ")}  ${ascii.join("")}`);
  }
  if (raw.length > shown.length) {
    lines.push(`… ${raw.length - shown.length} more bytes`);
  }
  return lines.join("\n");
}

/** decodeBase64 turns an API payload into bytes. */
export function decodeBase64(b64: string): Uint8Array {
  const binary = atob(b64);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
  return out;
}
