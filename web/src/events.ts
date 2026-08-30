// The live event stream.
//
// Server-sent events, not WebSocket. ADR-0011 said WebSocket, and ADR-0024 —
// which is later and decided the transport for the whole API — rejected it for
// this stream: the traffic is server-to-client by design, it is droppable by
// design, and SSE reconnects without any client code. What would justify
// revisiting is the console needing to *send* on the same channel, which it
// does not: every action it takes is a POST.
//
// Lossy by design (ASR-0012). The daemon downsamples and batches so that a
// browser can never back-pressure the engine; this side must therefore treat
// every message as the latest state rather than as an increment, because a
// message it never saw is normal operation and not an error.

export type EventKind =
  | "metrics"
  | "finding"
  | "campaign"
  | "worker"
  | "log"
  | "triage"
  | "corpus";

export interface StreamEvent {
  kind: EventKind;
  campaign?: string;
  worker?: number;
  seq: number;
  at: string;
  data: unknown;
}

type Listener = (e: StreamEvent) => void;

export class EventStream {
  private source: EventSource | null = null;
  private listeners = new Set<Listener>();
  private dropped = 0;
  private lastSeq = 0;

  constructor(
    private readonly kinds: EventKind[],
    private readonly campaign?: string,
  ) {}

  /** missed reports how many events the server told us we did not see. */
  get missed(): number {
    return this.dropped;
  }

  on(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  start(): void {
    if (this.source) return;
    const params = new URLSearchParams();
    if (this.kinds.length) params.set("kinds", this.kinds.join(","));
    if (this.campaign) params.set("campaign", this.campaign);

    const src = new EventSource(`/v1/events?${params.toString()}`);
    this.source = src;
    src.onmessage = (m) => {
      let event: StreamEvent;
      try {
        event = JSON.parse(m.data) as StreamEvent;
      } catch {
        return;
      }
      // A gap in the sequence is the server having dropped something to keep
      // the engine free, which is the contract. Counting it means the console
      // can say so rather than quietly showing an incomplete picture.
      if (this.lastSeq && event.seq > this.lastSeq + 1) {
        this.dropped += event.seq - this.lastSeq - 1;
      }
      this.lastSeq = event.seq;
      for (const fn of this.listeners) fn(event);
    };
    // No onerror handler that closes: EventSource reconnects on its own, and
    // taking over that job is how a console stops updating after one blip.
  }

  stop(): void {
    this.source?.close();
    this.source = null;
    this.listeners.clear();
  }
}

/** Live owns the page's single stream, so views do not each open one.
 *
 * One connection per page rather than one per view: the daemon bounds a
 * subscriber's queue deliberately (a deep queue does not stop a client falling
 * behind, it only delays the moment anyone notices), and a console that opened
 * six of them would be six subscribers falling behind instead of one.
 */
export class Live {
  private stream: EventStream | null = null;

  /** watch replaces whatever the previous view was listening to. */
  watch(kinds: EventKind[], campaign: string | undefined, fn: Listener): void {
    this.stop();
    const s = new EventStream(kinds, campaign);
    s.on(fn);
    s.start();
    this.stream = s;
  }

  get missed(): number {
    return this.stream?.missed ?? 0;
  }

  stop(): void {
    this.stream?.stop();
    this.stream = null;
  }
}
