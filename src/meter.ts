/**
 * @fileoverview The meter, batched, inside the seam a merchant already installed.
 *
 * WHY HERE. `enableLaneAuth` wraps `server.tool`, so Lane's code already runs on
 * every tool call in the merchant's process -- "it wraps `server.tool`, so what
 * it guards is what it guards". Metering costs the merchant NOTHING to adopt:
 * no new call, no new header, no new dependency. Every other placement was
 * rejected for a reason worth keeping written down:
 *
 *   Lane proxies in front of the MCP -- perfect visibility, but it adds a hop,
 *   makes Lane an availability dependency for the merchant's own server, and
 *   breaks the "agents connect straight to your endpoint" promise the wizard
 *   makes.
 *
 *   Verify the token online per call -- would hand Lane the event for free, and
 *   costs a network round trip on every tool call. The offline JWKS verify is a
 *   deliberate latency decision; undoing it for billing convenience is the wrong
 *   trade.
 *
 * ── WHAT THIS IS NOT ───────────────────────────────────────────────────────
 *
 * NOT A GATE. Metering must never decide whether a tool call proceeds. A meter
 * that could refuse would make Lane's availability a precondition for the
 * merchant's product, which is exactly the coupling the offline verify avoids.
 * So every failure path here is silent to the caller and the tool runs anyway.
 *
 * NOT A PRICE. A count and a unit name. Price is applied at settle from the
 * merchant's policy, because a ledger of priced amounts cannot be re-priced.
 *
 * THE UNIT IS `calls`. Lane prices per tool call; a merchant's own cost for a
 * call is wrapped into their per-call price. The field stays a string because
 * the ledger records what it is told and settlement decides what it prices --
 * anything other than `calls` is reported unpriced rather than guessed at.
 *
 * NOT A PROCESSOR CALL. Nothing here touches Finix. A $0.40 tool call cannot
 * carry a $0.30 fixed card fee, so the metering path is free of the processor
 * entirely.
 *
 * ── THE FLUSH, AND WHY AT-MOST-ONCE IS THE RIGHT DEFAULT ───────────────────
 *
 * Events buffer in memory and flush on a size or age trigger. A process that
 * dies with a partial buffer loses those units -- which is UNDER-reporting, and
 * under-reporting is the merchant's own loss. That asymmetry is the whole reason
 * this can be a simple in-memory buffer instead of a durable local queue: the
 * failure mode costs the reporter, not the payer, so it needs no control beyond
 * being honest about it.
 *
 * Over-reporting is the direction that would matter, and it cannot happen from a
 * retry: every event carries an idempotency key and the server records each one
 * exactly once.
 */

/**
 * One metered unit, before it is sent.
 *
 * THE INTENT AND MANDATE ARE OPTIONAL, and that is not laziness. A merchant's
 * server does not create them and cannot derive them -- the token it verifies
 * carries no intent (`VerifiedClaims` has `sub`, `jti`, `clientId`, `scopes`,
 * and nothing about a mandate). They arrive only if the AGENT passes them
 * through.
 *
 * When they are absent -- the agent did not send them, or the caller is not a
 * Lane agent -- the server records the event as unattributed. The work still
 * happened and the merchant still gets paid, by invoice rather than by capture,
 * because there is no authorization to capture against.
 *
 * BOTH OR NEITHER. Sending one without the other is refused by the server: it
 * would either invent a mandate or silently downgrade billable usage.
 */
export interface MeterEvent {
  /** `lint_...`, if the agent passed it through. */
  laneIntentId?: string;
  /** `mand_<lane_intent_id>_<6>`, if the agent passed it through. */
  mandateId?: string;
  /**
   * Which BILLING PERIOD this call belongs to, when the merchant charges for
   * tool calls: `YYYY-MM` for monthly, the access token's `jti` for per_session.
   *
   * ITS PRESENCE IS WHAT MAKES A CALL BILLABLE, and there is deliberately no
   * second `attribution` field beside it. Two fields carrying one fact are two
   * things that can disagree, and the ledger's own header says so.
   *
   * The merchant org is NOT sent. It is resolved from the reporting credential
   * server-side, so a merchant cannot claim another merchant's volume.
   */
  periodKey?: string;
  /** For an MCP tool call, the tool name. */
  productId: string;
  /** Who the call was attributed to, when known. */
  buyerId?: string;
  quantity: number;
  unit: string;
  /** Dedupe token. Generated per event, so a retried flush cannot double-count. */
  idempotencyKey: string;
  /** Anything identifying a non-Lane caller, for reconciliation only. */
  callerHint?: string;
}

export interface MeterConfig {
  /** Where to flush. `<base>/api/public/metering/usage`. */
  baseUrl: string;
  /** The merchant's org key. Identifies AND authorises the reporter. */
  orgKey: string;
  /** Flush when the buffer reaches this many events. */
  batchSize?: number;
  /** Flush when the oldest buffered event is this old, in ms. */
  maxAgeMs?: number;
  /** Injected for tests. */
  fetchImpl?: typeof fetch;
  /** Called when a flush fails. Observability only -- never a gate. */
  onError?: (err: unknown, lost: number) => void;
}

const DEFAULT_BATCH = 50;
const DEFAULT_MAX_AGE_MS = 10_000;
/** Bounded so a merchant whose flushes are all failing cannot grow the buffer
 *  until the process dies of it. Beyond this, the OLDEST events are dropped:
 *  losing the oldest keeps the most recent window intact, and the loss is
 *  under-reporting either way. */
const MAX_BUFFER = 1_000;

export class Meter {
  private buffer: MeterEvent[] = [];
  private oldestAt: number | null = null;
  private inFlight: Promise<void> | null = null;

  constructor(private readonly config: MeterConfig) {}

  private get batchSize(): number {
    return this.config.batchSize ?? DEFAULT_BATCH;
  }

  private get maxAgeMs(): number {
    return this.config.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
  }

  /**
   * Record one unit.
   *
   * SYNCHRONOUS AND NON-THROWING, both deliberate. The caller is a tool handler
   * on the hot path: it must not await a network write, and it must not have to
   * wrap this in a try/catch to be safe. A flush is kicked off in the background
   * when a trigger is met.
   */
  record(event: MeterEvent): void {
    if (this.buffer.length >= MAX_BUFFER) {
      // Drop the oldest, keep the recent window. Reported so a rising count is
      // visible rather than silent.
      const dropped = this.buffer.splice(0, this.buffer.length - MAX_BUFFER + 1);
      this.config.onError?.(new Error('meter buffer full'), dropped.length);
    }
    if (this.buffer.length === 0) this.oldestAt = Date.now();
    this.buffer.push(event);

    const aged = this.oldestAt !== null && Date.now() - this.oldestAt >= this.maxAgeMs;
    if (this.buffer.length >= this.batchSize || aged) void this.flush();
  }

  /**
   * Send whatever is buffered.
   *
   * ONE FLUSH AT A TIME. Two concurrent flushes would send overlapping slices,
   * and while the server would dedupe them by idempotency key, the duplicate
   * traffic is pure waste on a per-tool-call path.
   */
  async flush(): Promise<void> {
    if (this.inFlight) return this.inFlight;
    if (this.buffer.length === 0) return;

    const batch = this.buffer;
    this.buffer = [];
    this.oldestAt = null;

    const doFlush = async (): Promise<void> => {
      const fetchImpl = this.config.fetchImpl ?? fetch;
      try {
        const res = await fetchImpl(`${this.config.baseUrl}/api/public/metering/usage`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${this.config.orgKey}`,
          },
          body: JSON.stringify({events: batch}),
        });
        if (!res.ok) {
          // NOT RE-BUFFERED. A 4xx will fail identically next time and a retry
          // loop on the tool-call path is worse than the lost units, which are
          // the merchant's own under-report. A 5xx is reported so it is visible.
          this.config.onError?.(new Error(`meter flush failed: ${res.status}`), batch.length);
        }
      } catch (err) {
        this.config.onError?.(err, batch.length);
      }
    };

    this.inFlight = doFlush().finally(() => {
      this.inFlight = null;
    });
    return this.inFlight;
  }

  /** For tests and for a graceful shutdown hook. */
  get pending(): number {
    return this.buffer.length;
  }
}

/**
 * A unique dedupe token per event. Not an identifier -- it names no entity.
 *
 * Random rather than derived: two identical calls in the same millisecond are two
 * billable units, and a derived key would collapse them into one.
 */
export function meterIdempotencyKey(productId: string, laneIntentId = ''): string {
  const rand = Math.random().toString(36).slice(2, 10);
  return `${laneIntentId || 'unattributed'}:${productId}:${Date.now()}:${rand}`;
}

/**
 * How a merchant bills for tool calls.
 *
 * DECLARED HERE, NOT IMPORTED. This package publishes to npm with `jose` and
 * `zod` as its only dependencies, so it cannot reach the Lane monorepo's shared
 * types (`packages/types/settlement.ts`), where `BILLING_CADENCES` is the source
 * of truth. A local copy of a domain union is real drift risk, so that
 * definition is read off disk and compared in `mcp-sdk-billing.test.ts` rather
 * than trusted to stay in step.
 *
 *   monthly       Calls accumulate for the calendar month and are charged once
 *                 against a card on file. No hold.
 *   per_session   A hold is taken when the session opens and the actual is
 *                 captured when it closes, with the residual released.
 */
export const MCP_BILLING_CADENCES = ['monthly', 'per_session'] as const;
export type McpBillingCadence = (typeof MCP_BILLING_CADENCES)[number];

/**
 * The monthly period key: `YYYY-MM`, UTC.
 *
 * Mirrors `monthKeyOf` in the Lane monorepo's metering ledger
 * (`packages/infra/src/metering-ledger.ts`), which is what the ledger and the
 * settlement runner use. The two must agree exactly, or a merchant's calls land
 * in one period and are settled from another.
 */
export const billingMonthKey = (nowMs: number = Date.now()): string =>
  new Date(nowMs).toISOString().slice(0, 7);
