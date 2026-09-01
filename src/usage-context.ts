/**
 * @fileoverview What the agent supplies so a metered call can be attributed.
 *
 * WHY THE AGENT AND NOT THE MERCHANT. The merchant's server does not create
 * intents or mandates and cannot derive them: the token it verifies carries
 * `sub`, `jti`, `clientId`, `scopes`, `exp`, `iss` and nothing about a mandate.
 * The agent created the intent, so the agent is the only party that knows it.
 * The Lane harness sends this alongside the call.
 *
 * DE-IDENTIFIED BY CONSTRUCTION. Nothing here names a person. The two ids are
 * Lane's own opaque references, and `runId` is an agent-side correlation handle.
 * The buyer on the ledger row is taken from the TOKEN's pairwise `sub`, which is
 * `HMAC(userId || audience)` and therefore different at every merchant, so it
 * cannot be used to correlate a person across servers. The agent is never asked
 * for a user id, and one sent here would be ignored.
 *
 * ABSENCE IS A VALID STATE. A non-Lane agent sends no header at all, and a Lane
 * agent may omit it. The call still proceeds and the usage is still recorded, as
 * unattributed. Nothing here may refuse a tool call.
 */

/** The header the harness sets. One header, one JSON object, so the shape can
 *  grow without adding headers. */
export const USAGE_CONTEXT_HEADER = 'x-lane-usage';

/** The standardized object the harness sends. */
export interface LaneUsageContext {
  /** `lint_...` -- the authorization envelope the human approved. */
  laneIntentId: string;
  /** `mand_<lane_intent_id>_<6>`. */
  mandateId: string;
  /** Agent-side run correlation. Opaque, and never load-bearing: `trc_*`-class
   *  observability, not an identifier anything keys on. */
  runId?: string;
}

/** Shape of the two ids, checked so a malformed header is treated as absent
 *  rather than written into a key. */
const LANE_INTENT = /^lint_[0-9A-Za-z]{1,40}$/;
const MANDATE = /^mand_[0-9A-Za-z_]{1,80}$/;

/**
 * Parse the header, or return null.
 *
 * TOTAL, AND NEVER THROWS. This runs on the tool-call path. A malformed header
 * must not fail the call; it degrades to unattributed usage, which is recorded
 * and invoiced rather than captured.
 *
 * BOTH IDS OR NEITHER. One without the other would mean inventing a mandate or
 * silently downgrading billable usage, so a half-filled context is treated as
 * absent.
 */
export function parseUsageContext(raw: string | undefined | null): LaneUsageContext | null {
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (parsed === null || typeof parsed !== 'object') return null;
  const o = parsed as Record<string, unknown>;

  const laneIntentId = typeof o.laneIntentId === 'string' ? o.laneIntentId : '';
  const mandateId = typeof o.mandateId === 'string' ? o.mandateId : '';
  if (!LANE_INTENT.test(laneIntentId) || !MANDATE.test(mandateId)) return null;

  const runId = typeof o.runId === 'string' && o.runId !== '' ? o.runId : undefined;
  // Only the three known fields are carried forward. Anything else the harness
  // sends -- including a user id it should not send -- is dropped here rather
  // than reaching the ledger.
  return {laneIntentId, mandateId, ...(runId ? {runId} : {})};
}

/**
 * Find the usage header on whatever the transport handed the tool.
 *
 * Two transports, two shapes: the SDK passes an `extra` carrying the request,
 * and mcp-use passes a Hono context. Both are checked because a merchant may be
 * on either, and metering that silently worked on only one of them would look
 * like a partial rollout rather than a bug.
 */
export function usageContextFrom(carrier: unknown): LaneUsageContext | null {
  const header = readHeader(carrier, USAGE_CONTEXT_HEADER);
  return parseUsageContext(header);
}

function readHeader(carrier: unknown, name: string): string | undefined {
  if (!carrier || typeof carrier !== 'object') return undefined;
  const c = carrier as Record<string, unknown>;

  // Hono-style: `c.req.header(name)`.
  const req = c.req as {header?: (n: string) => string | undefined} | undefined;
  if (req && typeof req.header === 'function') return req.header(name);

  // Node-style: `requestInfo.headers` as a plain object.
  const info = c.requestInfo as {headers?: Record<string, unknown>} | undefined;
  const headers = info?.headers ?? (c.headers as Record<string, unknown> | undefined);
  if (headers) {
    const direct = headers[name] ?? headers[name.toUpperCase()];
    if (typeof direct === 'string') return direct;
    // A Headers instance rather than a plain object.
    const get = (headers as unknown as {get?: (n: string) => string | null}).get;
    if (typeof get === 'function') return get.call(headers, name) ?? undefined;
  }
  return undefined;
}
