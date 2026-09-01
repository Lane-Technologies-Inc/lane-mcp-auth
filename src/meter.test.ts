import {beforeEach, describe, expect, it, vi} from 'vitest';
import {Meter, meterIdempotencyKey, type MeterEvent} from './meter.js';

const ev = (over: Partial<MeterEvent> = {}): MeterEvent => ({
  laneIntentId: 'lint_01J',
  mandateId: 'mand_lint_01J_abc',
  productId: 'search_products',
  buyerId: 'user_1',
  quantity: 1,
  unit: 'calls',
  idempotencyKey: 'k1',
  ...over,
});

/** Typed so `calls[n][1]` is a RequestInit and not `undefined`. */
type FetchArgs = [string, RequestInit];
const okFetch = () =>
  vi.fn(async (..._a: FetchArgs) => new Response(null, {status: 200}));

const meter = (over: Partial<ConstructorParameters<typeof Meter>[0]> = {}) => {
  const fetchImpl = okFetch();
  const onError = vi.fn();
  const m = new Meter({
    baseUrl: 'https://api.test',
    orgKey: 'lane_org_sk_x',
    fetchImpl: fetchImpl as unknown as typeof fetch,
    onError,
    ...over,
  });
  return {m, fetchImpl, onError};
};

describe('recording', () => {
  // The caller is a tool handler on the hot path. It must not await a network
  // write, and it must not need a try/catch to be safe.
  it('is synchronous and does not flush on the first event', () => {
    const {m, fetchImpl} = meter({batchSize: 10});
    m.record(ev());
    expect(m.pending).toBe(1);
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  it('flushes once the batch is full', async () => {
    const {m, fetchImpl} = meter({batchSize: 3});
    m.record(ev({idempotencyKey: 'a'}));
    m.record(ev({idempotencyKey: 'b'}));
    m.record(ev({idempotencyKey: 'c'}));
    await m.flush();
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const body = JSON.parse(String(fetchImpl.mock.calls[0]![1].body));
    expect(body.events).toHaveLength(3);
  });

  it('sends the org key as the reporting credential', async () => {
    const {m, fetchImpl} = meter({batchSize: 1});
    m.record(ev());
    await m.flush();
    const init = fetchImpl.mock.calls[0]![1] as RequestInit;
    expect((init.headers as Record<string, string>).authorization).toBe('Bearer lane_org_sk_x');
  });
});

/**
 * NEVER A GATE. A meter that could refuse would make Lane's availability a
 * precondition for the merchant's product -- exactly the coupling the offline
 * token verify exists to avoid.
 */
describe('failure is silent to the caller', () => {
  it('does not throw when the flush rejects', async () => {
    const fetchImpl = vi.fn(async (..._a: FetchArgs): Promise<Response> => {
      throw new TypeError('offline');
    });
    const {m, onError} = meter({batchSize: 1, fetchImpl: fetchImpl as unknown as typeof fetch});
    expect(() => m.record(ev())).not.toThrow();
    await m.flush();
    expect(onError).toHaveBeenCalled();
  });

  it('does not throw on a non-2xx, and reports how many were lost', async () => {
    const fetchImpl = vi.fn(async (..._a: FetchArgs) => new Response('no', {status: 500}));
    const {m, onError} = meter({batchSize: 2, fetchImpl: fetchImpl as unknown as typeof fetch});
    m.record(ev({idempotencyKey: 'a'}));
    m.record(ev({idempotencyKey: 'b'}));
    await m.flush();
    expect(onError.mock.calls[0]![1]).toBe(2);
  });

  // A 4xx fails identically next time, and a retry loop on the tool-call path is
  // worse than the lost units -- which are the merchant's own under-report.
  it('does not re-buffer a failed batch', async () => {
    const fetchImpl = vi.fn(async (..._a: FetchArgs) => new Response('no', {status: 400}));
    const {m} = meter({batchSize: 1, fetchImpl: fetchImpl as unknown as typeof fetch});
    m.record(ev());
    await m.flush();
    expect(m.pending).toBe(0);
  });
});

describe('the buffer is bounded', () => {
  // A merchant whose flushes all fail must not grow the buffer until the process
  // dies of it.
  it('drops the oldest rather than growing without limit', () => {
    const {m, onError} = meter({batchSize: 100_000});
    for (let i = 0; i < 1_100; i += 1) m.record(ev({idempotencyKey: `k${i}`}));
    expect(m.pending).toBeLessThanOrEqual(1_000);
    expect(onError).toHaveBeenCalled();
  });
});

describe('concurrency', () => {
  // Two concurrent flushes would send overlapping slices. The server dedupes,
  // but the duplicate traffic is pure waste on a per-tool-call path.
  it('coalesces overlapping flushes', async () => {
    const {m, fetchImpl} = meter({batchSize: 100});
    m.record(ev());
    await Promise.all([m.flush(), m.flush(), m.flush()]);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('is a no-op with nothing buffered', async () => {
    const {m, fetchImpl} = meter();
    await m.flush();
    expect(fetchImpl).not.toHaveBeenCalled();
  });
});

describe('idempotency keys', () => {
  // Two identical calls in the same millisecond are two billable units, so a
  // derived key would collapse them into one.
  it('are unique for identical calls', () => {
    expect(meterIdempotencyKey('tool', 'lint_1')).not.toBe(meterIdempotencyKey('tool', 'lint_1'));
  });

  // The merchant may have no intent to key on, and an event still needs a
  // dedupe token.
  it('work with no intent', () => {
    const k = meterIdempotencyKey('tool');
    expect(k).toContain('unattributed');
    expect(k).not.toBe(meterIdempotencyKey('tool'));
  });
});

describe('what is never sent', () => {
  it('no price, amount or currency', async () => {
    const {m, fetchImpl} = meter({batchSize: 1});
    m.record(ev());
    await m.flush();
    const body = String(fetchImpl.mock.calls[0]![1].body);
    for (const forbidden of ['price', 'amount', 'currency', 'cents']) {
      expect(body).not.toContain(forbidden);
    }
  });
});


/**
 * A merchant's server cannot derive the intent -- the token it verifies carries
 * none. So an event without one must be sendable, and the server decides it is
 * unattributed.
 */
describe('events with no intent', () => {
  it('are sent without laneIntentId or mandateId', async () => {
    const {m, fetchImpl} = meter({batchSize: 1});
    m.record({
      productId: 'search_products',
      quantity: 1,
      unit: 'calls',
      idempotencyKey: 'u1',
    });
    await m.flush();
    const body = JSON.parse(String(fetchImpl.mock.calls[0]![1].body));
    expect(body.events[0].laneIntentId).toBeUndefined();
    expect(body.events[0].mandateId).toBeUndefined();
    expect(body.events[0].productId).toBe('search_products');
  });

  it('carry a caller hint when the merchant has one', async () => {
    const {m, fetchImpl} = meter({batchSize: 1});
    m.record({
      productId: 'search_products',
      quantity: 1,
      unit: 'calls',
      idempotencyKey: 'u1',
      callerHint: 'other-agent/1.0',
    });
    await m.flush();
    const body = JSON.parse(String(fetchImpl.mock.calls[0]![1].body));
    expect(body.events[0].callerHint).toBe('other-agent/1.0');
  });
});
