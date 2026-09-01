import {describe, expect, it} from 'vitest';
import {
  USAGE_CONTEXT_HEADER,
  parseUsageContext,
  usageContextFrom,
} from './usage-context.js';

const GOOD = JSON.stringify({laneIntentId: 'lint_01JABC', mandateId: 'mand_lint_01JABC_a1b2c3'});

describe('parsing', () => {
  it('accepts a well-formed context', () => {
    expect(parseUsageContext(GOOD)).toEqual({
      laneIntentId: 'lint_01JABC',
      mandateId: 'mand_lint_01JABC_a1b2c3',
    });
  });

  it('keeps runId when present', () => {
    const raw = JSON.stringify({
      laneIntentId: 'lint_01JABC',
      mandateId: 'mand_lint_01JABC_a1b2c3',
      runId: 'flr_1',
    });
    expect(parseUsageContext(raw)?.runId).toBe('flr_1');
  });

  // Absence is a valid state: a non-Lane agent sends no header.
  it('returns null for an absent header', () => {
    expect(parseUsageContext(undefined)).toBeNull();
    expect(parseUsageContext('')).toBeNull();
  });

  // This runs on the tool-call path. A malformed header must not throw.
  it('returns null rather than throwing on malformed input', () => {
    expect(parseUsageContext('not json')).toBeNull();
    expect(parseUsageContext('[]')).toBeNull();
    expect(parseUsageContext('null')).toBeNull();
  });

  // Half a context would mean inventing a mandate or downgrading billable usage.
  it('rejects one id without the other', () => {
    expect(parseUsageContext(JSON.stringify({laneIntentId: 'lint_01JABC'}))).toBeNull();
    expect(parseUsageContext(JSON.stringify({mandateId: 'mand_lint_01JABC_a1'}))).toBeNull();
  });

  // A malformed id must not be written into a ledger key.
  it('rejects ids of the wrong shape', () => {
    expect(
      parseUsageContext(JSON.stringify({laneIntentId: 'nope', mandateId: 'mand_lint_01JABC_a1'})),
    ).toBeNull();
    expect(
      parseUsageContext(JSON.stringify({laneIntentId: 'lint_01JABC', mandateId: 'nope'})),
    ).toBeNull();
  });
});

/**
 * De-identified by construction. The agent is never asked for a user id, and one
 * sent here is dropped rather than carried to the ledger.
 */
describe('de-identification', () => {
  it('drops any field it does not know, including a user id', () => {
    const raw = JSON.stringify({
      laneIntentId: 'lint_01JABC',
      mandateId: 'mand_lint_01JABC_a1b2c3',
      userId: 'user_real_person',
      email: 'someone@example.com',
    });
    const ctx = parseUsageContext(raw);
    expect(Object.keys(ctx ?? {}).sort()).toEqual(['laneIntentId', 'mandateId']);
    expect(JSON.stringify(ctx)).not.toContain('user_real_person');
    expect(JSON.stringify(ctx)).not.toContain('example.com');
  });
});

/**
 * Two transports, two carrier shapes. Metering that worked on only one would
 * look like a partial rollout rather than a bug.
 */
describe('finding the header on either transport', () => {
  it('reads a Hono-style context', () => {
    const carrier = {req: {header: (n: string) => (n === USAGE_CONTEXT_HEADER ? GOOD : undefined)}};
    expect(usageContextFrom(carrier)?.laneIntentId).toBe('lint_01JABC');
  });

  it('reads a plain headers object', () => {
    expect(usageContextFrom({headers: {[USAGE_CONTEXT_HEADER]: GOOD}})?.laneIntentId).toBe(
      'lint_01JABC',
    );
  });

  it('reads a Headers instance', () => {
    const headers = new Headers({[USAGE_CONTEXT_HEADER]: GOOD});
    expect(usageContextFrom({headers})?.laneIntentId).toBe('lint_01JABC');
  });

  it('reads requestInfo.headers', () => {
    expect(
      usageContextFrom({requestInfo: {headers: {[USAGE_CONTEXT_HEADER]: GOOD}}})?.laneIntentId,
    ).toBe('lint_01JABC');
  });

  it('is null for a carrier with no headers at all', () => {
    expect(usageContextFrom({})).toBeNull();
    expect(usageContextFrom(undefined)).toBeNull();
    expect(usageContextFrom('string')).toBeNull();
  });
});
