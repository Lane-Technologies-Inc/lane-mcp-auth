import {describe, expect, it} from 'vitest';

import {createDevAuthSeam, DEV_AUTH_ENV, devAuthStatus} from './dev.js';
import {PERSONALIZATION_SCOPE} from './types.js';

const ISS = 'https://auth.example/mcp';

describe('devAuthStatus', () => {
  it('is off until the env var is exactly 1', () => {
    expect(devAuthStatus({}).armed).toBe(false);
    expect(devAuthStatus({[DEV_AUTH_ENV]: 'true'}).armed).toBe(false);
    expect(devAuthStatus({[DEV_AUTH_ENV]: '1'}).armed).toBe(true);
  });

  it('REFUSES to arm when NODE_ENV=production, and says so', () => {
    const status = devAuthStatus({[DEV_AUTH_ENV]: '1', NODE_ENV: 'production'});
    expect(status.armed).toBe(false);
    expect(status.reason).toContain('production');
  });
});

describe('createDevAuthSeam', () => {
  it('derives a deterministic caller from the bearer, distinct per bearer', async () => {
    const seam = createDevAuthSeam({issuer: ISS});
    const a1 = await seam.verifyToken('alpha');
    const a2 = await seam.verifyToken('alpha');
    const b = await seam.verifyToken('beta');
    expect(a1.sub).toBe(a2.sub);
    expect(a1.jti).toBe(a2.jti);
    expect(b.sub).not.toBe(a1.sub);
    expect(a1.iss).toBe(ISS);
    // The token's own scopes are empty pre-step-up in the real protocol too.
    expect(a1.scopes).toEqual([]);
  });

  it('rejects an empty bearer', async () => {
    const seam = createDevAuthSeam({issuer: ISS});
    await expect(seam.verifyToken('  ')).rejects.toThrow();
  });

  it('grants only scopes Lane actually issues, plus the consent scope', async () => {
    const seam = createDevAuthSeam({
      issuer: ISS,
      scopes: ['email', 'made-up-scope', PERSONALIZATION_SCOPE.connection],
    });
    const granted = await seam.exchanger.exchange({subjectToken: 'x', resource: 'r'});
    expect(granted.scopes).toEqual(['email', PERSONALIZATION_SCOPE.connection]);
  });
});
