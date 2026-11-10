import { getApiErrorMessage } from './api';

describe('getApiErrorMessage', () => {
  it('uses a string detail from the API', () => {
    expect(getApiErrorMessage({ response: { status: 409, data: { detail: 'IP already blocked' } } })).toBe('IP already blocked');
  });

  it('joins FastAPI validation errors with field names', () => {
    const error = {
      response: {
        status: 422,
        data: { detail: [{ loc: ['body', 'password'], msg: 'Password must be at least 8 characters' }] },
      },
    };
    expect(getApiErrorMessage(error)).toBe('password: Password must be at least 8 characters');
  });

  it('explains permission, rate-limit, timeout and network failures', () => {
    expect(getApiErrorMessage({ response: { status: 403, data: {} } })).toMatch(/permission/i);
    expect(getApiErrorMessage({ response: { status: 429, data: {} } })).toMatch(/too many requests/i);
    expect(getApiErrorMessage({ code: 'ECONNABORTED' })).toMatch(/timed out/i);
    expect(getApiErrorMessage({ message: 'Network Error' })).toMatch(/cannot reach/i);
  });

  it('falls back to the provided message', () => {
    expect(getApiErrorMessage({}, 'fallback')).toBe('fallback');
  });
});
