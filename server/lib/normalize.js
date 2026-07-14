export function buildResult(overrides) {
  return {
    provider: '',
    displayName: '',
    verdict: 'unknown',
    score: 0,
    summary: '',
    details: {},
    link: null,
    error: null,
    ...overrides,
  };
}

export function errorResult(provider, displayName, error) {
  return buildResult({
    provider,
    displayName,
    verdict: 'unknown',
    error,
    summary:
      error === 'rate_limited'
        ? 'Rate limit reached for this provider'
        : error === 'not_configured'
        ? 'API key not configured'
        : 'Could not reach provider',
  });
}