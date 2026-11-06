import { applyJevAdvisory } from './jev-adapter.mjs';

// The JEV service must be internal and authenticated; never accept its URL from callers.
export async function evaluateWithJev({ hostResult, context, endpoint, token, timeoutMs = 250, fetchImpl = fetch }) {
  if (!hostResult || !['RETAIN', 'GATE', 'PRUNE'].includes(hostResult.decision)) {
    return { ...hostResult, decision: 'PRUNE', jev: { status: 'invalid_host_result' } };
  }
  if (hostResult.decision !== 'RETAIN') {
    return { ...hostResult, jev: { status: 'skipped_host_restriction' } };
  }
  if (!endpoint || !token || !Number.isFinite(timeoutMs) || timeoutMs < 1 || timeoutMs > 5000) {
    return { ...hostResult, decision: 'GATE', jev: { status: 'unavailable' } };
  }
  try {
    const response = await fetchImpl(endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: 'Bearer ' + token },
      body: JSON.stringify({ schemaVersion: '1', context }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!response.ok) throw new Error('model_http_error');
    const data = await response.json();
    const valid = data && ['ALLOW', 'DENY', 'FLAG'].includes(data.decision);
    const decision = valid ? data.decision : undefined;
    return {
      ...hostResult,
      decision: applyJevAdvisory(hostResult.decision, decision),
      jev: { status: valid ? 'ok' : 'invalid_response', decision: decision || 'FLAG',
        modelVersion: typeof data?.modelVersion === 'string' ? data.modelVersion.slice(0, 80) : 'unknown' },
    };
  } catch {
    return { ...hostResult, decision: 'GATE', jev: { status: 'unavailable', decision: 'FLAG' } };
  }
}
