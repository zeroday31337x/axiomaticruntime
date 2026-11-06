import { evaluateWithJev } from './jev-client.mjs';

// Optional policy classifier for routing. Does not authenticate requests or perform routing.
export async function classifyRoute({ authenticated, policyAllows, route, method, jev, fetchImpl }) {
  if (!authenticated || !policyAllows) return { decision: 'DENY', reason: 'host_policy' };
  if (typeof route !== 'string' || !route.startsWith('/') || route.length > 2048) {
    return { decision: 'DENY', reason: 'invalid_route' };
  }
  if (!['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].includes(method)) {
    return { decision: 'DENY', reason: 'invalid_method' };
  }
  const result = await evaluateWithJev({
    hostResult: { decision: 'RETAIN' },
    context: { route, method },
    endpoint: jev?.endpoint, token: jev?.token, timeoutMs: jev?.timeoutMs,
    fetchImpl,
  });
  return {
    decision: result.decision === 'RETAIN' ? 'ALLOW' : result.decision === 'PRUNE' ? 'DENY' : 'FLAG',
    reason: result.jev?.status || 'unknown',
    modelVersion: result.jev?.modelVersion,
  };
}
