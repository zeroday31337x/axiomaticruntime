// Baseline classifier for integration testing; NOT a trained JEV model.
// This component never grants authorization. Host authorization is mandatory.
export function classify(input) {
  if (!input || input.schemaVersion !== '1' || !input.context ||
      typeof input.context !== 'object' || Array.isArray(input.context)) {
    return { decision: 'FLAG', modelVersion: 'baseline-rules-0.1', reason: 'invalid_context' };
  }
  const c = input.context;
  const route = c.route;
  const method = c.method;
  if (typeof route === 'string') {
    if (!route.startsWith('/') || route.length > 2048 || /[\\\u0000-\u001f]/.test(route)) {
      return { decision: 'FLAG', modelVersion: 'baseline-rules-0.1', reason: 'suspicious_route' };
    }
    if (typeof method !== 'string' || !['GET','POST','PUT','PATCH','DELETE'].includes(method)) {
      return { decision: 'FLAG', modelVersion: 'baseline-rules-0.1', reason: 'invalid_method' };
    }
  }
  // No general ALLOW from an untrained classifier. Review all other cases.
  return { decision: 'FLAG', modelVersion: 'baseline-rules-0.1', reason: 'untrained_model' };
}
