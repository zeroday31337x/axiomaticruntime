# JEV decision service — integration scaffold

This is a **rules-only, conservative placeholder**, not a trained JEV model. It returns FLAG by default and therefore blocks automatic execution through the fail-closed client. It is intended for integration tests only; do not enable on production request paths.

Build: `docker build -t zdx-jev-dev ./jev-service`.

Run privately: `docker run --rm -p 127.0.0.1:8091:8091 -e JEV_SERVICE_TOKEN='<at-least-32-random-bytes>' zdx-jev-dev`.

Endpoint: authenticated POST /v1/classify with `{"schemaVersion":"1","context":{"route":"/health","method":"GET"}}`. Health: GET /health.

The host-side client must use the trusted internal endpoint and its own server-held token; never expose this token to model inputs or public clients. The container should be deployed on a private Docker network, not exposed publicly.

Before real deployment: replace the placeholder with a validated trained classifier, version model artifacts, measure accuracy/latency, and ensure the model cannot authorize requests that host policy denies.
