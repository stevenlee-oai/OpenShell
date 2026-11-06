# Network supervisor

This crate forbids unsafe code, including its local tests. Typed socket APIs
provide original-destination lookup for transparent proxying.

Socket attribution tests pass a duplicate connected socket as a spawned child's
stdin. Re-executing the test binary checks multiple holders with the same binary
identity; executing a different binary checks ambiguous shared-socket identity.
The fixture kills and reaps the child when the parent test ends.

The manual proxy performance baseline still counts allocations. Its test-only
global allocator uses `openshell-driver-vm::allocation_tracking`; the unsafe
allocator implementation belongs to the VM crate. The VM dependency disables
default features, so this instrumentation does not
require the compute runtime or Unix-only sandbox library. It is a development
dependency only.

## Sandbox instance inputs

`run_networking` takes a `SandboxInstanceNetwork` with the sandbox identity,
the sandbox instance's `GatewayEndpoint`, the SPIFFE Workload API socket for
provider token grants, the `policy.local` denial source, and proxy CA files.
None of these are read from the process environment, so one process can run
several sandbox instances. Each instance owns its provider token cache and
HTTP client; a token acquired for one sandbox is never served to another.
Without a Workload API socket, token grants fail closed. A process hosting
several instances serves `/v1/denials` from a per-instance
`SandboxInstanceDenialLog` instead of the shared shorthand log files.

## Reserved destinations

`preauthorize_transparent_open` matches a staged TCP open against the reserved
OTLP relay address (`openshell_core::sandbox_env::OTLP_RELAY_ADDR`) before host
mapping, policy evaluation, and SSRF checks. The address is an unroutable
label, so the proxy never dials it. When `run_networking` receives a
`ReservedDestination`, the proxy hands the workload stream to its
`ReservedStreamHandler`; a handler that refuses, for example at its connection
cap, turns the open into a resource-exhausted denial. Without a handler, the
proxy denies the open at once. It logs the first attempt at warn and later ones
at debug, and emits no OCSF denial event: a standard OpenTelemetry SDK retries
for the life of the agent, and one event per retry would flood the OCSF log.
The supervisor installs its OTLP relay receiver as the handler while the agent
trace relay is active.

## Static credential placement

Substitution checks the declared request location before writing upstream.
Credentials without placement metadata default to the Authorization header. HTTP placement violations return a safe 403 response;
WebSocket violations close the connection with policy denial. Both paths emit a
domain event and a detection finding without credential values or placeholders.
Explicit body and WebSocket
rewrite flags authorize those locations for ordinary static credentials. SigV4
signing retains the endpoint-scoped resolver's existing trusted access.

## Test an external request credential authority

The network test suite exercises request-time bearer injection with a controlled
TLS authority. To exercise an operator's authority and HTTPS MCP origin, run
the ignored test with a private JSON descriptor:

```sh
OPENSHELL_TEST_BROKER_REQUEST=/path/to/private-request.json \
  cargo test -p openshell-supervisor-network --lib external_request_credential_dispatch \
  -- --ignored --nocapture
```

Use a regular file readable only by your user (mode 0600). Specify the
registration in `middlewareName`, `brokerUrl`, `brokerCaPem` and `audience`.
Supply its gateway-issued `supervisorToken` and matching `sandboxId`,
`sandboxName` and `workspace`. `bindingConfig` holds the authority's
policy configuration. The fixture connects to `originAddress` (IP and port),
validates TLS against `originHost` with `originCaPem`, and sends a
`tools/call` JSON object from `body` to the logical `originHost`,
`originPort` and `path`.

The test prints `OPENSHELL_TEST_HTTP_STATUS` from the downstream response.
Inspect a controlled origin for the actual arrival, credential version, and
absence of denied requests without recording raw bearer values. Run the probe
again after refresh or revocation to compare decisions. The fixture executes
the inspected supervisor relay in process; the operator supplies the identity
and endpoint that a live gateway and isolation backend normally provision.
